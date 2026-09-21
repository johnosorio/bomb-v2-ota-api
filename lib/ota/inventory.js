// User-scoped PostgREST adapter. No process-memory fallback on DB failure.
export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const DEVICE_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
const FIELDS = "id,scope_id,device_id,model,label,created_by,created_at";
const own = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
export class OtaError extends Error {
  constructor(status, code) { super(code); this.status = status; this.code = code; }
}
const invalid = () => { throw new OtaError(400, "INVALID_INPUT"); };
const unavailable = () => { throw new OtaError(503, "OTA_UNAVAILABLE"); };
const plain = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

export function registration(body) {
  if (!plain(body) || Object.keys(body).length !== 3 ||
      !["scope_id", "device_id", "label"].every((key) => own(body, key))) invalid();
  if (typeof body.scope_id !== "string" || !UUID.test(body.scope_id) ||
      typeof body.device_id !== "string" || !DEVICE_ID.test(body.device_id) ||
      typeof body.label !== "string" || body.label !== body.label.trim() ||
      [...body.label].length < 1 || [...body.label].length > 80 || /[\u0000-\u001f\u007f]/u.test(body.label)) invalid();
  return { scope_id: body.scope_id.toLowerCase(), device_id: body.device_id, label: body.label };
}

export function listing(query = {}) {
  if (!plain(query) || Object.keys(query).some((key) => !["scope_id", "limit", "offset"].includes(key)) ||
      typeof query.scope_id !== "string" || !UUID.test(query.scope_id)) invalid();
  const number = (key, fallback, minimum, maximum) => {
    if (!own(query, key)) return fallback;
    if (typeof query[key] !== "string" || !/^(0|[1-9][0-9]*)$/.test(query[key])) invalid();
    const value = Number(query[key]);
    if (!Number.isSafeInteger(value) || value < minimum || value > maximum) invalid();
    return value;
  };
  return { scope_id: query.scope_id.toLowerCase(), limit: number("limit", 50, 1, 100), offset: number("offset", 0, 0, 1000000) };
}

export function configuration(env) {
  if (env.OTA_ADMIN_ENABLED !== "true") throw new OtaError(503, "OTA_ADMIN_DISABLED");
  let url;
  try { url = new URL(env.SUPABASE_URL); } catch { unavailable(); }
  if (url.protocol !== "https:" || !/^[a-z0-9-]+\.supabase\.co$/.test(url.hostname) ||
      url.port || url.username || url.password || url.search || url.hash || url.pathname !== "/" ||
      !/^sb_publishable_[A-Za-z0-9_-]+$/.test(env.SUPABASE_PUBLISHABLE_KEY || "")) unavailable();
  return { origin: url.origin, key: env.SUPABASE_PUBLISHABLE_KEY };
}

function device(row) {
  if (!plain(row) || !["id", "scope_id", "created_by"].every((key) => typeof row[key] === "string" && UUID.test(row[key])) ||
      row.model !== "CoreS3" || typeof row.device_id !== "string" || !DEVICE_ID.test(row.device_id) ||
      typeof row.label !== "string" || typeof row.created_at !== "string") unavailable();
  return Object.fromEntries(FIELDS.split(",").map((key) => [key, row[key]]));
}

export function inventory(config, authorization, fetchImpl = globalThis.fetch) {
  // Do not decode/trust a caller-supplied actor. Auth server verifies this token.
  if (typeof authorization !== "string" || !/^Bearer [A-Za-z0-9._~-]+$/i.test(authorization) || authorization.length > 8192)
    throw new OtaError(401, "UNAUTHENTICATED");
  const headers = { apikey: config.key, Authorization: authorization, Accept: "application/json" };
  async function request(path, options = {}, auth = false) {
    let response, payload;
    try {
      response = await fetchImpl(`${config.origin}${path}`, {
        ...options, headers: { ...headers, ...options.headers },
        redirect: "error", signal: AbortSignal.timeout(5000)
      });
      payload = await response.json();
    } catch { unavailable(); }
    if (!response.ok) {
      if (auth && [401, 403].includes(response.status)) throw new OtaError(401, "UNAUTHENTICATED");
      if (!auth && response.status === 401) throw new OtaError(401, "UNAUTHENTICATED");
      if (!auth && response.status < 500) {
        if (payload?.code === "42501") throw new OtaError(403, "FORBIDDEN");
        if (payload?.code === "23505") throw new OtaError(409, "DEVICE_CONFLICT");
        if (payload?.code === "22023") throw new OtaError(400, "INVALID_INPUT");
      }
      unavailable();
    }
    return payload;
  }
  return {
    async authenticate() {
      const user = await request("/auth/v1/user", {}, true);
      if (!plain(user) || typeof user.id !== "string" || !UUID.test(user.id)) unavailable();
      if (user.is_anonymous === true) throw new OtaError(403, "FORBIDDEN");
      return user.id;
    },
    async list({ scope_id, limit, offset }, userId) {
      const access = new URLSearchParams({ select: "scope_id", scope_id: `eq.${scope_id}`, user_id: `eq.${userId}`, limit: "1" });
      const memberships = await request(`/rest/v1/ota_memberships?${access}`);
      if (!Array.isArray(memberships)) unavailable();
      if (!memberships.length) throw new OtaError(403, "FORBIDDEN");
      const query = new URLSearchParams({ select: FIELDS, scope_id: `eq.${scope_id}`, order: "created_at.asc,id.asc", limit: String(limit), offset: String(offset) });
      const rows = await request(`/rest/v1/ota_devices?${query}`);
      if (!Array.isArray(rows) || rows.length > limit) unavailable();
      return rows.map((row) => { if (row.scope_id !== scope_id) unavailable(); return device(row); });
    },
    async register({ scope_id, device_id, label }) {
      const row = await request("/rest/v1/rpc/ota_register_device", {
        method: "POST", headers: { "Content-Type": "application/json", Accept: "application/vnd.pgrst.object+json" },
        body: JSON.stringify({ p_scope_id: scope_id, p_device_id: device_id, p_label: label })
      });
      if (row?.scope_id !== scope_id || row?.device_id !== device_id || row?.label !== label) unavailable();
      return device(row);
    }
  };
}
