import { configuration, OtaError, userScopedClient, UUID } from "./inventory.js";

const plain = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const own = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
const invalid = () => { throw new OtaError(400, "INVALID_INPUT"); };
const unavailable = () => { throw new OtaError(503, "OTA_UNAVAILABLE"); };

export function contextListing(query = {}) {
  if (!plain(query) || Object.keys(query).some((key) => !["action", "limit", "offset"].includes(key)) ||
      query.action !== "context") invalid();
  const number = (key, fallback, minimum, maximum) => {
    if (!own(query, key)) return fallback;
    if (typeof query[key] !== "string" || !/^(0|[1-9][0-9]*)$/.test(query[key])) invalid();
    const value = Number(query[key]);
    if (!Number.isSafeInteger(value) || value < minimum || value > maximum) invalid();
    return value;
  };
  return { limit: number("limit", 50, 1, 100), offset: number("offset", 0, 0, 1000000) };
}

function scope(row) {
  const joined = row?.ota_scopes;
  if (!plain(row) || typeof row.scope_id !== "string" || !UUID.test(row.scope_id) ||
      !["admin", "viewer"].includes(row.role) || !plain(joined) ||
      typeof joined.id !== "string" || !UUID.test(joined.id) || joined.id !== row.scope_id ||
      typeof joined.name !== "string" || joined.name !== joined.name.trim() ||
      [...joined.name].length < 1 || [...joined.name].length > 120 || /[\u0000-\u001f\u007f]/u.test(joined.name)) unavailable();
  return { id: row.scope_id, name: joined.name, role: row.role };
}

export function adminContext(env, authorization, fetchImpl = globalThis.fetch) {
  const client = userScopedClient(configuration(env), authorization, fetchImpl);
  return {
    authenticate: client.authenticate,
    async list({ limit, offset }, userId) {
      const query = new URLSearchParams({
        select: "scope_id,role,ota_scopes(id,name)", user_id: `eq.${userId}`,
        order: "scope_id.asc", limit: String(limit), offset: String(offset)
      });
      const rows = await client.request(`/rest/v1/ota_memberships?${query}`);
      if (!Array.isArray(rows) || rows.length > limit) unavailable();
      return rows.map(scope);
    }
  };
}
