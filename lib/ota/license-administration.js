// Administrative entitlements only. Never call the signer using these receipts.
import { configuration, userScopedClient, UUID, OtaError } from "./inventory.js";

const plain = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const exact = (value, keys) => plain(value) && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
const uuid = (value) => typeof value === "string" && UUID.test(value);
const uint32 = (value, min = 0) => Number.isInteger(value) && value >= min && value <= 4294967295;
const invalid = () => { throw new OtaError(400, "INVALID_INPUT"); };
const unavailable = () => { throw new OtaError(503, "OTA_UNAVAILABLE"); };
const actions = {
  approve_identity: ["action", "mac", "device_key_sha256"],
  grant: ["action", "expected_revision", "not_before", "expires_at"],
  revoke: ["action", "expected_revision"]
};

export function licenseCommand(body) {
  if (!plain(body) || typeof body.action !== "string" || !Object.hasOwn(actions, body.action)) invalid();
  const keys = actions[body.action];
  if (!exact(body, ["device_id", "request_id", ...keys]) || !uuid(body.device_id) || !uuid(body.request_id)) invalid();
  if (body.action === "approve_identity") {
    if (typeof body.mac !== "string" || !/^[0-9A-F]{2}(:[0-9A-F]{2}){5}$/.test(body.mac) ||
        typeof body.device_key_sha256 !== "string" || !/^[0-9a-f]{64}$/.test(body.device_key_sha256)) invalid();
  } else {
    if (!uint32(body.expected_revision)) invalid();
    if (body.action === "grant" && (!uint32(body.not_before, 1) || !uint32(body.expires_at, 1) || body.not_before >= body.expires_at)) invalid();
  }
  return { device_id: body.device_id.toLowerCase(), request_id: body.request_id.toLowerCase(),
    command: Object.fromEntries(keys.map((key) => [key, body[key]])) };
}

export function licenseQuery(query) {
  if (!exact(query, ["device_id"]) || !uuid(query.device_id)) invalid();
  return query.device_id.toLowerCase();
}

const stateKeys = ["device_id", "credential_id", "mac", "device_key_sha256", "license_id", "revision", "status",
  "issued_at", "not_before", "expires_at", "updated_by", "updated_at"];
function state(row, deviceId) {
  if (!plain(row) || row.device_id !== deviceId || !["device_id", "credential_id", "license_id", "updated_by"].every((key) => uuid(row[key])) ||
      !uint32(row.revision) || typeof row.mac !== "string" || !/^[0-9A-F]{2}(:[0-9A-F]{2}){5}$/.test(row.mac) ||
      typeof row.device_key_sha256 !== "string" || !/^[0-9a-f]{64}$/.test(row.device_key_sha256) ||
      typeof row.updated_at !== "string" || !Number.isFinite(Date.parse(row.updated_at))) unavailable();
  if (row.status === "unlicensed") {
    if (row.revision !== 0 || row.issued_at !== null || row.not_before !== null || row.expires_at !== null) unavailable();
  } else if (["granted", "revoked"].includes(row.status)) {
    if (row.revision === 0 || !["issued_at", "not_before", "expires_at"].every((key) => uint32(row[key], 1)) ||
        row.issued_at >= row.expires_at || row.not_before >= row.expires_at) unavailable();
  } else unavailable();
  return Object.fromEntries(stateKeys.map((key) => [key, row[key]]));
}

export function licenseAdministration(env, authorization, fetchImpl) {
  if (env.OTA_LICENSE_ADMIN_ENABLED !== "true") throw new OtaError(503, "OTA_LICENSE_ADMIN_DISABLED");
  const client = userScopedClient(configuration(env), authorization, fetchImpl, "LICENSE_CONFLICT");
  const rpc = (name, body) => client.request(`/rest/v1/rpc/${name}`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body)
  });
  return {
    authenticate: client.authenticate,
    async get(deviceId) {
      const row = await rpc("ota_get_device_license", { p_device_id: deviceId });
      return row === null ? null : state(row, deviceId);
    },
    async mutate({ device_id, request_id, command }) {
      const receipt = await rpc("ota_admin_license", { p_device_id: device_id, p_request_id: request_id, p_command: command });
      if (!plain(receipt) || receipt.device_id !== device_id || receipt.request_id !== request_id || receipt.action !== command.action) unavailable();
      const snapshot = state(receipt.snapshot, device_id);
      if (command.action === "approve_identity") {
        if (snapshot.status !== "unlicensed" || snapshot.mac !== command.mac || snapshot.device_key_sha256 !== command.device_key_sha256) unavailable();
      } else if (snapshot.revision !== command.expected_revision + 1 || snapshot.status !== (command.action === "grant" ? "granted" : "revoked") ||
          (command.action === "grant" && (snapshot.not_before !== command.not_before || snapshot.expires_at !== command.expires_at))) unavailable();
      return { device_id, request_id, action: command.action, snapshot };
    }
  };
}
