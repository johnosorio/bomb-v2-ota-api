import { createPrivateKey, randomBytes } from "node:crypto";
import { OtaError } from "./inventory.js";
import { verifyDeviceRequest, UUID, HEX32, REALM, matches, uint32, exact } from "./device-proof.js";
import { createDeviceResponse } from "./device-response.js";
import { gatewayDatabaseConfig, gatewayTransaction } from "./gateway-db.js";

const unavailable = () => { throw new OtaError(503, "OTA_GATEWAY_UNAVAILABLE"); };
export function deviceGatewayConfig(env) {
  if (env.OTA_DEVICE_GATEWAY_ENABLED !== "true") throw new OtaError(503, "OTA_DEVICE_GATEWAY_DISABLED");
  try {
    if (!matches(REALM, env.OTA_DEVICE_REALM) || !matches(/^[A-Za-z0-9_-]{1,40}$/, env.OTA_LICENSE_SIGNING_KID) ||
        typeof env.OTA_LICENSE_SIGNING_PRIVATE_KEY !== "string" || env.OTA_LICENSE_SIGNING_PRIVATE_KEY.length > 8192 ||
        !env.OTA_LICENSE_SIGNING_PRIVATE_KEY.startsWith("-----BEGIN PRIVATE KEY-----")) unavailable();
    const key = createPrivateKey(env.OTA_LICENSE_SIGNING_PRIVATE_KEY);
    if (key.type !== "private" || key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") unavailable();
    return { realm: env.OTA_DEVICE_REALM, signer: { kid: env.OTA_LICENSE_SIGNING_KID, privateKey: key }, database: gatewayDatabaseConfig(env) };
  } catch { unavailable(); }
}

const challengeFields = ["id", "device_id", "credential_id", "mac", "device_key_sha256", "realm", "client_nonce", "nonce", "issued_at", "expires_at"];
function checkChallenge(c, proof) {
  if (!exact(c, challengeFields) || ![c.id, c.device_id, c.credential_id].every(v => matches(UUID, v)) ||
      !matches(HEX32, c.nonce) || !uint32(c.issued_at, 1) || !uint32(c.expires_at, 1) || c.expires_at !== c.issued_at + 120 ||
      !["mac", "device_key_sha256", "realm", "client_nonce"].every(k => c[k] === proof[k]) ||
      (proof.action === "exchange" && (c.id !== proof.challenge_id || c.nonce !== proof.nonce ||
        c.device_id !== proof.device_id || c.credential_id !== proof.credential_id))) unavailable();
  return c;
}

export async function deviceGateway(body, config, { transaction = gatewayTransaction(config.database),
  nonce = () => randomBytes(32).toString("hex"), respond = createDeviceResponse } = {}) {
  // Possession verification precedes every DB call. MAC is an identifier only.
  const proof = verifyDeviceRequest(body, config.realm);
  const identity = Object.fromEntries(["mac", "device_key_sha256", "realm", "client_nonce",
    ...(proof.action === "exchange" ? ["device_id", "credential_id"] : [])].map(k => [k, proof[k]]));
  return transaction(async (query) => {
    if (proof.action === "challenge") {
      const serverNonce = nonce();
      if (!matches(HEX32, serverNonce)) unavailable();
      const result = await query("SELECT public.ota_gateway_challenge($1::jsonb,$2::text) AS data", [JSON.stringify(identity), serverNonce]);
      if (result.rows.length !== 1) unavailable();
      return { schema_version: 1, challenge: checkChallenge(result.rows[0].data, proof) };
    }
    const result = await query("SELECT public.ota_gateway_consume($1::jsonb,$2::uuid,$3::text,$4::text) AS data",
      [JSON.stringify(identity), proof.challenge_id, proof.nonce, config.signer.kid]);
    const value = result.rows[0]?.data;
    if (result.rows.length !== 1 || !exact(value, ["challenge", "license", "observed_at"]) || !uint32(value.observed_at, 1)) unavailable();
    const challenge = checkChallenge(value.challenge, proof);
    if (value.observed_at < challenge.issued_at || value.observed_at >= challenge.expires_at) unavailable();
    // Sign before COMMIT, with the same device lock that administrative changes use.
    // Signing, audit and one-use consumption either all commit or all roll back.
    return respond(value.license, challenge, value.observed_at, config.signer);
  });
}
