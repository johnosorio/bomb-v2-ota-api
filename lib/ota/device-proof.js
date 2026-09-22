import { createHash, createPublicKey, verify } from "node:crypto";
import { OtaError } from "./inventory.js";

export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const HEX32 = /^[0-9a-f]{64}$/;
export const MAC = /^[0-9A-F]{2}(:[0-9A-F]{2}){5}$/;
export const REALM = /^[a-z0-9][a-z0-9_-]{0,39}$/;
export const matches = (pattern, value) => typeof value === "string" && pattern.test(value);
export const uint32 = (value, min = 0) => Number.isInteger(value) && value >= min && value <= 4294967295;
export const exact = (value, fields) => value !== null && typeof value === "object" && !Array.isArray(value) &&
  Object.keys(value).length === fields.length && fields.every((name) => Object.hasOwn(value, name));
const bad = () => { throw new OtaError(400, "INVALID_INPUT"); };
export const sha256 = (value) => createHash("sha256").update(value).digest("hex");

export function canonicalBytes(value, length) {
  if (typeof value !== "string" || value.length > Math.ceil(length * 4 / 3) || !/^[A-Za-z0-9_-]+$/.test(value)) bad();
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== length || bytes.toString("base64url") !== value) bad();
  return bytes;
}

function publicKey(value) {
  try {
    // The profile is uncompressed named-curve P-256 SPKI DER, exactly 91 bytes.
    const der = canonicalBytes(value, 91);
    const key = createPublicKey({ key: der, type: "spki", format: "der" });
    if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1" ||
        !key.export({ type: "spki", format: "der" }).equals(der)) bad();
    return { key, digest: sha256(der) };
  } catch { bad(); }
}

// Two different domain separators prevent a bootstrap proof becoming an exchange.
// ASCII, newline separated, trailing newline; no device wall clock required.
export function deviceProofInput(body, realm, digest) {
  return Buffer.from([body.action === "challenge" ? "BOMB-LICENSE-REQUEST" : "BOMB-LICENSE-EXCHANGE",
    "1", realm, ...(body.action === "exchange" ? [body.device_id, body.credential_id] : []), body.mac, digest, body.client_nonce,
    ...(body.action === "exchange" ? [body.challenge_id, body.nonce] : []), ""].join("\n"), "ascii");
}

export function verifyDeviceRequest(body, realm) {
  const fields = ["action", "mac", "public_key", "client_nonce", "signature"];
  if (body?.action === "exchange") fields.push("device_id", "credential_id", "challenge_id", "nonce");
  if (!exact(body, fields) || !["challenge", "exchange"].includes(body.action) || !matches(REALM, realm) ||
      !matches(MAC, body.mac) ||
      !matches(HEX32, body.client_nonce) || (body.action === "exchange" &&
      (!matches(UUID, body.device_id) || !matches(UUID, body.credential_id) || !matches(UUID, body.challenge_id) || !matches(HEX32, body.nonce)))) bad();
  const { key, digest } = publicKey(body.public_key);
  const signature = canonicalBytes(body.signature, 64);
  if (!verify("sha256", deviceProofInput(body, realm, digest), { key, dsaEncoding: "ieee-p1363" }, signature))
    throw new OtaError(401, "INVALID_DEVICE_PROOF");
  return { action: body.action, realm, mac: body.mac, device_key_sha256: digest, client_nonce: body.client_nonce,
    ...(body.action === "exchange" ? { device_id: body.device_id, credential_id: body.credential_id, challenge_id: body.challenge_id, nonce: body.nonce } : {}) };
}
