// OTA-03 building block, NOT an HTTP issuer or an authorization/DB adapter.
// Only server-authorized, durably versioned grants may reach signLicense().
import { KeyObject, sign, verify } from "node:crypto";

export const LICENSE_ISSUER = "bomb-ota";
export const LICENSE_AUDIENCE = "bomb-cores3-game";
export const LICENSE_TYPE = "bomb-license+jwt";
export const MAX_LICENSE_BYTES = 2048;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const KID = /^[A-Za-z0-9_-]{1,40}$/;
const MAC = /^(?:[0-9A-F]{2}:){5}[0-9A-F]{2}$/;
const HASH = /^[0-9a-f]{64}$/;
const FIELDS = ["v", "iss", "aud", "sub", "credential_id", "device_key_sha256", "mac", "model",
  "license_id", "revision", "iat", "nbf", "exp"];
export class LicenseDocumentError extends Error {
  constructor() { super("INVALID_LICENSE_DOCUMENT"); this.name = "LicenseDocumentError"; }
}
const invalid = () => { throw new LicenseDocumentError(); };
const plain = (value) => value !== null && typeof value === "object" &&
  (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
const uint32 = (value) => Number.isInteger(value) && value >= 0 && value <= 0xffffffff;
function exact(value, names) {
  if (!plain(value) || Object.keys(value).length !== names.length ||
      !names.every((name) => Object.hasOwn(value, name))) invalid();
}
function matches(pattern, value) { return typeof value === "string" && pattern.test(value); }
function key(value, type) {
  if (!(value instanceof KeyObject) || value.type !== type || value.asymmetricKeyType !== "ec" ||
      value.asymmetricKeyDetails?.namedCurve !== "prime256v1") invalid();
  return value;
}
function claims(value) {
  exact(value, FIELDS);
  if (value.v !== 1 || value.iss !== LICENSE_ISSUER || value.aud !== LICENSE_AUDIENCE ||
      value.model !== "CoreS3" || ![value.sub, value.credential_id, value.license_id].every((v) => matches(UUID, v)) ||
      !matches(HASH, value.device_key_sha256) || !matches(MAC, value.mac) ||
      ![value.revision, value.iat, value.nbf, value.exp].every(uint32) || value.revision === 0 ||
      value.iat === 0 || value.nbf === 0 || value.nbf >= value.exp || value.iat >= value.exp) invalid();
  return Object.fromEntries(FIELDS.map((field) => [field, value[field]]));
}
const encode = (value) => Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
function decode(part) {
  if (typeof part !== "string" || !/^[A-Za-z0-9_-]+$/.test(part)) invalid();
  const bytes = Buffer.from(part, "base64url");
  if (bytes.toString("base64url") !== part) invalid();
  return bytes;
}
function json(part) {
  const bytes = decode(part);
  const value = JSON.parse(bytes.toString("utf8"));
  // Restricted profile: no duplicate keys, whitespace, escaped-key aliases or
  // alternate JSON encodings. The issuer emits exactly this representation.
  if (encode(value) !== part) invalid();
  return value;
}
function safe(operation) {
  try { return operation(); } catch { invalid(); }
}

export function signLicense(document, options = {}) {
  return safe(() => {
    const { kid, privateKey } = options;
    if (!matches(KID, kid)) invalid();
    const payload = claims(document);
    const input = `${encode({ alg: "ES256", typ: LICENSE_TYPE, kid })}.${encode(payload)}`;
    const signature = sign("sha256", Buffer.from(input, "ascii"),
      { key: key(privateKey, "private"), dsaEncoding: "ieee-p1363" });
    const token = `${input}.${signature.toString("base64url")}`;
    if (signature.length !== 64 || token.length > MAX_LICENSE_BYTES) invalid();
    return token;
  });
}

// expected comes from enrolled identity + durable revision floor, never claims
// supplied by an untrusted caller. This does not check revocation or persist SD.
export function verifyLicense(token, options = {}) {
  return safe(() => {
    const { keys, expected, now } = options;
    if (typeof token !== "string" || token.length > MAX_LICENSE_BYTES || !(keys instanceof Map) ||
        !uint32(now) || now === 0) invalid();
    exact(expected, ["sub", "credential_id", "device_key_sha256", "mac", "minimum_revision"]);
    if (!matches(UUID, expected.sub) || !matches(UUID, expected.credential_id) ||
        !matches(HASH, expected.device_key_sha256) || !matches(MAC, expected.mac) ||
        !uint32(expected.minimum_revision) || expected.minimum_revision === 0) invalid();
    const parts = token.split(".");
    if (parts.length !== 3) invalid();
    const header = json(parts[0]);
    exact(header, ["alg", "typ", "kid"]);
    if (header.alg !== "ES256" || header.typ !== LICENSE_TYPE || !matches(KID, header.kid) ||
        !keys.has(header.kid)) invalid();
    if (encode({ alg: "ES256", typ: LICENSE_TYPE, kid: header.kid }) !== parts[0]) invalid();
    const signature = decode(parts[2]);
    if (signature.length !== 64 || !verify("sha256", Buffer.from(`${parts[0]}.${parts[1]}`, "ascii"),
      { key: key(keys.get(header.kid), "public"), dsaEncoding: "ieee-p1363" }, signature)) invalid();
    const document = claims(json(parts[1]));
    if (encode(document) !== parts[1] || ["sub", "credential_id", "device_key_sha256", "mac"].some(
      (field) => document[field] !== expected[field]) || document.revision < expected.minimum_revision ||
      document.iat > now || document.nbf > now || now >= document.exp) invalid();
    return Object.freeze(document);
  });
}
