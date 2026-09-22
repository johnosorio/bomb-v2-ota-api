// Node reference verifier/emitter. CoreS3 verification and durable clock are later work.
import { KeyObject, sign, verify } from "node:crypto";
import { signLicense, verifyLicense, LICENSE_ISSUER, LICENSE_AUDIENCE } from "./license-document.js";
import { UUID, HEX32, MAC, REALM, matches, uint32, exact, sha256 } from "./device-proof.js";

export const STATUS_TYPE = "bomb-license-status+jwt";
export const STATUS_AUDIENCE = "bomb-cores3-status";
export const RESPONSE_TTL = 120;
const KID = /^[A-Za-z0-9_-]{1,40}$/;
const fields = ["v", "iss", "aud", "realm", "sub", "credential_id", "device_key_sha256", "mac", "license_id",
  "revision", "state", "challenge_id", "client_nonce", "nonce", "server_time", "license_sha256"];
const bad = () => { throw new Error("INVALID_DEVICE_RESPONSE"); };
const encode = (v) => Buffer.from(JSON.stringify(v)).toString("base64url");
function key(value, type) {
  if (!(value instanceof KeyObject) || value.type !== type || value.asymmetricKeyType !== "ec" ||
      value.asymmetricKeyDetails?.namedCurve !== "prime256v1") bad();
  return value;
}
function decode(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) bad();
  const b = Buffer.from(value, "base64url");
  if (b.toString("base64url") !== value) bad();
  return b;
}
function json(value) {
  const p = JSON.parse(decode(value).toString("utf8"));
  if (encode(p) !== value) bad();
  return p;
}
function claims(p) {
  if (!exact(p, fields) || p.v !== 1 || p.iss !== LICENSE_ISSUER || p.aud !== STATUS_AUDIENCE ||
      !matches(REALM, p.realm) || ![p.sub, p.credential_id, p.license_id, p.challenge_id].every(v => matches(UUID, v)) ||
      !matches(MAC, p.mac) || ![p.device_key_sha256, p.client_nonce, p.nonce].every(v => matches(HEX32, v)) ||
      !uint32(p.revision) || !uint32(p.server_time, 1) ||
      !["unlicensed", "revoked", "expired", "not_yet_valid", "valid"].includes(p.state) ||
      (p.state === "unlicensed" ? p.revision !== 0 : p.revision === 0) ||
      (p.state === "valid" ? !matches(HEX32, p.license_sha256) : p.license_sha256 !== null)) bad();
  return Object.fromEntries(fields.map(k => [k, p[k]]));
}

export function createDeviceResponse(row, challenge, now, signer) {
  if (!row || !uint32(now, 1) || !uint32(row.revision) || !matches(KID, signer?.kid) ||
      !["device_id", "credential_id", "mac", "device_key_sha256"].every(k => row[k] === challenge[k])) bad();
  key(signer.privateKey, "private");
  let state;
  if (row.status === "unlicensed") {
    if (row.revision !== 0 || row.issued_at !== null || row.not_before !== null || row.expires_at !== null) bad();
    state = "unlicensed";
  } else {
    if (!["granted", "revoked"].includes(row.status) || row.revision === 0 ||
        ![row.issued_at, row.not_before, row.expires_at].every(v => uint32(v, 1)) ||
        row.issued_at >= row.expires_at || row.not_before >= row.expires_at) bad();
    state = row.status === "revoked" ? "revoked" : now >= row.expires_at ? "expired" :
      now < Math.max(row.issued_at, row.not_before) ? "not_yet_valid" : "valid";
  }
  const license = state === "valid" ? signLicense({ v: 1, iss: LICENSE_ISSUER, aud: LICENSE_AUDIENCE,
    sub: row.device_id, credential_id: row.credential_id, device_key_sha256: row.device_key_sha256,
    mac: row.mac, model: "CoreS3", license_id: row.license_id, revision: row.revision,
    iat: row.issued_at, nbf: row.not_before, exp: row.expires_at }, signer) : null;
  const p = claims({ v: 1, iss: LICENSE_ISSUER, aud: STATUS_AUDIENCE, realm: challenge.realm,
    sub: row.device_id, credential_id: row.credential_id, device_key_sha256: row.device_key_sha256,
    mac: row.mac, license_id: row.license_id, revision: row.revision, state,
    challenge_id: challenge.id, client_nonce: challenge.client_nonce, nonce: challenge.nonce,
    server_time: now, license_sha256: license === null ? null : sha256(license) });
  const input = `${encode({ alg: "ES256", typ: STATUS_TYPE, kid: signer.kid })}.${encode(p)}`;
  const signature = sign("sha256", Buffer.from(input, "ascii"), { key: signer.privateKey, dsaEncoding: "ieee-p1363" });
  return { schema_version: 1, status_document: `${input}.${signature.toString("base64url")}`, license_document: license };
}

export function verifyDeviceResponse(response, { keys, expected } = {}) {
  try {
    if (!exact(response, ["schema_version", "status_document", "license_document"]) || response.schema_version !== 1 ||
        typeof response.status_document !== "string" || response.status_document.length > 4096 || !(keys instanceof Map) ||
        !exact(expected, ["device_id", "credential_id", "device_key_sha256", "mac", "realm", "challenge_id", "client_nonce", "nonce",
          "minimum_revision", "last_server_time", "elapsed_seconds"]) || !uint32(expected.minimum_revision) ||
        !uint32(expected.last_server_time) || !Number.isFinite(expected.elapsed_seconds) ||
        expected.elapsed_seconds < 0 || expected.elapsed_seconds >= RESPONSE_TTL) bad();
    const parts = response.status_document.split(".");
    if (parts.length !== 3) bad();
    const h = json(parts[0]);
    if (!exact(h, ["alg", "typ", "kid"]) || h.alg !== "ES256" || h.typ !== STATUS_TYPE || !matches(KID, h.kid) ||
        !keys.has(h.kid) || encode({ alg: h.alg, typ: h.typ, kid: h.kid }) !== parts[0]) bad();
    const signature = decode(parts[2]);
    if (signature.length !== 64 || !verify("sha256", Buffer.from(`${parts[0]}.${parts[1]}`, "ascii"),
      { key: key(keys.get(h.kid), "public"), dsaEncoding: "ieee-p1363" }, signature)) bad();
    const p = claims(json(parts[1]));
    if (encode(p) !== parts[1] || p.sub !== expected.device_id ||
        !["credential_id", "device_key_sha256", "mac", "realm", "challenge_id", "client_nonce", "nonce"].every(k => p[k] === expected[k]) ||
        p.revision < expected.minimum_revision || p.server_time < expected.last_server_time) bad();
    let license = null;
    if (p.state === "valid") {
      if (typeof response.license_document !== "string" || response.license_document.length > 2048 ||
          sha256(response.license_document) !== p.license_sha256) bad();
      // Conservative upper time bound: the server observation happened after
      // the pending request began. Never revive a grant expired in transit.
      license = verifyLicense(response.license_document, { keys, now: p.server_time + Math.ceil(expected.elapsed_seconds), expected: {
        sub: p.sub, credential_id: p.credential_id, device_key_sha256: p.device_key_sha256, mac: p.mac, minimum_revision: p.revision } });
      if (license.revision !== p.revision || license.license_id !== p.license_id) bad();
    } else if (response.license_document !== null) bad();
    return Object.freeze({ status: Object.freeze(p), license });
  } catch { bad(); }
}
