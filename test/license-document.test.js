import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign, webcrypto } from "node:crypto";
import { signLicense, verifyLicense, LicenseDocumentError, MAX_LICENSE_BYTES } from "../lib/ota/license-document.js";

// Synthetic keys live only in this test process. No real credentials or fixtures
// containing private keys are read, printed or written to disk.
const pair = () => generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const signing = pair();
const keys = new Map([["test-key", signing.publicKey]]);
const grant = { v: 1, iss: "bomb-ota", aud: "bomb-cores3-game",
  sub: "10000000-0000-0000-0000-000000000001", credential_id: "20000000-0000-0000-0000-000000000002",
  device_key_sha256: "ab".repeat(32), mac: "02:00:00:00:00:01", model: "CoreS3",
  license_id: "30000000-0000-0000-0000-000000000003", revision: 2,
  iat: 1800000000, nbf: 1800000000, exp: 1800003600 };
const expected = { sub: grant.sub, credential_id: grant.credential_id,
  device_key_sha256: grant.device_key_sha256, mac: grant.mac, minimum_revision: 2 };
const issue = (value = grant, opts = {}) => signLicense(value, { kid: "test-key", privateKey: signing.privateKey, ...opts });
const check = (token, opts = {}) => verifyLicense(token, { keys, expected, now: grant.iat, ...opts });
const rejected = (fn) => assert.throws(fn, (e) => e instanceof LicenseDocumentError && e.message === "INVALID_LICENSE_DOCUMENT");
const b64 = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
const rawIssue = (header, body) => {
  const input = `${typeof header === "string" ? Buffer.from(header).toString("base64url") : b64(header)}.${typeof body === "string" ? Buffer.from(body).toString("base64url") : b64(body)}`;
  return `${input}.${sign("sha256", Buffer.from(input), { key: signing.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url")}`;
};
const header = { alg: "ES256", typ: "bomb-license+jwt", kid: "test-key" };

test("ES256 license round trip is independently verified with WebCrypto", async () => {
  const token = issue();
  assert.deepEqual(check(token), grant);
  assert.ok(Object.isFrozen(check(token)));
  const [h, p, s] = token.split(".");
  assert.equal(Buffer.from(s, "base64url").length, 64);
  const publicKey = await webcrypto.subtle.importKey("spki", signing.publicKey.export({ type: "spki", format: "der" }),
    { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  assert.equal(await webcrypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, publicKey,
    Buffer.from(s, "base64url"), Buffer.from(`${h}.${p}`)), true);
});
test("payload/header/signature mutation and another signer are rejected", () => {
  const token = issue(); const [h, p, s] = token.split(".");
  for (const modified of [`${h}.${b64({ ...grant, exp: grant.exp + 100 })}.${s}`,
    `${b64({ ...header, kid: "unknown" })}.${p}.${s}`, `${h}.${p}.${"A".repeat(86)}`]) rejected(() => check(modified));
  rejected(() => check(token, { keys: new Map([["test-key", pair().publicKey]]) }));
});
test("fixed algorithm/type and local key registry reject confusion and remote keys", () => {
  for (const changed of [{ ...header, alg: "none" }, { ...header, alg: "HS256" },
    { ...header, typ: "JWT" }, { ...header, jku: "https://example.invalid/keys" },
    { ...header, kid: "__proto__" }, { ...header, kid: "../key" }]) rejected(() => check(rawIssue(changed, grant)));
  rejected(() => check(issue(), { keys: { "test-key": signing.publicKey } }));
});
test("binding requires device ID, credential, public-key digest and MAC together", () => {
  for (const changed of [{ sub: grant.license_id }, { credential_id: grant.sub },
    { device_key_sha256: "cd".repeat(32) }, { mac: "02:00:00:00:00:02" }])
    rejected(() => check(issue(), { expected: { ...expected, ...changed } }));
});
test("strict numeric/date/revision/issuer/model/schema validation", () => {
  for (const changed of [{ v: 2 }, { iss: "demo" }, { aud: "admin" }, { model: "Bomb01" },
    { revision: 0 }, { revision: 1.5 }, { revision: 0x100000000 }, { exp: "1800003600" },
    { iat: 0 }, { nbf: 0 }, { exp: grant.nbf }, { nbf: grant.exp + 1 }, { iat: grant.exp },
    { private_key: "forbidden" }, { mac: "not-a-mac" }, { device_key_sha256: "ab" }]) {
    rejected(() => issue({ ...grant, ...changed }));
    rejected(() => check(rawIssue(header, { ...grant, ...changed })));
  }
});
test("expiration is exclusive, not-before inclusive; unknown clock fails closed", () => {
  const token = issue();
  assert.deepEqual(check(token, { now: grant.exp - 1 }), grant);
  for (const now of [grant.iat - 1, grant.exp, grant.exp + 1, 0, -1, NaN, 1.5, "1800000000", 0x100000000])
    rejected(() => check(token, { now }));
  rejected(() => check(issue({ ...grant, nbf: grant.iat + 1 })));
  const future = { ...grant, nbf: grant.iat + 10 };
  rejected(() => check(issue(future), { now: future.nbf - 1 }));
  assert.deepEqual(check(issue(future), { now: future.nbf }), future);
});
test("renewal advances revision; older SD document cannot bypass durable revision floor", () => {
  rejected(() => check(issue({ ...grant, revision: 1 })));
  assert.equal(check(issue({ ...grant, revision: 3 })).revision, 3);
  rejected(() => check(issue(), { expected: { ...expected, minimum_revision: 3 } }));
  for (const minimum_revision of [0, -1, undefined, "2"])
    rejected(() => check(issue(), { expected: { ...expected, minimum_revision } }));
});
test("noncanonical encoding, extra fields and duplicate JSON keys are rejected", () => {
  const token = issue();
  for (const value of ["", "a.b", "a.b.c.d", token + "=", "a".repeat(MAX_LICENSE_BYTES + 1), null, 42])
    rejected(() => check(value));
  const duplicate = JSON.stringify(grant).replace('"v":1', '"v":0,"v":1');
  rejected(() => check(rawIssue(header, duplicate)));
  rejected(() => check(rawIssue(header, JSON.stringify(grant, null, 2))));
  rejected(() => check(rawIssue(JSON.stringify(header).replace('"alg":"ES256"', '"alg":"none","alg":"ES256"'), grant)));
  rejected(() => check(rawIssue(JSON.stringify(header, null, 2), grant)));
  rejected(() => check(rawIssue({ kid: header.kid, typ: header.typ, alg: header.alg }, grant)));
  const [h, p, s] = token.split(".");
  rejected(() => check(`${h}=.${p}.${s}`));
  rejected(() => check(`${h}.${p}.${s.slice(0, -2)}`));
});
test("wrong curve/key type, absent context and malformed key configuration fail safely", () => {
  const otherCurve = generateKeyPairSync("ec", { namedCurve: "secp384r1" });
  for (const privateKey of [undefined, signing.publicKey, otherCurve.privateKey, "not a key"])
    rejected(() => issue(grant, { privateKey }));
  rejected(() => check(issue(), { keys: new Map([["test-key", signing.privateKey]]) }));
  rejected(() => check(issue(), { keys: new Map([["test-key", otherCurve.publicKey]]) }));
  rejected(() => verifyLicense(issue()));
  rejected(() => verifyLicense(issue(), null));
  rejected(() => signLicense(grant, null));
  for (const wrong of [generateKeyPairSync("ed25519"), generateKeyPairSync("rsa", { modulusLength: 2048 })]) {
    rejected(() => issue(grant, { privateKey: wrong.privateKey }));
    rejected(() => check(issue(), { keys: new Map([["test-key", wrong.publicKey]]) }));
  }
  rejected(() => check(issue(), { expected: {} }));
  rejected(() => issue(grant, { kid: "" }));
});
