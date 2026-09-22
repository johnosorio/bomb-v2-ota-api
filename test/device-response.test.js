import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { createDeviceResponse, verifyDeviceResponse } from "../lib/ota/device-response.js";

// Test-only P-256 keys are generated in RAM and never persisted or printed.
const pair = () => generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const signer = pair();
const keys = new Map([["test-key", signer.publicKey]]);
const now = 1_800_000_000;
const challenge = { id: "30000000-0000-0000-0000-000000000003", realm: "production",
  device_id: "10000000-0000-0000-0000-000000000001", credential_id: "20000000-0000-0000-0000-000000000002",
  device_key_sha256: "ab".repeat(32), mac: "02:00:00:00:00:01", client_nonce: "cd".repeat(32), nonce: "ef".repeat(32) };
const granted = { device_id: challenge.device_id, credential_id: challenge.credential_id, mac: challenge.mac,
  device_key_sha256: challenge.device_key_sha256, license_id: "40000000-0000-0000-0000-000000000004",
  revision: 2, status: "granted", issued_at: now - 60, not_before: now - 30, expires_at: now + 3_600 };
const expected = { device_id: challenge.device_id, credential_id: challenge.credential_id,
  device_key_sha256: challenge.device_key_sha256, mac: challenge.mac, realm: challenge.realm,
  challenge_id: challenge.id, client_nonce: challenge.client_nonce, nonce: challenge.nonce,
  minimum_revision: 2, last_server_time: now - 1, elapsed_seconds: 119 };
const emit = (row = granted, at = now) => createDeviceResponse(row, challenge, at, { kid: "test-key", privateKey: signer.privateKey });
const check = (response, options = {}) => verifyDeviceResponse(response, { keys, expected, ...options });
const rejected = (fn) => assert.throws(fn, (error) => error instanceof Error && error.message === "INVALID_DEVICE_RESPONSE");

test("signed valid license response binds the challenge and returns its license", () => {
  const response = emit();
  const verified = check(response);
  assert.equal(verified.status.state, "valid");
  assert.equal(verified.status.license_sha256.length, 64);
  assert.equal(verified.license.revision, granted.revision);
  assert.ok(Object.isFrozen(verified));
});

test("signed denials cover unlicensed, revoked, expired and not-yet-valid states", () => {
  const rows = [
    { ...granted, revision: 0, status: "unlicensed", issued_at: null, not_before: null, expires_at: null },
    { ...granted, status: "revoked" },
    { ...granted, expires_at: now },
    { ...granted, issued_at: now + 1, not_before: now + 1, expires_at: now + 3_600 }
  ];
  for (const [row, state] of rows.map((row, index) => [row, ["unlicensed", "revoked", "expired", "not_yet_valid"][index]])) {
    const result = verifyDeviceResponse(emit(row), { keys, expected: { ...expected, minimum_revision: row.revision } });
    assert.equal(result.status.state, state);
    assert.equal(result.license, null);
  }
});

test("tampering, type confusion, license swaps and mismatched context or revision are rejected", () => {
  const response = emit();
  const [header, payload, signature] = response.status_document.split(".");
  const changedPayload = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(payload, "base64url")), realm: "staging" })).toString("base64url");
  for (const changed of [{ ...response, status_document: `${header}.${changedPayload}.${signature}` },
    { ...response, schema_version: "1" }, { ...response, license_document: emit({ ...granted, license_id: "40000000-0000-0000-0000-000000000009" }).license_document }]) rejected(() => check(changed));
  rejected(() => check(response, { expected: { ...expected, nonce: "aa".repeat(32) } }));
  rejected(() => check(response, { expected: { ...expected, minimum_revision: granted.revision + 1 } }));
});

test("rollback, TTL bounds and expiry during transit fail closed", () => {
  const response = emit();
  rejected(() => check(response, { expected: { ...expected, last_server_time: now + 1 } }));
  for (const elapsed_seconds of [-1, 120, NaN, "119"]) rejected(() => check(response, { expected: { ...expected, elapsed_seconds } }));
  const nearExpiry = emit({ ...granted, expires_at: now + 60 });
  rejected(() => check(nearExpiry, { expected: { ...expected, elapsed_seconds: 61 } }));
});

test("malformed headers, unsupported algorithms and wrong keyring curves are rejected", () => {
  const response = emit();
  const [header, payload, signature] = response.status_document.split(".");
  const none = Buffer.from(JSON.stringify({ alg: "none", typ: "bomb-license-status+jwt", kid: "test-key" })).toString("base64url");
  for (const status_document of [`${none}.${payload}.${signature}`, `$.${payload}.${signature}`, `${header}.${payload}.A`])
    rejected(() => check({ ...response, status_document }));
  const p384 = generateKeyPairSync("ec", { namedCurve: "secp384r1" });
  rejected(() => check(response, { keys: new Map([["test-key", p384.publicKey]]) }));
  rejected(() => check(response, { keys: new Map([["test-key", signer.privateKey]]) }));
});
