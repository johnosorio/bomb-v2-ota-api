import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign, webcrypto } from "node:crypto";
import { deviceProofInput, sha256, verifyDeviceRequest } from "../lib/ota/device-proof.js";
import { OtaError } from "../lib/ota/inventory.js";

// Test-only P-256 keys are generated in RAM and never written or logged.
const pair = () => generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const device = pair();
const realm = "production";
const challenge = { action: "challenge", mac: "02:00:00:00:00:01", client_nonce: "ab".repeat(32) };
const exchange = { ...challenge, action: "exchange", device_id: "10000000-0000-0000-0000-000000000001",
  credential_id: "20000000-0000-0000-0000-000000000002", challenge_id: "30000000-0000-0000-0000-000000000003",
  nonce: "cd".repeat(32) };

function request(body = challenge, signer = device) {
  const der = signer.publicKey.export({ type: "spki", format: "der" });
  const public_key = der.toString("base64url");
  const input = deviceProofInput(body, realm, sha256(der));
  const signature = sign("sha256", input, { key: signer.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
  return { ...body, public_key, signature };
}
const rejected = (fn, code = "INVALID_INPUT") => assert.throws(fn,
  (error) => error instanceof OtaError && error.status === (code === "INVALID_DEVICE_PROOF" ? 401 : 400) && error.code === code);

test("P-256 proof accepts only canonical SPKI and has an independent IEEE-P1363 transcript", async () => {
  const body = request();
  const verified = verifyDeviceRequest(body, realm);
  assert.deepEqual(verified, { action: "challenge", realm, mac: challenge.mac,
    device_key_sha256: sha256(device.publicKey.export({ type: "spki", format: "der" })), client_nonce: challenge.client_nonce });
  const key = await webcrypto.subtle.importKey("spki", Buffer.from(body.public_key, "base64url"),
    { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  assert.equal(await webcrypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key,
    Buffer.from(body.signature, "base64url"), deviceProofInput(challenge, realm, verified.device_key_sha256)), true);
});

test("proof binds signer, realm, action domain and every request nonce and identity", () => {
  const body = request(exchange);
  assert.equal(verifyDeviceRequest(body, realm).action, "exchange");
  rejected(() => verifyDeviceRequest(body, "staging"), "INVALID_DEVICE_PROOF");
  rejected(() => verifyDeviceRequest({ ...body, action: "challenge" }, realm), "INVALID_INPUT");
  for (const changed of [{ device_id: "10000000-0000-0000-0000-000000000009" },
    { credential_id: "20000000-0000-0000-0000-000000000009" }, { client_nonce: "ef".repeat(32) },
    { nonce: "ef".repeat(32) }, { challenge_id: "30000000-0000-0000-0000-000000000009" },
    { public_key: request(challenge, pair()).public_key }, { signature: request(exchange, pair()).signature }])
    rejected(() => verifyDeviceRequest({ ...body, ...changed }, realm), "INVALID_DEVICE_PROOF");
});

test("proof rejects malformed keys, signatures, curves and unknown fields before acceptance", () => {
  const body = request();
  const p384 = generateKeyPairSync("ec", { namedCurve: "secp384r1" }).publicKey.export({ type: "spki", format: "der" }).toString("base64url");
  for (const changed of [{ public_key: "not-base64" }, { public_key: "A".repeat(122) }, { public_key: p384 },
    { signature: "A".repeat(85) }, { signature: `${body.signature}=` }, { extra: true },
    { device_id: exchange.device_id }, { credential_id: exchange.credential_id }, { mac: "02:00:00:00:00:1" },
    { client_nonce: "AB".repeat(32) }]) rejected(() => verifyDeviceRequest({ ...body, ...changed }, realm));
  for (const badRealm of ["", "Production", "a".repeat(41), null]) rejected(() => verifyDeviceRequest(body, badRealm));
});
