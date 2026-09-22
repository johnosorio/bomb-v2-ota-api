import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { createHandler } from "../api/ota/device-license.js";
import { deviceGateway } from "../lib/ota/device-gateway.js";
import { deviceProofInput, sha256 } from "../lib/ota/device-proof.js";

// Synthetic P-256 material exists only in this Node process; URLs/passwords are fixtures.
const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const realm = "production";
const challengeRequest = { action: "challenge", mac: "02:00:00:00:00:01", client_nonce: "ab".repeat(32) };
const ids = { device_id: "10000000-0000-0000-0000-000000000001", credential_id: "20000000-0000-0000-0000-000000000002",
  challenge_id: "30000000-0000-0000-0000-000000000003", nonce: "cd".repeat(32) };
const proof = (body = challengeRequest) => {
  const der = pair.publicKey.export({ type: "spki", format: "der" });
  return { ...body, public_key: der.toString("base64url"), signature: sign("sha256", deviceProofInput(body, realm, sha256(der)),
    { key: pair.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url") };
};
const env = (overrides = {}) => ({ OTA_DEVICE_GATEWAY_ENABLED: "true", OTA_DEVICE_REALM: realm, OTA_LICENSE_SIGNING_KID: "test-key",
  OTA_LICENSE_SIGNING_PRIVATE_KEY: pair.privateKey.export({ type: "pkcs8", format: "pem" }),
  OTA_GATEWAY_DATABASE_URL: "postgresql://bomb_ota_gateway:synthetic_password@db.abcdefghijklmnopqrst.supabase.co:5432/postgres", ...overrides });
const row = (overrides = {}) => ({ id: ids.challenge_id, device_id: ids.device_id, credential_id: ids.credential_id,
  mac: challengeRequest.mac, device_key_sha256: sha256(pair.publicKey.export({ type: "spki", format: "der" })), realm,
  client_nonce: challengeRequest.client_nonce, nonce: ids.nonce, issued_at: 1_800_000_000, expires_at: 1_800_000_120, ...overrides });

async function invoke(input = {}, settings = env(), dependencies = {}) {
  const result = { headers: {}, calls: 0 };
  const response = { setHeader(k, v) { result.headers[k] = v; }, status(v) { result.status = v; return this; },
    json(v) { result.calls += 1; result.body = v; return this; } };
  await createHandler({ env: settings, dependencies })({ method: "POST", query: {}, headers: { "content-type": "application/json" }, body: proof(), ...input }, response);
  return result;
}

test("HTTP gates reject method, query, size and type before configuration or DB", async () => {
  let transactions = 0;
  const dependencies = { transaction: async () => { transactions += 1; } };
  for (const [input, settings, status] of [
    [{ method: "GET" }, {}, 405], [{ query: { x: "1" } }, {}, 400],
    [{ headers: { "content-type": "text/plain" } }, {}, 415], [{ headers: { "content-type": "application/json", "content-length": "4097" } }, {}, 413],
    [{ body: "{" }, {}, 400], [{ body: "x".repeat(4097) }, {}, 413],
    [{ body: { circular: null } }, { OTA_DEVICE_GATEWAY_ENABLED: "false" }, 503]
  ]) {
    const result = await invoke(input, env(settings), dependencies);
    assert.equal(result.status, status);
  }
  assert.equal(transactions, 0);
});

test("proof and signer configuration fail closed before the database", async () => {
  let transactions = 0;
  const dependencies = { transaction: async () => { transactions += 1; } };
  const invalidProof = await invoke({ body: { ...proof(), signature: "A".repeat(86) } }, env(), dependencies);
  assert.deepEqual(invalidProof.body, { error: "INVALID_DEVICE_PROOF" });
  const other = generateKeyPairSync("ec", { namedCurve: "secp384r1" });
  const badSigner = await invoke({}, env({ OTA_LICENSE_SIGNING_PRIVATE_KEY: other.privateKey.export({ type: "pkcs8", format: "pem" }) }), dependencies);
  assert.deepEqual(badSigner.body, { error: "OTA_GATEWAY_UNAVAILABLE" });
  assert.equal(JSON.stringify(badSigner.body).includes("PRIVATE KEY"), false);
  assert.equal(transactions, 0);
});

test("gateway accepts only provider data bound to proof and within challenge time", async () => {
  const config = { realm, signer: { kid: "test-key", privateKey: pair.privateKey } };
  const transactionFor = (data) => async (operation) => operation(async () => ({ rows: [{ data }] }));
  const accepted = await deviceGateway(proof(), config, { nonce: () => ids.nonce, transaction: transactionFor(row()) });
  assert.deepEqual(accepted, { schema_version: 1, challenge: row() });
  for (const changed of [{ realm: "staging" }, { mac: "02:00:00:00:00:09" }, { expires_at: row().issued_at + 119 }])
    await assert.rejects(() => deviceGateway(proof(), config, { nonce: () => ids.nonce, transaction: transactionFor(row(changed)) }),
      (error) => error.code === "OTA_GATEWAY_UNAVAILABLE");
  const exchange = proof({ ...challengeRequest, action: "exchange", ...ids });
  const consumed = { challenge: row(), license: {}, observed_at: row().expires_at };
  await assert.rejects(() => deviceGateway(exchange, config, { transaction: transactionFor(consumed), respond: () => ({ forbidden: true }) }),
    (error) => error.code === "OTA_GATEWAY_UNAVAILABLE");
});
