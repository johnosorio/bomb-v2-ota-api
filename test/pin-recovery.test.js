import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { createHandler as createDeviceHandler } from "../lib/ota/pin-device-handler.js";
import { createHandler as createAdminHandler } from "../lib/ota/pin-admin-handler.js";
import { createHandler as createPortalHandler } from "../lib/ota/pin-portal-handler.js";
import { createHandler as createRouterHandler } from "../api/ota/pin.js";
import { actions, proofInput } from "../lib/ota/pin-recovery.js";
import { sha256 } from "../lib/ota/device-proof.js";

const realm = "production";
const mac = "02:00:00:00:00:01";
const requestId = "a1".repeat(32);
const nonce = "b2".repeat(32);
const deviceId = "10000000-0000-0000-0000-000000000001";
const credentialId = "20000000-0000-0000-0000-000000000002";
const userId = "30000000-0000-0000-0000-000000000003";
const devicePair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const otherPair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const publicDer = devicePair.publicKey.export({ format: "der", type: "spki" });
const publicKey = publicDer.toString("base64url");
const fingerprint = sha256(publicDer);
const env = (overrides = {}) => ({
  OTA_PIN_RECOVERY_ENABLED: "true",
  OTA_ADMIN_ENABLED: "true",
  OTA_DEVICE_REALM: realm,
  SUPABASE_URL: "https://fixture-project.supabase.co",
  SUPABASE_PUBLISHABLE_KEY: "sb_publishable_synthetic_fixture",
  OTA_GATEWAY_DATABASE_URL: "postgresql://synthetic-secret.invalid/fixture",
  OTA_GATEWAY_DATABASE_CA: "SYNTHETIC_DATABASE_CA_SECRET",
  OTA_SERVICE_ROLE_KEY: "SYNTHETIC_SERVICE_ROLE_SECRET",
  OTA_LICENSE_SIGNING_PRIVATE_KEY: "SYNTHETIC_PRIVATE_SIGNING_SECRET",
  ...overrides
});

function signedRequest(action = "create", signingRealm = realm) {
  const body = { action, mac, public_key: publicKey, request_id: requestId, nonce };
  body.signature = sign("sha256", proofInput(body, signingRealm, fingerprint), {
    key: devicePair.privateKey, dsaEncoding: "ieee-p1363"
  }).toString("base64url");
  return body;
}

function recoveryRow(overrides = {}) {
  return {
    request_id: requestId,
    device_id: deviceId,
    credential_id: credentialId,
    realm,
    status: "pending",
    issued_at: 1_800_000_000,
    expires_at: 1_800_000_600,
    nonce,
    ...overrides
  };
}

function adminRow(overrides = {}) {
  const { nonce: _nonce, ...row } = recoveryRow(overrides);
  return { ...row, device_label: "Synthetic CoreS3", device_code: "BOMB-PIN-01" };
}

function recorder() {
  const result = { headers: {}, status: 200 };
  const response = {
    setHeader(name, value) { result.headers[name] = value; },
    status(value) { result.status = value; return this; },
    json(body) { result.body = body; return this; }
  };
  return { result, response };
}

async function invoke(handler, overrides = {}) {
  const { result, response } = recorder();
  await handler({
    method: "POST",
    query: {},
    headers: { "content-type": "application/json" },
    body: signedRequest(),
    ...overrides
  }, response);
  return result;
}

function transactionFixture(data, counters = { begin: 0, commit: 0, rollback: 0, queries: [] }) {
  const transaction = async operation => {
    counters.begin++;
    try {
      const value = await operation(async (sql, values) => {
        counters.queries.push({ sql, values });
        return { rows: [{ data: typeof data === "function" ? data(sql, values) : data }] };
      });
      counters.commit++;
      return value;
    } catch (error) {
      counters.rollback++;
      throw error;
    }
  };
  return { transaction, counters };
}

test("device proof signs each supported action and binds identity, realm, request and nonce", async () => {
  assert.deepEqual(actions, ["create", "status", "cancel", "consume"]);
  const states = { create: "pending", status: "approved", cancel: "cancelled", consume: "consumed" };
  for (const action of actions) {
    const body = signedRequest(action);
    const canonical = Buffer.from([
      "BOMB-PIN-RECOVERY", "1", realm, action, mac, fingerprint, requestId, nonce, ""
    ].join("\n"), "ascii");
    assert.deepEqual(proofInput(body, realm, fingerprint), canonical);
    const row = recoveryRow({ status: states[action] });
    const { transaction, counters } = transactionFixture(row);
    const result = await invoke(createDeviceHandler({ env: env(), transaction }), { body });
    assert.equal(result.status, 200, action);
    assert.deepEqual(result.body, { schema_version: 1, recovery: row }, action);
    assert.equal(counters.begin, 1, action);
    assert.equal(counters.commit, 1, action);
    assert.equal(counters.rollback, 0, action);
    assert.equal(counters.queries.length, 1, action);
    assert.equal(counters.queries[0].sql,
      "SELECT public.ota_pin_device($1::jsonb,$2::text,$3::text,$4::text) AS data");
    assert.deepEqual(counters.queries[0].values, [
      JSON.stringify({ mac, device_key_sha256: fingerprint, realm }), action, requestId, nonce
    ]);
  }
});

test("proof rejects action, nonce, realm, key and signature tampering before transaction", async () => {
  const tamperedSignatureBytes = Buffer.from(signedRequest().signature, "base64url");
  tamperedSignatureBytes[0] ^= 1;
  const changedPublicKey = otherPair.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const cases = [
    { body: { ...signedRequest(), action: "approve" }, status: 400, error: "INVALID_INPUT" },
    { body: { ...signedRequest(), action: "status" }, status: 401, error: "INVALID_DEVICE_PROOF" },
    { body: { ...signedRequest(), nonce: "c3".repeat(32) }, status: 401, error: "INVALID_DEVICE_PROOF" },
    { body: signedRequest("create", "staging"), status: 401, error: "INVALID_DEVICE_PROOF" },
    { body: { ...signedRequest(), public_key: changedPublicKey }, status: 401, error: "INVALID_DEVICE_PROOF" },
    { body: { ...signedRequest(), signature: tamperedSignatureBytes.toString("base64url") }, status: 401, error: "INVALID_DEVICE_PROOF" },
    { body: { ...signedRequest(), request_id: "c4".repeat(32) }, status: 401, error: "INVALID_DEVICE_PROOF" },
    { body: { ...signedRequest(), realm }, status: 400, error: "INVALID_INPUT" }
  ];
  for (const item of cases) {
    const tx = transactionFixture(recoveryRow());
    const result = await invoke(createDeviceHandler({ env: env(), transaction: tx.transaction }), { body: item.body });
    assert.equal(result.status, item.status);
    assert.deepEqual(result.body, { error: item.error });
    assert.equal(tx.counters.begin, 0);
    assert.equal(tx.counters.queries.length, 0);
  }
  const invalidRealm = transactionFixture(recoveryRow());
  const result = await invoke(createDeviceHandler({
    env: env({ OTA_DEVICE_REALM: "Not a realm" }), transaction: invalidRealm.transaction
  }));
  assert.deepEqual(result.body, { error: "INVALID_INPUT" });
  assert.equal(invalidRealm.counters.begin, 0);
});

test("configuration disablement and strict HTTP body checks fail before transaction", async () => {
  const disabled = transactionFixture(recoveryRow());
  const disabledResult = await invoke(createDeviceHandler({
    env: env({ OTA_PIN_RECOVERY_ENABLED: "TRUE" }), transaction: disabled.transaction
  }));
  assert.equal(disabledResult.status, 503);
  assert.deepEqual(disabledResult.body, { error: "PIN_RECOVERY_DISABLED" });
  assert.equal(disabled.counters.begin, 0);

  for (const overrides of [
    { OTA_ADMIN_ENABLED: "false" },
    { SUPABASE_URL: "https://unexpected.invalid" },
    { SUPABASE_PUBLISHABLE_KEY: "" }
  ]) {
    const tx = transactionFixture(recoveryRow());
    const result = await invoke(createDeviceHandler({ env: env(overrides), transaction: tx.transaction }));
    assert.equal(result.status, 503);
    assert.equal(tx.counters.begin, 0, "device must not create a request without portal prerequisites");
  }

  const cases = [
    [{ method: "GET" }, 405],
    [{ headers: { "content-type": "text/plain" } }, 415],
    [{ headers: { "content-type": "application/json", "content-length": "4097" } }, 413],
    [{ headers: { "content-type": "application/json", "content-length": ["12"] } }, 400],
    [{ body: "{" }, 400],
    [{ body: "x".repeat(4097) }, 413],
    [{ body: null }, 400],
    [{ body: [] }, 400],
    [{ body: { ...signedRequest(), extra: true } }, 400]
  ];
  for (const [input, expectedStatus] of cases) {
    const tx = transactionFixture(recoveryRow());
    const result = await invoke(createDeviceHandler({ env: env(), transaction: tx.transaction }), input);
    assert.equal(result.status, expectedStatus);
    assert.equal(tx.counters.begin, 0);
  }
});

test("expired, cancelled and consumed snapshots are returned when their echoes match", async () => {
  for (const status of ["expired", "cancelled", "consumed"]) {
    const row = status === "expired"
      ? recoveryRow({ status, issued_at: 1, expires_at: 601 })
      : recoveryRow({ status });
    const tx = transactionFixture(row);
    const body = signedRequest(status === "cancelled" ? "cancel" : "status");
    const result = await invoke(createDeviceHandler({ env: env(), transaction: tx.transaction }), { body });
    assert.equal(result.status, 200);
    assert.deepEqual(result.body.recovery, row);
    assert.equal(tx.counters.commit, 1);
  }
});

test("response echo and snapshot mismatches throw inside transaction and roll it back", async () => {
  const mismatches = [
    recoveryRow({ request_id: "d5".repeat(32) }),
    recoveryRow({ nonce: "e6".repeat(32) }),
    recoveryRow({ realm: "staging" }),
    recoveryRow({ expires_at: 1_800_000_601 })
  ];
  for (const row of mismatches) {
    const tx = transactionFixture(row);
    const result = await invoke(createDeviceHandler({ env: env(), transaction: tx.transaction }));
    assert.equal(result.status, 503);
    assert.deepEqual(result.body, { error: "PIN_RECOVERY_UNAVAILABLE" });
    assert.equal(tx.counters.begin, 1);
    assert.equal(tx.counters.commit, 0);
    assert.equal(tx.counters.rollback, 1);
  }
  const throwing = transactionFixture(null);
  const handler = createDeviceHandler({ env: env(), transaction: async operation => {
    throwing.counters.begin++;
    try { return await operation(async () => { throw new Error("synthetic private SQL detail"); }); }
    catch (error) { throwing.counters.rollback++; throw error; }
  } });
  const failed = await invoke(handler);
  assert.equal(failed.status, 503);
  assert.deepEqual(failed.body, { error: "PIN_RECOVERY_UNAVAILABLE" });
  assert.equal(JSON.stringify(failed.body).includes("private SQL"), false);
  assert.equal(throwing.counters.commit, 0);
  assert.equal(throwing.counters.rollback, 1);
});

function fetchFixture(replies) {
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url: String(url), ...options });
    assert.ok(replies.length, "unexpected Auth/PostgREST fetch");
    const reply = replies.shift();
    if (reply instanceof Error) throw reply;
    return {
      ok: (reply.status || 200) < 400,
      status: reply.status || 200,
      async json() {
        if (reply.invalidJson) throw new Error("synthetic private response");
        return reply.body;
      }
    };
  };
  return { calls, fetchImpl };
}

const authOk = () => ({ body: { id: userId, is_anonymous: false } });
const authorization = "Bearer synthetic.user.jwt";

async function invokeAdmin(fetchImpl, input = {}) {
  return invoke(createAdminHandler({ env: env(), fetchImpl }), {
    method: "GET", headers: { authorization }, ...input
  });
}

test("administrator API verifies Auth JWT before scoped list and decision RPCs", async () => {
  const listed = [adminRow({ status: "pending" }), adminRow({
    request_id: "f7".repeat(32), status: "expired", issued_at: 1, expires_at: 601
  })];
  const listFetch = fetchFixture([authOk(), { body: listed }]);
  const listResult = await invokeAdmin(listFetch.fetchImpl);
  assert.equal(listResult.status, 200);
  assert.deepEqual(listResult.body, { schema_version: 1, recoveries: listed });
  assert.equal(listResult.headers["Cache-Control"], "private, no-store");
  assert.equal(listResult.headers.Vary, "Authorization");
  assert.ok(listFetch.calls[0].url.endsWith("/auth/v1/user"));
  assert.equal(listFetch.calls[0].headers.Authorization, authorization);
  assert.ok(listFetch.calls[1].url.endsWith("/rest/v1/rpc/ota_pin_list"));
  assert.equal(listFetch.calls[1].method, "POST");
  assert.deepEqual(JSON.parse(listFetch.calls[1].body), {});

  const decision = recoveryRow({ status: "approved" });
  delete decision.nonce;
  const decisionFetch = fetchFixture([authOk(), { body: decision }]);
  const decisionResult = await invokeAdmin(decisionFetch.fetchImpl, {
    method: "POST",
    headers: { authorization, "content-type": "application/json" },
    body: { request_id: requestId, action: "approve" }
  });
  assert.equal(decisionResult.status, 200);
  assert.deepEqual(decisionResult.body, { schema_version: 1, recovery: decision });
  assert.ok(decisionFetch.calls[1].url.endsWith("/rest/v1/rpc/ota_pin_admin"));
  assert.deepEqual(JSON.parse(decisionFetch.calls[1].body), {
    p_request_id: requestId, p_action: "approve"
  });
  for (const call of [...listFetch.calls, ...decisionFetch.calls]) {
    assert.equal(call.headers.Authorization, authorization);
    assert.equal(call.headers.apikey, env().SUPABASE_PUBLISHABLE_KEY);
    assert.notEqual(call.headers.apikey, env().OTA_SERVICE_ROLE_KEY);
    assert.equal(call.redirect, "error");
  }
});

test("administrator rejects missing/anonymous/wrong-scope users and extra decision fields", async () => {
  const missing = fetchFixture([]);
  const missingResult = await invokeAdmin(missing.fetchImpl, {
    headers: { "content-type": "application/json" }
  });
  assert.equal(missingResult.status, 401);
  assert.deepEqual(missingResult.body, { error: "UNAUTHENTICATED" });
  assert.equal(missing.calls.length, 0);

  for (const reply of [
    { status: 401, body: { message: "synthetic JWT detail" } },
    { body: { id: userId, is_anonymous: true } }
  ]) {
    const authFetch = fetchFixture([reply]);
    const result = await invokeAdmin(authFetch.fetchImpl);
    assert.ok([401, 403].includes(result.status));
    assert.equal(authFetch.calls.length, 1);
    assert.equal(JSON.stringify(result.body).includes("synthetic JWT detail"), false);
  }

  const wrongScope = fetchFixture([authOk(), {
    status: 403, body: { code: "42501", message: "synthetic foreign scope detail" }
  }]);
  const denied = await invokeAdmin(wrongScope.fetchImpl);
  assert.equal(denied.status, 403);
  assert.deepEqual(denied.body, { error: "FORBIDDEN" });
  assert.equal(wrongScope.calls.length, 2);
  assert.equal(JSON.stringify(denied.body).includes("foreign scope"), false);

  const extra = fetchFixture([authOk()]);
  const invalidDecision = await invokeAdmin(extra.fetchImpl, {
    method: "POST",
    headers: { authorization, "content-type": "application/json" },
    body: { request_id: requestId, action: "approve", actor: userId }
  });
  assert.equal(invalidDecision.status, 400);
  assert.deepEqual(invalidDecision.body, { error: "INVALID_INPUT" });
  assert.equal(extra.calls.length, 1); // Auth validation happened; no mutation RPC.
});

test("administrator API errors are sanitized and configuration disabled fails closed", async () => {
  for (const [reply, expectedStatus, expectedError] of [
    [{ status: 409, body: { code: "23505", message: "synthetic private conflict" } }, 409, "RECOVERY_CONFLICT"],
    [{ status: 400, body: { code: "22023", message: "synthetic private SQL" } }, 400, "INVALID_INPUT"],
    [{ status: 500, body: { code: "42501", message: "synthetic private SQL" } }, 503, "OTA_UNAVAILABLE"],
    [new Error("synthetic provider URL"), 503, "OTA_UNAVAILABLE"],
    [{ invalidJson: true }, 503, "OTA_UNAVAILABLE"],
    [{ body: { not: "an array" } }, 503, "PIN_RECOVERY_UNAVAILABLE"]
  ]) {
    const f = fetchFixture([authOk(), reply]);
    const result = await invokeAdmin(f.fetchImpl);
    assert.equal(result.status, expectedStatus);
    assert.deepEqual(result.body, { error: expectedError });
    assert.equal(JSON.stringify(result.body).includes("synthetic"), false);
  }

  const disabled = fetchFixture([]);
  const result = await invoke(createAdminHandler({
    env: env({ OTA_PIN_RECOVERY_ENABLED: "false" }), fetchImpl: disabled.fetchImpl
  }), { method: "GET", headers: { authorization } });
  assert.equal(result.status, 503);
  assert.deepEqual(result.body, { error: "PIN_RECOVERY_DISABLED" });
  assert.equal(disabled.calls.length, 0);
});

test("public portal publishes only Supabase URL and publishable key", async () => {
  const portal = createPortalHandler({ env: env() });
  const result = await invoke(portal, { method: "GET", body: undefined, headers: {} });
  assert.equal(result.status, 200);
  assert.deepEqual(result.body, {
    supabase_url: "https://fixture-project.supabase.co",
    publishable_key: "sb_publishable_synthetic_fixture"
  });
  const serialized = JSON.stringify(result.body);
  for (const secretName of ["SYNTHETIC_DATABASE_CA_SECRET", "SYNTHETIC_SERVICE_ROLE_SECRET",
    "SYNTHETIC_PRIVATE_SIGNING_SECRET", "synthetic-secret.invalid"])
    assert.equal(serialized.includes(secretName), false);

  const disabled = await invoke(createPortalHandler({ env: env({ OTA_PIN_RECOVERY_ENABLED: "false" }) }), {
    method: "GET", body: undefined, headers: {}
  });
  assert.equal(disabled.status, 503);
  assert.deepEqual(disabled.body, { error: "PIN_RECOVERY_DISABLED" });
});

test("single PIN router dispatches public config, authenticated admin and signed device actions", async () => {
  const publicConfig = await invoke(createRouterHandler({ env: env() }), {
    method: "GET", query: { action: "config" }, headers: {}, body: undefined
  });
  assert.equal(publicConfig.status, 200);
  assert.deepEqual(publicConfig.body, {
    supabase_url: "https://fixture-project.supabase.co",
    publishable_key: "sb_publishable_synthetic_fixture"
  });

  const listed = [adminRow({ status: "pending" })];
  const listFetch = fetchFixture([authOk(), { body: listed }]);
  const adminList = await invoke(createRouterHandler({ env: env(), fetchImpl: listFetch.fetchImpl }), {
    method: "GET", query: {}, headers: { authorization }, body: undefined
  });
  assert.equal(adminList.status, 200);
  assert.deepEqual(adminList.body, { schema_version: 1, recoveries: listed });
  assert.equal(listFetch.calls.length, 2);
  assert.ok(listFetch.calls[0].url.endsWith("/auth/v1/user"));
  assert.ok(listFetch.calls[1].url.endsWith("/rest/v1/rpc/ota_pin_list"));

  for (const action of ["approve", "reject"]) {
    const decision = recoveryRow({ status: action === "approve" ? "approved" : "rejected" });
    delete decision.nonce;
    const adminFetch = fetchFixture([authOk(), { body: decision }]);
    const adminResult = await invoke(createRouterHandler({ env: env(), fetchImpl: adminFetch.fetchImpl }), {
      method: "POST", query: {},
      headers: { authorization, "content-type": "application/json" },
      body: { request_id: requestId, action }
    });
    assert.equal(adminResult.status, 200, action);
    assert.deepEqual(adminResult.body, { schema_version: 1, recovery: decision }, action);
    assert.ok(adminFetch.calls[0].url.endsWith("/auth/v1/user"));
    assert.ok(adminFetch.calls[1].url.endsWith("/rest/v1/rpc/ota_pin_admin"));
    assert.deepEqual(JSON.parse(adminFetch.calls[1].body), {
      p_request_id: requestId, p_action: action
    });
  }

  const deviceRow = recoveryRow({ status: "pending" });
  const deviceTx = transactionFixture(deviceRow);
  const deviceResult = await invoke(createRouterHandler({ env: env(), transaction: deviceTx.transaction }), {
    method: "POST", query: {}, headers: { "content-type": "application/json" },
    body: signedRequest("create")
  });
  assert.equal(deviceResult.status, 200);
  assert.deepEqual(deviceResult.body, { schema_version: 1, recovery: deviceRow });
  assert.equal(deviceTx.counters.commit, 1);
});

test("single PIN router rejects unknown query fields and unsupported methods", async () => {
  const f = fetchFixture([]);
  const handler = createRouterHandler({ env: env(), fetchImpl: f.fetchImpl });
  for (const query of [{ action: "unknown" }, { unexpected: "value" }]) {
    const result = await invoke(handler, { method: "GET", query, headers: {}, body: undefined });
    assert.equal(result.status, 400);
    assert.deepEqual(result.body, { error: "INVALID_INPUT" });
  }
  const deviceTx = transactionFixture(recoveryRow());
  const postQuery = await invoke(createRouterHandler({ env: env(), transaction: deviceTx.transaction }), {
    method: "POST", query: { unexpected: "value" }, headers: { "content-type": "application/json" },
    body: signedRequest("create")
  });
  assert.equal(postQuery.status, 400);
  assert.deepEqual(postQuery.body, { error: "INVALID_INPUT" });
  assert.equal(deviceTx.counters.begin, 0);

  for (const method of ["PUT", "PATCH", "DELETE", "OPTIONS"]) {
    const result = await invoke(handler, { method, query: {}, headers: {}, body: undefined });
    assert.equal(result.status, 405);
    assert.deepEqual(result.body, { error: "METHOD_NOT_ALLOWED" });
  }
  assert.equal(f.calls.length, 0);
});
