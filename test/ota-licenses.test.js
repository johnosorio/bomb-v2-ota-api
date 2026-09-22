import test from "node:test";
import assert from "node:assert/strict";
import { createHandler } from "../api/ota/licenses.js";

const device = "10000000-0000-0000-0000-000000000001";
const request = "20000000-0000-0000-0000-000000000001";
const user = "30000000-0000-0000-0000-000000000001";
const credential = "40000000-0000-0000-0000-000000000001";
const license = "50000000-0000-0000-0000-000000000001";
const auth = { authorization: "Bearer synthetic.user.jwt", "content-type": "application/json" };
const env = {
  OTA_ADMIN_ENABLED: "true",
  OTA_LICENSE_ADMIN_ENABLED: "true",
  SUPABASE_URL: "https://example.supabase.co",
  SUPABASE_PUBLISHABLE_KEY: "sb_publishable_fixture"
};
const identity = { action: "approve_identity", device_id: device, request_id: request,
  mac: "02:00:00:00:00:01", device_key_sha256: "ab".repeat(32) };
const grant = { action: "grant", device_id: device, request_id: "20000000-0000-0000-0000-000000000002",
  expected_revision: 0, not_before: 1800000000, expires_at: 1800003600 };
const revoke = { action: "revoke", device_id: device, request_id: "20000000-0000-0000-0000-000000000003", expected_revision: 1 };

function snapshot(overrides = {}) {
  return { device_id: device, credential_id: credential, mac: identity.mac, device_key_sha256: identity.device_key_sha256,
    license_id: license, revision: 0, status: "unlicensed", issued_at: null, not_before: null, expires_at: null,
    updated_by: user, updated_at: "2026-09-22T00:00:00.000Z", ...overrides };
}
const verifiedUser = () => ({ body: { id: user, is_anonymous: false } });
const receipt = (command, current) => ({ body: { device_id: device, request_id: command.request_id,
  action: command.action, snapshot: current } });

function fixture(replies = [], settings = env) {
  const calls = [];
  const handler = createHandler({ env: settings, fetchImpl: async (url, options) => {
    calls.push({ url, ...options });
    assert.ok(replies.length, "unexpected provider request");
    const reply = replies.shift();
    if (reply instanceof Error) throw reply;
    return { ok: (reply.status || 200) < 400, status: reply.status || 200, json: async () => {
      if (reply.invalidJson) throw new Error("private provider payload");
      return reply.body;
    } };
  } });
  return { calls, async invoke(input = {}) {
    const result = { headers: {} };
    const response = { setHeader(key, value) { result.headers[key] = value; },
      status(value) { result.status = value; return this; }, json(value) { result.body = value; return this; } };
    await handler({ method: "POST", headers: auth, body: identity, query: {}, ...input }, response);
    return result;
  } };
}

function rpc(call, name, body) {
  assert.ok(call.url.endsWith(`/rest/v1/rpc/${name}`));
  assert.equal(call.method, "POST");
  assert.deepEqual(JSON.parse(call.body), body);
  assert.equal(call.headers.Authorization, auth.authorization);
  assert.equal(call.headers.apikey, env.SUPABASE_PUBLISHABLE_KEY);
  assert.notEqual(call.headers.Authorization, `Bearer ${env.SUPABASE_PUBLISHABLE_KEY}`);
  assert.equal(call.redirect, "error");
  assert.ok(call.signal instanceof AbortSignal);
}

test("disabled flags and invalid configuration fail before any fetch", async () => {
  for (const settings of [{ ...env, OTA_LICENSE_ADMIN_ENABLED: "false" }, { ...env, OTA_LICENSE_ADMIN_ENABLED: "TRUE" },
    { ...env, OTA_ADMIN_ENABLED: "false" }, { ...env, SUPABASE_PUBLISHABLE_KEY: "service_role_secret" }]) {
    const f = fixture([], settings);
    const result = await f.invoke();
    assert.equal(result.status, 503);
    assert.equal(f.calls.length, 0);
  }
});

test("authorization and unsupported methods are bounded before mutation", async () => {
  for (const authorization of [undefined, "", "Basic secret", ["Bearer x"], "Bearer x\\nsecret", `Bearer ${"x".repeat(8193)}`]) {
    const f = fixture();
    assert.equal((await f.invoke({ headers: { authorization } })).status, 401);
    assert.equal(f.calls.length, 0);
  }
  for (const method of ["DELETE", "PATCH", "PUT", "OPTIONS"]) {
    const f = fixture();
    assert.equal((await f.invoke({ method })).status, 405);
    assert.equal(f.calls.length, 0);
  }
});

test("POST enforces content type and transport/normalized size", async () => {
  const wrongType = fixture([verifiedUser()]);
  assert.equal((await wrongType.invoke({ headers: { authorization: auth.authorization, "content-type": "text/plain" } })).status, 415);
  assert.equal(wrongType.calls.length, 1);
  for (const input of [{ body: "x".repeat(4097) }, { body: identity, headers: { ...auth, "content-length": "4097" } },
    { body: identity, headers: { ...auth, "content-length": ["1"] } }]) {
    const f = fixture(input.headers ? [] : [verifiedUser()]);
    const result = await f.invoke(input);
    assert.equal(result.status, input.headers ? (Array.isArray(input.headers["content-length"]) ? 400 : 413) : 413);
    assert.equal(f.calls.length, input.headers ? 0 : 1);
  }
});

test("strict commands reject unknown, null, inherited and invalid fields before RPC", async () => {
  const inherited = Object.create({ action: "grant" });
  Object.assign(inherited, { device_id: device, request_id: request, expected_revision: 0, not_before: 1, expires_at: 2 });
  for (const body of [null, [], {}, "{", { ...identity, actor: user }, { ...identity, private_key: "synthetic" },
    { ...identity, action: "unknown" }, { ...identity, action: "__proto__" }, { ...grant, action: ["grant"], not_before: 0, expires_at: 0 },
    { ...identity, device_id: "bad" },
    { ...identity, request_id: null }, { ...identity, mac: "02:00:00:00:00:1" }, { ...identity, device_key_sha256: "AB".repeat(32) },
    { ...grant, expected_revision: -1 }, { ...grant, expected_revision: 4294967296 }, { ...grant, not_before: 0 },
    { ...grant, not_before: 2, expires_at: 2 }, { ...grant, not_before: 2.5 }, inherited]) {
    const f = fixture([verifiedUser()]);
    assert.equal((await f.invoke({ body })).status, 400, JSON.stringify(body));
    assert.equal(f.calls.length, 1);
  }
});

test("unverified or anonymous Auth identities never reach license RPCs", async () => {
  for (const [reply, status] of [[{ status: 401, body: { message: "private auth" } }, 401],
    [{ body: { id: user, is_anonymous: true } }, 403], [{ body: { id: "invalid" } }, 503]]) {
    const f = fixture([reply]);
    const result = await f.invoke();
    assert.equal(result.status, status);
    assert.equal(f.calls.length, 1);
    assert.equal(JSON.stringify(result.body).includes("private"), false);
  }
});

test("response integrity rejects mismatched receipts, dates, states and revisions", async () => {
  const current = snapshot({ revision: 1, status: "granted", issued_at: 1800000000, not_before: grant.not_before, expires_at: grant.expires_at });
  for (const body of [
    { ...receipt(grant, current).body, request_id: request },
    { ...receipt(grant, current).body, action: "revoke" },
    receipt(grant, { ...current, revision: 2 }).body,
    receipt(grant, { ...current, status: "revoked" }).body,
    receipt(grant, { ...current, not_before: current.not_before + 1 }).body,
    receipt(grant, { ...current, expires_at: current.expires_at + 1 }).body,
    receipt(grant, { ...current, issued_at: current.expires_at }).body,
    receipt(grant, { ...current, updated_at: "invalid" }).body
  ]) {
    const f = fixture([verifiedUser(), { body }]);
    assert.equal((await f.invoke({ body: grant })).status, 503);
  }
  const f = fixture([verifiedUser(), receipt(grant, { ...current, private_field: "must not escape" })]);
  const result = await f.invoke({ body: grant });
  assert.equal(result.status, 200);
  assert.equal(result.headers["Cache-Control"], "private, no-store");
  assert.equal(result.headers.Vary, "Authorization");
  assert.equal(result.headers["Access-Control-Allow-Origin"], undefined);
  assert.equal(JSON.stringify(result.body).includes("must not escape"), false);
});

test("commands use only the verified user JWT and exact RPC bodies", async () => {
  const approved = snapshot();
  const granted = snapshot({ revision: 1, status: "granted", issued_at: 1800000000, not_before: grant.not_before, expires_at: grant.expires_at });
  const revoked = snapshot({ revision: 2, status: "revoked", issued_at: 1800000001, not_before: grant.not_before, expires_at: grant.expires_at });
  for (const [command, current] of [[identity, approved], [grant, granted], [revoke, revoked]]) {
    const f = fixture([verifiedUser(), receipt(command, current)]);
    const result = await f.invoke({ body: command });
    assert.equal(result.status, 200);
    assert.deepEqual(result.body, { schema_version: 1, receipt: { device_id: device, request_id: command.request_id,
      action: command.action, snapshot: current } });
    assert.ok(f.calls[0].url.endsWith("/auth/v1/user"));
    assert.equal(f.calls[0].headers.Authorization, auth.authorization);
    rpc(f.calls[1], "ota_admin_license", { p_device_id: device, p_request_id: command.request_id,
      p_command: Object.fromEntries(Object.entries(command).filter(([key]) => !["device_id", "request_id"].includes(key)) ) });
  }
});

test("historical receipt retry is returned unchanged and cannot include caller authority", async () => {
  const old = snapshot();
  const f = fixture([verifiedUser(), receipt(identity, old), verifiedUser(), receipt(identity, old)]);
  const first = await f.invoke({ body: identity });
  const retry = await f.invoke({ body: { ...identity } });
  assert.deepEqual(retry.body, first.body);
  assert.deepEqual(JSON.parse(f.calls[1].body), JSON.parse(f.calls[3].body));
  for (const body of [{ ...identity, actor: user }, { ...identity, private_key: "not-a-key" }]) {
    const rejected = fixture([verifiedUser()]);
    assert.equal((await rejected.invoke({ body })).status, 400);
    assert.equal(rejected.calls.length, 1);
  }
});

test("GET returns null or current state through its exact RPC without cross-device data", async () => {
  const empty = fixture([verifiedUser(), { body: null }]);
  assert.deepEqual((await empty.invoke({ method: "GET", query: { device_id: device } })).body, { schema_version: 1, license: null });
  rpc(empty.calls[1], "ota_get_device_license", { p_device_id: device });
  const current = snapshot({ revision: 1, status: "granted", issued_at: 1800000000, not_before: 1800000000, expires_at: 1800003600 });
  const f = fixture([verifiedUser(), { body: current }]);
  assert.deepEqual((await f.invoke({ method: "GET", query: { device_id: device } })).body.license, current);
  for (const row of [{ ...current, device_id: user }, { ...current, credential_id: "bad" }]) {
    const denied = fixture([verifiedUser(), { body: row }]);
    const result = await denied.invoke({ method: "GET", query: { device_id: device } });
    assert.deepEqual(result.body, { error: "OTA_UNAVAILABLE" });
  }
});

test("GET query is exact and malformed upstream failures are sanitized", async () => {
  for (const query of [{}, { device_id: device, actor: user }, { device_id: [device] }, { device_id: "bad" }]) {
    const f = fixture([verifiedUser()]);
    assert.equal((await f.invoke({ method: "GET", query })).status, 400);
    assert.equal(f.calls.length, 1);
  }
  for (const [reply, status, error] of [[{ status: 403, body: { code: "42501", message: "private SQL" } }, 403, "FORBIDDEN"],
    [{ status: 409, body: { code: "23505", message: "private SQL" } }, 409, "LICENSE_CONFLICT"],
    [{ status: 400, body: { code: "22023", message: "private SQL" } }, 400, "INVALID_INPUT"],
    [{ status: 500, body: { code: "42501", message: "private SQL" } }, 503, "OTA_UNAVAILABLE"],
    [new Error("private URL"), 503, "OTA_UNAVAILABLE"], [{ invalidJson: true }, 503, "OTA_UNAVAILABLE"], [{ body: [] }, 503, "OTA_UNAVAILABLE"]]) {
    const f = fixture([verifiedUser(), reply]);
    const result = await f.invoke();
    assert.equal(result.status, status);
    assert.deepEqual(result.body, { error });
    assert.ok(!JSON.stringify(result.body).includes("private"));
  }
});
