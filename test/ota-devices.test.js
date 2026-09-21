import test from "node:test";
import assert from "node:assert/strict";
import { createHandler } from "../api/ota/devices.js";

const scope = "10000000-0000-0000-0000-000000000001";
const user = "20000000-0000-0000-0000-000000000001";
const row = { id: "30000000-0000-0000-0000-000000000001", scope_id: scope,
  device_id: "CORES3-TEST", model: "CoreS3", label: "Test", created_by: user, created_at: "2026-09-21T00:00:00Z" };
const input = { scope_id: scope, device_id: row.device_id, label: row.label };
const env = { OTA_ADMIN_ENABLED: "true", SUPABASE_URL: "https://example.supabase.co", SUPABASE_PUBLISHABLE_KEY: "sb_publishable_fixture" };
const auth = { authorization: "Bearer test.user.token", "content-type": "application/json" };
function fixture(replies = [], settings = env) {
  const calls = [];
  const handler = createHandler({ env: settings, fetchImpl: async (url, options) => {
    calls.push({ url, ...options });
    assert.ok(replies.length, "unexpected provider request");
    const reply = replies.shift();
    if (reply instanceof Error) throw reply;
    return { ok: (reply.status || 200) < 400, status: reply.status || 200, json: async () => {
      if (reply.invalidJson) throw new Error("secret provider payload");
      return reply.body;
    } };
  } });
  return { calls, async invoke(request = {}) {
    const result = { headers: {} };
    const response = { setHeader(key, value) { result.headers[key] = value; },
      status(value) { result.status = value; return this; }, json(value) { result.body = value; return this; } };
    await handler({ method: "POST", headers: auth, body: input, ...request }, response);
    return result;
  } };
}
const validUser = () => ({ body: { id: user, is_anonymous: false } });

test("feature disabled and bad configuration fail closed without provider requests", async () => {
  for (const settings of [{}, { ...env, OTA_ADMIN_ENABLED: "TRUE" },
    { ...env, SUPABASE_PUBLISHABLE_KEY: "service_role_secret" },
    { ...env, SUPABASE_URL: "https://example.supabase.co.evil.test" },
    { ...env, SUPABASE_URL: "http://example.supabase.co" },
    { ...env, SUPABASE_URL: "https://user:secret@example.supabase.co" },
    { ...env, SUPABASE_URL: "https://example.supabase.co/custom" }]) {
    const f = fixture([], settings);
    assert.equal((await f.invoke()).status, 503);
    assert.equal(f.calls.length, 0);
  }
});
test("unsupported methods cannot mutate inventory", async () => {
  for (const method of ["DELETE", "PATCH", "OPTIONS", "PUT"]) {
    const f = fixture();
    assert.equal((await f.invoke({ method })).status, 405);
    assert.equal(f.calls.length, 0);
  }
});
test("missing/malformed/oversized bearer credentials never reach provider", async () => {
  for (const authorization of [undefined, "", "Basic secret", ["Bearer x"], "Bearer x\nsecret", `Bearer ${"x".repeat(8193)}`]) {
    const f = fixture();
    assert.equal((await f.invoke({ headers: { authorization } })).status, 401);
    assert.equal(f.calls.length, 0);
  }
});
test("invalid and anonymous users cannot reach database", async () => {
  for (const [reply, status] of [[{ status: 401, body: { message: "token secret" } }, 401],
    [{ body: { id: user, is_anonymous: true } }, 403], [{ body: { id: "bad" } }, 503]]) {
    const f = fixture([reply]);
    const result = await f.invoke();
    assert.equal(result.status, status);
    assert.equal(f.calls.length, 1);
    assert.ok(!JSON.stringify(result).includes("token secret"));
  }
});
test("registration uses verified user JWT, fixed RPC and filters output", async () => {
  const f = fixture([validUser(), { body: { ...row, private_field: "must not escape" } }]);
  const result = await f.invoke();
  assert.equal(result.status, 200);
  assert.deepEqual(result.body, { schema_version: 1, device: row });
  assert.equal(result.headers["Cache-Control"], "private, no-store");
  assert.equal(result.headers["Access-Control-Allow-Origin"], undefined);
  assert.ok(f.calls[0].url.endsWith("/auth/v1/user"));
  assert.ok(f.calls[1].url.endsWith("/rest/v1/rpc/ota_register_device"));
  assert.deepEqual(JSON.parse(f.calls[1].body), { p_scope_id: scope, p_device_id: row.device_id, p_label: row.label });
  assert.equal(f.calls[1].headers.Accept, "application/vnd.pgrst.object+json");
  for (const call of f.calls) {
    assert.equal(call.headers.Authorization, auth.authorization);
    assert.equal(call.headers.apikey, env.SUPABASE_PUBLISHABLE_KEY);
    assert.equal(call.redirect, "error");
    assert.ok(call.signal instanceof AbortSignal);
  }
});
test("registration accepts JSON strings and exact retry response from DB", async () => {
  const f = fixture([validUser(), { body: row }, validUser(), { body: row }]);
  const first = await f.invoke({ body: JSON.stringify(input) });
  const retry = await f.invoke();
  assert.deepEqual(first.body, retry.body);
});
test("strict JSON input prevents caller supplied roles, actor and model", async () => {
  for (const body of [null, [], {}, "{", { ...input, actor: user }, { ...input, model: "Bomb01" },
    { ...input, role: "admin" }, { ...input, scope_id: "bad" }, { ...input, device_id: "a/b" },
    { ...input, label: " spaced " }, { ...input, label: "" }, { ...input, label: "x".repeat(81) },
    { ...input, label: "new\nline" }, { ...input, device_id: 42 }]) {
    const f = fixture([validUser()]);
    assert.equal((await f.invoke({ body })).status, 400, JSON.stringify(body));
    assert.equal(f.calls.length, 1);
  }
});
test("payload size and content type are bounded", async () => {
  const f = fixture([validUser(), validUser()]);
  assert.equal((await f.invoke({ body: "x".repeat(4097) })).status, 413);
  assert.equal((await f.invoke({ headers: { authorization: auth.authorization, "content-type": "text/plain" } })).status, 415);
});
test("database permission, conflict, expiry and provider failures are sanitized", async () => {
  for (const [http, code, status, error] of [
    [403, "42501", 403, "FORBIDDEN"], [409, "23505", 409, "DEVICE_CONFLICT"],
    [400, "22023", 400, "INVALID_INPUT"], [401, "PGRST301", 401, "UNAUTHENTICATED"],
    [500, "42501", 503, "OTA_UNAVAILABLE"], [404, "PGRST202", 503, "OTA_UNAVAILABLE"]]) {
    const f = fixture([validUser(), { status: http, body: { code, message: "private SQL details" } }]);
    const result = await f.invoke();
    assert.equal(result.status, status);
    assert.deepEqual(result.body, { error });
  }
  for (const reply of [new Error("private URL"), { invalidJson: true }, { body: [] }, { body: { ...row, scope_id: user } }]) {
    const f = fixture([validUser(), reply]);
    assert.deepEqual((await f.invoke()).body, { error: "OTA_UNAVAILABLE" });
  }
});
test("scope membership is checked and list is bounded/ordered", async () => {
  const f = fixture([validUser(), { body: [{ scope_id: scope }] }, { body: [row] }]);
  const result = await f.invoke({ method: "GET", query: { scope_id: scope, limit: "2", offset: "3" } });
  assert.equal(result.status, 200);
  assert.deepEqual(result.body, { schema_version: 1, devices: [row], limit: 2, offset: 3 });
  const membership = new URL(f.calls[1].url);
  assert.equal(membership.searchParams.get("user_id"), `eq.${user}`);
  const devices = new URL(f.calls[2].url);
  assert.equal(devices.searchParams.get("scope_id"), `eq.${scope}`);
  assert.equal(devices.searchParams.get("order"), "created_at.asc,id.asc");
  assert.equal(devices.searchParams.get("limit"), "2");
});
test("missing membership denies rather than exposing empty foreign scope", async () => {
  const f = fixture([validUser(), { body: [] }]);
  assert.equal((await f.invoke({ method: "GET", query: { scope_id: scope } })).status, 403);
  assert.equal(f.calls.length, 2);
});
test("accessible empty scope returns 200 and listing validates all filters", async () => {
  const f = fixture([validUser(), { body: [{ scope_id: scope }] }, { body: [] }]);
  assert.deepEqual((await f.invoke({ method: "GET", query: { scope_id: scope } })).body.devices, []);
  for (const query of [{}, { scope_id: [scope] }, { scope_id: scope, actor: user },
    { scope_id: scope, limit: "101" }, { scope_id: scope, limit: "0" },
    { scope_id: scope, offset: "-1" }, { scope_id: scope, offset: "1000001" },
    { scope_id: scope, limit: ["1", "2"] }, { scope_id: scope, limit: "1e2" }]) {
    const f = fixture([validUser()]);
    assert.equal((await f.invoke({ method: "GET", query })).status, 400);
    assert.equal(f.calls.length, 1);
  }
});
test("unexpected cross-scope upstream rows fail closed", async () => {
  const f = fixture([validUser(), { body: [{ scope_id: scope }] }, { body: [{ ...row, scope_id: user }] }]);
  assert.equal((await f.invoke({ method: "GET", query: { scope_id: scope } })).status, 503);
});
test("oversized declared transport body is rejected even after platform parsing", async () => {
  const padded = JSON.stringify(input) + " ".repeat(4200);
  const f = fixture();
  assert.equal((await f.invoke({ body: JSON.parse(padded), headers: { ...auth, "content-length": String(Buffer.byteLength(padded)) } })).status, 413);
  assert.equal(f.calls.length, 0);
  const malformed = fixture();
  assert.equal((await malformed.invoke({ headers: { ...auth, "content-length": ["10", "20"] } })).status, 400);
  assert.equal(malformed.calls.length, 0);
});
test("parsed bodies without a declared length enforce normalized JSON, not wire bytes", async () => {
  const f = fixture([validUser(), { body: row }]);
  const padded = JSON.stringify(input) + " ".repeat(4200);
  assert.equal((await f.invoke({ body: JSON.parse(padded) })).status, 200);
});
