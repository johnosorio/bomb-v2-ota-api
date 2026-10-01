import test from "node:test";
import assert from "node:assert/strict";
import { createHandler } from "../api/ota/devices.js";

const scope = "10000000-0000-0000-0000-000000000001";
const user = "20000000-0000-0000-0000-000000000001";
const env = { OTA_ADMIN_ENABLED: "true", SUPABASE_URL: "https://example.supabase.co", SUPABASE_PUBLISHABLE_KEY: "sb_publishable_fixture" };
const auth = "Bearer test.user.token";
const member = { scope_id: scope, role: "admin", ota_scopes: { id: scope, name: "Fixture scope", private_field: "hidden" }, private_field: "hidden" };

function fixture(replies = []) {
  const calls = [];
  const handler = createHandler({ env, fetchImpl: async (url, options) => {
    calls.push({ url, ...options });
    assert.ok(replies.length, "unexpected provider request");
    const reply = replies.shift();
    if (reply instanceof Error) throw reply;
    return { ok: (reply.status || 200) < 400, status: reply.status || 200, json: async () => {
      if (reply.invalidJson) throw new Error("private provider reply");
      return reply.body;
    } };
  } });
  return { calls, async invoke(request = {}) {
    const result = { headers: {} };
    const response = { setHeader(key, value) { result.headers[key] = value; },
      status(value) { result.status = value; return this; }, json(value) { result.body = value; return this; } };
    await handler({ method: "GET", query: { action: "context" }, headers: { authorization: auth }, ...request }, response);
    return result;
  } };
}

const validUser = () => ({ body: { id: user, is_anonymous: false } });

test("context lists only authenticated RLS memberships, paginates, and filters fields", async () => {
  const f = fixture([validUser(), { body: [member] }]);
  const result = await f.invoke({ query: { action: "context", limit: "2", offset: "3" } });
  assert.deepEqual(result.body, { schema_version: 1, scopes: [{ id: scope, name: "Fixture scope", role: "admin" }], limit: 2, offset: 3 });
  const query = new URL(f.calls[1].url).searchParams;
  assert.equal(query.get("select"), "scope_id,role,ota_scopes(id,name)");
  assert.equal(query.get("user_id"), `eq.${user}`);
  assert.equal(query.get("order"), "scope_id.asc");
  assert.equal(query.get("limit"), "2");
  assert.equal(query.get("offset"), "3");
  assert.equal(f.calls[1].headers.Authorization, auth);
  assert.equal(f.calls[1].headers.apikey, env.SUPABASE_PUBLISHABLE_KEY);
});

test("context rejects malformed query and unauthenticated or anonymous callers before memberships", async () => {
  for (const query of [{ action: "context", scope_id: scope }, { action: "context", limit: "0" },
    { action: "context", limit: "101" }, { action: "context", offset: "1000001" }, { action: "context", offset: "-1" }]) {
    const f = fixture();
    const result = await f.invoke({ query });
    assert.equal(result.status, 400);
    assert.equal(f.calls.length, 0);
  }
  for (const [headers, replies, status, calls] of [
    [{}, [], 401, 0],
    [{ authorization: auth }, [{ status: 401, body: { message: "token" } }], 401, 1],
    [{ authorization: auth }, [{ body: { id: user, is_anonymous: true } }], 403, 1]
  ]) {
    const f = fixture(replies);
    const result = await f.invoke({ headers });
    assert.equal(result.status, status);
    assert.equal(f.calls.length, calls);
  }
});

test("context fails closed on malformed joins and provider errors without leaking details", async () => {
  for (const reply of [
    new Error("private URL"), { invalidJson: true }, { body: {} }, { body: [{ ...member, role: "owner" }] },
    { body: [{ ...member, ota_scopes: { id: user, name: "Other" } }] }, { status: 500, body: { message: "private SQL" } }
  ]) {
    const f = fixture([validUser(), reply]);
    const result = await f.invoke();
    assert.deepEqual(result.body, { error: "OTA_UNAVAILABLE" });
  }
});

test("GET listing and POST registration keep their existing route contract", async () => {
  const f = fixture([validUser(), { body: [] }]);
  const result = await f.invoke({ query: { scope_id: scope } });
  assert.equal(result.status, 403);
  assert.ok(f.calls[1].url.includes("ota_memberships"));
  const post = fixture();
  const postResult = await post.invoke({ method: "POST", query: { action: "context" },
    body: { scope_id: scope, device_id: "CORES3-VALID", label: "Valid registration" },
    headers: { authorization: auth, "content-type": "application/json" } });
  assert.equal(postResult.status, 400);
  assert.equal(post.calls.length, 0);
});
