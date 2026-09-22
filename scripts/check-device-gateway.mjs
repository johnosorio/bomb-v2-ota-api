// Imported ONLY by the disposable, socket-only PostgreSQL harness. No env reads.
import assert from "node:assert/strict";
import pg from "pg";
import { generateKeyPairSync, sign, randomBytes, randomUUID } from "node:crypto";
import { deviceGateway } from "../lib/ota/device-gateway.js";
import { gatewayTransaction } from "../lib/ota/gateway-db.js";
import { deviceProofInput, sha256 } from "../lib/ota/device-proof.js";
import { verifyDeviceResponse } from "../lib/ota/device-response.js";
import { createHandler } from "../api/ota/device-license.js";

export async function checkDeviceGateway(socket) {
  assert.match(socket, /^\/private\/tmp\/bomb-ota-pg-[A-Za-z0-9]+$/);
  const connection = { host: socket, port: 5432, database: "postgres", password: "unused-local-trust", ssl: false,
    connectionTimeoutMillis: 3000, query_timeout: 5000, application_name: "bomb-ota-test-gateway" };
  let owner = new pg.Client({ ...connection, user: "ota_test_owner", application_name: "bomb-ota-test-owner" });
  owner.on("error", () => {});
  await owner.connect();
  const user = "20000000-0000-0000-0000-000000000001";
  const scope = "10000000-0000-0000-0000-000000000001";
  const deviceKey = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const serverKey = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const der = deviceKey.publicKey.export({ type: "spki", format: "der" });
  const digest = sha256(der);
  const config = { realm: "isolated-gateway-test", signer: { kid: "isolated", privateKey: serverKey.privateKey }, database: {} };
  const transaction = gatewayTransaction({}, () => new pg.Client({ ...connection, user: "bomb_ota_gateway" }));
  // Exercise HTTP handler -> real pg transaction -> signer, with only the socket
  // transport injected. The URL below is synthetic and is never connected to.
  const env = { OTA_DEVICE_GATEWAY_ENABLED: "true", OTA_DEVICE_REALM: config.realm,
    OTA_LICENSE_SIGNING_KID: config.signer.kid,
    OTA_LICENSE_SIGNING_PRIVATE_KEY: serverKey.privateKey.export({ type: "pkcs8", format: "pem" }),
    OTA_GATEWAY_DATABASE_URL: "postgresql://bomb_ota_gateway:synthetic@db.abcdefghijklmnopqrst.supabase.co:5432/postgres" };
  const call = async (body, extra = {}) => {
    const r = {};
    const response = { setHeader() {}, status(status) { r.status = status; return this; }, json(value) { r.body = value; return this; } };
    await createHandler({ env, dependencies: { transaction, ...extra } })({ method: "POST", query: {}, headers: { "content-type": "application/json" }, body }, response);
    if (r.status !== 200) throw Object.assign(new Error(r.body.error), { status: r.status, code: r.body.error });
    return r.body;
  };
  const keys = new Map([["isolated", serverKey.publicKey]]);
  const signed = (body) => ({ ...body, signature: sign("sha256", deviceProofInput(body, config.realm, digest),
    { key: deviceKey.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url") });
  const initial = () => signed({ action: "challenge", mac: "02:00:00:00:00:71", public_key: der.toString("base64url"), client_nonce: randomBytes(32).toString("hex") });
  const exchange = (c) => signed({ action: "exchange", device_id: c.device_id, credential_id: c.credential_id,
    mac: c.mac, public_key: der.toString("base64url"), client_nonce: c.client_nonce, challenge_id: c.id, nonce: c.nonce });
  const verified = (result, c, minimum_revision = 0) => verifyDeviceResponse(result, { keys, expected: {
    device_id: c.device_id, credential_id: c.credential_id, device_key_sha256: digest, mac: c.mac, realm: config.realm,
    challenge_id: c.id, client_nonce: c.client_nonce, nonce: c.nonce, minimum_revision, last_server_time: 0, elapsed_seconds: 0 } });
  const admin = async (sql, values = []) => {
    await owner.query("BEGIN");
    try {
      await owner.query("SET LOCAL ROLE authenticated");
      await owner.query("SELECT set_config('request.jwt.claim.sub',$1,true)", [user]);
      const r = await owner.query(sql, values);
      await owner.query("COMMIT"); return r.rows[0].data;
    } catch (e) { await owner.query("ROLLBACK"); throw e; }
  };
  let id;
  const mutate = (command) => admin("SELECT public.ota_admin_license($1,$2,$3::jsonb) AS data", [id, randomUUID(), JSON.stringify(command)]);
  const auditCount = async () => Number((await owner.query("SELECT count(*) AS n FROM ota_private.device_license_deliveries WHERE device_id=$1", [id])).rows[0].n);
  const expireOld = () => owner.query("UPDATE ota_private.device_challenges SET issued_at=1,expires_at=121 WHERE device_id=$1", [id]);
  const code = (status) => (e) => e.status === status;
  try {
    assert.equal((await owner.query("SHOW listen_addresses")).rows[0].listen_addresses, "");
    // Test-only provisioning; production migration leaves LOGIN disabled.
    await owner.query("ALTER ROLE bomb_ota_gateway LOGIN");
    id = (await admin("SELECT to_jsonb(d) AS data FROM public.ota_register_device($1,$2,$3) d", [scope, "GATEWAY-LOCAL", "Gateway fixture"])).id;
    await mutate({ action: "approve_identity", mac: "02:00:00:00:00:71", device_key_sha256: digest });

    const restricted = new pg.Client({ ...connection, user: "bomb_ota_gateway" });
    restricted.on("error", () => {}); await restricted.connect();
    try {
      for (const sql of ["SELECT * FROM public.ota_device_licenses", "SELECT * FROM ota_private.device_challenges",
        "SET ROLE authenticated", "CREATE TABLE public.gateway_forbidden(id int)",
        "SELECT public.ota_get_device_license('50000000-0000-0000-0000-000000000001')"]) {
        await assert.rejects(restricted.query(sql), e => e.code === "42501");
      }
      await restricted.query("SELECT set_config('request.jwt.claim.sub',$1,false)", [user]);
      await assert.rejects(restricted.query("SELECT public.ota_admin_license($1,$2,$3)", [id, randomUUID(), '{"action":"revoke","expected_revision":0}']), e => e.code === "42501");
      await assert.rejects(restricted.query("SELECT public.ota_gateway_challenge($1,$2)", [JSON.stringify({ mac: "x".repeat(5000) }), "a".repeat(64)]), e => e.code === "22023");
    } finally { await restricted.end(); }
    for (const role of ["anon", "authenticated", "service_role"]) {
      assert.equal((await owner.query("SELECT has_function_privilege($1,'public.ota_gateway_challenge(jsonb,text)','EXECUTE') AS ok", [role])).rows[0].ok, false);
      assert.equal((await owner.query("SELECT has_function_privilege($1,'public.ota_gateway_consume(jsonb,uuid,text,text)','EXECUTE') AS ok", [role])).rows[0].ok, false);
    }
    // Fail closed if operator grants broaden the runtime role after migration.
    await owner.query("GRANT SELECT ON public.ota_devices TO bomb_ota_gateway");
    await assert.rejects(call(initial()), code(503));
    await owner.query("REVOKE SELECT ON public.ota_devices FROM bomb_ota_gateway");
    await owner.query("GRANT authenticated TO bomb_ota_gateway");
    await assert.rejects(call(initial()), code(503));
    await owner.query("REVOKE authenticated FROM bomb_ota_gateway");
    await owner.query("GRANT USAGE ON SCHEMA ota_private TO bomb_ota_gateway");
    await assert.rejects(call(initial()), code(503));
    await owner.query("REVOKE USAGE ON SCHEMA ota_private FROM bomb_ota_gateway");

    // No prior UUID provisioning needed. Initial proof alone grants no license.
    let request = initial();
    let c = (await call(request)).challenge;
    assert.deepEqual((await call(request)).challenge, c);
    assert.equal(c.device_id, id);
    let reply = await call(exchange(c));
    assert.equal(verified(reply, c).status.state, "unlicensed");
    await assert.rejects(call(exchange(c)), code(409));
    await assert.rejects(call(request), code(409));
    const other = signed({ ...initial(), mac: "02:00:00:00:00:72" });
    await assert.rejects(call(other), code(403));
    const exp = Math.floor(Date.now() / 1000) + 3600;
    await mutate({ action: "grant", expected_revision: 0, not_before: 1, expires_at: exp });

    // Parallel functions/connections: one consumption, one delivery audit.
    c = (await call(initial())).challenge;
    const before = await auditCount();
    const results = await Promise.allSettled(Array.from({ length: 8 }, () => call(exchange(c))));
    assert.equal(results.filter(r => r.status === "fulfilled").length, 1);
    assert.ok(results.filter(r => r.status === "rejected").every(r => r.reason.status === 409));
    reply = results.find(r => r.status === "fulfilled").value;
    assert.equal(verified(reply, c).license.revision, 1);
    assert.equal(await auditCount(), before + 1);

    // Hold the device row while exchange starts. Revocation commits before its
    // lock is acquired; the post-lock read MUST see revision 2, never the old grant.
    c = (await call(initial())).challenge;
    await owner.query("BEGIN");
    await owner.query("SELECT id FROM public.ota_devices WHERE id=$1 FOR UPDATE", [id]);
    const waiting = call(exchange(c));
    let lockObserved = false;
    for (let i = 0; i < 100; i++) {
      await owner.query("SELECT pg_stat_clear_snapshot()");
      const r = await owner.query("SELECT count(*) AS n FROM pg_stat_activity WHERE application_name='bomb-ota-test-gateway' AND wait_event_type='Lock'");
      if (Number(r.rows[0].n)>0) { lockObserved = true; break; }
      await new Promise(r => setTimeout(r, 10));
    }
    assert.ok(lockObserved, "exchange must be waiting on the admin device lock");
    await owner.query("SET LOCAL ROLE authenticated");
    await owner.query("SELECT set_config('request.jwt.claim.sub',$1,true)", [user]);
    await owner.query("SELECT public.ota_admin_license($1,$2,$3::jsonb)", [id, randomUUID(), '{"action":"revoke","expected_revision":1}']);
    await owner.query("COMMIT");
    assert.equal(verified(await waiting, c, 2).status.state, "revoked");
    await mutate({ action: "grant", expected_revision: 2, not_before: 1, expires_at: exp });

    // Signing failure: consumption and audit roll back, allowing same proof retry.
    c = (await call(initial())).challenge;
    const prior = await auditCount();
    await assert.rejects(call(exchange(c), { respond: () => { throw new Error("test signer unavailable"); } }), code(503));
    assert.equal(await auditCount(), prior);
    assert.equal(verified(await call(exchange(c)), c, 3).license.revision, 3);

    // Audit failure similarly prevents delivery and consumption.
    c = (await call(initial())).challenge;
    await owner.query("CREATE FUNCTION ota_private.fail_delivery_test() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test audit failure'; END $$");
    await owner.query("CREATE TRIGGER fail_delivery_test BEFORE INSERT ON ota_private.device_license_deliveries FOR EACH ROW EXECUTE FUNCTION ota_private.fail_delivery_test()");
    await assert.rejects(call(exchange(c)), code(503));
    await owner.query("DROP TRIGGER fail_delivery_test ON ota_private.device_license_deliveries; DROP FUNCTION ota_private.fail_delivery_test()");
    assert.equal(verified(await call(exchange(c)), c, 3).status.state, "valid");

    // Nonce/realm/time changes cannot consume a different pending challenge.
    c = (await call(initial())).challenge;
    await assert.rejects(call(signed({ ...exchange(c), nonce: "b".repeat(64) })), code(409));
    const otherRealm = { ...config, realm: "another-realm" };
    const realmBody = exchange(c);
    realmBody.signature = sign("sha256", deviceProofInput(realmBody, otherRealm.realm, digest), { key: deviceKey.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
    await assert.rejects(deviceGateway(realmBody, otherRealm, { transaction }), code(409));
    await expireOld();
    await assert.rejects(call(exchange(c)), code(409));

    // Quota remains durable across functions, consumed challenges count too.
    const quota = [];
    for (let i = 0; i < 8; i++) { const r = initial(); quota.push({ request: r, challenge: (await call(r)).challenge }); }
    await assert.rejects(call(initial()), code(429));
    assert.deepEqual((await call(quota[0].request)).challenge, quota[0].challenge);
    await expireOld();
    const pending = (await call(initial())).challenge;
    const consumed = (await call(initial())).challenge;
    await call(exchange(consumed));
    const count = await auditCount();
    await owner.end(); owner = null;
    process.stdout.write("Gateway real PostgreSQL: restricted login, bootstrap, one-use, 8-way race, revocation lock, signer/audit rollback, TTL, realm and quota passed.\n");
    return async () => {
      assert.equal(verified(await call(exchange(pending)), pending, 3).license.revision, 3);
      await assert.rejects(call(exchange(consumed)), code(409));
      const inspect = new pg.Client({ ...connection, user: "ota_test_owner" });
      inspect.on("error", () => {}); await inspect.connect();
      try {
        assert.equal(Number((await inspect.query("SELECT count(*) AS n FROM ota_private.device_license_deliveries WHERE device_id=$1", [id])).rows[0].n), count + 1);
      } finally { await inspect.end(); }
      process.stdout.write("Gateway pending and consumed challenges/audit survive PostgreSQL restart.\n");
    };
  } finally {
    if (owner) { try { await owner.query("ROLLBACK"); } finally { await owner.end(); } }
  }
}
