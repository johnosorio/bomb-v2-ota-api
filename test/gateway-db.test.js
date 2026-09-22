import test from "node:test";
import assert from "node:assert/strict";
import { gatewayDatabaseConfig, gatewayTransaction, GATEWAY_ROLE_CHECK } from "../lib/ota/gateway-db.js";
import { OtaError } from "../lib/ota/inventory.js";

const url = "postgresql://bomb_ota_gateway:synthetic_password@db.abcdefghijklmnopqrst.supabase.co:5432/postgres";
const config = () => gatewayDatabaseConfig({ OTA_GATEWAY_DATABASE_URL: url });
const unavailable = (fn) => assert.throws(fn, (error) => error instanceof OtaError && error.status === 503 && error.code === "OTA_GATEWAY_UNAVAILABLE");

function fakeClient({ role = true, fail = null, commit = null } = {}) {
  const log = [];
  return { log, on() {}, async connect() { log.push("connect"); }, async end() { log.push("end"); },
    async query(sql, values) {
      log.push([sql, values]);
      if (fail && sql === fail.sql) throw Object.assign(new Error("synthetic private provider detail"), { code: fail.code });
      if (sql === "COMMIT" && commit) await commit;
      if (sql === GATEWAY_ROLE_CHECK) return { rows: [{ ok: role }] };
      return { rows: [{ ok: true }] };
    } };
}

test("database config pins Supabase TLS and rejects URL/CA privilege overrides", () => {
  const settings = config();
  assert.equal(settings.ssl.rejectUnauthorized, true);
  assert.equal(settings.host, "db.abcdefghijklmnopqrst.supabase.co");
  for (const OTA_GATEWAY_DATABASE_URL of [
    "postgresql://postgres:synthetic_password@db.abcdefghijklmnopqrst.supabase.co:5432/postgres",
    `${url}?sslmode=disable`, "postgresql://bomb_ota_gateway:synthetic_password@db.example.invalid:5432/postgres"
  ]) unavailable(() => gatewayDatabaseConfig({ OTA_GATEWAY_DATABASE_URL }));
  unavailable(() => gatewayDatabaseConfig({ OTA_GATEWAY_DATABASE_URL: url, OTA_GATEWAY_DATABASE_CA: "-----BEGIN CERTIFICATE-----\nPRIVATE KEY" }));
});

test("transaction enforces BEGIN, local limits, role check, operation, COMMIT and end", async () => {
  const client = fakeClient();
  const transaction = gatewayTransaction(config(), () => client);
  const result = await transaction((query) => query("SELECT fixture", ["value"]));
  assert.deepEqual(result, { rows: [{ ok: true }] });
  assert.equal(client.log[1][0], "BEGIN ISOLATION LEVEL READ COMMITTED");
  assert.match(client.log[2][0], /SET LOCAL statement_timeout/);
  assert.equal(client.log[3][0], GATEWAY_ROLE_CHECK);
  assert.deepEqual(client.log.slice(4).map(v => Array.isArray(v) ? v[0] : v), ["SELECT fixture", "COMMIT", "end"]);
});

test("a transaction result is not observable until its controllable COMMIT resolves", async () => {
  let releaseCommit;
  const client = fakeClient({ commit: new Promise(resolve => { releaseCommit = resolve; }) });
  const candidate = { schema_version: 1, status_document: "synthetic" };
  let published = false;
  const pending = gatewayTransaction(config(), () => client)(async () => candidate).then(value => {
    published = true;
    return value;
  });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(published, false);
  releaseCommit();
  assert.deepEqual(await pending, candidate);
  assert.equal(published, true);
});

test("failed role, operation and commit roll back, sanitize errors and expose no output", async () => {
  const denied = fakeClient({ role: false });
  await assert.rejects(() => gatewayTransaction(config(), () => denied)(() => { throw new Error("must not run"); }),
    (error) => error instanceof OtaError && error.code === "OTA_GATEWAY_UNAVAILABLE");
  assert.equal(denied.log.some(v => Array.isArray(v) && v[0] === "ROLLBACK"), true);
  const forbidden = fakeClient({ fail: { sql: "SELECT fixture", code: "42501" } });
  await assert.rejects(() => gatewayTransaction(config(), () => forbidden)((query) => query("SELECT fixture")),
    (error) => error instanceof OtaError && error.status === 403 && error.code === "DEVICE_NOT_AUTHORIZED");
  const commitFailed = fakeClient({ fail: { sql: "COMMIT", code: "XX000" } });
  let published;
  await assert.rejects(async () => { published = await gatewayTransaction(config(), () => commitFailed)(async () =>
    ({ schema_version: 1, status_document: "synthetic" })); },
  (error) => error instanceof OtaError && error.code === "OTA_GATEWAY_UNAVAILABLE");
  assert.equal(published, undefined);
  assert.equal(commitFailed.log.some(v => Array.isArray(v) && v[0] === "ROLLBACK"), true);
});
