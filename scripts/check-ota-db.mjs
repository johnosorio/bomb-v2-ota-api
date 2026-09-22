// Explicit npm run test:db only; not part of node --test auto discovery.
// Disposable local PostgreSQL only. Never reads dotenv/credentials/DATABASE_URL.
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, readdir, realpath } from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { checkDeviceGateway } from "./check-device-gateway.mjs";

const exec = promisify(execFile);
const root = fileURLToPath(new URL("../", import.meta.url));
// Ignore inherited PGHOST/PGSERVICE/PGPASSWORD and startup files entirely.
const cleanEnv = { PATH: process.env.PATH, LANG: "C", LC_ALL: "C", PGCONNECT_TIMEOUT: "5" };
const pgBin = process.env.OTA_TEST_PG_BIN;
if (pgBin && !isAbsolute(pgBin)) throw new Error("OTA_TEST_PG_BIN must be an absolute local binary directory");
const run = (command, args, options = {}) => exec(pgBin ? join(pgBin, command) : command, args, {
  cwd: root, env: cleanEnv, timeout: 30000, maxBuffer: 1024 * 1024, ...options
});
// libpq alone includes initdb/pg_ctl but not the server; fail before making a cluster.
const version = (await run("postgres", ["--version"])).stdout.trim();
const temp = await realpath(await mkdtemp("/private/tmp/bomb-ota-pg-"));
const data = join(temp, "data");
const log = join(temp, "postgres.log");
const args = ["-X", "-h", temp, "-U", "ota_test_owner", "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-A", "-t"];
const sql = (statement) => run("psql", [...args, "-c", statement]);
const file = (path) => run("psql", [...args, "-f", resolve(root, path)]);
const startArgs = ["-D", data, "-l", log, "-w", "start", "-o", `-c listen_addresses='' -k '${temp}'`];
async function startCluster() {
  await run("pg_ctl", startArgs);
  assert.equal((await sql("show listen_addresses")).stdout.trim(), "", "test server must not listen on TCP");
  assert.equal((await sql("show unix_socket_directories")).stdout.trim(), temp);
}
let initialized = false;
try {
  await run("initdb", ["-D", data, "-A", "trust", "--no-locale", "--encoding=UTF8", "-U", "ota_test_owner"]);
  initialized = true;
  // Socket only, in a private 0700 temp directory; no TCP or remote connection.
  await startCluster();
  await file("test/sql/bootstrap.sql");
  for (const name of (await readdir(join(root, "supabase/migrations"))).filter((name) => name.endsWith(".sql")).sort()) {
    await file(`supabase/migrations/${name}`);
  }
  const result = await file("test/sql/ota-foundation.sql");
  process.stdout.write(result.stdout);
  process.stdout.write((await file("test/sql/ota-privileges.sql")).stdout);
  process.stdout.write((await file("test/sql/ota-licenses.sql")).stdout);

  // Independent committed fixtures for real multi-connection race tests.
  const scope = "90000000-0000-0000-0000-000000000001";
  const user = "90000000-0000-0000-0000-000000000002";
  await sql(`insert into auth.users(id) values ('${user}');
    insert into public.ota_scopes(id,name) values ('${scope}','Concurrency fixture');
    insert into public.ota_memberships(scope_id,user_id,role) values ('${scope}','${user}','admin');`);
  const identity = `set role authenticated; set request.jwt.claim.sub='${user}';`;
  const register = (id, label) => `select id from public.ota_register_device('${scope}','${id}','${label}');`;
  const same = await Promise.all(Array.from({ length: 8 }, () => sql(identity + register("RACE-SAME", "Same"))));
  const ids = same.map((result) => result.stdout.trim().split("\n").at(-1));
  assert.equal(new Set(ids).size, 1, "concurrent exact retries must return one ID");
  const changed = await Promise.allSettled([
    sql(identity + register("RACE-CHANGED", "First")), sql(identity + register("RACE-CHANGED", "Second"))
  ]);
  assert.equal(changed.filter((r) => r.status === "fulfilled").length, 1, "conflicting payloads: exactly one success");
  assert.match(changed.find((r) => r.status === "rejected").reason.stderr, /conflict/i);
  const persisted = await sql(`select
    (select count(*) from public.ota_devices where scope_id='${scope}'),
    (select count(*) from public.ota_audit_events where scope_id='${scope}');`);
  assert.equal(persisted.stdout.trim(), "2|2", "one audit per committed device across connections");
  const licenseDevice = ids[0];
  const licenseCall = (request, command) => identity + `select public.ota_admin_license('${licenseDevice}','${request}','${JSON.stringify(command)}'::jsonb);`;
  const approval = { action: "approve_identity", mac: "02:00:00:00:00:90", device_key_sha256: "9".repeat(64) };
  const licenseRetries = await Promise.all(Array.from({ length: 8 }, () => sql(licenseCall("91000000-0000-0000-0000-000000000001", approval))));
  assert.equal(new Set(licenseRetries.map((r) => r.stdout.trim().split("\n").at(-1))).size, 1, "approval retries return one durable receipt");
  const grant = { action: "grant", expected_revision: 0, not_before: 1, expires_at: 4102444800 };
  const competingGrants = await Promise.allSettled([2, 3].map((n) => sql(licenseCall(`91000000-0000-0000-0000-00000000000${n}`, grant))));
  assert.equal(competingGrants.filter((r) => r.status === "fulfilled").length, 1, "CAS: only one concurrent grant wins");
  assert.match(competingGrants.find((r) => r.status === "rejected").reason.stderr, /license operation conflict/);
  const competingRenewal = await Promise.allSettled([
    sql(licenseCall("91000000-0000-0000-0000-000000000004", { ...grant, expected_revision: 1 })),
    sql(licenseCall("91000000-0000-0000-0000-000000000005", { action: "revoke", expected_revision: 1 }))
  ]);
  assert.equal(competingRenewal.filter((r) => r.status === "fulfilled").length, 1, "renew/revoke CAS cannot overwrite a newer revision");
  assert.match(competingRenewal.find((r) => r.status === "rejected").reason.stderr, /license operation conflict/);
  const licenseState = async () => (await sql(`select revision,status,(select count(*) from public.ota_license_operations where device_id='${licenseDevice}') from public.ota_device_licenses where device_id='${licenseDevice}';`)).stdout.trim();
  const beforeLicenseRestart = await licenseState();
  assert.match(beforeLicenseRestart, /^2\|(granted|revoked)\|3$/);
  const checkGatewayAfterRestart = await checkDeviceGateway(temp);
  // Server restart as well as independent connections must retain committed data.
  await run("pg_ctl", ["-D", data, "-w", "stop", "-m", "fast"]);
  await startCluster();
  await checkGatewayAfterRestart();
  const afterRestart = await sql(identity + "select count(*) from public.ota_devices;");
  assert.equal(afterRestart.stdout.trim().split("\n").at(-1), "2", "RLS-visible inventory survives DB restart");
  assert.equal(await licenseState(), beforeLicenseRestart, "license revision/state/receipts survive restart");
  const historicalApproval = await sql(licenseCall("91000000-0000-0000-0000-000000000001", approval));
  assert.equal(historicalApproval.stdout.trim().split("\n").at(-1), licenseRetries[0].stdout.trim().split("\n").at(-1), "historical approval survives restart without changing state");
  assert.equal(await licenseState(), beforeLicenseRestart);
  process.stdout.write(`SQL, concurrency and restart checks passed on ${version}.\n`);
} finally {
  if (initialized) {
    try { await run("pg_ctl", ["-D", data, "-w", "stop", "-m", "fast"]); }
    catch (error) {
      // Already stopped is safe; any live-server stop error must fail the run.
      try { await run("pg_ctl", ["-D", data, "status"]); }
      catch (status) { if (status.code === 3) { initialized = false; } else { throw error; } }
      if (initialized) throw error;
    }
  }
  process.stdout.write(`Stopped local test cluster retained for inspection: ${temp}\n`);
}
