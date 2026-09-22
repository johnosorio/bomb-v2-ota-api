import pg from "pg";
import { OtaError } from "./inventory.js";

const unavailable = () => { throw new OtaError(503, "OTA_GATEWAY_UNAVAILABLE"); };
export function gatewayDatabaseConfig(env) {
  try {
    const u = new URL(env.OTA_GATEWAY_DATABASE_URL);
    const pool = /^[a-z0-9-]+\.pooler\.supabase\.com$/.test(u.hostname);
    const direct = /^db\.[a-z0-9]{20}\.supabase\.co$/.test(u.hostname);
    const user = decodeURIComponent(u.username);
    if (!["postgres:", "postgresql:"].includes(u.protocol) || !(pool || direct) ||
        u.pathname !== "/postgres" || u.search || u.hash || !u.password ||
        (pool ? !/^bomb_ota_gateway\.[a-z0-9]{20}$/.test(user) || !["5432", "6543"].includes(u.port) :
          user !== "bomb_ota_gateway" || u.port !== "5432")) unavailable();
    const ca = env.OTA_GATEWAY_DATABASE_CA;
    if (ca !== undefined && (typeof ca !== "string" || ca.length > 16384 || !ca.startsWith("-----BEGIN CERTIFICATE-----") || ca.includes("PRIVATE KEY"))) unavailable();
    // No URL options can override TLS. All connection values explicit: no PG* fallback.
    return { host: u.hostname, port: Number(u.port), database: "postgres", user, password: decodeURIComponent(u.password),
      ssl: { rejectUnauthorized: true, ...(ca === undefined ? {} : { ca }) },
      connectionTimeoutMillis: 3000, query_timeout: 5000, application_name: "bomb-ota-device-gateway" };
  } catch { unavailable(); }
}

export const GATEWAY_ROLE_CHECK = `SELECT session_user=current_user AND current_user='bomb_ota_gateway'
  AND NOT (r.rolsuper OR r.rolinherit OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls)
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members WHERE member=r.oid)
  AND NOT pg_catalog.has_schema_privilege(current_user,'public','CREATE')
  AND NOT pg_catalog.has_schema_privilege(current_user,'ota_private','USAGE')
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname IN ('public','ota_private') AND c.relkind IN ('r','p','v','m')
      AND pg_catalog.has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='public' AND (p.prosecdef OR p.proname LIKE 'ota\\_%' ESCAPE '\\')
      AND p.oid NOT IN ('public.ota_gateway_challenge(jsonb,text)'::regprocedure,'public.ota_gateway_consume(jsonb,uuid,text,text)'::regprocedure)
      AND pg_catalog.has_function_privilege(current_user,p.oid,'EXECUTE')) AS ok
  FROM pg_catalog.pg_roles r WHERE r.rolname=current_user`;

export function gatewayTransaction(config, makeClient = (settings) => new pg.Client(settings)) {
  return async (operation) => {
    const client = makeClient(config);
    // Idle/network errors are propagated by query failures, never raw-logged.
    client.on("error", () => {});
    try {
      await client.connect();
      await client.query("BEGIN ISOLATION LEVEL READ COMMITTED");
      await client.query("SET LOCAL statement_timeout='4000'; SET LOCAL lock_timeout='2000'; SET LOCAL idle_in_transaction_session_timeout='5000'");
      const checked = await client.query(GATEWAY_ROLE_CHECK);
      if (checked.rows.length !== 1 || checked.rows[0].ok !== true) unavailable();
      const result = await operation((sql, values) => client.query(sql, values));
      await client.query("COMMIT");
      return result;
    } catch (error) {
      try { await client.query("ROLLBACK"); } catch { /* Unknown commit outcome: no signed output. */ }
      if (error instanceof OtaError) throw error;
      const mapped = { "42501": [403, "DEVICE_NOT_AUTHORIZED"], "23505": [409, "CHALLENGE_UNAVAILABLE"],
        "22023": [400, "INVALID_INPUT"], "54000": [429, "CHALLENGE_LIMIT"] }[error?.code];
      if (mapped) throw new OtaError(...mapped);
      unavailable();
    } finally {
      try { await client.end(); } catch { /* No pooled connection left with session privileges. */ }
    }
  };
}
