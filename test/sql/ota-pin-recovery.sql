-- Disposable PostgreSQL test only. Run after bootstrap, all current migrations,
-- and 20261001000100_ota_pin_recovery.sql in the isolated test cluster.
CREATE FUNCTION public.ota_pin_test_assert(p_ok boolean, p_message text) RETURNS void
LANGUAGE plpgsql AS $$ BEGIN
  IF p_ok IS DISTINCT FROM true THEN RAISE EXCEPTION 'assertion: %', p_message; END IF;
END; $$;

INSERT INTO auth.users(id) VALUES
 ('82000000-0000-0000-0000-000000000001'),
 ('82000000-0000-0000-0000-000000000002'),
 ('82000000-0000-0000-0000-000000000003'),
 ('82000000-0000-0000-0000-000000000004');
INSERT INTO public.ota_scopes(id,name) VALUES
 ('82000000-0000-0000-0000-000000000010','PIN scope A'),
 ('82000000-0000-0000-0000-000000000011','PIN scope B');
INSERT INTO public.ota_memberships(scope_id,user_id,role) VALUES
 ('82000000-0000-0000-0000-000000000010','82000000-0000-0000-0000-000000000001','admin'),
 ('82000000-0000-0000-0000-000000000010','82000000-0000-0000-0000-000000000002','viewer'),
 ('82000000-0000-0000-0000-000000000011','82000000-0000-0000-0000-000000000003','admin');
INSERT INTO public.ota_devices(id,scope_id,device_id,label,created_by) VALUES
 ('82000000-0000-0000-0000-000000000100','82000000-0000-0000-0000-000000000010','PIN-DEVICE-A','PIN device A','82000000-0000-0000-0000-000000000001'),
 ('82000000-0000-0000-0000-000000000101','82000000-0000-0000-0000-000000000011','PIN-DEVICE-B','PIN device B','82000000-0000-0000-0000-000000000003');

BEGIN;
SET LOCAL ROLE authenticated;
SET LOCAL request.jwt.claim.sub = '82000000-0000-0000-0000-000000000001';
SELECT public.ota_admin_license('82000000-0000-0000-0000-000000000100','82000000-0000-0000-0000-000000000201',
  jsonb_build_object('action','approve_identity','mac','02:00:00:00:08:10','device_key_sha256',repeat('96',32)));
COMMIT;

DO $$ DECLARE r text; p text; BEGIN
  FOREACH r IN ARRAY ARRAY['ota_private.pin_recoveries','ota_private.pin_recovery_events'] LOOP
    PERFORM public.ota_pin_test_assert((SELECT relrowsecurity FROM pg_class WHERE oid=r::regclass),'PIN private RLS');
    FOREACH p IN ARRAY ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER'] LOOP
      PERFORM public.ota_pin_test_assert(NOT has_table_privilege('anon',r,p),'anon private grant');
      PERFORM public.ota_pin_test_assert(NOT has_table_privilege('authenticated',r,p),'authenticated private grant');
      PERFORM public.ota_pin_test_assert(NOT has_table_privilege('service_role',r,p),'service private grant');
      PERFORM public.ota_pin_test_assert(NOT has_table_privilege('bomb_ota_gateway',r,p),'gateway private grant');
    END LOOP;
  END LOOP;
  PERFORM public.ota_pin_test_assert(has_function_privilege('bomb_ota_gateway','public.ota_pin_device(jsonb,text,text,text)','EXECUTE'),'gateway RPC grant');
  FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
    PERFORM public.ota_pin_test_assert(NOT has_function_privilege(r,'public.ota_pin_device(jsonb,text,text,text)','EXECUTE'),'device RPC leak');
  END LOOP;
  PERFORM public.ota_pin_test_assert(has_function_privilege('authenticated','public.ota_pin_admin(text,text)','EXECUTE'),'admin grant');
  PERFORM public.ota_pin_test_assert(has_function_privilege('authenticated','public.ota_pin_list()','EXECUTE'),'list grant');
  FOREACH r IN ARRAY ARRAY['anon','service_role','bomb_ota_gateway'] LOOP
    PERFORM public.ota_pin_test_assert(NOT has_function_privilege(r,'public.ota_pin_admin(text,text)','EXECUTE'),'admin RPC leak');
    PERFORM public.ota_pin_test_assert(NOT has_function_privilege(r,'public.ota_pin_list()','EXECUTE'),'list RPC leak');
  END LOOP;
END; $$;

BEGIN;
SET LOCAL ROLE bomb_ota_gateway;
DO $$ DECLARE a jsonb; b jsonb; BEGIN
  a := public.ota_pin_device(jsonb_build_object('mac','02:00:00:00:08:10','device_key_sha256',repeat('96',32),'realm','pin-test'),
    'create',repeat('1',64),repeat('2',64));
  b := public.ota_pin_device(jsonb_build_object('mac','02:00:00:00:08:10','device_key_sha256',repeat('96',32),'realm','pin-test'),
    'create',repeat('1',64),repeat('3',64));
  IF a->>'status' <> 'pending' OR a->>'nonce' <> repeat('2',64) OR b->>'nonce' <> repeat('3',64)
    OR a->>'issued_at' <> b->>'issued_at' OR a->>'expires_at' <> b->>'expires_at' THEN
    RAISE EXCEPTION 'create retry did not retain its original TTL';
  END IF;
END; $$;
COMMIT;
SELECT public.ota_pin_test_assert((SELECT count(*) FROM ota_private.pin_recoveries WHERE request_id=repeat('1',64))=1,'single idempotent request');
SELECT public.ota_pin_test_assert((SELECT count(*) FROM ota_private.pin_recovery_events WHERE request_id=repeat('1',64))=1,'single create audit');

BEGIN;
SET LOCAL ROLE bomb_ota_gateway;
SELECT public.ota_pin_device(jsonb_build_object('mac','02:00:00:00:08:10','device_key_sha256',repeat('96',32),'realm','pin-test'),'create',repeat('4',64),repeat('5',64));
SELECT public.ota_pin_device(jsonb_build_object('mac','02:00:00:00:08:10','device_key_sha256',repeat('96',32),'realm','pin-test'),'create',repeat('6',64),repeat('7',64));
SELECT public.ota_pin_device(jsonb_build_object('mac','02:00:00:00:08:10','device_key_sha256',repeat('96',32),'realm','pin-test'),'create',repeat('8',64),repeat('9',64));
DO $$ BEGIN
  PERFORM public.ota_pin_device(jsonb_build_object('mac','02:00:00:00:08:10','device_key_sha256',repeat('96',32),'realm','pin-test'),'create',repeat('c',64),repeat('d',64));
  RAISE EXCEPTION 'fifth live request accepted';
EXCEPTION WHEN SQLSTATE '54000' THEN NULL; END; $$;
COMMIT;

BEGIN;
SET LOCAL ROLE authenticated;
SET LOCAL request.jwt.claim.sub = '82000000-0000-0000-0000-000000000002';
DO $$ BEGIN
  PERFORM public.ota_pin_admin(repeat('1',64),'approve');
  RAISE EXCEPTION 'viewer approved request';
EXCEPTION WHEN SQLSTATE '42501' THEN NULL; END; $$;
COMMIT;
BEGIN;
SET LOCAL ROLE authenticated;
SET LOCAL request.jwt.claim.sub = '82000000-0000-0000-0000-000000000003';
DO $$ BEGIN
  PERFORM public.ota_pin_admin(repeat('1',64),'approve');
  RAISE EXCEPTION 'foreign admin approved request';
EXCEPTION WHEN SQLSTATE '42501' THEN NULL; END; $$;
COMMIT;
BEGIN;
SET LOCAL ROLE authenticated;
SET LOCAL request.jwt.claim.sub = '82000000-0000-0000-0000-000000000001';
DO $$ DECLARE a jsonb; b jsonb; BEGIN
  a := public.ota_pin_admin(repeat('1',64),'approve');
  b := public.ota_pin_admin(repeat('1',64),'approve');
  IF a <> b OR a->>'status' <> 'approved' OR a ? 'nonce' THEN RAISE EXCEPTION 'approval retry contract'; END IF;
END; $$;
COMMIT;

BEGIN;
SET LOCAL ROLE bomb_ota_gateway;
DO $$ DECLARE a jsonb; b jsonb; BEGIN
  a := public.ota_pin_device(jsonb_build_object('mac','02:00:00:00:08:10','device_key_sha256',repeat('96',32),'realm','pin-test'),'consume',repeat('1',64),repeat('e',64));
  b := public.ota_pin_device(jsonb_build_object('mac','02:00:00:00:08:10','device_key_sha256',repeat('96',32),'realm','pin-test'),'consume',repeat('1',64),repeat('e',64));
  IF a->>'status' <> 'consumed' OR b->>'status' <> 'consumed' THEN RAISE EXCEPTION 'consume retry contract'; END IF;
  BEGIN
    PERFORM public.ota_pin_device(jsonb_build_object('mac','02:00:00:00:08:10','device_key_sha256',repeat('96',32),'realm','pin-test'),'consume',repeat('1',64),repeat('f',64));
    RAISE EXCEPTION 'different consume nonce accepted';
  EXCEPTION WHEN SQLSTATE '23505' THEN NULL; END;
END; $$;
COMMIT;
SELECT public.ota_pin_test_assert((SELECT count(*) FROM ota_private.pin_recovery_events WHERE request_id=repeat('1',64))=3,'create approve consume audit');

BEGIN;
SET LOCAL ROLE bomb_ota_gateway;
DO $$ BEGIN
  PERFORM public.ota_pin_device(jsonb_build_object('mac','02:00:00:00:08:10','device_key_sha256',repeat('96',32),'realm','pin-test'),NULL,repeat('1',64),repeat('e',64));
  RAISE EXCEPTION 'NULL device action accepted';
EXCEPTION WHEN SQLSTATE '22023' THEN NULL; END; $$;
COMMIT;
BEGIN;
SET LOCAL ROLE authenticated;
SET LOCAL request.jwt.claim.sub = '82000000-0000-0000-0000-000000000001';
DO $$ BEGIN
  PERFORM public.ota_pin_admin(repeat('1',64),NULL);
  RAISE EXCEPTION 'NULL admin action accepted';
EXCEPTION WHEN SQLSTATE '22023' THEN NULL; END; $$;
COMMIT;

-- A successful consume retry is still bounded by the original request TTL.
UPDATE ota_private.pin_recoveries SET issued_at=1,expires_at=601 WHERE request_id=repeat('1',64);
BEGIN;
SET LOCAL ROLE bomb_ota_gateway;
DO $$ BEGIN
  PERFORM public.ota_pin_device(jsonb_build_object('mac','02:00:00:00:08:10','device_key_sha256',repeat('96',32),'realm','pin-test'),'consume',repeat('1',64),repeat('e',64));
  RAISE EXCEPTION 'expired consumed retry accepted';
EXCEPTION WHEN SQLSTATE '23505' THEN NULL; END; $$;
COMMIT;

-- Expiry is calculated at read time and does not mutate the historical state.
UPDATE ota_private.pin_recoveries SET issued_at=1,expires_at=601 WHERE request_id=repeat('4',64);
BEGIN;
SET LOCAL ROLE bomb_ota_gateway;
DO $$ DECLARE r jsonb; BEGIN
  r := public.ota_pin_device(jsonb_build_object('mac','02:00:00:00:08:10','device_key_sha256',repeat('96',32),'realm','pin-test'),'status',repeat('4',64),repeat('0',64));
  IF r->>'status' <> 'expired' OR r->>'nonce' <> repeat('0',64) THEN RAISE EXCEPTION 'expired status missing'; END IF;
END; $$;
COMMIT;

-- A credential replacement blocks all requests for the old credential.
BEGIN;
SET LOCAL ROLE authenticated;
SET LOCAL request.jwt.claim.sub = '82000000-0000-0000-0000-000000000001';
SELECT public.ota_admin_license('82000000-0000-0000-0000-000000000100','82000000-0000-0000-0000-000000000203',
  jsonb_build_object('action','replace_credential','expected_revision',0,
    'expected_credential_id',(SELECT credential_id::text FROM public.ota_device_licenses WHERE device_id='82000000-0000-0000-0000-000000000100'),
    'reason','lost','device_key_sha256',repeat('97',32)));
COMMIT;
BEGIN;
SET LOCAL ROLE bomb_ota_gateway;
DO $$ BEGIN
  PERFORM public.ota_pin_device(jsonb_build_object('mac','02:00:00:00:08:10','device_key_sha256',repeat('96',32),'realm','pin-test'),'status',repeat('4',64),repeat('0',64));
  RAISE EXCEPTION 'old credential read request';
EXCEPTION WHEN SQLSTATE '42501' THEN NULL; END; $$;
COMMIT;

-- Real two-connection race, local socket only: the second create waits on the
-- device row and becomes the same durable retry after the first commits.
CREATE EXTENSION IF NOT EXISTS dblink;
SELECT dblink_connect('pin_a',format('host=%s port=%s dbname=%s user=ota_test_owner',current_setting('unix_socket_directories'),current_setting('port'),current_database()));
SELECT dblink_connect('pin_b',format('host=%s port=%s dbname=%s user=ota_test_owner',current_setting('unix_socket_directories'),current_setting('port'),current_database()));
CREATE TEMP TABLE pin_race_results(data jsonb);
SELECT dblink_exec('pin_a','BEGIN');
SELECT dblink_exec('pin_a','SET LOCAL ROLE bomb_ota_gateway');
SELECT dblink_send_query('pin_a',$q$SELECT public.ota_pin_device('{"mac":"02:00:00:00:08:10","device_key_sha256":"9797979797979797979797979797979797979797979797979797979797979797","realm":"pin-test"}'::jsonb,'create','dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd','eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee')$q$);
INSERT INTO pin_race_results SELECT data::jsonb FROM dblink_get_result('pin_a') AS t(data text);
SELECT * FROM dblink_get_result('pin_a') AS t(data text);
SELECT dblink_exec('pin_b','BEGIN');
SELECT dblink_exec('pin_b','SET LOCAL ROLE bomb_ota_gateway');
SELECT dblink_send_query('pin_b',$q$SELECT public.ota_pin_device('{"mac":"02:00:00:00:08:10","device_key_sha256":"9797979797979797979797979797979797979797979797979797979797979797","realm":"pin-test"}'::jsonb,'create','dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd','ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')$q$);
SELECT pg_catalog.pg_sleep(0.1);
SELECT public.ota_pin_test_assert(dblink_is_busy('pin_b')=1,'concurrent retry waits on device lock');
SELECT dblink_exec('pin_a','COMMIT');
INSERT INTO pin_race_results SELECT data::jsonb FROM dblink_get_result('pin_b') AS t(data text);
SELECT * FROM dblink_get_result('pin_b') AS t(data text);
SELECT public.ota_pin_test_assert((SELECT count(*) FROM pin_race_results)=2,'two race responses');
SELECT public.ota_pin_test_assert((SELECT count(*) FROM ota_private.pin_recoveries WHERE request_id=repeat('d',64))=1,'race wrote one recovery');
SELECT public.ota_pin_test_assert((SELECT count(*) FROM ota_private.pin_recovery_events WHERE request_id=repeat('d',64) AND event='created')=1,'race wrote one audit');
SELECT dblink_disconnect('pin_a');
SELECT dblink_disconnect('pin_b');

-- Approval and device cancellation serialize through the same device lock.
BEGIN;
SET LOCAL ROLE bomb_ota_gateway;
SELECT public.ota_pin_device(jsonb_build_object('mac','02:00:00:00:08:10','device_key_sha256',repeat('97',32),'realm','pin-test'),'create',repeat('e',64),repeat('a',64));
COMMIT;
SELECT dblink_connect('pin_approve',format('host=%s port=%s dbname=%s user=ota_test_owner',current_setting('unix_socket_directories'),current_setting('port'),current_database()));
SELECT dblink_connect('pin_cancel',format('host=%s port=%s dbname=%s user=ota_test_owner',current_setting('unix_socket_directories'),current_setting('port'),current_database()));
SELECT dblink_exec('pin_approve','BEGIN');
SELECT dblink_exec('pin_approve','SET LOCAL ROLE authenticated');
SELECT dblink_exec('pin_approve',$q$SET LOCAL request.jwt.claim.sub = '82000000-0000-0000-0000-000000000001'$q$);
SELECT dblink_send_query('pin_approve',$q$SELECT public.ota_pin_admin('eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee','approve')$q$);
SELECT * FROM dblink_get_result('pin_approve') AS t(data text);
SELECT * FROM dblink_get_result('pin_approve') AS t(data text);
SELECT dblink_exec('pin_cancel','BEGIN');
SELECT dblink_exec('pin_cancel','SET LOCAL ROLE bomb_ota_gateway');
SELECT dblink_send_query('pin_cancel',$q$SELECT public.ota_pin_device('{"mac":"02:00:00:00:08:10","device_key_sha256":"9797979797979797979797979797979797979797979797979797979797979797","realm":"pin-test"}'::jsonb,'cancel','eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee','bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb')$q$);
SELECT pg_catalog.pg_sleep(0.1);
SELECT public.ota_pin_test_assert(dblink_is_busy('pin_cancel')=1,'cancel waits for approval lock');
SELECT dblink_exec('pin_approve','COMMIT');
SELECT * FROM dblink_get_result('pin_cancel') AS t(data text);
SELECT * FROM dblink_get_result('pin_cancel') AS t(data text);
SELECT dblink_exec('pin_cancel','COMMIT');
SELECT public.ota_pin_test_assert((SELECT status='cancelled' FROM ota_private.pin_recoveries WHERE request_id=repeat('e',64)),'approval then cancel serialization');
SELECT public.ota_pin_test_assert((SELECT count(*) FROM ota_private.pin_recovery_events WHERE request_id=repeat('e',64) AND event IN ('approved','cancelled'))=2,'approval cancel audit');
SELECT dblink_disconnect('pin_approve');
SELECT dblink_disconnect('pin_cancel');

-- A credential replacement waits for an approval, then invalidates that
-- approved request and its former credential for all later device calls.
BEGIN;
SET LOCAL ROLE bomb_ota_gateway;
SELECT public.ota_pin_device(jsonb_build_object('mac','02:00:00:00:08:10','device_key_sha256',repeat('97',32),'realm','pin-test'),'create',repeat('f',64),repeat('a',64));
COMMIT;
SELECT dblink_connect('pin_approval',format('host=%s port=%s dbname=%s user=ota_test_owner',current_setting('unix_socket_directories'),current_setting('port'),current_database()));
SELECT dblink_connect('pin_replace',format('host=%s port=%s dbname=%s user=ota_test_owner',current_setting('unix_socket_directories'),current_setting('port'),current_database()));
SELECT dblink_exec('pin_approval','BEGIN');
SELECT dblink_exec('pin_approval','SET LOCAL ROLE authenticated');
SELECT dblink_exec('pin_approval',$q$SET LOCAL request.jwt.claim.sub = '82000000-0000-0000-0000-000000000001'$q$);
SELECT dblink_send_query('pin_approval',$q$SELECT public.ota_pin_admin('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff','approve')$q$);
SELECT * FROM dblink_get_result('pin_approval') AS t(data text);
SELECT * FROM dblink_get_result('pin_approval') AS t(data text);
SELECT dblink_exec('pin_replace','BEGIN');
SELECT dblink_exec('pin_replace','SET LOCAL ROLE authenticated');
SELECT dblink_exec('pin_replace',$q$SET LOCAL request.jwt.claim.sub = '82000000-0000-0000-0000-000000000001'$q$);
SELECT dblink_send_query('pin_replace',$q$SELECT public.ota_admin_license('82000000-0000-0000-0000-000000000100','82000000-0000-0000-0000-000000000204',jsonb_build_object('action','replace_credential','expected_revision',1,'expected_credential_id',(SELECT credential_id::text FROM public.ota_device_licenses WHERE device_id='82000000-0000-0000-0000-000000000100'),'reason','lost','device_key_sha256',repeat('98',32)))$q$);
SELECT pg_catalog.pg_sleep(0.1);
SELECT public.ota_pin_test_assert(dblink_is_busy('pin_replace')=1,'credential replacement waits for approval lock');
SELECT dblink_exec('pin_approval','COMMIT');
SELECT * FROM dblink_get_result('pin_replace') AS t(data text);
SELECT * FROM dblink_get_result('pin_replace') AS t(data text);
SELECT dblink_exec('pin_replace','COMMIT');
SELECT dblink_disconnect('pin_approval');
SELECT dblink_disconnect('pin_replace');
BEGIN;
SET LOCAL ROLE bomb_ota_gateway;
DO $$ BEGIN
  PERFORM public.ota_pin_device(jsonb_build_object('mac','02:00:00:00:08:10','device_key_sha256',repeat('97',32),'realm','pin-test'),'status',repeat('f',64),repeat('a',64));
  RAISE EXCEPTION 'replaced credential read approved request';
EXCEPTION WHEN SQLSTATE '42501' THEN NULL; END; $$;
COMMIT;

-- Append-only audit failure rolls back the approval transition.
CREATE FUNCTION public.ota_test_pin_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.request_id=repeat('9',64) AND NEW.event='approved' THEN RAISE EXCEPTION 'test audit failure'; END IF;
  RETURN NEW;
END; $$;
CREATE TRIGGER ota_test_pin_audit_failure BEFORE INSERT ON ota_private.pin_recovery_events
  FOR EACH ROW EXECUTE FUNCTION public.ota_test_pin_audit_failure();
BEGIN;
SET LOCAL ROLE bomb_ota_gateway;
SELECT public.ota_pin_device(jsonb_build_object('mac','02:00:00:00:08:10','device_key_sha256',repeat('98',32),'realm','pin-test'),'create',repeat('9',64),repeat('8',64));
COMMIT;
BEGIN;
SET LOCAL ROLE authenticated;
SET LOCAL request.jwt.claim.sub = '82000000-0000-0000-0000-000000000001';
DO $$ BEGIN
  PERFORM public.ota_pin_admin(repeat('9',64),'approve');
  RAISE EXCEPTION 'approval committed despite audit failure';
EXCEPTION WHEN OTHERS THEN
  IF SQLERRM <> 'test audit failure' THEN RAISE; END IF;
END; $$;
COMMIT;
SELECT public.ota_pin_test_assert((SELECT status='pending' FROM ota_private.pin_recoveries WHERE request_id=repeat('9',64)),'audit failure rollback status');
SELECT public.ota_pin_test_assert((SELECT count(*) FROM ota_private.pin_recovery_events WHERE request_id=repeat('9',64) AND event='approved')=0,'audit failure rollback event');

BEGIN;
SET LOCAL ROLE authenticated;
SET LOCAL request.jwt.claim.sub = '82000000-0000-0000-0000-000000000001';
SELECT public.ota_pin_test_assert(jsonb_array_length(public.ota_pin_list()) >= 1,'admin list');
COMMIT;
DROP FUNCTION public.ota_pin_test_assert(boolean,text);
DROP TRIGGER ota_test_pin_audit_failure ON ota_private.pin_recovery_events;
DROP FUNCTION public.ota_test_pin_audit_failure();
-- Test-only concurrency extension must not broaden the later gateway checks.
DROP EXTENSION dblink;
\echo 'PIN recovery SQL, RLS/grants, replay, expiry, credential transition, race and rollback checks passed'
