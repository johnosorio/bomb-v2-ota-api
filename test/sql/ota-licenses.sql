-- Local disposable DB only; run after foundation/privilege fixtures.
CREATE FUNCTION public.ota_test_assert(p_ok boolean, p_message text) RETURNS void
LANGUAGE plpgsql AS $$ BEGIN
  IF p_ok IS DISTINCT FROM true THEN RAISE EXCEPTION 'assertion: %', p_message; END IF;
END; $$;
CREATE FUNCTION public.ota_test_denied(p_sql text, p_code text) RETURNS void
LANGUAGE plpgsql AS $$ BEGIN
  BEGIN
    EXECUTE p_sql;
  EXCEPTION WHEN OTHERS THEN
    IF SQLSTATE = p_code THEN RETURN; END IF;
    RAISE;
  END;
  RAISE EXCEPTION 'expected SQLSTATE %', p_code;
END; $$;

INSERT INTO public.ota_devices(id,scope_id,device_id,label,created_by) VALUES
 ('50000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000001','LICENSE-A','License A','20000000-0000-0000-0000-000000000001'),
 ('50000000-0000-0000-0000-000000000002','10000000-0000-0000-0000-000000000002','LICENSE-B','License B','20000000-0000-0000-0000-000000000002'),
 ('50000000-0000-0000-0000-000000000003','10000000-0000-0000-0000-000000000001','LICENSE-C','License C','20000000-0000-0000-0000-000000000001');
DO $$ DECLARE r text; p text; BEGIN
  FOREACH r IN ARRAY ARRAY['ota_device_licenses','ota_license_operations'] LOOP
    PERFORM public.ota_test_assert((SELECT relrowsecurity FROM pg_class WHERE oid=('public.'||r)::regclass),'RLS');
    PERFORM public.ota_test_assert(has_table_privilege('authenticated','public.'||r,'SELECT'),'member read');
    FOREACH p IN ARRAY ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','TRIGGER','REFERENCES'] LOOP
      PERFORM public.ota_test_assert(NOT has_table_privilege('anon','public.'||r,p),'anon privilege');
      PERFORM public.ota_test_assert(NOT has_table_privilege('service_role','public.'||r,p),'service role privilege');
      IF p <> 'SELECT' THEN
        PERFORM public.ota_test_assert(NOT has_table_privilege('authenticated','public.'||r,p),'direct DML');
      END IF;
    END LOOP;
  END LOOP;
  FOREACH r IN ARRAY ARRAY['public.ota_admin_license(uuid,uuid,jsonb)','public.ota_get_device_license(uuid)'] LOOP
    PERFORM public.ota_test_assert(has_function_privilege('authenticated',r,'EXECUTE'),'RPC granted');
    PERFORM public.ota_test_assert(NOT has_function_privilege('anon',r,'EXECUTE'),'anon RPC');
    PERFORM public.ota_test_assert(NOT has_function_privilege('service_role',r,'EXECUTE'),'service RPC');
    PERFORM public.ota_test_assert((SELECT prosecdef AND proconfig = ARRAY['search_path=""'] FROM pg_proc WHERE oid=r::regprocedure),'definer search path');
  END LOOP;
END; $$;

SET ROLE authenticated;
SET request.jwt.claim.sub = '';
SELECT public.ota_test_denied($q$SELECT public.ota_get_device_license('50000000-0000-0000-0000-000000000001')$q$,'42501');
SET request.jwt.claim.sub = '20000000-0000-0000-0000-000000000001';
SELECT public.ota_test_assert(public.ota_get_device_license('50000000-0000-0000-0000-000000000001') IS NULL,'unapproved is null');
SELECT public.ota_test_denied($q$SELECT public.ota_get_device_license('50000000-0000-0000-0000-000000000002')$q$,'42501');
SELECT public.ota_test_denied($q$SELECT public.ota_get_device_license('59999999-0000-0000-0000-000000000001')$q$,'42501');
SELECT public.ota_test_denied($q$SELECT public.ota_admin_license('50000000-0000-0000-0000-000000000002',gen_random_uuid(),'{"action":"revoke","expected_revision":1}')$q$,'42501');

DO $$ DECLARE d uuid := '50000000-0000-0000-0000-000000000001'; a jsonb; b jsonb; c jsonb; bad jsonb; BEGIN
  c := jsonb_build_object('action','approve_identity','mac','02:00:00:00:00:01','device_key_sha256',repeat('a',64));
  a := public.ota_admin_license(d,'60000000-0000-0000-0000-000000000001',c);
  b := public.ota_admin_license(d,'60000000-0000-0000-0000-000000000001',c);
  PERFORM public.ota_test_assert(a=b AND a#>>'{snapshot,status}'='unlicensed','approval exact retry');
  PERFORM public.ota_test_denied(format('SELECT public.ota_admin_license(%L,%L,%L)',d,'60000000-0000-0000-0000-000000000001',c||'{"mac":"02:00:00:00:00:02"}'),'23505');
  PERFORM public.ota_test_denied(format('SELECT public.ota_admin_license(%L,gen_random_uuid(),%L)',d,c),'23505');
  FOREACH bad IN ARRAY ARRAY['null'::jsonb,'[]'::jsonb,'{}'::jsonb,c||'{"actor_id":"fake"}',c||'{"mac":null}',c||'{"device_key_sha256":42}',
    '{"action":"grant","expected_revision":null,"not_before":1,"expires_at":4102444800}'::jsonb,
    '{"action":"grant","expected_revision":0,"not_before":0,"expires_at":4102444800}'::jsonb,
    '{"action":"grant","expected_revision":0,"not_before":1,"expires_at":4294967296}'::jsonb,
    '{"action":"grant","expected_revision":0,"not_before":1.5,"expires_at":4102444800}'::jsonb,
    '{"action":"grant","expected_revision":0,"not_before":1,"expires_at":2}'::jsonb,
    '{"action":"revoke","expected_revision":"0"}'::jsonb,
    '{"action":"revoke","expected_revision":4294967296}'::jsonb] LOOP
    PERFORM public.ota_test_denied(format('SELECT public.ota_admin_license(%L,gen_random_uuid(),%L)',d,bad),'22023');
  END LOOP;
  PERFORM public.ota_test_denied(format('SELECT public.ota_admin_license(%L,NULL,%L)',d,c),'22023');
  PERFORM public.ota_test_denied(format('SELECT public.ota_admin_license(%L,gen_random_uuid(),%L)',d,
    jsonb_build_object('action',repeat('x',5000))),'22023');
  PERFORM public.ota_test_denied(format('SELECT public.ota_admin_license(%L,gen_random_uuid(),%L)',d,'{"action":"revoke","expected_revision":0}'),'23505');
  a := public.ota_admin_license(d,'60000000-0000-0000-0000-000000000002','{"action":"grant","expected_revision":0,"not_before":1,"expires_at":4102444800}');
  PERFORM public.ota_test_assert(a#>>'{snapshot,revision}'='1' AND a#>>'{snapshot,status}'='granted','initial grant');
  b := public.ota_admin_license(d,'60000000-0000-0000-0000-000000000003','{"action":"revoke","expected_revision":1}');
  PERFORM public.ota_test_assert(b#>>'{snapshot,revision}'='2' AND b#>>'{snapshot,status}'='revoked' AND b#>>'{snapshot,expires_at}'=a#>>'{snapshot,expires_at}','revoke retains dates');
  c := public.ota_admin_license(d,'60000000-0000-0000-0000-000000000002','{"action":"grant","expected_revision":0,"not_before":1,"expires_at":4102444800}');
  PERFORM public.ota_test_assert(a=c AND public.ota_get_device_license(d)->>'status'='revoked','historical retry does not un-revoke');
  PERFORM public.ota_test_denied(format('SELECT public.ota_admin_license(%L,gen_random_uuid(),%L)',d,'{"action":"grant","expected_revision":1,"not_before":1,"expires_at":4102444800}'),'23505');
  b := public.ota_admin_license(d,'60000000-0000-0000-0000-000000000004','{"action":"grant","expected_revision":2,"not_before":4000000000,"expires_at":4102444800}');
  PERFORM public.ota_test_assert(b#>>'{snapshot,revision}'='3' AND b#>>'{snapshot,license_id}'=a#>>'{snapshot,license_id}','future grant after revoke monotonic stable license');
  PERFORM public.ota_test_assert((SELECT count(*)=4 FROM public.ota_license_operations WHERE device_id=d),'one audit per success');
END; $$;

-- Identity reuse cannot cross scopes; a uniqueness error must leave no receipt.
SET request.jwt.claim.sub = '20000000-0000-0000-0000-000000000002';
DO $$ DECLARE c jsonb; BEGIN
 c := jsonb_build_object('action','approve_identity','mac','02:00:00:00:00:01','device_key_sha256',repeat('b',64));
 PERFORM public.ota_test_denied(format('SELECT public.ota_admin_license(%L,gen_random_uuid(),%L)','50000000-0000-0000-0000-000000000002',c),'23505');
 c := c||jsonb_build_object('mac','02:00:00:00:00:02','device_key_sha256',repeat('a',64));
 PERFORM public.ota_test_denied(format('SELECT public.ota_admin_license(%L,gen_random_uuid(),%L)','50000000-0000-0000-0000-000000000002',c),'23505');
 PERFORM public.ota_test_assert((SELECT count(*)=0 FROM public.ota_license_operations),'no cross-scope receipts');
END; $$;
SET request.jwt.claim.sub = '20000000-0000-0000-0000-000000000003';
SELECT public.ota_test_assert(public.ota_get_device_license('50000000-0000-0000-0000-000000000001')->>'revision'='3','viewer read');
SELECT public.ota_test_denied($q$SELECT public.ota_admin_license('50000000-0000-0000-0000-000000000001',gen_random_uuid(),'{"action":"revoke","expected_revision":3}')$q$,'42501');
SET request.jwt.claims = '{"is_anonymous":true}';
SELECT public.ota_test_assert((SELECT count(*)=0 FROM public.ota_device_licenses) AND (SELECT count(*)=0 FROM public.ota_license_operations),'anonymous Auth no reads');
SELECT public.ota_test_denied($q$SELECT public.ota_get_device_license('50000000-0000-0000-0000-000000000001')$q$,'42501');
SELECT public.ota_test_denied($q$SELECT public.ota_admin_license('50000000-0000-0000-0000-000000000001',gen_random_uuid(),'{"action":"revoke","expected_revision":3}')$q$,'42501');
RESET request.jwt.claims;
RESET ROLE;

-- An audit insertion failure rolls back state and revision together.
CREATE FUNCTION public.ota_test_fail_license_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 RAISE EXCEPTION USING ERRCODE='P0002', MESSAGE='test audit failure'; END; $$;
CREATE TRIGGER ota_test_fail_license_audit BEFORE INSERT ON public.ota_license_operations FOR EACH ROW EXECUTE FUNCTION public.ota_test_fail_license_audit();
SET ROLE authenticated;
SET request.jwt.claim.sub = '20000000-0000-0000-0000-000000000001';
SELECT public.ota_test_denied($q$SELECT public.ota_admin_license('50000000-0000-0000-0000-000000000001',gen_random_uuid(),'{"action":"revoke","expected_revision":3}')$q$,'P0002');
SELECT public.ota_test_assert(public.ota_get_device_license('50000000-0000-0000-0000-000000000001')->>'revision'='3','audit failure rollback');
RESET ROLE;
DROP TRIGGER ota_test_fail_license_audit ON public.ota_license_operations;
DROP FUNCTION public.ota_test_fail_license_audit();

-- Receipt actor cannot be changed even by another valid administrator.
INSERT INTO public.ota_memberships VALUES ('10000000-0000-0000-0000-000000000001','20000000-0000-0000-0000-000000000004','admin');
SET ROLE authenticated;
SET request.jwt.claim.sub = '20000000-0000-0000-0000-000000000004';
SELECT public.ota_test_denied($q$SELECT public.ota_admin_license('50000000-0000-0000-0000-000000000001','60000000-0000-0000-0000-000000000003','{"action":"revoke","expected_revision":1}')$q$,'23505');
RESET ROLE;
DELETE FROM public.ota_memberships WHERE user_id='20000000-0000-0000-0000-000000000004';
SET ROLE authenticated;
SELECT public.ota_test_denied($q$SELECT public.ota_get_device_license('50000000-0000-0000-0000-000000000001')$q$,'42501');
RESET ROLE;

-- Exhaustion fails closed, never wraps to revision zero.
UPDATE public.ota_device_licenses SET revision=4294967295 WHERE device_id='50000000-0000-0000-0000-000000000001';
SET ROLE authenticated;
SET request.jwt.claim.sub = '20000000-0000-0000-0000-000000000001';
SELECT public.ota_test_denied($q$SELECT public.ota_admin_license('50000000-0000-0000-0000-000000000001',gen_random_uuid(),'{"action":"revoke","expected_revision":4294967295}')$q$,'23505');
RESET ROLE;
DROP FUNCTION public.ota_test_assert(boolean,text), public.ota_test_denied(text,text);
\echo 'License RLS, transitions, strict validation, CAS, audit rollback, replay and exhaustion passed'
