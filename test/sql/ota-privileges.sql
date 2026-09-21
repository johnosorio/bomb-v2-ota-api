-- Defense-in-depth checks against Supabase-like inherited grants.
DO $$
DECLARE
  relation text;
  privilege text;
BEGIN
  FOREACH relation IN ARRAY ARRAY['ota_scopes','ota_memberships','ota_devices','ota_audit_events'] LOOP
    IF NOT (SELECT relrowsecurity FROM pg_class WHERE oid=('public.' || relation)::regclass) THEN
      RAISE EXCEPTION 'RLS disabled on %', relation;
    END IF;
    IF has_table_privilege('anon', 'public.' || relation, 'SELECT') OR
       NOT has_table_privilege('authenticated', 'public.' || relation, 'SELECT') THEN
      RAISE EXCEPTION 'incorrect read grants on %', relation;
    END IF;
    FOREACH privilege IN ARRAY ARRAY['INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER'] LOOP
      IF has_table_privilege('anon', 'public.' || relation, privilege) OR
         has_table_privilege('authenticated', 'public.' || relation, privilege) THEN
        RAISE EXCEPTION 'direct privilege % leaked on %', privilege, relation;
      END IF;
    END LOOP;
  END LOOP;
  IF has_function_privilege('anon', 'public.ota_register_device(uuid,text,text)', 'EXECUTE') OR
     NOT has_function_privilege('authenticated', 'public.ota_register_device(uuid,text,text)', 'EXECUTE') THEN
    RAISE EXCEPTION 'incorrect RPC execution grants';
  END IF;
END;
$$;

BEGIN;
SET LOCAL ROLE authenticated;
SET LOCAL request.jwt.claim.sub = '';
DO $$
BEGIN
  PERFORM public.ota_register_device('10000000-0000-0000-0000-000000000001','NO-UID','No UID');
  RAISE EXCEPTION 'missing UID authorized';
EXCEPTION WHEN SQLSTATE '42501' THEN NULL;
END;
$$;
COMMIT;

BEGIN;
SET LOCAL ROLE authenticated;
SET LOCAL request.jwt.claim.sub = '20000000-0000-0000-0000-000000000001';
DO $$
BEGIN
  PERFORM public.ota_register_device('10000000-0000-0000-0000-000000000002','WRONG-SCOPE','Wrong scope');
  RAISE EXCEPTION 'admin registered in a foreign scope';
EXCEPTION WHEN SQLSTATE '42501' THEN NULL;
END;
$$;
COMMIT;
-- Supabase anonymous Auth users are authenticated-role identities. Even an
-- operator's accidental membership grant must not allow direct REST/RPC access.
BEGIN;
SET LOCAL ROLE authenticated;
SET LOCAL request.jwt.claim.sub = '20000000-0000-0000-0000-000000000001';
SET LOCAL request.jwt.claims = '{"is_anonymous":true}';
DO $$
BEGIN
  IF (SELECT count(*) FROM public.ota_scopes) <> 0 OR
     (SELECT count(*) FROM public.ota_memberships) <> 0 OR
     (SELECT count(*) FROM public.ota_devices) <> 0 OR
     (SELECT count(*) FROM public.ota_audit_events) <> 0 THEN
    RAISE EXCEPTION 'anonymous Auth user read data via accidental membership';
  END IF;
  PERFORM public.ota_register_device('10000000-0000-0000-0000-000000000001','ANON-MEMBER','Denied');
  RAISE EXCEPTION 'anonymous Auth user registered via accidental membership';
EXCEPTION WHEN SQLSTATE '42501' THEN NULL;
END;
$$;
COMMIT;
\echo 'Extra grant/no-UID/cross-scope/anonymous-Auth checks passed'
