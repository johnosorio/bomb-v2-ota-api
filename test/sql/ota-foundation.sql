-- Requires the coordinator's isolated PG17/18 harness to have already applied
-- the migration, created auth.users(id uuid primary key), auth.uid(), and the
-- anon/authenticated roles. The harness must simulate Supabase's permissive
-- default table grants before applying the migration. Fixtures intentionally
-- commit and remain available for the runner's separate-connection/concurrency
-- checks; run this only against a fresh isolated database.

INSERT INTO auth.users (id) VALUES
  ('20000000-0000-0000-0000-000000000001'),
  ('20000000-0000-0000-0000-000000000002'),
  ('20000000-0000-0000-0000-000000000003'),
  ('20000000-0000-0000-0000-000000000004');

INSERT INTO public.ota_scopes (id, name) VALUES
  ('10000000-0000-0000-0000-000000000001', 'OTA test scope A'),
  ('10000000-0000-0000-0000-000000000002', 'OTA test scope B');

INSERT INTO public.ota_memberships (scope_id, user_id, role) VALUES
  ('10000000-0000-0000-0000-000000000001', '20000000-0000-0000-0000-000000000001', 'admin'),
  ('10000000-0000-0000-0000-000000000001', '20000000-0000-0000-0000-000000000003', 'viewer'),
  ('10000000-0000-0000-0000-000000000002', '20000000-0000-0000-0000-000000000002', 'admin');

-- Anonymous clients have neither direct reads nor RPC execution.
BEGIN;
SET LOCAL ROLE anon;
DO $$
BEGIN
  PERFORM 1 FROM public.ota_scopes;
  RAISE EXCEPTION 'expected anon SELECT denial';
EXCEPTION WHEN SQLSTATE '42501' THEN
  NULL;
END;
$$;
DO $$
BEGIN
  PERFORM public.ota_register_device(
    '10000000-0000-0000-0000-000000000001', 'anon-device-001', 'Anonymous');
  RAISE EXCEPTION 'expected anon EXECUTE denial';
EXCEPTION WHEN SQLSTATE '42501' THEN
  NULL;
END;
$$;
COMMIT;

-- An authenticated identity without a membership sees no scope data and cannot register.
BEGIN;
SET LOCAL ROLE authenticated;
SET LOCAL request.jwt.claim.sub = '20000000-0000-0000-0000-000000000004';
DO $$
BEGIN
  IF (SELECT count(*) FROM public.ota_scopes) <> 0 THEN
    RAISE EXCEPTION 'non-member read leaked a scope';
  END IF;
  IF (SELECT count(*) FROM public.ota_memberships) <> 0 THEN
    RAISE EXCEPTION 'non-member read leaked a membership';
  END IF;
  PERFORM public.ota_register_device(
    '10000000-0000-0000-0000-000000000001', 'outsider-device-001', 'Outsider');
  RAISE EXCEPTION 'expected non-member registration denial';
EXCEPTION WHEN SQLSTATE '42501' THEN
  NULL;
END;
$$;
COMMIT;

-- A scope-A administrator creates the first device and its actor-derived audit event.
BEGIN;
SET LOCAL ROLE authenticated;
SET LOCAL request.jwt.claim.sub = '20000000-0000-0000-0000-000000000001';
DO $$
DECLARE
  registered public.ota_devices;
BEGIN
  SELECT * INTO registered FROM public.ota_register_device(
    '10000000-0000-0000-0000-000000000001', 'cores3-a-001', 'CoreS3 A');

  IF registered.scope_id <> '10000000-0000-0000-0000-000000000001'
    OR registered.model <> 'CoreS3'
    OR registered.created_by <> '20000000-0000-0000-0000-000000000001'
  THEN
    RAISE EXCEPTION 'unexpected registered device row';
  END IF;

  IF (SELECT count(*) FROM public.ota_audit_events AS event
      WHERE event.device_id = registered.id
        AND event.scope_id = registered.scope_id
        AND event.actor_id = '20000000-0000-0000-0000-000000000001'
        AND event.action = 'DEVICE_REGISTERED') <> 1
  THEN
    RAISE EXCEPTION 'registration audit actor or event is wrong';
  END IF;
END;
$$;
COMMIT;

-- A different tenant owns a globally unique device identifier in scope B.
BEGIN;
SET LOCAL ROLE authenticated;
SET LOCAL request.jwt.claim.sub = '20000000-0000-0000-0000-000000000002';
SELECT public.ota_register_device(
  '10000000-0000-0000-0000-000000000002', 'cores3-b-001', 'CoreS3 B');
COMMIT;

-- Exact retry is idempotent; collisions stay generic and do not disclose scope B.
BEGIN;
SET LOCAL ROLE authenticated;
SET LOCAL request.jwt.claim.sub = '20000000-0000-0000-0000-000000000001';
DO $$
DECLARE
  existing_id uuid;
  retried public.ota_devices;
BEGIN
  SELECT id INTO existing_id
  FROM public.ota_devices
  WHERE device_id = 'cores3-a-001';

  SELECT * INTO retried FROM public.ota_register_device(
    '10000000-0000-0000-0000-000000000001', 'cores3-a-001', 'CoreS3 A');

  IF retried.id <> existing_id THEN
    RAISE EXCEPTION 'exact retry did not return the stored device';
  END IF;
  IF (SELECT count(*) FROM public.ota_audit_events WHERE device_id = existing_id) <> 1 THEN
    RAISE EXCEPTION 'exact retry created an audit event';
  END IF;
  IF (SELECT count(*) FROM public.ota_devices
      WHERE scope_id = '10000000-0000-0000-0000-000000000002') <> 0 THEN
    RAISE EXCEPTION 'scope B device was visible to scope A';
  END IF;
  IF (SELECT count(*) FROM public.ota_memberships
      WHERE scope_id = '10000000-0000-0000-0000-000000000001') <> 1 THEN
    RAISE EXCEPTION 'membership policy exposed another user';
  END IF;

  BEGIN
    PERFORM public.ota_register_device(
      '10000000-0000-0000-0000-000000000001', 'cores3-b-001', 'CoreS3 B');
    RAISE EXCEPTION 'expected cross-scope conflict';
  EXCEPTION WHEN unique_violation THEN
    IF SQLERRM <> 'device registration conflict' THEN
      RAISE;
    END IF;
  END;

  BEGIN
    PERFORM public.ota_register_device(
      '10000000-0000-0000-0000-000000000001', 'cores3-a-001', 'Renamed CoreS3 A');
    RAISE EXCEPTION 'expected same-scope label conflict';
  EXCEPTION WHEN unique_violation THEN
    IF SQLERRM <> 'device registration conflict' THEN
      RAISE;
    END IF;
  END;
END;
$$;
COMMIT;

-- Direct DML stays denied even to an authenticated administrator.
BEGIN;
SET LOCAL ROLE authenticated;
SET LOCAL request.jwt.claim.sub = '20000000-0000-0000-0000-000000000001';
DO $$
BEGIN
  INSERT INTO public.ota_devices (scope_id, device_id, model, label, created_by)
  VALUES ('10000000-0000-0000-0000-000000000001', 'direct-device-001', 'CoreS3', 'Direct',
          '20000000-0000-0000-0000-000000000001');
  RAISE EXCEPTION 'expected direct INSERT denial';
EXCEPTION WHEN SQLSTATE '42501' THEN
  NULL;
END;
$$;
DO $$
BEGIN
  UPDATE public.ota_devices SET label = 'Mutated' WHERE device_id = 'cores3-a-001';
  RAISE EXCEPTION 'expected direct UPDATE denial';
EXCEPTION WHEN SQLSTATE '42501' THEN
  NULL;
END;
$$;
DO $$
BEGIN
  DELETE FROM public.ota_devices WHERE device_id = 'cores3-a-001';
  RAISE EXCEPTION 'expected direct DELETE denial';
EXCEPTION WHEN SQLSTATE '42501' THEN
  NULL;
END;
$$;
COMMIT;

-- SQL validates Unicode code points, JavaScript-compatible trimming, and ASCII controls.
BEGIN;
SET LOCAL ROLE authenticated;
SET LOCAL request.jwt.claim.sub = '20000000-0000-0000-0000-000000000001';
DO $$
DECLARE
  unicode_label text := pg_catalog.repeat(U&'\00E9', 80);
BEGIN
  PERFORM public.ota_register_device(
    '10000000-0000-0000-0000-000000000001', 'unicode-80', unicode_label);

  BEGIN
    PERFORM public.ota_register_device(
      '10000000-0000-0000-0000-000000000001', 'unicode-81', pg_catalog.repeat(U&'\00E9', 81));
    RAISE EXCEPTION 'expected 81-code-point label denial';
  EXCEPTION WHEN SQLSTATE '22023' THEN
    NULL;
  END;

  BEGIN
    PERFORM public.ota_register_device(
      '10000000-0000-0000-0000-000000000001', 'trimmed-label', U&'\FEFFTrimmed');
    RAISE EXCEPTION 'expected Unicode-trimmed label denial';
  EXCEPTION WHEN SQLSTATE '22023' THEN
    NULL;
  END;

  BEGIN
    PERFORM public.ota_register_device(
      '10000000-0000-0000-0000-000000000001', 'control-label', 'Control' || pg_catalog.chr(127));
    RAISE EXCEPTION 'expected ASCII control label denial';
  EXCEPTION WHEN SQLSTATE '22023' THEN
    NULL;
  END;
END;
$$;
COMMIT;

-- If auditing fails, the SECURITY DEFINER transaction must leave no device behind.
CREATE FUNCTION public.ota_test_fail_audit_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'test audit failure';
END;
$$;
CREATE TRIGGER ota_test_fail_audit_insert
  BEFORE INSERT ON public.ota_audit_events
  FOR EACH ROW EXECUTE FUNCTION public.ota_test_fail_audit_insert();

BEGIN;
SET LOCAL ROLE authenticated;
SET LOCAL request.jwt.claim.sub = '20000000-0000-0000-0000-000000000001';
DO $$
BEGIN
  PERFORM public.ota_register_device(
    '10000000-0000-0000-0000-000000000001', 'audit-fail-001', 'Must Roll Back');
  RAISE EXCEPTION 'expected audit-trigger failure';
EXCEPTION WHEN OTHERS THEN
  IF SQLERRM <> 'test audit failure' THEN
    RAISE;
  END IF;
END;
$$;
COMMIT;

DROP TRIGGER ota_test_fail_audit_insert ON public.ota_audit_events;
DROP FUNCTION public.ota_test_fail_audit_insert();

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM public.ota_devices WHERE device_id = 'audit-fail-001')
    OR EXISTS (
      SELECT 1 FROM public.ota_audit_events AS event
      JOIN public.ota_devices AS device ON device.id = event.device_id
      WHERE device.device_id = 'audit-fail-001'
    )
  THEN
    RAISE EXCEPTION 'audit failure did not roll back the device transaction';
  END IF;
END;
$$;

-- A viewer can read only its own scope and cannot invoke the registration RPC successfully.
BEGIN;
SET LOCAL ROLE authenticated;
SET LOCAL request.jwt.claim.sub = '20000000-0000-0000-0000-000000000003';
DO $$
BEGIN
  IF (SELECT count(*) FROM public.ota_scopes) <> 1
    OR (SELECT count(*) FROM public.ota_devices) <> 2
    OR (SELECT count(*) FROM public.ota_audit_events) <> 2
  THEN
    RAISE EXCEPTION 'viewer could not read its own scope data';
  END IF;
  IF EXISTS (SELECT 1 FROM public.ota_devices
             WHERE scope_id = '10000000-0000-0000-0000-000000000002') THEN
    RAISE EXCEPTION 'viewer read scope B data';
  END IF;
  BEGIN
    PERFORM public.ota_register_device(
      '10000000-0000-0000-0000-000000000001', 'viewer-device-001', 'Viewer');
    RAISE EXCEPTION 'expected viewer registration denial';
  EXCEPTION WHEN SQLSTATE '42501' THEN
    NULL;
  END;
END;
$$;
COMMIT;
