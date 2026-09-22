-- OTA-03.2a: administrative authorization only, NOT device activation/issuance.
BEGIN;

CREATE TABLE public.ota_device_licenses (
  device_id uuid PRIMARY KEY REFERENCES public.ota_devices(id),
  credential_id uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
  mac text NOT NULL UNIQUE CHECK (mac ~ '^[0-9A-F]{2}(:[0-9A-F]{2}){5}$'),
  device_key_sha256 text NOT NULL UNIQUE CHECK (device_key_sha256 ~ '^[0-9a-f]{64}$'),
  license_id uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
  revision bigint NOT NULL DEFAULT 0 CHECK (revision BETWEEN 0 AND 4294967295),
  status text NOT NULL DEFAULT 'unlicensed' CHECK (status IN ('unlicensed','granted','revoked')),
  issued_at bigint,
  not_before bigint,
  expires_at bigint,
  updated_by uuid NOT NULL REFERENCES auth.users(id),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT ota_license_state_valid CHECK (
    (status = 'unlicensed' AND revision = 0 AND issued_at IS NULL AND not_before IS NULL AND expires_at IS NULL)
    OR (status IN ('granted','revoked') AND revision > 0
      AND issued_at IS NOT NULL AND not_before IS NOT NULL AND expires_at IS NOT NULL
      AND issued_at BETWEEN 1 AND 4294967295 AND not_before BETWEEN 1 AND 4294967295
      AND expires_at BETWEEN 1 AND 4294967295 AND issued_at < expires_at AND not_before < expires_at)
  )
);

-- Append-only receipts are the successful-operation audit, not an event bus.
-- Response snapshots are historical acknowledgements, NEVER signing authority.
CREATE TABLE public.ota_license_operations (
  device_id uuid NOT NULL REFERENCES public.ota_devices(id),
  request_id uuid NOT NULL,
  actor_id uuid NOT NULL REFERENCES auth.users(id),
  command jsonb NOT NULL CHECK (jsonb_typeof(command) = 'object'),
  result jsonb NOT NULL CHECK (jsonb_typeof(result) = 'object'),
  occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (device_id, request_id)
);

ALTER TABLE public.ota_device_licenses ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ota_license_operations ENABLE ROW LEVEL SECURITY;
CREATE POLICY ota_device_licenses_member_select ON public.ota_device_licenses
  FOR SELECT TO authenticated USING (
    (auth.jwt() ->> 'is_anonymous') IS DISTINCT FROM 'true' AND EXISTS (
      SELECT 1 FROM public.ota_devices d JOIN public.ota_memberships m ON m.scope_id = d.scope_id
      WHERE d.id = ota_device_licenses.device_id AND m.user_id = auth.uid()
    )
  );
CREATE POLICY ota_license_operations_member_select ON public.ota_license_operations
  FOR SELECT TO authenticated USING (
    (auth.jwt() ->> 'is_anonymous') IS DISTINCT FROM 'true' AND EXISTS (
      SELECT 1 FROM public.ota_devices d JOIN public.ota_memberships m ON m.scope_id = d.scope_id
      WHERE d.id = ota_license_operations.device_id AND m.user_id = auth.uid()
    )
  );
REVOKE ALL ON public.ota_device_licenses, public.ota_license_operations FROM PUBLIC, anon, authenticated, service_role;
GRANT SELECT ON public.ota_device_licenses, public.ota_license_operations TO authenticated;

CREATE FUNCTION public.ota_get_device_license(p_device_id uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE v_result jsonb;
BEGIN
  IF auth.uid() IS NULL OR (auth.jwt() ->> 'is_anonymous') = 'true' OR NOT EXISTS (
    SELECT 1 FROM public.ota_devices d JOIN public.ota_memberships m ON m.scope_id = d.scope_id
    WHERE d.id = p_device_id AND m.user_id = auth.uid()
  ) THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'not authorized';
  END IF;
  SELECT pg_catalog.to_jsonb(l) INTO v_result FROM public.ota_device_licenses l WHERE l.device_id = p_device_id;
  RETURN v_result;
END;
$$;

CREATE FUNCTION public.ota_admin_license(p_device_id uuid, p_request_id uuid, p_command jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE
  v_actor uuid := auth.uid();
  v_scope uuid;
  v_action text;
  v_license public.ota_device_licenses;
  v_receipt public.ota_license_operations;
  v_result jsonb;
  v_now bigint;
  v_expected bigint;
  v_nbf bigint;
  v_exp bigint;
  v_keys text[];
BEGIN
  IF v_actor IS NULL OR (auth.jwt() ->> 'is_anonymous') = 'true' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'not authorized';
  END IF;
  -- Direct PostgREST RPC bypasses HTTP handler limits. Bound the binary JSONB
  -- command before locks/field traversal (not a claim about original wire bytes).
  IF p_request_id IS NULL OR pg_catalog.jsonb_typeof(p_command) IS DISTINCT FROM 'object'
    OR pg_catalog.pg_column_size(p_command) > 4096 THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid license command';
  END IF;
  -- Unauthorized callers never acquire a lock on another scope's device.
  SELECT d.scope_id INTO v_scope FROM public.ota_devices d
    JOIN public.ota_memberships m ON m.scope_id = d.scope_id
    WHERE d.id = p_device_id AND m.user_id = v_actor AND m.role = 'admin'
    FOR SHARE OF m;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'not authorized';
  END IF;
  -- All mutations, including first approval and receipts, serialize on this row.
  PERFORM 1 FROM public.ota_devices WHERE id = p_device_id AND scope_id = v_scope FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'not authorized';
  END IF;
  v_action := p_command ->> 'action';
  IF v_action = 'approve_identity' THEN
    v_keys := ARRAY['action','mac','device_key_sha256'];
    IF pg_catalog.jsonb_typeof(p_command->'mac') IS DISTINCT FROM 'string'
      OR pg_catalog.jsonb_typeof(p_command->'device_key_sha256') IS DISTINCT FROM 'string'
      OR (p_command->>'mac') !~ '^[0-9A-F]{2}(:[0-9A-F]{2}){5}$'
      OR (p_command->>'device_key_sha256') !~ '^[0-9a-f]{64}$' THEN
      RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid license command';
    END IF;
  ELSIF v_action IN ('grant','revoke') THEN
    v_keys := CASE WHEN v_action = 'grant' THEN ARRAY['action','expected_revision','not_before','expires_at']
      ELSE ARRAY['action','expected_revision'] END;
    IF pg_catalog.jsonb_typeof(p_command->'expected_revision') IS DISTINCT FROM 'number'
      OR (p_command->>'expected_revision') !~ '^(0|[1-9][0-9]{0,9})$' THEN
      RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid license command';
    END IF;
    v_expected := (p_command->>'expected_revision')::bigint;
    IF v_expected > 4294967295 THEN
      RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid license command';
    END IF;
    IF v_action = 'grant' THEN
      IF pg_catalog.jsonb_typeof(p_command->'not_before') IS DISTINCT FROM 'number'
        OR pg_catalog.jsonb_typeof(p_command->'expires_at') IS DISTINCT FROM 'number'
        OR (p_command->>'not_before') !~ '^[1-9][0-9]{0,9}$'
        OR (p_command->>'expires_at') !~ '^[1-9][0-9]{0,9}$' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid license command';
      END IF;
      v_nbf := (p_command->>'not_before')::bigint;
      v_exp := (p_command->>'expires_at')::bigint;
      IF v_nbf > 4294967295 OR v_exp > 4294967295 OR v_nbf >= v_exp THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid license command';
      END IF;
    END IF;
  ELSE
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid license command';
  END IF;
  IF NOT (p_command ?& v_keys) OR (SELECT count(*) FROM pg_catalog.jsonb_object_keys(p_command)) <> cardinality(v_keys) THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid license command';
  END IF;
  SELECT * INTO v_receipt FROM public.ota_license_operations
    WHERE device_id = p_device_id AND request_id = p_request_id;
  IF FOUND THEN
    IF v_receipt.actor_id <> v_actor OR v_receipt.command <> p_command THEN
      RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'license operation conflict';
    END IF;
    RETURN v_receipt.result;
  END IF;
  SELECT * INTO v_license FROM public.ota_device_licenses WHERE device_id = p_device_id;
  IF v_action = 'approve_identity' THEN
    -- Rebinding/recovery is intentionally absent, not an implicit identity reset.
    IF FOUND THEN
      RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'license operation conflict';
    END IF;
    INSERT INTO public.ota_device_licenses(device_id,mac,device_key_sha256,updated_by)
      VALUES (p_device_id,p_command->>'mac',p_command->>'device_key_sha256',v_actor)
      RETURNING * INTO v_license;
  ELSE
    IF NOT FOUND OR v_license.revision <> v_expected OR v_license.revision >= 4294967295
      OR (v_action = 'revoke' AND v_license.status <> 'granted') THEN
      RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'license operation conflict';
    END IF;
    v_now := pg_catalog.floor(EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()))::bigint;
    IF v_action = 'grant' AND (v_now NOT BETWEEN 1 AND 4294967295 OR v_exp <= v_now) THEN
      RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid license command';
    END IF;
    UPDATE public.ota_device_licenses SET revision = revision + 1,
      status = CASE WHEN v_action = 'grant' THEN 'granted' ELSE 'revoked' END,
      issued_at = CASE WHEN v_action = 'grant' THEN v_now ELSE issued_at END,
      not_before = CASE WHEN v_action = 'grant' THEN v_nbf ELSE not_before END,
      expires_at = CASE WHEN v_action = 'grant' THEN v_exp ELSE expires_at END,
      updated_by = v_actor, updated_at = pg_catalog.clock_timestamp()
      WHERE device_id = p_device_id RETURNING * INTO v_license;
  END IF;
  v_result := pg_catalog.jsonb_build_object('request_id',p_request_id,'action',v_action,
    'device_id',p_device_id,'snapshot',pg_catalog.to_jsonb(v_license));
  INSERT INTO public.ota_license_operations(device_id,request_id,actor_id,command,result)
    VALUES (p_device_id,p_request_id,v_actor,p_command,v_result);
  RETURN v_result;
END;
$$;
REVOKE ALL ON FUNCTION public.ota_get_device_license(uuid), public.ota_admin_license(uuid,uuid,jsonb)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.ota_get_device_license(uuid), public.ota_admin_license(uuid,uuid,jsonb) TO authenticated;
COMMIT;
