-- OTA-03.2c: forward-only credential recovery; no remote provisioning.
BEGIN;
-- Persist the receipt generation separately; never rewrite historical snapshots.
ALTER TABLE public.ota_license_operations ADD COLUMN receipt_version smallint NOT NULL DEFAULT 1 CHECK(receipt_version IN (1,2));
ALTER TABLE public.ota_license_operations ALTER COLUMN receipt_version SET DEFAULT 2;
ALTER TABLE public.ota_device_licenses ADD COLUMN credential_status text NOT NULL DEFAULT 'active'
  CHECK (credential_status IN ('active','revoked'));
-- Revision is shared by entitlement and credential changes, including before first grant.
ALTER TABLE public.ota_device_licenses DROP CONSTRAINT ota_license_state_valid;
ALTER TABLE public.ota_device_licenses ADD CONSTRAINT ota_license_state_valid CHECK (
  (status='unlicensed' AND issued_at IS NULL AND not_before IS NULL AND expires_at IS NULL)
  OR (status IN ('granted','revoked') AND revision>0
    AND issued_at IS NOT NULL AND not_before IS NOT NULL AND expires_at IS NOT NULL
    AND issued_at BETWEEN 1 AND 4294967295 AND not_before BETWEEN 1 AND 4294967295
    AND expires_at BETWEEN 1 AND 4294967295 AND issued_at<expires_at AND not_before<expires_at)
);
CREATE TABLE ota_private.device_credentials (
  credential_id uuid PRIMARY KEY,
  device_id uuid NOT NULL REFERENCES public.ota_devices(id),
  device_key_sha256 text NOT NULL UNIQUE CHECK (device_key_sha256 ~ '^[0-9a-f]{64}$'),
  approved_by uuid NOT NULL REFERENCES auth.users(id),
  approved_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  retired_at timestamptz,
  retired_by uuid REFERENCES auth.users(id),
  retired_reason text,
  retired_revision bigint,
  UNIQUE(credential_id,device_id,device_key_sha256),
  CHECK ((retired_at IS NULL AND retired_by IS NULL AND retired_reason IS NULL AND retired_revision IS NULL)
    OR (retired_at IS NOT NULL AND retired_by IS NOT NULL AND retired_reason IS NOT NULL
      AND retired_revision IS NOT NULL AND retired_reason IN ('lost','compromised','maintenance')
      AND retired_revision BETWEEN 1 AND 4294967295))
);
CREATE UNIQUE INDEX ota_one_active_credential ON ota_private.device_credentials(device_id) WHERE retired_at IS NULL;
ALTER TABLE ota_private.device_credentials ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON ota_private.device_credentials FROM PUBLIC, anon, authenticated, service_role, bomb_ota_gateway;
-- Existing approval receipts retain the original author/time (updated_by can be a later grant admin).
INSERT INTO ota_private.device_credentials(credential_id,device_id,device_key_sha256,approved_by,approved_at)
  SELECT l.credential_id,l.device_id,l.device_key_sha256,
    COALESCE(o.actor_id,l.updated_by),COALESCE(o.occurred_at,l.updated_at)
  FROM public.ota_device_licenses l LEFT JOIN public.ota_license_operations o
    ON o.device_id=l.device_id AND o.command->>'action'='approve_identity'
    AND o.result->'snapshot'->>'credential_id'=l.credential_id::text;
ALTER TABLE public.ota_device_licenses ADD CONSTRAINT ota_current_credential_history
  FOREIGN KEY(credential_id,device_id,device_key_sha256)
  REFERENCES ota_private.device_credentials(credential_id,device_id,device_key_sha256)
  DEFERRABLE INITIALLY DEFERRED;

CREATE OR REPLACE FUNCTION public.ota_admin_license(p_device_id uuid, p_request_id uuid, p_command jsonb)
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
  v_credential uuid;
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
  ELSIF v_action IN ('grant','revoke','revoke_credential','replace_credential') THEN
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
    IF v_action IN ('revoke_credential','replace_credential') THEN
      v_keys := ARRAY['action','expected_revision','expected_credential_id','reason'];
      IF pg_catalog.jsonb_typeof(p_command->'expected_credential_id') IS DISTINCT FROM 'string'
        OR p_command->>'expected_credential_id' !~ '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'
        OR pg_catalog.jsonb_typeof(p_command->'reason') IS DISTINCT FROM 'string'
        OR p_command->>'reason' NOT IN ('lost','compromised','maintenance') THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid license command';
      END IF;
      v_credential := (p_command->>'expected_credential_id')::uuid;
      IF v_action = 'replace_credential' THEN
        v_keys := v_keys || ARRAY['device_key_sha256'];
        IF pg_catalog.jsonb_typeof(p_command->'device_key_sha256') IS DISTINCT FROM 'string'
          OR p_command->>'device_key_sha256' !~ '^[0-9a-f]{64}$' THEN
          RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid license command';
        END IF;
      END IF;
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
    RETURN v_receipt.result || pg_catalog.jsonb_build_object('receipt_version',v_receipt.receipt_version);
  END IF;
  SELECT * INTO v_license FROM public.ota_device_licenses WHERE device_id = p_device_id;
  IF v_action = 'approve_identity' THEN
    -- Initial approval never replaces an existing identity.
    IF FOUND THEN
      RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'license operation conflict';
    END IF;
    -- Reserve the digest in the same ledger->current-row order as replacement.
    v_credential := gen_random_uuid();
    INSERT INTO ota_private.device_credentials(credential_id,device_id,device_key_sha256,approved_by)
      VALUES(v_credential,p_device_id,p_command->>'device_key_sha256',v_actor);
    INSERT INTO public.ota_device_licenses(device_id,credential_id,mac,device_key_sha256,updated_by)
      VALUES (p_device_id,v_credential,p_command->>'mac',p_command->>'device_key_sha256',v_actor)
      RETURNING * INTO v_license;
  ELSIF v_action IN ('revoke_credential','replace_credential') THEN
    IF NOT FOUND OR v_license.revision <> v_expected OR v_license.revision >= 4294967295
      OR v_license.credential_id <> v_credential
      OR (v_action='revoke_credential' AND v_license.credential_status <> 'active') THEN
      RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='license operation conflict';
    END IF;
    -- Retired keys stay globally reserved, including after recovery on another device.
    -- Unique indexes arbitrate cross-device races; any conflict rolls back everything.
    UPDATE ota_private.device_credentials SET retired_at=pg_catalog.clock_timestamp(),
      retired_by=v_actor,retired_reason=p_command->>'reason',retired_revision=v_license.revision+1
      WHERE credential_id=v_license.credential_id AND retired_at IS NULL;
    IF v_action='replace_credential' THEN
      v_credential := gen_random_uuid();
      INSERT INTO ota_private.device_credentials(credential_id,device_id,device_key_sha256,approved_by)
        VALUES(v_credential,p_device_id,p_command->>'device_key_sha256',v_actor);
    END IF;
    UPDATE public.ota_device_licenses SET revision=revision+1,
      credential_id=v_credential,
      device_key_sha256=CASE WHEN v_action='replace_credential' THEN p_command->>'device_key_sha256' ELSE device_key_sha256 END,
      credential_status=CASE WHEN v_action='replace_credential' THEN 'active' ELSE 'revoked' END,
      updated_by=v_actor,updated_at=pg_catalog.clock_timestamp()
      WHERE device_id=p_device_id RETURNING * INTO v_license;
    -- No pending or consumed challenge can cross an identity transition.
    -- Delivery audit lives separately and is retained.
    DELETE FROM ota_private.device_challenges WHERE device_id=p_device_id;
  ELSE
    IF NOT FOUND OR v_license.revision <> v_expected OR v_license.revision >= 4294967295
      OR (v_action = 'revoke' AND v_license.status <> 'granted')
      OR (v_action = 'grant' AND v_license.credential_status <> 'active') THEN
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
  RETURN v_result || pg_catalog.jsonb_build_object('receipt_version',2);
END;
$$;
CREATE OR REPLACE FUNCTION ota_private.gateway_license(p_identity jsonb)
RETURNS public.ota_device_licenses LANGUAGE plpgsql SET search_path = '' AS $$
DECLARE v_license public.ota_device_licenses; v_field text;
BEGIN
  IF pg_catalog.jsonb_typeof(p_identity) IS DISTINCT FROM 'object' OR pg_catalog.pg_column_size(p_identity)>1024 THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid device input';
  END IF;
  IF (SELECT count(*) FROM pg_catalog.jsonb_object_keys(p_identity))<>6 THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid device input';
  END IF;
  FOREACH v_field IN ARRAY ARRAY['device_id','credential_id','mac','device_key_sha256','realm','client_nonce'] LOOP
    IF pg_catalog.jsonb_typeof(p_identity->v_field) IS DISTINCT FROM 'string' THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid device input';
    END IF;
  END LOOP;
  IF p_identity->>'device_id' !~ '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'
    OR p_identity->>'credential_id' !~ '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'
    OR p_identity->>'mac' !~ '^[0-9A-F]{2}(:[0-9A-F]{2}){5}$'
    OR p_identity->>'device_key_sha256' !~ '^[0-9a-f]{64}$'
    OR p_identity->>'client_nonce' !~ '^[0-9a-f]{64}$'
    OR p_identity->>'realm' !~ '^[a-z0-9][a-z0-9_-]{0,39}$' THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid device input';
  END IF;
  -- Precheck avoids locking arbitrary other devices for an unapproved key.
  PERFORM 1 FROM public.ota_device_licenses l WHERE l.device_id=(p_identity->>'device_id')::uuid
    AND l.credential_id=(p_identity->>'credential_id')::uuid AND l.mac=p_identity->>'mac'
    AND l.device_key_sha256=p_identity->>'device_key_sha256' AND l.credential_status='active'
    AND EXISTS(SELECT 1 FROM ota_private.device_credentials c WHERE c.credential_id=l.credential_id
      AND c.device_id=l.device_id AND c.device_key_sha256=l.device_key_sha256 AND c.retired_at IS NULL);
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='device not authorized'; END IF;
  PERFORM 1 FROM public.ota_devices WHERE id=(p_identity->>'device_id')::uuid FOR UPDATE;
  -- A NEW statement snapshot after acquiring the device lock: never sign a
  -- pre-lock grant while a concurrent admin revocation was committing.
  SELECT * INTO v_license FROM public.ota_device_licenses l WHERE l.device_id=(p_identity->>'device_id')::uuid
    AND l.credential_id=(p_identity->>'credential_id')::uuid AND l.mac=p_identity->>'mac'
    AND l.device_key_sha256=p_identity->>'device_key_sha256' AND l.credential_status='active'
    AND EXISTS(SELECT 1 FROM ota_private.device_credentials c WHERE c.credential_id=l.credential_id
      AND c.device_id=l.device_id AND c.device_key_sha256=l.device_key_sha256 AND c.retired_at IS NULL);
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='device not authorized'; END IF;
  RETURN v_license;
END; $$;
REVOKE ALL ON FUNCTION ota_private.gateway_license(jsonb) FROM PUBLIC, anon, authenticated, service_role, bomb_ota_gateway;


REVOKE ALL ON FUNCTION public.ota_admin_license(uuid,uuid,jsonb) FROM PUBLIC, anon, authenticated, service_role, bomb_ota_gateway;
GRANT EXECUTE ON FUNCTION public.ota_admin_license(uuid,uuid,jsonb) TO authenticated;
COMMIT;
