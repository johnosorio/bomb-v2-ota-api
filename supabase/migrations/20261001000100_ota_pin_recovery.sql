-- OTA-03.3b: device-initiated PIN recovery approvals.  No PIN, PIN digest,
-- private key, or game code is persisted here.
BEGIN;

CREATE TABLE ota_private.pin_recoveries (
  request_id text PRIMARY KEY CHECK (request_id ~ '^[0-9a-f]{64}$'),
  device_id uuid NOT NULL REFERENCES public.ota_devices(id),
  credential_id uuid NOT NULL REFERENCES ota_private.device_credentials(credential_id),
  realm text NOT NULL CHECK (realm ~ '^[a-z0-9][a-z0-9_-]{0,39}$'),
  issued_at bigint NOT NULL CHECK (issued_at BETWEEN 1 AND 4294966695),
  expires_at bigint NOT NULL CHECK (expires_at = issued_at + 600),
  status text NOT NULL CHECK (status IN ('pending','approved','rejected','cancelled','consumed')),
  approved_by uuid REFERENCES auth.users(id),
  decided_at timestamptz,
  consume_nonce text CHECK (consume_nonce IS NULL OR consume_nonce ~ '^[0-9a-f]{64}$'),
  consumed_at timestamptz,
  CONSTRAINT ota_pin_recoveries_state_valid CHECK (
    (status = 'pending' AND approved_by IS NULL AND decided_at IS NULL
      AND consume_nonce IS NULL AND consumed_at IS NULL)
    OR (status = 'approved' AND approved_by IS NOT NULL AND decided_at IS NOT NULL
      AND consume_nonce IS NULL AND consumed_at IS NULL)
    OR (status = 'rejected' AND approved_by IS NULL AND decided_at IS NOT NULL
      AND consume_nonce IS NULL AND consumed_at IS NULL)
    OR (status = 'cancelled' AND consume_nonce IS NULL AND consumed_at IS NULL
      AND ((approved_by IS NULL AND decided_at IS NULL) OR (approved_by IS NOT NULL AND decided_at IS NOT NULL)))
    OR (status = 'consumed' AND approved_by IS NOT NULL AND decided_at IS NOT NULL
      AND consume_nonce IS NOT NULL AND consumed_at IS NOT NULL)
  )
);
CREATE INDEX ota_pin_recoveries_live_by_device
  ON ota_private.pin_recoveries(device_id, credential_id, expires_at)
  WHERE status IN ('pending','approved');

CREATE TABLE ota_private.pin_recovery_events (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  request_id text NOT NULL REFERENCES ota_private.pin_recoveries(request_id),
  device_id uuid NOT NULL REFERENCES public.ota_devices(id),
  event text NOT NULL CHECK (event IN ('created','approved','rejected','cancelled','consumed')),
  actor uuid REFERENCES auth.users(id),
  occurred_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  UNIQUE(request_id,event)
);

CREATE FUNCTION ota_private.pin_recovery_events_append_only()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
BEGIN
  RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'pin recovery events are append only';
END;
$$;
CREATE TRIGGER ota_pin_recovery_events_append_only
  BEFORE UPDATE OR DELETE ON ota_private.pin_recovery_events
  FOR EACH ROW EXECUTE FUNCTION ota_private.pin_recovery_events_append_only();

ALTER TABLE ota_private.pin_recoveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE ota_private.pin_recovery_events ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON ota_private.pin_recoveries, ota_private.pin_recovery_events
  FROM PUBLIC, anon, authenticated, service_role, bomb_ota_gateway;
REVOKE ALL ON SEQUENCE ota_private.pin_recovery_events_id_seq
  FROM PUBLIC, anon, authenticated, service_role, bomb_ota_gateway;
REVOKE ALL ON FUNCTION ota_private.pin_recovery_events_append_only()
  FROM PUBLIC, anon, authenticated, service_role, bomb_ota_gateway;

-- Validates the exact three-field identity, then serializes with every
-- credential mutation on ota_devices before returning a current credential.
CREATE FUNCTION ota_private.pin_recovery_current_license(p_identity jsonb)
RETURNS public.ota_device_licenses LANGUAGE plpgsql SET search_path = '' AS $$
DECLARE
  v_license public.ota_device_licenses;
  v_field text;
BEGIN
  IF pg_catalog.jsonb_typeof(p_identity) IS DISTINCT FROM 'object'
    OR pg_catalog.pg_column_size(p_identity) > 512
    OR (SELECT count(*) FROM pg_catalog.jsonb_object_keys(p_identity)) <> 3 THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid pin recovery input';
  END IF;
  FOREACH v_field IN ARRAY ARRAY['mac','device_key_sha256','realm'] LOOP
    IF pg_catalog.jsonb_typeof(p_identity -> v_field) IS DISTINCT FROM 'string' THEN
      RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid pin recovery input';
    END IF;
  END LOOP;
  IF p_identity ->> 'mac' !~ '^[0-9A-F]{2}(:[0-9A-F]{2}){5}$'
    OR p_identity ->> 'device_key_sha256' !~ '^[0-9a-f]{64}$'
    OR p_identity ->> 'realm' !~ '^[a-z0-9][a-z0-9_-]{0,39}$' THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid pin recovery input';
  END IF;

  -- Do not lock an arbitrary device for an unknown identity.
  SELECT l.* INTO v_license
    FROM public.ota_device_licenses l
    JOIN ota_private.device_credentials c ON c.credential_id = l.credential_id
    WHERE l.mac = p_identity ->> 'mac'
      AND l.device_key_sha256 = p_identity ->> 'device_key_sha256'
      AND l.credential_status = 'active'
      AND c.device_id = l.device_id
      AND c.device_key_sha256 = l.device_key_sha256
      AND c.retired_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'device not authorized';
  END IF;

  PERFORM 1 FROM public.ota_devices WHERE id = v_license.device_id FOR UPDATE;
  -- A new statement snapshot after the lock closes the revocation/replacement race.
  SELECT l.* INTO v_license
    FROM public.ota_device_licenses l
    JOIN ota_private.device_credentials c ON c.credential_id = l.credential_id
    WHERE l.device_id = v_license.device_id
      AND l.mac = p_identity ->> 'mac'
      AND l.device_key_sha256 = p_identity ->> 'device_key_sha256'
      AND l.credential_status = 'active'
      AND c.device_id = l.device_id
      AND c.device_key_sha256 = l.device_key_sha256
      AND c.retired_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'device not authorized';
  END IF;
  RETURN v_license;
END;
$$;

CREATE FUNCTION public.ota_pin_device(
  p_identity jsonb, p_action text, p_request_id text, p_nonce text
)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE
  v_license public.ota_device_licenses;
  v_recovery ota_private.pin_recoveries;
  v_now bigint;
  v_status text;
BEGIN
  IF p_action IS NULL OR p_action NOT IN ('create','status','cancel','consume')
    OR p_request_id IS NULL OR p_request_id !~ '^[0-9a-f]{64}$'
    OR p_nonce IS NULL OR p_nonce !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid pin recovery input';
  END IF;
  v_license := ota_private.pin_recovery_current_license(p_identity);
  v_now := pg_catalog.floor(EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()))::bigint;
  IF v_now NOT BETWEEN 1 AND 4294966695 THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid pin recovery input';
  END IF;

  SELECT * INTO v_recovery FROM ota_private.pin_recoveries
    WHERE request_id = p_request_id FOR UPDATE;
  IF FOUND AND (v_recovery.device_id <> v_license.device_id
    OR v_recovery.credential_id <> v_license.credential_id
    OR v_recovery.realm <> p_identity ->> 'realm') THEN
    RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'pin recovery conflict';
  END IF;

  IF p_action = 'create' THEN
    IF NOT FOUND THEN
      IF (SELECT count(*) FROM ota_private.pin_recoveries
          WHERE device_id = v_license.device_id AND credential_id = v_license.credential_id
            AND status IN ('pending','approved') AND expires_at > v_now) >= 4 THEN
        RAISE EXCEPTION USING ERRCODE = '54000', MESSAGE = 'pin recovery limit';
      END IF;
      INSERT INTO ota_private.pin_recoveries(request_id,device_id,credential_id,realm,issued_at,expires_at,status)
        VALUES(p_request_id,v_license.device_id,v_license.credential_id,p_identity ->> 'realm',v_now,v_now+600,'pending')
        RETURNING * INTO v_recovery;
      INSERT INTO ota_private.pin_recovery_events(request_id,device_id,event,actor)
        VALUES(v_recovery.request_id,v_recovery.device_id,'created',NULL);
    END IF;
  ELSIF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'pin recovery conflict';
  ELSIF p_action = 'cancel' THEN
    IF v_recovery.status IN ('pending','approved') THEN
      UPDATE ota_private.pin_recoveries SET status = 'cancelled'
        WHERE request_id = v_recovery.request_id RETURNING * INTO v_recovery;
      INSERT INTO ota_private.pin_recovery_events(request_id,device_id,event,actor)
        VALUES(v_recovery.request_id,v_recovery.device_id,'cancelled',NULL);
    ELSIF v_recovery.status <> 'cancelled' THEN
      RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'pin recovery conflict';
    END IF;
  ELSIF p_action = 'consume' THEN
    IF v_recovery.status = 'consumed' THEN
      IF v_recovery.expires_at <= v_now OR v_recovery.consume_nonce <> p_nonce THEN
        RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'pin recovery conflict';
      END IF;
    ELSIF v_recovery.status = 'approved' AND v_recovery.expires_at > v_now THEN
      UPDATE ota_private.pin_recoveries
        SET status = 'consumed', consume_nonce = p_nonce, consumed_at = pg_catalog.clock_timestamp()
        WHERE request_id = v_recovery.request_id RETURNING * INTO v_recovery;
      INSERT INTO ota_private.pin_recovery_events(request_id,device_id,event,actor)
        VALUES(v_recovery.request_id,v_recovery.device_id,'consumed',NULL);
    ELSE
      RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'pin recovery conflict';
    END IF;
  END IF;

  v_status := CASE WHEN v_recovery.status IN ('pending','approved') AND v_recovery.expires_at <= v_now
    THEN 'expired' ELSE v_recovery.status END;
  RETURN pg_catalog.jsonb_build_object('request_id',v_recovery.request_id,'device_id',v_recovery.device_id,
    'credential_id',v_recovery.credential_id,'realm',v_recovery.realm,'status',v_status,
    'issued_at',v_recovery.issued_at,'expires_at',v_recovery.expires_at,'nonce',p_nonce);
END;
$$;

CREATE FUNCTION public.ota_pin_admin(p_request_id text, p_action text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE
  v_actor uuid := auth.uid();
  v_device_id uuid;
  v_scope_id uuid;
  v_recovery ota_private.pin_recoveries;
  v_event_actor uuid;
  v_now bigint;
  v_target_status text;
BEGIN
  IF v_actor IS NULL OR (auth.jwt() ->> 'is_anonymous') = 'true' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'not authorized';
  END IF;
  IF p_request_id IS NULL OR p_request_id !~ '^[0-9a-f]{64}$'
    OR p_action IS NULL OR p_action NOT IN ('approve','reject') THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid pin recovery command';
  END IF;
  -- Scope authorization is obtained before the device lock, matching ota_admin_license.
  SELECT r.device_id,d.scope_id INTO v_device_id,v_scope_id
    FROM ota_private.pin_recoveries r
    JOIN public.ota_devices d ON d.id = r.device_id
    JOIN public.ota_memberships m ON m.scope_id = d.scope_id
    WHERE r.request_id = p_request_id AND m.user_id = v_actor AND m.role = 'admin'
    FOR SHARE OF m;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'not authorized';
  END IF;
  PERFORM 1 FROM public.ota_devices WHERE id = v_device_id AND scope_id = v_scope_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'not authorized';
  END IF;
  SELECT * INTO v_recovery FROM ota_private.pin_recoveries WHERE request_id = p_request_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'pin recovery conflict';
  END IF;
  -- The record can never survive a current credential transition.
  PERFORM 1 FROM public.ota_device_licenses l
    JOIN ota_private.device_credentials c ON c.credential_id = l.credential_id
    WHERE l.device_id = v_recovery.device_id AND l.credential_id = v_recovery.credential_id
      AND l.credential_status = 'active' AND c.device_id = l.device_id
      AND c.device_key_sha256 = l.device_key_sha256 AND c.retired_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'pin recovery conflict';
  END IF;
  v_target_status := CASE WHEN p_action = 'approve' THEN 'approved' ELSE 'rejected' END;
  IF v_recovery.status = v_target_status THEN
    SELECT actor INTO v_event_actor FROM ota_private.pin_recovery_events
      WHERE request_id = v_recovery.request_id AND event = v_target_status;
    IF FOUND AND v_event_actor = v_actor THEN
      RETURN pg_catalog.jsonb_build_object('request_id',v_recovery.request_id,'device_id',v_recovery.device_id,
        'credential_id',v_recovery.credential_id,'realm',v_recovery.realm,'status',v_recovery.status,
        'issued_at',v_recovery.issued_at,'expires_at',v_recovery.expires_at);
    END IF;
    RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'pin recovery conflict';
  END IF;
  v_now := pg_catalog.floor(EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()))::bigint;
  IF v_recovery.status <> 'pending' OR v_recovery.expires_at <= v_now THEN
    RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'pin recovery conflict';
  END IF;
  UPDATE ota_private.pin_recoveries
    SET status = v_target_status,
      approved_by = CASE WHEN p_action = 'approve' THEN v_actor ELSE NULL END,
      decided_at = pg_catalog.clock_timestamp()
    WHERE request_id = v_recovery.request_id RETURNING * INTO v_recovery;
  INSERT INTO ota_private.pin_recovery_events(request_id,device_id,event,actor)
    VALUES(v_recovery.request_id,v_recovery.device_id,v_target_status,v_actor);
  RETURN pg_catalog.jsonb_build_object('request_id',v_recovery.request_id,'device_id',v_recovery.device_id,
    'credential_id',v_recovery.credential_id,'realm',v_recovery.realm,'status',v_recovery.status,
    'issued_at',v_recovery.issued_at,'expires_at',v_recovery.expires_at);
END;
$$;

CREATE FUNCTION public.ota_pin_list()
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE v_actor uuid := auth.uid(); v_now bigint;
BEGIN
  IF v_actor IS NULL OR (auth.jwt() ->> 'is_anonymous') = 'true' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'not authorized';
  END IF;
  v_now := pg_catalog.floor(EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()))::bigint;
  RETURN COALESCE((SELECT pg_catalog.jsonb_agg(q.item ORDER BY q.issued_at DESC)
    FROM (
      SELECT r.issued_at, pg_catalog.jsonb_build_object('request_id',r.request_id,'device_id',r.device_id,
        'credential_id',r.credential_id,'realm',r.realm,
        'status',CASE WHEN r.status IN ('pending','approved') AND r.expires_at <= v_now THEN 'expired' ELSE r.status END,
        'issued_at',r.issued_at,'expires_at',r.expires_at,'device_label',d.label,'device_code',d.device_id) AS item
      FROM ota_private.pin_recoveries r
      JOIN public.ota_devices d ON d.id = r.device_id
      JOIN public.ota_memberships m ON m.scope_id = d.scope_id
      WHERE m.user_id = v_actor AND m.role = 'admin' AND r.issued_at >= v_now - 2592000
      ORDER BY r.issued_at DESC LIMIT 100
    ) q), '[]'::jsonb);
END;
$$;

REVOKE ALL ON FUNCTION ota_private.pin_recovery_current_license(jsonb)
  FROM PUBLIC, anon, authenticated, service_role, bomb_ota_gateway;
REVOKE ALL ON FUNCTION public.ota_pin_device(jsonb,text,text,text), public.ota_pin_admin(text,text), public.ota_pin_list()
  FROM PUBLIC, anon, authenticated, service_role, bomb_ota_gateway;
GRANT EXECUTE ON FUNCTION public.ota_pin_device(jsonb,text,text,text) TO bomb_ota_gateway;
GRANT EXECUTE ON FUNCTION public.ota_pin_admin(text,text), public.ota_pin_list() TO authenticated;
COMMIT;
