-- OTA-03.2b. Gateway is a trusted proof verifier, NOT an end-user DB identity.
-- No password/login provisioned by migration; remote enabling is a separate step.
BEGIN;
CREATE ROLE bomb_ota_gateway NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT USAGE ON SCHEMA public TO bomb_ota_gateway;
CREATE SCHEMA ota_private;
REVOKE ALL ON SCHEMA ota_private FROM PUBLIC, anon, authenticated, service_role, bomb_ota_gateway;

CREATE TABLE ota_private.device_challenges (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id uuid NOT NULL REFERENCES public.ota_devices(id),
  credential_id uuid NOT NULL,
  mac text NOT NULL,
  device_key_sha256 text NOT NULL,
  realm text NOT NULL CHECK (realm ~ '^[a-z0-9][a-z0-9_-]{0,39}$'),
  client_nonce text NOT NULL CHECK (client_nonce ~ '^[0-9a-f]{64}$'),
  nonce text NOT NULL CHECK (nonce ~ '^[0-9a-f]{64}$'),
  issued_at bigint NOT NULL CHECK (issued_at BETWEEN 1 AND 4294967175),
  expires_at bigint NOT NULL CHECK (expires_at = issued_at + 120),
  consumed boolean NOT NULL DEFAULT false,
  UNIQUE(device_id,realm,client_nonce)
);
CREATE TABLE ota_private.device_license_deliveries (
  challenge_id uuid PRIMARY KEY,
  device_id uuid NOT NULL REFERENCES public.ota_devices(id),
  credential_id uuid NOT NULL,
  revision bigint NOT NULL CHECK (revision BETWEEN 0 AND 4294967295),
  administrative_status text NOT NULL CHECK (administrative_status IN ('unlicensed','granted','revoked')),
  signing_kid text NOT NULL CHECK (signing_kid ~ '^[A-Za-z0-9_-]{1,40}$'),
  observed_at bigint NOT NULL CHECK (observed_at BETWEEN 1 AND 4294967295)
);
ALTER TABLE ota_private.device_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE ota_private.device_license_deliveries ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON ota_private.device_challenges, ota_private.device_license_deliveries
  FROM PUBLIC, anon, authenticated, service_role, bomb_ota_gateway;

-- Private helper centralizes strict bounds and the lock order used by admin RPC.
CREATE FUNCTION ota_private.gateway_license(p_identity jsonb)
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
    AND l.device_key_sha256=p_identity->>'device_key_sha256';
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='device not authorized'; END IF;
  PERFORM 1 FROM public.ota_devices WHERE id=(p_identity->>'device_id')::uuid FOR UPDATE;
  -- A NEW statement snapshot after acquiring the device lock: never sign a
  -- pre-lock grant while a concurrent admin revocation was committing.
  SELECT * INTO v_license FROM public.ota_device_licenses l WHERE l.device_id=(p_identity->>'device_id')::uuid
    AND l.credential_id=(p_identity->>'credential_id')::uuid AND l.mac=p_identity->>'mac'
    AND l.device_key_sha256=p_identity->>'device_key_sha256';
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='device not authorized'; END IF;
  RETURN v_license;
END; $$;
REVOKE ALL ON FUNCTION ota_private.gateway_license(jsonb) FROM PUBLIC, anon, authenticated, service_role, bomb_ota_gateway;

CREATE FUNCTION public.ota_gateway_challenge(p_identity jsonb,p_nonce text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE v_license public.ota_device_licenses; v_challenge ota_private.device_challenges; v_now bigint; v_identity jsonb; v_field text;
BEGIN
  IF p_nonce IS NULL OR p_nonce !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid device input';
  END IF;
  IF pg_catalog.jsonb_typeof(p_identity) IS DISTINCT FROM 'object' OR pg_catalog.pg_column_size(p_identity)>1024 THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid device input';
  END IF;
  IF (SELECT count(*) FROM pg_catalog.jsonb_object_keys(p_identity))<>4 THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid device input';
  END IF;
  FOREACH v_field IN ARRAY ARRAY['mac','device_key_sha256','realm','client_nonce'] LOOP
    IF pg_catalog.jsonb_typeof(p_identity->v_field) IS DISTINCT FROM 'string' THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid device input';
    END IF;
  END LOOP;
  SELECT * INTO v_license FROM public.ota_device_licenses WHERE mac=p_identity->>'mac' AND device_key_sha256=p_identity->>'device_key_sha256';
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='device not authorized'; END IF;
  v_identity := p_identity || pg_catalog.jsonb_build_object('device_id',v_license.device_id,'credential_id',v_license.credential_id);
  v_license := ota_private.gateway_license(v_identity);
  v_now := pg_catalog.floor(EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()))::bigint;
  DELETE FROM ota_private.device_challenges WHERE device_id=v_license.device_id AND expires_at<=v_now;
  SELECT * INTO v_challenge FROM ota_private.device_challenges WHERE device_id=v_license.device_id
    AND realm=p_identity->>'realm' AND client_nonce=p_identity->>'client_nonce';
  IF FOUND THEN
    IF v_challenge.consumed THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='challenge unavailable'; END IF;
    RETURN pg_catalog.to_jsonb(v_challenge)-'consumed';
  END IF;
  IF (SELECT count(*) FROM ota_private.device_challenges WHERE device_id=v_license.device_id)>=8 THEN
    RAISE EXCEPTION USING ERRCODE='54000',MESSAGE='challenge limit';
  END IF;
  INSERT INTO ota_private.device_challenges(device_id,credential_id,mac,device_key_sha256,realm,client_nonce,nonce,issued_at,expires_at)
    VALUES(v_license.device_id,v_license.credential_id,v_license.mac,v_license.device_key_sha256,
      p_identity->>'realm',p_identity->>'client_nonce',p_nonce,v_now,v_now+120) RETURNING * INTO v_challenge;
  RETURN pg_catalog.to_jsonb(v_challenge)-'consumed';
END; $$;

CREATE FUNCTION public.ota_gateway_consume(p_identity jsonb,p_challenge_id uuid,p_nonce text,p_signing_kid text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE v_license public.ota_device_licenses; v_challenge ota_private.device_challenges; v_now bigint;
BEGIN
  IF p_challenge_id IS NULL OR p_nonce IS NULL OR p_nonce !~ '^[0-9a-f]{64}$'
    OR p_signing_kid IS NULL OR p_signing_kid !~ '^[A-Za-z0-9_-]{1,40}$' THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid device input';
  END IF;
  v_license := ota_private.gateway_license(p_identity);
  v_now := pg_catalog.floor(EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()))::bigint;
  SELECT * INTO v_challenge FROM ota_private.device_challenges WHERE id=p_challenge_id
    AND device_id=v_license.device_id AND credential_id=v_license.credential_id
    AND mac=v_license.mac AND device_key_sha256=v_license.device_key_sha256
    AND realm=p_identity->>'realm' AND client_nonce=p_identity->>'client_nonce' AND nonce=p_nonce
    AND NOT consumed AND expires_at>v_now AND issued_at<=v_now FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='challenge unavailable'; END IF;
  UPDATE ota_private.device_challenges SET consumed=true WHERE id=v_challenge.id;
  INSERT INTO ota_private.device_license_deliveries(challenge_id,device_id,credential_id,revision,administrative_status,signing_kid,observed_at)
    VALUES(v_challenge.id,v_license.device_id,v_license.credential_id,v_license.revision,v_license.status,p_signing_kid,v_now);
  RETURN pg_catalog.jsonb_build_object('challenge',pg_catalog.to_jsonb(v_challenge)-'consumed',
    'license',pg_catalog.to_jsonb(v_license),'observed_at',v_now);
END; $$;
REVOKE ALL ON FUNCTION public.ota_gateway_challenge(jsonb,text), public.ota_gateway_consume(jsonb,uuid,text,text)
  FROM PUBLIC, anon, authenticated, service_role, bomb_ota_gateway;
GRANT EXECUTE ON FUNCTION public.ota_gateway_challenge(jsonb,text), public.ota_gateway_consume(jsonb,uuid,text,text) TO bomb_ota_gateway;
COMMIT;
