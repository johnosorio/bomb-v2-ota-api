-- Verify backfill author/time and byte-equivalent historical receipt JSONB.
DO $$ DECLARE l public.ota_device_licenses; c ota_private.device_credentials; o public.ota_license_operations; BEGIN
  SELECT * INTO l FROM public.ota_device_licenses WHERE mac='02:00:00:00:00:81';
  SELECT * INTO c FROM ota_private.device_credentials WHERE credential_id=l.credential_id;
  SELECT * INTO o FROM public.ota_license_operations WHERE device_id=l.device_id AND command->>'action'='approve_identity';
  IF c.credential_id IS NULL OR c.device_key_sha256<>l.device_key_sha256 OR c.approved_by<>o.actor_id
    OR c.approved_at<>o.occurred_at OR c.retired_at IS NOT NULL OR l.credential_status<>'active'
    OR l.updated_by=c.approved_by OR o.result->'snapshot' ? 'credential_status' THEN
    RAISE EXCEPTION 'credential history backfill failed';
  END IF;
END $$;
SET ROLE authenticated;
SET request.jwt.claim.sub='81000000-0000-0000-0000-000000000001';
DO $$ DECLARE o public.ota_license_operations; r jsonb; BEGIN
  SELECT * INTO o FROM public.ota_license_operations WHERE request_id='83000000-0000-0000-0000-000000000001';
  r := public.ota_admin_license(o.device_id,o.request_id,o.command);
  IF r->>'receipt_version'<>'1' OR (r-'receipt_version') IS DISTINCT FROM o.result THEN RAISE EXCEPTION 'legacy receipt changed'; END IF;
  IF public.ota_get_device_license(o.device_id)->>'revision'<>'1' THEN RAISE EXCEPTION 'legacy replay mutated state'; END IF;
END $$;
RESET ROLE;
RESET request.jwt.claim.sub;
\echo 'Credential history upgrade and legacy receipt replay passed'
