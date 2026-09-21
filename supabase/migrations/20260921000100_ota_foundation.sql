-- OTA-01/02: minimal user-scoped CoreS3 inventory.
-- Scope names are provisional access-group labels, not commercial entities.

BEGIN;

CREATE TABLE public.ota_scopes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ota_scopes_name_valid
    CHECK (name = pg_catalog.btrim(name) AND pg_catalog.char_length(name) BETWEEN 1 AND 120)
);

CREATE TABLE public.ota_memberships (
  scope_id uuid NOT NULL REFERENCES public.ota_scopes(id),
  user_id uuid NOT NULL REFERENCES auth.users(id),
  role text NOT NULL,
  PRIMARY KEY (scope_id, user_id),
  CONSTRAINT ota_memberships_role_valid CHECK (role IN ('admin', 'viewer'))
);

CREATE TABLE public.ota_devices (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scope_id uuid NOT NULL REFERENCES public.ota_scopes(id),
  device_id text NOT NULL,
  model text NOT NULL DEFAULT 'CoreS3',
  label text NOT NULL,
  created_by uuid NOT NULL REFERENCES auth.users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ota_devices_device_id_key UNIQUE (device_id),
  CONSTRAINT ota_devices_device_id_valid
    CHECK (device_id ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$'),
  CONSTRAINT ota_devices_model_valid CHECK (model = 'CoreS3'),
  CONSTRAINT ota_devices_label_valid
    CHECK (
      label = pg_catalog.btrim(label, U&'\0009\000A\000B\000C\000D\0020\00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000\FEFF')
      AND pg_catalog.char_length(label) BETWEEN 1 AND 80
      AND label !~ E'[\x01-\x1F\x7F]'
    )
);

CREATE TABLE public.ota_audit_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scope_id uuid NOT NULL REFERENCES public.ota_scopes(id),
  actor_id uuid NOT NULL REFERENCES auth.users(id),
  action text NOT NULL,
  device_id uuid NOT NULL REFERENCES public.ota_devices(id),
  occurred_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ota_audit_events_action_valid CHECK (action = 'DEVICE_REGISTERED')
);

ALTER TABLE public.ota_scopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ota_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ota_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ota_audit_events ENABLE ROW LEVEL SECURITY;

-- Bootstrap of scopes and memberships remains an operator-only SQL operation.
-- There are deliberately no insert, update, or delete policies.
CREATE POLICY ota_scopes_member_select
  ON public.ota_scopes
  FOR SELECT
  TO authenticated
  USING (
    (auth.jwt() ->> 'is_anonymous') IS DISTINCT FROM 'true' AND
    EXISTS (
      SELECT 1
      FROM public.ota_memberships AS membership
      WHERE membership.scope_id = ota_scopes.id
        AND membership.user_id = auth.uid()
    )
  );

CREATE POLICY ota_memberships_self_select
  ON public.ota_memberships
  FOR SELECT
  TO authenticated
  USING (user_id = auth.uid() AND (auth.jwt() ->> 'is_anonymous') IS DISTINCT FROM 'true');

CREATE POLICY ota_devices_member_select
  ON public.ota_devices
  FOR SELECT
  TO authenticated
  USING (
    (auth.jwt() ->> 'is_anonymous') IS DISTINCT FROM 'true' AND
    EXISTS (
      SELECT 1
      FROM public.ota_memberships AS membership
      WHERE membership.scope_id = ota_devices.scope_id
        AND membership.user_id = auth.uid()
    )
  );

CREATE POLICY ota_audit_events_member_select
  ON public.ota_audit_events
  FOR SELECT
  TO authenticated
  USING (
    (auth.jwt() ->> 'is_anonymous') IS DISTINCT FROM 'true' AND
    EXISTS (
      SELECT 1
      FROM public.ota_memberships AS membership
      WHERE membership.scope_id = ota_audit_events.scope_id
        AND membership.user_id = auth.uid()
    )
  );

-- Remove inherited/default table grants before restoring user-scoped reads.
REVOKE ALL ON TABLE public.ota_scopes, public.ota_memberships,
  public.ota_devices, public.ota_audit_events FROM PUBLIC;
REVOKE ALL ON TABLE public.ota_scopes, public.ota_memberships,
  public.ota_devices, public.ota_audit_events FROM anon;
REVOKE ALL ON TABLE public.ota_scopes, public.ota_memberships,
  public.ota_devices, public.ota_audit_events FROM authenticated;
GRANT SELECT ON TABLE public.ota_scopes, public.ota_memberships,
  public.ota_devices, public.ota_audit_events TO authenticated;

CREATE FUNCTION public.ota_register_device(
  p_scope_id uuid,
  p_device_id text,
  p_label text
)
RETURNS public.ota_devices
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_actor_id uuid := auth.uid();
  v_device public.ota_devices;
  v_trim_characters constant text := U&'\0009\000A\000B\000C\000D\0020\00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000\FEFF';
BEGIN
  IF v_actor_id IS NULL OR (auth.jwt() ->> 'is_anonymous') = 'true' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'not authorized';
  END IF;

  IF p_scope_id IS NULL
    OR p_device_id IS NULL
    OR p_label IS NULL
    OR p_device_id !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$'
    OR p_label <> pg_catalog.btrim(p_label, v_trim_characters)
    OR pg_catalog.char_length(p_label) NOT BETWEEN 1 AND 80
    OR p_label ~ E'[\x01-\x1F\x7F]'
  THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid device registration';
  END IF;

  PERFORM 1
  FROM public.ota_memberships AS membership
  WHERE membership.scope_id = p_scope_id
    AND membership.user_id = v_actor_id
    AND membership.role = 'admin';

  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'not authorized';
  END IF;

  INSERT INTO public.ota_devices (scope_id, device_id, model, label, created_by)
  VALUES (p_scope_id, p_device_id, 'CoreS3', p_label, v_actor_id)
  ON CONFLICT (device_id) DO NOTHING
  RETURNING * INTO v_device;

  IF FOUND THEN
    INSERT INTO public.ota_audit_events (scope_id, actor_id, action, device_id)
    VALUES (v_device.scope_id, v_actor_id, 'DEVICE_REGISTERED', v_device.id);
    RETURN v_device;
  END IF;

  SELECT device.*
  INTO v_device
  FROM public.ota_devices AS device
  WHERE device.device_id = p_device_id
    AND device.scope_id = p_scope_id
    AND device.label = p_label;

  IF FOUND THEN
    RETURN v_device;
  END IF;

  RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'device registration conflict';
END;
$$;

REVOKE ALL ON FUNCTION public.ota_register_device(uuid, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ota_register_device(uuid, text, text) FROM anon;
REVOKE ALL ON FUNCTION public.ota_register_device(uuid, text, text) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.ota_register_device(uuid, text, text) TO authenticated;
COMMIT;
