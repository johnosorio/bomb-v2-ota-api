-- Disposable runner only: old state/receipts BEFORE the recovery migration.
INSERT INTO auth.users(id) VALUES ('81000000-0000-0000-0000-000000000001'),('81000000-0000-0000-0000-000000000002');
INSERT INTO public.ota_scopes(id,name) VALUES ('82000000-0000-0000-0000-000000000001','Upgrade fixture');
INSERT INTO public.ota_memberships(scope_id,user_id,role) VALUES
  ('82000000-0000-0000-0000-000000000001','81000000-0000-0000-0000-000000000001','admin'),
  ('82000000-0000-0000-0000-000000000001','81000000-0000-0000-0000-000000000002','admin');
SET ROLE authenticated;
SET request.jwt.claim.sub='81000000-0000-0000-0000-000000000001';
SELECT id AS upgrade_device FROM public.ota_register_device('82000000-0000-0000-0000-000000000001','UPGRADE-LEGACY','Upgrade') \gset
SELECT public.ota_admin_license(:'upgrade_device','83000000-0000-0000-0000-000000000001',
  jsonb_build_object('action','approve_identity','mac','02:00:00:00:00:81','device_key_sha256',repeat('81',32)));
SET request.jwt.claim.sub='81000000-0000-0000-0000-000000000002';
SELECT public.ota_admin_license(:'upgrade_device','83000000-0000-0000-0000-000000000002',
  '{"action":"grant","expected_revision":0,"not_before":1,"expires_at":4102444800}');
RESET ROLE;
RESET request.jwt.claim.sub;
