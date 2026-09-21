# OTA inventory — real Preview validation, 2026-09-21

The administrative inventory increment is connected and verified in Preview.
This is NOT a complete OTA cycle or a production release. There is no new CoreS3
screen or device authentication yet. Firmware/binaries were not modified.

## Targets and changes

Operator explicitly selected the existing `boom-manager` Supabase project
`cdurakjehpvcwmvsgire` for development/testing; no second project, paid branch,
production promotion or plan upgrade. Vercel project: `bomb-v2-ota-api`.

- First Preview (24 integration checks):
  `https://bomb-v2-ota-kkivpyb1t-johnosorios-projects.vercel.app`.
- Independent second Preview (persistence checks):
  `https://bomb-v2-ota-p26sufei2-johnosorios-projects.vercel.app`.
- Second deployment ID: `dpl_EV5ho1KLPtbVoR4S2CC3ceHSjWZi`; inspected as
  `target: preview`, `READY`, Node.js 24.x, 11 function handlers.
- Production `https://bomb-v2-ota-api.vercel.app/api/ota/devices` still returns
  HTTP 404. No `--prod`, promotion, alias change or production env update ran.

Both deployments were made from the canonical working tree on
`feat/ota-phase1-foundation`, base `1a31a57`, with uncommitted changes. Vercel's
commit metadata is the base commit, not a commit containing the new source.
No new commit/tag/push was made during this validation.

## Git checkpoint after validation

Paired annotated tag: `checkpoint/ota-inventory-preview-2026-09-21` in this
repository and `bomb-v2`. Backend publication stays on
`feat/ota-phase1-foundation`, without merging into production `master`.
This checkpoint preserves the implementation, tests and evidence; it does not
change the metadata of the two existing Preview deployments or publish firmware.
Before committing, the 25 API tests, real PostgreSQL suite (including concurrency
and restart), migration hash and whitespace checks were rechecked successfully.
The firmware repository's credential-helper suite also passed 10/10.
No new remote tests or test-account provisioning were needed for this checkpoint.

## Migration and credentials

CLI 2.117.0 dry-run listed only `20260921000100_ota_foundation.sql`; no seeds,
roles or Vault updates. Applied with `db push --linked --skip-vault --yes` from
the canonical backend, using the approved password via process environment.
The backend now owns `supabase/config.toml` and all application migrations.
The old firmware-repo CLI bootstrap remains historical, not a second migration
owner. Do not run application migrations from that directory.

Applied migration SHA-256:
`5aceb366f35cd551da9f17022712e2ea5ff70c7ef94b941c2584b8f054883bff`.
Do not edit this applied migration; future SQL changes need a new migration.
Post-apply read-only TLS check: PostgreSQL 17.6; four public tables, zero without
RLS, and Supabase migration history present.

Vercel received only `OTA_ADMIN_ENABLED=true`, `SUPABASE_URL` and the publishable
key, as deployment-specific runtime env. No database password, service-role key
or user password was uploaded. Source defaults remain disabled. `.vercelignore`
excludes docs, tests, scripts, Supabase files, config and all `.env*` files.
Vercel link generated an ignored `.env.local`; its permissions were set to 0600.

Provisioning used a server-side key only in a local coordinator process, to
create four synthetic Auth identities with confirmed `example.invalid` addresses
and random passwords. No mail was sent; no signup/Auth configuration was changed.
Two clearly labelled test scopes had admin A, viewer A and admin B memberships;
the fourth identity had no membership. User JWTs, never the privileged key,
were used by the API/RPC integration tests. Fixture credentials remained in an
ignored private 0600 file, outside the deployment directory.

Deployment protection stayed enabled. Official `vercel curl` generated/managed
its project protection-bypass token for authorized testing; that transport token
does not bypass the application's Supabase authorization. No token was printed
or committed. Auth headers for requests were passed on stdin, not command args.

## Results

- `npm test`: 25/25 on local Node 26.0.0; no regressions in baseline/demo tests.
- Real PostgreSQL 17.11 local suite re-run against the applied migration: RLS,
  grants, anonymous Auth claim, rollback, concurrency and restart all pass.
- First Preview: **24/24 integration checks** in
  `scripts/check-ota-preview.mjs`: four real Auth logins; absent/invalid bearer;
  anonymous REST denial; outsider/foreign-admin/viewer-write denials; caller
  actor rejection; registration with server-derived actor; exact retry; changed
  payload/cross-scope conflicts; viewer reads; direct REST RLS; direct RPC and
  table-write denials; four concurrent RPC retries with singular-object response;
  one audit; oversized declared body; four private-source paths return 404;
  legacy stable manifest still resolves.
- Second Preview: **3/3 persistence checks**, `--persistence-only`: real Auth,
  read original registered device, confirm original single audit. Same device
  UUID `4ede58f3-ebba-4f42-a2e9-3dcbc89346c7` after independent deployment.
  This verifies cross-deployment persistence, not forced eviction of every
  provider-managed warm instance or a physical device restart.
- `git diff --check` and runner syntax check pass.

The first deploy succeeded, but the coordinator's URL parser initially assumed
Vercel would retain the full project name. Listing deployments found the READY
Preview with a shortened prefix; no duplicate deployment was made to repair that
parsing issue. The second deployment was intentional for persistence testing.

## Test access cleanup

After testing, the memberships created for the two synthetic scopes were removed,
the four synthetic Auth accounts were banned and locally stored passwords discarded.
The two labelled scopes, one inventory row and its audit are retained as evidence.
This does not provision a human administrator or an administration portal.
The operator can bootstrap a real admin later through a separate authorized flow.

## Repeating the check

The runner requires `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY`, `OTA_PREVIEW_URL`
and `OTA_PREVIEW_FIXTURE` supplied privately. It refuses the production hostname,
a different Supabase project, a closed fixture, and fixture files not mode 0600.
Run `node scripts/check-ota-preview.mjs`, or add `--persistence-only` for reads.
The test writes only its synthetic registration; exact reruns are idempotent.
A closed fixture cannot be silently reactivated; provision a new approved run.
Local coordinator provisioning scripts are temporary operational tooling, not a
public endpoint or reusable commercial administration feature.

## Remaining limits and next step

OTA-03: verified CoreS3 identity and revocable device credential next. Releases,
immutable artifacts, deployments/receipts, UI and physical OTA recovery remain.
Human administrator setup is not complete. Legacy demo endpoints remain demo,
not production-grade inventory or commercial authorization.

Real expired-token timing and real anonymous-Auth signup were not tested; no Auth
feature flags were changed to manufacture cases. Anonymous Auth is covered by
SQL/HTTP fixtures; real anonymous REST-role access was denied remotely. Chunked
transport/parser limits remain unverified; normalized JSON and declared oversized
bodies are covered. No forced upstream outage or physical OTA/rollback occurred.
The manifest still allows Node >=18 and Vercel warns of automatic major upgrades;
pin a supported runtime before production expansion (current Preview uses 24.x).

Rollback remains additive: disable Preview feature/remove its env or deployment;
keep schema/audit. Feature disable alone does not revoke Supabase RPC membership.
Never use reset/drop to undo this increment.

Coordinator handled remote targets, credentials, migration and tests. Terra medium
reviewed packaging read-only; its exclusions were integrated and tested. The BOMB
skill required distinguishing real SQL, real Auth/Preview and physical evidence.
Sources: [Preview environments](https://vercel.com/docs/deployments/environments),
[protected deployment testing](https://vercel.com/docs/cli/curl),
[Supabase migrations](https://supabase.com/docs/reference/cli/supabase-db-push),
[server-side user provisioning](https://supabase.com/docs/reference/javascript/auth-admin-createuser).
