# Phase 1 / increment 1: administrative inventory foundation

2026-09-21. Implementation branch `feat/ota-phase1-foundation`, base `1a31a57`.
Partial OTA-01/02 plus FIX-01, not a complete OTA service. Firmware stays CoreS3
0.2.35 / Bomb01 B01-GAME-13. Migration now applied to operator-approved
development `boom-manager`; API validated in Preview, never promoted to production.
[Local validation](OTA_FOUNDATION_VALIDATION.md) and
[real Preview evidence and remaining limits](OTA_PREVIEW_VALIDATION.md).

## Requirements and decisions

Confirmed: OTA CoreS3 first; preserve local gameplay; authenticated administration,
persistent data and isolation; no commercial modules or Bomb01 OTA in this phase.
Engineering decision for this increment: an OTA scope is an access group, NOT a
customer/site hierarchy. A CoreS3 belongs to one scope here; a user may belong to
several. Transfers, invitations and commercial hierarchy remain unimplemented.
No new game decision is required. Operator selected `boom-manager` for development
validation. Initial human administrator remains to be provisioned separately;
the validation used synthetic accounts, not operator credentials shared in chat.

A separate `/api/ota/devices` route preserves legacy firmware endpoints. Replacing
legacy Maps in place would let unauthenticated heartbeats contaminate privileged
inventory. Do not migrate their records implicitly. New registered device IDs
are administrative identifiers, not proof of physical possession (OTA-03).

User JWT -> verified Supabase Auth user -> PostgREST under that SAME JWT -> RLS.
One small fetch adapter is the persistence boundary; native fetch avoids adding
an SDK for three operations. A service-role adapter would require duplicating
all authorization and would bypass RLS; it is deliberately excluded.

## Contract v1

`OTA_ADMIN_ENABLED` must be exactly `true`; otherwise 503 `OTA_ADMIN_DISABLED`.
Configure HTTPS `SUPABASE_URL` and `SUPABASE_PUBLISHABLE_KEY`, never a service key.
Caller supplies `Authorization: Bearer <Supabase user access token>`; no cookies,
body actor, client SITE or MAC grants access. Anonymous Auth users are rejected
in both HTTP and DB (is_anonymous JWT claim), even if mistakenly granted membership.
The handler is same-origin by default (no permissive CORS).

- GET `?scope_id=<uuid>&limit=50&offset=0`: membership required, including viewer.
  Limit 1..100, offset 0..1000000, ordered by creation time then UUID. Returns
  `{schema_version:1,devices:[...],limit,offset}`. Empty accessible scope -> 200;
  nonexistent/inaccessible scope -> 403. Unknown/duplicate query fields rejected.
- POST JSON `{scope_id,device_id,label}` only, <=4096 normalized UTF-8 JSON bytes; scope admin
  required. ID is case-sensitive ASCII alphanumeric/underscore/hyphen, starts
  alphanumeric, 1..64; label trimmed, 1..80 Unicode code points, no controls.
  Model fixed `CoreS3`; caller cannot set ownership, actor, role, timestamps.
  Returns 200 `{schema_version:1,device:{id,scope_id,device_id,model,label,
  created_by,created_at}}`, also for exact retry.
- Errors: 400 malformed input/JSON, 401 missing/invalid/expired user token,
  403 insufficient scope role, 409 `DEVICE_CONFLICT`, 413 too large, 415 non-JSON,
  405 unsupported method, 503 missing config/provider/network/timeout failure.
  No provider error details, tokens, database connection strings or caches.

Bodies with declared Content-Length >4096 are rejected before Auth/RPC. When
Vercel supplies a pre-parsed object without Content-Length (e.g. chunked input),
the application can bound normalized JSON, not lost whitespace/transport bytes.
Original request/parser limits remain a platform control to verify in Preview;
this increment does not claim a hard 4 KiB transport limit for that case.

Global device-ID uniqueness prevents accidental dual registration; same ID,
scope and label returns the original row (including original creator/time).
Different label or scope returns generic 409, not another tenant's details.
The generic conflict still reveals identifier unavailability; IDs are not secrets.
There is no update/transfer/delete endpoint in this increment.

## Database and authority

Only this repository owns `supabase/migrations`. Firmware repository's existing
Supabase CLI bootstrap is not a second migration owner. No duplicate config or
remote link is generated here automatically.

| Table | Authority / access |
| --- | --- |
| ota_scopes | Access groups; privileged bootstrap writes, members read |
| ota_memberships | Explicit admin/viewer grants; privileged writes, own user reads |
| ota_devices | Registration via admin-checked RPC; members read |
| ota_audit_events | DEVICE_REGISTERED event inside same transaction; members read |

RLS on every table. Revoke direct DML and PUBLIC/anon function execution. A fixed
search_path SECURITY DEFINER RPC checks `auth.uid()` + admin membership before
writing. Audit actor comes from that UID, not input. A unique constraint handles
concurrent registrations; device + audit commit together. No success audit on
denial, duplicate or rollback. Rejected-request observability is future work;
do not log raw requests or tokens to compensate.

There are no licenses, game secrets, credentials, observed version/presence,
releases or installation results in these tables. Registration does not mean
ONLINE, update installed, or BOOT_CONFIRMED. Legacy state remains demo-only.

## Failure, recovery and activation

Per-provider request deadline 5 seconds; fail closed with no memory fallback.
If the response is lost after commit, repeat the same POST: same row, one audit.
Different retry content conflicts, never silently edits the previous row. DB
failure rolls back device and audit. Process restart has no inventory state to
restore; PostgreSQL is authority. Offset pagination is bounded, not a snapshot
under concurrent additions. Revoked membership is checked again by RLS/RPC.

Activation order: isolated Preview database -> review/apply migration with an
authorized operator -> create verified Auth users -> privileged bootstrap scope
and explicit membership -> configure Preview env -> verify Auth/REST permissions
and idempotency -> enable route in Preview. Do NOT reuse production data/secrets.
No application self-grant endpoint. Bootstrap is temporary operator provisioning;
the no-manual-SQL administration UX belongs to OTA-07, not completed here.

Rollback: disable feature flag/restore prior API; keep additive tables and audit.
Do not DROP tables or reverse migrations destructively. Legacy firmware routes
and artifacts are unchanged. Feature flag gates Vercel route only: once migration
is applied, authenticated Supabase REST/RPC access is controlled by DB policies,
not this flag. Full shutdown requires revoking relevant grants/memberships too.

## Acceptance and remaining work

Run `npm test` for HTTP/mocked-provider/legacy compatibility. Run isolated SQL
tests for real constraints, grants, RLS, transactional rollback, concurrency and
persistence across connections. Local SQL auth.uid shim does NOT validate real
JWT verification or PostgREST RPC response shape; Preview must cover both.
Firmware/physical validation remains OTA-08. Do not label OTA-01/02 complete until
the remaining OTA schema/contracts and Preview acceptance are demonstrated.

Coordinator owns auth/HTTP integration; Luna handles bounded FIX-01; Terra handles
SQL/tests; independent review targets scope isolation and retry/rollback risks.
No agent makes remote writes, publishes firmware or executes PlatformIO here.

Primary references: [Supabase RLS](https://supabase.com/docs/guides/database/postgres/row-level-security),
[database functions](https://supabase.com/docs/guides/database/functions),
[Auth user verification](https://supabase.com/docs/guides/auth/jwts),
[PostgREST functions](https://postgrest.org/en/latest/references/api/functions.html).
