# Increment 1 evidence — 2026-09-21

Branch `feat/ota-phase1-foundation`, base `1a31a57`. This document records the
initial local-only stage. Later migration and deployments are recorded separately
in [real Preview evidence](OTA_PREVIEW_VALIDATION.md). At that local-only stage
there was no new commit/push. No firmware change, production promotion or physical
test. [Contract](OTA_FOUNDATION.md). Git publication is recorded in the Preview evidence.

## Passing checks

- `npm test`: 25/25 on Node 26.0.0, including the eight baseline tests. Covers
  rejected legacy PATCH without mutation, valid legacy actions, feature gate,
  configuration, Auth/RPC error handling, JWT forwarding, strict inputs, scope
  membership/list filtering, sanitized responses and payload-size contract.
- `OTA_TEST_PG_BIN=/opt/homebrew/opt/postgresql@17/bin npm run test:db`: passes
  on PostgreSQL 17.11, isolated Unix socket with TCP disabled and checked both
  before and after restart. Real SQL, not a mocked database.
- SQL coverage: all four tables RLS/grants, anon-role denial, missing UID,
  non-member, admin/viewer separation, cross-scope denial, direct DML denial,
  actor-derived audit, Unicode/trim constraints, exact retries, conflicting
  contents, forced audit failure rolls back device creation. Auth-anonymous
  claim denies reads and RPC even with an accidentally provisioned membership.
- Eight concurrent equal registrations return the same UUID, one row and one
  audit; concurrent different labels yield exactly one success and one conflict.
  Independent connections and server restart retain the committed inventory.
- `git diff --check`: passes. Main-repo credential-helper fixture suite: 10/10;
  no real credentials loaded by these tests.

The SQL harness bootstraps **test-only** auth.uid/auth.jwt functions and roles.
It does not exercise Supabase Auth signature verification or PostgREST. Default
grants are deliberately permissive to check migration revocations. This is
PostgreSQL major 17 coverage, not the remote project's exact 17.6 patch version.
Node 18 compatibility is not execution-tested; manifest still declares >=18.

## Review and rework

Luna medium implemented FIX-01; coordinator corrected two fixture assumptions
against the existing transition table before integration. Terra high prepared
SQL/tests; coordinator corrected patch format, transaction wrapper and composite
row SELECT assignment, then executed the database suite. A separate Terra high
review found the parsed-JSON byte-limit ambiguity and DB anonymous-Auth gap;
both addressed and regression tested. No measured token/time savings claimed.
The BOMB skills drove separate contracts, bounded write sets and real DB checks.

First restart test exposed a harness bug: a fresh pg_ctl start omitted the
socket/TCP flags. That local fixture run failed and was stopped; corrected
runner reuses explicit flags and asserts settings after every start. Final run
passed and its test cluster is stopped. No production connection was involved.

## Local test tooling

Initial libpq 18.1 install had client tools but no postgres server. Approved
Homebrew install supplied PostgreSQL 17.11 and upgraded krb5 to 1.22.2. Its global
link step conflicted with libpq; no existing links were overwritten. Only new
`/opt/homebrew/share/postgresql@17` and `/opt/homebrew/lib/postgresql@17` resource
links were created. Tests use an explicit binary directory; no permanent service.
Temporary test data/logs remain under `/private/tmp/bomb-ota-pg-*`, stopped and
without operator data; no recursive deletion was performed.

## Next gate — not performed here

1. Choose an isolated Supabase/Vercel Preview target and bootstrap administrator;
   do not assume the existing Free project is safe to seed or reset.
2. Authorized operator reviews/applies additive migration and provisions verified
   Auth users plus scope membership. Configure env privately, not in commits/chat.
3. Exercise real Auth and direct PostgREST under anon/admin/viewer/foreign/expired
   and anonymous-user tokens; assert single-object RPC response and RLS denies.
4. Verify Vercel packaging/runtime, HTTP parser/transport limits, cold start and
   lost-response retry. Feature flag disable is not a DB permission revocation.
5. Continue OTA-03 device identity, then releases/deployments/receipts/UI and
   physical OTA-08. This increment has no new CoreS3 screen to test yet.
