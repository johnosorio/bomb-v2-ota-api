# BOMB OTA backend

This is the canonical API repository; firmware lives in sibling `bomb-v2`.
Before changes read `../bomb-v2/AGENT_WORKFLOW.md` and the applicable `bomb-coder`
or `bomb-deep-dive` skill references there. If unavailable, request that context;
do not create a replacement clone. Current contract: `docs/OTA_FOUNDATION.md`.

JavaScript ESM, native fetch, Node >=18, `npm test`. Migrations belong here only.
Migration `20260921000100` is applied to development boom-manager: do not edit
it in place; create a forward migration. See `docs/OTA_PREVIEW_VALIDATION.md`.
Use transactions for inventory + audit, user-scoped JWT/RLS for database access,
strict inputs, and fail closed. Never use a service-role key in the HTTP adapter.
Legacy demo routes are not production authorization and remain separate.

Subagents have disjoint scopes, no subdelegation, Git writes, remote migrations,
deployment, credentials or hardware operations. Coordinator reviews and verifies.
No production deploy, STABLE promotion or firmware upload as part of tests.
Preserve unrelated edits and existing binaries. Distinguish unit, real SQL,
Preview/Auth integration and physical tests. Phase 1 is not complete yet.
