# PIN recovery: portal and physical confirmation

Recorded 2026-10-01. Migration, public portal, verified human account and physical
CoreS3 identity are active. OTA 0.2.43 → 0.2.44 and healthy boot are confirmed;
complete PIN recovery remains under physical acceptance. Firmware contract: sibling
[PIN_RECOVERY_CONTRACT.md](../../bomb-v2/PIN_RECOVERY_CONTRACT.md).

## Scope and delivery

CoreS3 initiates a signed P-256 request using its existing identity. An Auth
administrator in that device scope approves in `/admin/`; the operator then
touches New PIN on CoreS3 and enters/repeats the PIN locally. The device consumes
the approval before writing and verifying NVS. No PIN or private key reaches the
server, and recovery never opens a local administrator session automatically.

TTL is 600 seconds. Cancellation, rejection, expiry, credential revocation and
replacement cannot revive an approval. Response-loss retries use the same
consume nonce. A consumed server approval does not prove that NVS was saved;
the portal explicitly asks the operator to check the result on CoreS3.

One API function `/api/ota/pin` dispatches public Auth configuration, scoped
human decisions/listing and signed device operations. The existing demo state
helper moved from `api/_state.js` to `lib/demo-state.js`, with unchanged demo
behavior, so the deployment contains 12 handlers. The package allowlist includes
only the three reviewed public portal assets. No private environment file is
included. STABLE manifest/artifact remain the already public 0.2.42 bytes; this
portal increment must not regress them to the feature branch's old 0.2.13.

## Required environment

- `OTA_PIN_RECOVERY_ENABLED=true` and `OTA_ADMIN_ENABLED=true`.
- `SUPABASE_URL` and `SUPABASE_PUBLISHABLE_KEY` for the intended project.
- `OTA_DEVICE_REALM=development`, matching this CoreS3 build.
- `OTA_GATEWAY_DATABASE_URL` and `OTA_GATEWAY_DATABASE_CA` for the existing
  restricted `bomb_ota_gateway` login, with verified TLS.

The PIN path does not require a service-role key or the license signing private
key. Do not enable other gated APIs as a side effect. Both PIN and administrator
configuration are checked before a device can create a request.

## Concrete activation sequence (separate authorization required)

1. Preserve source commits/tags remotely and preserve the firmware candidate
   with its hash, partition hash and source provenance before touching hardware.
   Prepared firmware: source `4e4265a83d84d315e8904c6f2920b815120bf6b9`,
   1,484,896 bytes, SHA-256
   `9fe689993eaf65dd3e9761206a3af43559bad9d1c19a7a37205a6a35dc6d363e`.
2. Apply only forward migration `20261001000100_ota_pin_recovery.sql` to the
   configured Development project `cdurakjehpvcwmvsgire`, checking the existing
   migration chain first. No reset, seed or destructive down migration.
3. Deploy the exact reviewed package to the existing Vercel project
   `prj_TSJNPhTCvKIdh8qJn5uMYASVUrET`, verify the protected candidate, then switch
   the public alias only after checks. Preserve STABLE 0.2.42 for this step.
4. Invite the operator's supplied email through Auth, with the portal's exact
   redirect allowed. The operator chooses the password in the browser; do not
   ask for or log it. Bootstrap one scope and its administrator membership;
   this is not a grant of commercial license or access to other scopes.
5. Publish the separately preserved CoreS3 0.2.44 artifact through the release
   workflow against the now-deployed backend base. Verify manifest and artifact
   bytes before requesting installation on the device.
6. With separately authorized installation, obtain only the public SHA-256
   fingerprint printed by 0.2.44 over USB. Register the physical CoreS3 and
   approve its existing identity in that administrator scope. No NVS dump,
   key regeneration, Wi-Fi reset, license extension or Bomb01 load.
7. Run the real acceptance below. Do not label the firmware physically stable
   based on build/API tests. Keep the previous deployment and installed
   candidate available; disabling the PIN flag closes the new path safely.

Read-only readiness showed no existing account for the operator email and no
inventory identity for `bm-cores3-E3F61B44` / MAC `44:1B:F6:E3:86:74`.
Recheck immediately before provisioning and stop on conflicting ownership.
Never infer ownership from MAC. The first assisted fingerprint read removes
manual transcription; automatic pending enrollment at credential creation is
a separate unfinished flow, not part of this release.

## Evidence and pending acceptance

- Backend `npm test`: 90/90, including device proof, exact response bindings,
  human Auth/scopes, malformed input, disabled configuration and no leaked
  private settings; existing release workflow/package tests included.
- Complete isolated PostgreSQL 17.11 suite: permissions, transactional audit,
  cancellation/approval/credential races and restart passed. Test helper,
  trigger and dblink extension are removed before the gateway guard runs.
- Firmware: 28 native tests; 12 NVS cases and eight network worker scenarios
  under ASan/UBSan; real mbedTLS signatures independently verified in Node.
- Independent firmware/backend review found no remaining authorization bypass.
  The missing administrator-config gate was corrected with regression cases.
- Browser fixture: 17/17 Chrome headless checks passed with synthetic API/Auth,
  including XSS-as-text, wrong-code/back without POST, exact approve/reject,
  expired JWT, external invitation activation and logout/storage cleanup. No
  page errors or real Auth network traffic. Mocks do not prove deployed Auth,
  TLS or the device interface.

Real acceptance: invite/login, wrong-scope denial, signed device identity,
request/list, cancel and reject without PIN change, approve then physical touch,
new/repeated PIN, return to login, reboot with new PIN, and preservation of
identity, Wi-Fi, license, SD and game state. No physical test is complete yet.
Wi-Fi must already be connected; recovery cannot currently configure a new
network from the locked screen. Forgotten portal-password self-service is also
outside this initial invitation/login flow.


## Authorized activation evidence — 2026-10-01

The operator explicitly authorized migration, deployment/invitation and OTA.
Only `20261001000100_ota_pin_recovery.sql` was pending/applied; SHA-256
`4f8310aa3f7a423d458a1ca42ad0b4c9a1adf87c68936ba7242e73eb7d4faf55`.
Restricted gateway login passed the real TLS/privilege check after migration.
Only the exact portal redirect was added to Auth; 12 undeclared remote settings
were preserved. The operator accepted the invitation and confirmed login; Auth
also reported the email confirmed. One scope/admin membership was bootstrapped.

Portal source `c0a0b9f9e8504a4244cf67682c4ab6344d317801` was deployed preserving
0.2.42 first. Portal asset hashes, CSP, public Auth config and anonymous 401 were
verified before and after promotion. Then the preserved firmware was published:

- Release commit `5286d97e280af8cbe80841c83dfbbfea59e60abd`.
- Release tag `ota/stable-0.2.44`; exact source tag
  `checkpoint/ota-pin-source-0.2.44-2026-10-01` points to `4e4265a`.
- Public deployment `dpl_9NPgziS9LdVLYXG4inpuTU3g3exy`, public verification
  2026-10-01 15:32:47 UTC. Source and release refs were verified remotely first.
- No rebuild or USB flash: actual OTA delivered 1,484,896 bytes with exact
  `9fe689993eaf65dd3e9761206a3af43559bad9d1c19a7a37205a6a35dc6d363e` SHA,
  followed by the pending-health and healthy-boot messages. Operator confirmed
  installed 0.2.44.
- Public fingerprint was read over the connected CoreS3 USB after OTA. A checked
  operator-only SQL bootstrap used the confirmed account's scoped RPC context,
  under authenticated role; registration/identity approval and audit committed
  together. No existing identity was replaced; license remains `unlicensed`.

The firmware release adapter preserved the seven PIN/Auth/gateway environment
variables and used the existing protection bypass only for the exact candidate
origin; public verification was anonymous. Generic release tooling still needs
this environment/authentication integration committed instead of a temporary
adapter. Never deploy a later package without preserving those requirements.

Pending: physical PIN approval/save/re-login/reboot and negative journeys. Do
not confuse healthy OTA boot with complete acceptance of the recovery feature.
