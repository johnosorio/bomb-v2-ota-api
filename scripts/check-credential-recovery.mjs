// OTA-03.2c integration check. It is deliberately socket-only and
// imports no credentials: all key material exists only for this process.
import assert from "node:assert/strict";
import pg from "pg";
import { generateKeyPairSync, randomBytes, randomUUID, sign } from "node:crypto";
import { createHandler } from "../api/ota/device-license.js";
import { gatewayTransaction } from "../lib/ota/gateway-db.js";
import { deviceProofInput, sha256 } from "../lib/ota/device-proof.js";
import { verifyDeviceResponse } from "../lib/ota/device-response.js";

export async function checkCredentialRecovery(socket) {
  assert.match(socket, /^\/private\/tmp\/bomb-ota-pg-[A-Za-z0-9]+$/);
  const connection = { host: socket, port: 5432, database: "postgres", password: "unused-local-trust", ssl: false,
    connectionTimeoutMillis: 3000, query_timeout: 5000, application_name: "bomb-ota-test-recovery" };
  let owner = new pg.Client({ ...connection, user: "ota_test_owner", application_name: "bomb-ota-test-recovery-owner" });
  owner.on("error", () => {}); await owner.connect();
  const user = "70000000-0000-0000-0000-000000000001";
  const viewer = "70000000-0000-0000-0000-000000000002";
  const foreign = "70000000-0000-0000-0000-000000000003";
  const scope = "70000000-0000-0000-0000-000000000010";
  const foreignScope = "70000000-0000-0000-0000-000000000011";
  const deviceKey = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const replacementKey = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const serverKey = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const der = deviceKey.publicKey.export({ type: "spki", format: "der" });
  const replacementDer = replacementKey.publicKey.export({ type: "spki", format: "der" });
  const digest = sha256(der); const replacementDigest = sha256(replacementDer);
  const realm = "isolated-recovery-test";
  const transaction = gatewayTransaction({}, () => new pg.Client({ ...connection, user: "bomb_ota_gateway" }));
  const env = { OTA_DEVICE_GATEWAY_ENABLED: "true", OTA_DEVICE_REALM: realm, OTA_LICENSE_SIGNING_KID: "isolated",
    OTA_LICENSE_SIGNING_PRIVATE_KEY: serverKey.privateKey.export({ type: "pkcs8", format: "pem" }),
    OTA_GATEWAY_DATABASE_URL: "postgresql://bomb_ota_gateway:synthetic@db.abcdefghijklmnopqrst.supabase.co:5432/postgres" };
  const gateway = async (body) => {
    const result = {}; const response = { setHeader() {}, status(status) { result.status = status; return this; }, json(value) { result.body = value; return this; } };
    await createHandler({ env, dependencies: { transaction } })({ method: "POST", query: {}, headers: { "content-type": "application/json" }, body }, response);
    if (result.status !== 200) throw Object.assign(new Error(result.body.error), { status: result.status, code: result.body.error });
    return result.body;
  };
  const signed = (key, keyDigest, body) => ({ ...body, signature: sign("sha256", deviceProofInput(body, realm, keyDigest), { key: key.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url") });
  const proofFor = (key, keyDer, keyDigest, mac, c) => c === undefined
    ? signed(key, keyDigest, { action: "challenge", mac, public_key: keyDer.toString("base64url"), client_nonce: randomBytes(32).toString("hex") })
    : signed(key, keyDigest, { action: "exchange", device_id: c.device_id, credential_id: c.credential_id, mac, public_key: keyDer.toString("base64url"), client_nonce: c.client_nonce, challenge_id: c.id, nonce: c.nonce });
  const challenge = (key = deviceKey, keyDer = der, keyDigest = digest) => signed(key, keyDigest, { action: "challenge", mac: "02:00:00:00:00:91", public_key: keyDer.toString("base64url"), client_nonce: randomBytes(32).toString("hex") });
  const exchange = (key, keyDer, keyDigest, c) => signed(key, keyDigest, { action: "exchange", device_id: c.device_id, credential_id: c.credential_id, mac: c.mac, public_key: keyDer.toString("base64url"), client_nonce: c.client_nonce, challenge_id: c.id, nonce: c.nonce });
  const code = (status) => (error) => error.status === status;
  const admin = async (sql, values = [], actor = user) => {
    await owner.query("BEGIN");
    try { await owner.query("SET LOCAL ROLE authenticated"); await owner.query("SELECT set_config('request.jwt.claim.sub',$1,true)", [actor]);
      const result = await owner.query(sql, values); await owner.query("COMMIT"); return result.rows[0]?.data; }
    catch (error) { await owner.query("ROLLBACK"); throw error; }
  };
  const independentMutate = async (device, command, request = randomUUID()) => {
    const client = new pg.Client({ ...connection, user: "ota_test_owner", application_name: "bomb-ota-test-recovery-race" });
    client.on("error", () => {}); await client.connect();
    try {
      await client.query("BEGIN"); await client.query("SET LOCAL ROLE authenticated");
      await client.query("SELECT set_config('request.jwt.claim.sub',$1,true)", [user]);
      const result = await client.query("SELECT public.ota_admin_license($1,$2,$3::jsonb) AS data", [device, request, JSON.stringify(command)]);
      await client.query("COMMIT"); return result.rows[0].data;
    } catch (error) { try { await client.query("ROLLBACK"); } catch {} throw error; }
    finally { await client.end(); }
  };
  let id; let oldCredential; let grantExpiry;
  const mutate = (command, request = randomUUID(), actor = user, device = id) => admin("SELECT public.ota_admin_license($1,$2,$3::jsonb) AS data", [device, request, JSON.stringify(command)], actor);
  const current = async () => (await owner.query("SELECT to_jsonb(l) AS data FROM public.ota_device_licenses l WHERE device_id=$1", [id])).rows[0].data;
  const challenges = async () => Number((await owner.query("SELECT count(*) AS n FROM ota_private.device_challenges WHERE device_id=$1", [id])).rows[0].n);
  try {
    await owner.query("ALTER ROLE bomb_ota_gateway LOGIN");
    await owner.query("INSERT INTO auth.users(id) VALUES($1),($2),($3)", [user, viewer, foreign]);
    await owner.query("INSERT INTO public.ota_scopes(id,name) VALUES($1,'Recovery'),($2,'Foreign')", [scope, foreignScope]);
    await owner.query("INSERT INTO public.ota_memberships(scope_id,user_id,role) VALUES($1,$2,'admin'),($1,$3,'viewer'),($4,$5,'admin')", [scope, user, viewer, foreignScope, foreign]);
    id = (await admin("SELECT to_jsonb(d) AS data FROM public.ota_register_device($1,$2,$3) d", [scope, "RECOVERY-LOCAL", "Recovery fixture"])).id;
    await mutate({ action: "approve_identity", mac: "02:00:00:00:00:91", device_key_sha256: digest });
    oldCredential = (await current()).credential_id;
    grantExpiry = Math.floor(Date.now() / 1000) + 3600;
    await mutate({ action: "grant", expected_revision: 0, not_before: 1, expires_at: grantExpiry });

    // Scope and private-ledger denials must precede every mutation.
    await assert.rejects(mutate({ action: "revoke_credential", expected_revision: 1, expected_credential_id: oldCredential, reason: "lost" }, randomUUID(), viewer), e => e.code === "42501");
    await assert.rejects(mutate({ action: "revoke_credential", expected_revision: 1, expected_credential_id: oldCredential, reason: "lost" }, randomUUID(), foreign), e => e.code === "42501");
    await owner.query("SET ROLE anon");
    await assert.rejects(owner.query("SELECT * FROM ota_private.device_credentials"), e => e.code === "42501");
    await owner.query("RESET ROLE");
    await owner.query("SET ROLE authenticated");
    await owner.query("SELECT set_config('request.jwt.claim.sub',$1,false)", [viewer]);
    await assert.rejects(owner.query("SELECT * FROM ota_private.device_credentials"), e => e.code === "42501");
    await owner.query("RESET ROLE");

    // Pending old-key proof is invalidated atomically by credential revocation.
    const oldPending = (await gateway(challenge())).challenge;
    assert.equal(await challenges(), 1);
    // The gateway has already verified the proof, then waits on the same device
    // lock as the admin mutation. Attach rejection handling before polling.
    await owner.query("BEGIN"); await owner.query("SELECT id FROM public.ota_devices WHERE id=$1 FOR UPDATE", [id]);
    const waiting = gateway(exchange(deviceKey, der, digest, oldPending));
    const waitingHandled = waiting.then(() => ({ ok: true }), error => ({ ok: false, error }));
    let lockObserved = false;
    for (let attempt = 0; attempt < 100; attempt++) {
      await owner.query("SELECT pg_stat_clear_snapshot()");
      const activity = await owner.query("SELECT count(*) AS n FROM pg_stat_activity WHERE application_name='bomb-ota-test-recovery' AND wait_event_type='Lock'");
      if (Number(activity.rows[0].n) > 0) { lockObserved = true; break; }
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    assert.ok(lockObserved, "old-key exchange must wait for the admin device lock");
    const revokeRequest = randomUUID();
    await owner.query("SET LOCAL ROLE authenticated"); await owner.query("SELECT set_config('request.jwt.claim.sub',$1,true)", [user]);
    const revoked = (await owner.query("SELECT public.ota_admin_license($1,$2,$3::jsonb) AS data", [id, revokeRequest,
      JSON.stringify({ action: "revoke_credential", expected_revision: 1, expected_credential_id: oldCredential, reason: "lost" })])).rows[0].data;
    await owner.query("COMMIT");
    assert.equal(revoked.receipt_version, 2); assert.equal(revoked.snapshot.revision, 2); assert.equal(revoked.snapshot.credential_status, "revoked");
    assert.equal(Number((await owner.query("SELECT receipt_version FROM public.ota_license_operations WHERE device_id=$1 AND request_id=$2", [id, revokeRequest])).rows[0].receipt_version), 2);
    assert.equal(await challenges(), 0);
    const waited = await waitingHandled; assert.equal(waited.ok, false); assert.equal(waited.error.status, 403);
    await assert.rejects(gateway(challenge()), code(403));
    await assert.rejects(mutate({ action: "grant", expected_revision: 2, not_before: 1, expires_at: grantExpiry }), e => e.code === "23505");
    const unchanged = await current();
    await assert.rejects(mutate({ action: "revoke_credential", expected_revision: 1, expected_credential_id: oldCredential, reason: "lost" }), e => e.code === "23505");
    await assert.rejects(mutate({ action: "replace_credential", expected_revision: 2, expected_credential_id: randomUUID(), reason: "lost", device_key_sha256: replacementDigest }), e => e.code === "23505");
    await assert.deepEqual(await current(), unchanged, "stale revoke cannot modify state");
    assert.deepEqual(await mutate({ action: "revoke_credential", expected_revision: 1, expected_credential_id: oldCredential, reason: "lost" }, revokeRequest), revoked, "historical receipt is idempotent");
    await assert.rejects(mutate({ action: "revoke_credential", expected_revision: 1, expected_credential_id: oldCredential, reason: "compromised" }, revokeRequest), e => e.code === "23505");

    // Credential recovery restores the binding but preserves the active grant and dates.
    const replacement = await mutate({ action: "replace_credential", expected_revision: 2, expected_credential_id: oldCredential, reason: "compromised", device_key_sha256: replacementDigest });
    const afterReplacement = await current();
    assert.equal(afterReplacement.revision, 3); assert.equal(afterReplacement.credential_status, "active");
    assert.equal(afterReplacement.status, "granted"); assert.equal(afterReplacement.issued_at, unchanged.issued_at); assert.equal(afterReplacement.expires_at, unchanged.expires_at);
    assert.notEqual(afterReplacement.credential_id, oldCredential); assert.equal(afterReplacement.device_key_sha256, replacementDigest);
    await assert.rejects(gateway(challenge()), code(403));
    const replacementChallenge = (await gateway(challenge(replacementKey, replacementDer, replacementDigest))).challenge;
    const replacementReply = await gateway(exchange(replacementKey, replacementDer, replacementDigest, replacementChallenge));
    const replacementState = verifyDeviceResponse(replacementReply, { keys: new Map([["isolated", serverKey.publicKey]]), expected: { device_id: id, credential_id: afterReplacement.credential_id, device_key_sha256: replacementDigest, mac: "02:00:00:00:00:91", realm, challenge_id: replacementChallenge.id, client_nonce: replacementChallenge.client_nonce, nonce: replacementChallenge.nonce, minimum_revision: 3, last_server_time: 0, elapsed_seconds: 0 } });
    assert.equal(replacementState.status.state, "valid"); assert.equal(replacementState.license.exp, grantExpiry);
    assert.equal(replacement.snapshot.license_id, unchanged.license_id);

    // Entitlement revocation is independent; a later credential replacement must retain it.
    await mutate({ action: "revoke", expected_revision: 3 });
    const revokedCredential = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const revokedDer = revokedCredential.publicKey.export({ type: "spki", format: "der" }); const revokedDigest = sha256(revokedDer);
    const revokedReplacement = await mutate({ action: "replace_credential", expected_revision: 4, expected_credential_id: afterReplacement.credential_id, reason: "maintenance", device_key_sha256: revokedDigest });
    assert.equal(revokedReplacement.snapshot.status, "revoked"); assert.equal(revokedReplacement.snapshot.expires_at, grantExpiry);
    const revokedChallenge = (await gateway(challenge(revokedCredential, revokedDer, revokedDigest))).challenge;
    const revokedReply = await gateway(exchange(revokedCredential, revokedDer, revokedDigest, revokedChallenge));
    assert.equal(verifyDeviceResponse(revokedReply, { keys: new Map([["isolated", serverKey.publicKey]]), expected: { device_id: id, credential_id: revokedReplacement.snapshot.credential_id, device_key_sha256: revokedDigest, mac: "02:00:00:00:00:91", realm, challenge_id: revokedChallenge.id, client_nonce: revokedChallenge.client_nonce, nonce: revokedChallenge.nonce, minimum_revision: 5, last_server_time: 0, elapsed_seconds: 0 } }).status.state, "revoked");

    // Replacement has the same post-lock rule as revocation: no old binding is signed.
    const replacePending = (await gateway(challenge(revokedCredential, revokedDer, revokedDigest))).challenge;
    await owner.query("BEGIN"); await owner.query("SELECT id FROM public.ota_devices WHERE id=$1 FOR UPDATE", [id]);
    const replaceWaiting = gateway(exchange(revokedCredential, revokedDer, revokedDigest, replacePending));
    const replaceHandled = replaceWaiting.then(() => ({ ok: true }), error => ({ ok: false, error }));
    lockObserved = false;
    for (let attempt = 0; attempt < 100; attempt++) {
      await owner.query("SELECT pg_stat_clear_snapshot()");
      const activity = await owner.query("SELECT count(*) AS n FROM pg_stat_activity WHERE application_name='bomb-ota-test-recovery' AND wait_event_type='Lock'");
      if (Number(activity.rows[0].n) > 0) { lockObserved = true; break; }
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    assert.ok(lockObserved, "old-key exchange must wait for credential replacement");
    const finalKey = generateKeyPairSync("ec", { namedCurve: "prime256v1" }); const finalDer = finalKey.publicKey.export({ type: "spki", format: "der" }); const finalDigest = sha256(finalDer);
    await owner.query("SET LOCAL ROLE authenticated"); await owner.query("SELECT set_config('request.jwt.claim.sub',$1,true)", [user]);
    await owner.query("SELECT public.ota_admin_license($1,$2,$3::jsonb)", [id, randomUUID(), JSON.stringify({ action: "replace_credential", expected_revision: 5, expected_credential_id: revokedReplacement.snapshot.credential_id, reason: "lost", device_key_sha256: finalDigest })]);
    await owner.query("COMMIT");
    const replaceWaited = await replaceHandled; assert.equal(replaceWaited.ok, false); assert.equal(replaceWaited.error.status, 403);
    const finalState = await current(); assert.equal(finalState.revision, 6); assert.equal(finalState.status, "revoked");

    // A second fixture proves an active grant survives recovery unchanged.
    const activeId = (await admin("SELECT to_jsonb(d) AS data FROM public.ota_register_device($1,$2,$3) d", [scope, "RECOVERY-ACTIVE", "Active fixture"])).id;
    const activeKey = generateKeyPairSync("ec", { namedCurve: "prime256v1" }); const activeDer = activeKey.publicKey.export({ type: "spki", format: "der" }); const activeDigest = sha256(activeDer);
    const activeReplacementKey = generateKeyPairSync("ec", { namedCurve: "prime256v1" }); const activeReplacementDer = activeReplacementKey.publicKey.export({ type: "spki", format: "der" }); const activeReplacementDigest = sha256(activeReplacementDer);
    const activeMutate = (command, request = randomUUID()) => mutate(command, request, user, activeId);
    await activeMutate({ action: "approve_identity", mac: "02:00:00:00:00:92", device_key_sha256: activeDigest });
    await activeMutate({ action: "grant", expected_revision: 0, not_before: 1, expires_at: grantExpiry });
    const activeBefore = (await owner.query("SELECT to_jsonb(l) AS data FROM public.ota_device_licenses l WHERE device_id=$1", [activeId])).rows[0].data;
    const activeReplacement = await activeMutate({ action: "replace_credential", expected_revision: 1, expected_credential_id: activeBefore.credential_id, reason: "maintenance", device_key_sha256: activeReplacementDigest });
    assert.equal(activeReplacement.snapshot.status, "granted"); assert.equal(activeReplacement.snapshot.expires_at, activeBefore.expires_at);
    await assert.rejects(activeMutate({ action: "replace_credential", expected_revision: 2, expected_credential_id: activeReplacement.snapshot.credential_id, reason: "lost", device_key_sha256: digest }), e => e.code === "23505", "historical digest is reserved globally");

    // CAS lets exactly one replacement commit and challenge/audit rollback keeps all recovery state.
    const raceKeyA = generateKeyPairSync("ec", { namedCurve: "prime256v1" }); const raceKeyB = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const race = await Promise.allSettled([sha256(raceKeyA.publicKey.export({ type: "spki", format: "der" })), sha256(raceKeyB.publicKey.export({ type: "spki", format: "der" }))].map(device_key_sha256 => independentMutate(activeId, { action: "replace_credential", expected_revision: 2, expected_credential_id: activeReplacement.snapshot.credential_id, reason: "lost", device_key_sha256 })));
    assert.equal(race.filter(r => r.status === "fulfilled").length, 1); assert.equal(race.filter(r => r.status === "rejected").length, 1); assert.equal(race.find(r => r.status === "rejected").reason.code, "23505");

    // Approval writes license then ledger; replacement writes the new ledger row
    // before changing its license. A fresh digest can therefore commit on only one
    // of two different devices, without an orphan from the losing transaction.
    const crossA = (await admin("SELECT to_jsonb(d) AS data FROM public.ota_register_device($1,$2,$3) d", [scope, "RECOVERY-CROSS-A", "Cross replacement"])).id;
    const crossB = (await admin("SELECT to_jsonb(d) AS data FROM public.ota_register_device($1,$2,$3) d", [scope, "RECOVERY-CROSS-B", "Cross approval"])).id;
    const crossOld = generateKeyPairSync("ec", { namedCurve: "prime256v1" }); const crossOldDer = crossOld.publicKey.export({ type: "spki", format: "der" }); const crossOldDigest = sha256(crossOldDer);
    await mutate({ action: "approve_identity", mac: "02:00:00:00:00:94", device_key_sha256: crossOldDigest }, randomUUID(), user, crossA);
    const crossCredential = (await owner.query("SELECT credential_id FROM public.ota_device_licenses WHERE device_id=$1", [crossA])).rows[0].credential_id;
    const sharedKey = generateKeyPairSync("ec", { namedCurve: "prime256v1" }); const sharedDigest = sha256(sharedKey.publicKey.export({ type: "spki", format: "der" }));
    const crossCounts = async () => ({
      ledger: Number((await owner.query("SELECT count(*) AS n FROM ota_private.device_credentials WHERE device_id = ANY($1::uuid[])", [[crossA, crossB]])).rows[0].n),
      licenses: Number((await owner.query("SELECT count(*) AS n FROM public.ota_device_licenses WHERE device_id = ANY($1::uuid[])", [[crossA, crossB]])).rows[0].n),
      operations: Number((await owner.query("SELECT count(*) AS n FROM public.ota_license_operations WHERE device_id = ANY($1::uuid[])", [[crossA, crossB]])).rows[0].n)
    });
    const crossBefore = await crossCounts();
    const crossRace = await Promise.allSettled([
      independentMutate(crossA, { action: "replace_credential", expected_revision: 0, expected_credential_id: crossCredential, reason: "lost", device_key_sha256: sharedDigest }),
      independentMutate(crossB, { action: "approve_identity", mac: "02:00:00:00:00:95", device_key_sha256: sharedDigest })
    ]);
    assert.equal(crossRace.filter(result => result.status === "fulfilled").length, 1);
    assert.equal(crossRace.filter(result => result.status === "rejected").length, 1);
    assert.equal(crossRace.find(result => result.status === "rejected").reason.code, "23505");
    const crossAfter = await crossCounts();
    assert.equal(crossAfter.ledger, crossBefore.ledger + 1, "losing digest transaction leaves no ledger row");
    assert.equal(crossAfter.operations, crossBefore.operations + 1, "losing digest transaction leaves no receipt/audit");
    assert.equal(Number((await owner.query("SELECT count(*) AS n FROM ota_private.device_credentials WHERE device_key_sha256=$1", [sharedDigest])).rows[0].n), 1);
    const crossWinner = crossRace.find(result => result.status === "fulfilled").value;
    assert.equal(crossAfter.licenses, crossWinner.action === "approve_identity" ? 2 : 1, "license and ledger commit together for either ordering");

    const crossOldState = (await owner.query("SELECT retired_at FROM ota_private.device_credentials WHERE credential_id=$1", [crossCredential])).rows[0];
    assert.equal(crossOldState.retired_at === null, crossWinner.action === "approve_identity", "losing replacement cannot retire the original key");
    const crossLicense = (await owner.query("SELECT to_jsonb(l) AS data FROM public.ota_device_licenses l WHERE device_id=$1", [crossA])).rows[0].data;
    assert.equal(crossLicense.revision, crossWinner.action === "approve_identity" ? 0 : 1);
    assert.equal(crossLicense.device_key_sha256, crossWinner.action === "approve_identity" ? crossOldDigest : sharedDigest);

    // An unlicensed credential can be revoked, then replaced.  The shared
    // revision advances for both operations, while the signed state remains unlicensed.
    const unlicensedId = (await admin("SELECT to_jsonb(d) AS data FROM public.ota_register_device($1,$2,$3) d", [scope, "RECOVERY-UNLICENSED", "Unlicensed fixture"])).id;
    const unlicensedOld = generateKeyPairSync("ec", { namedCurve: "prime256v1" }); const unlicensedNew = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const unlicensedOldDer = unlicensedOld.publicKey.export({ type: "spki", format: "der" }); const unlicensedNewDer = unlicensedNew.publicKey.export({ type: "spki", format: "der" });
    const unlicensedOldDigest = sha256(unlicensedOldDer); const unlicensedNewDigest = sha256(unlicensedNewDer);
    const unlicensedMutate = (command, request = randomUUID()) => mutate(command, request, user, unlicensedId);
    await unlicensedMutate({ action: "approve_identity", mac: "02:00:00:00:00:93", device_key_sha256: unlicensedOldDigest });
    const unlicensedBefore = (await owner.query("SELECT to_jsonb(l) AS data FROM public.ota_device_licenses l WHERE device_id=$1", [unlicensedId])).rows[0].data;
    const unlicensedRevocation = await unlicensedMutate({ action: "revoke_credential", expected_revision: 0, expected_credential_id: unlicensedBefore.credential_id, reason: "lost" });
    assert.equal(unlicensedRevocation.snapshot.revision, 1); assert.equal(unlicensedRevocation.snapshot.status, "unlicensed");
    await assert.rejects(gateway(proofFor(unlicensedOld, unlicensedOldDer, unlicensedOldDigest, "02:00:00:00:00:93")), code(403));
    await assert.rejects(unlicensedMutate({ action: "grant", expected_revision: 1, not_before: 1, expires_at: grantExpiry }), e => e.code === "23505");
    const unlicensedReplacement = await unlicensedMutate({ action: "replace_credential", expected_revision: 1, expected_credential_id: unlicensedBefore.credential_id, reason: "lost", device_key_sha256: unlicensedNewDigest });
    assert.equal(unlicensedReplacement.snapshot.revision, 2);
    const unlicensedChallenge = (await gateway(proofFor(unlicensedNew, unlicensedNewDer, unlicensedNewDigest, "02:00:00:00:00:93"))).challenge;
    const unlicensedReply = await gateway(proofFor(unlicensedNew, unlicensedNewDer, unlicensedNewDigest, "02:00:00:00:00:93", unlicensedChallenge));
    assert.equal(verifyDeviceResponse(unlicensedReply, { keys: new Map([["isolated", serverKey.publicKey]]), expected: { device_id: unlicensedId, credential_id: unlicensedReplacement.snapshot.credential_id, device_key_sha256: unlicensedNewDigest, mac: "02:00:00:00:00:93", realm, challenge_id: unlicensedChallenge.id, client_nonce: unlicensedChallenge.client_nonce, nonce: unlicensedChallenge.nonce, minimum_revision: 2, last_server_time: 0, elapsed_seconds: 0 } }).status.state, "unlicensed");

    const pending = (await gateway(challenge(finalKey, finalDer, finalDigest))).challenge;
    const ledger = async () => (await owner.query("SELECT to_jsonb(c) AS data FROM ota_private.device_credentials c WHERE device_id=$1 ORDER BY credential_id", [id])).rows.map(row => row.data);
    const beforeRollback = { state: await current(), ledger: await ledger(), challengeCount: await challenges() };
    await owner.query("CREATE FUNCTION ota_private.fail_recovery_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test audit failure'; END $$");
    await owner.query("CREATE TRIGGER fail_recovery_audit BEFORE INSERT ON public.ota_license_operations FOR EACH ROW EXECUTE FUNCTION ota_private.fail_recovery_audit()");
    await assert.rejects(mutate({ action: "replace_credential", expected_revision: 6, expected_credential_id: finalState.credential_id, reason: "lost", device_key_sha256: sha256(randomBytes(40)) }), e => e.message.includes("test audit failure"));
    await owner.query("DROP TRIGGER fail_recovery_audit ON public.ota_license_operations; DROP FUNCTION ota_private.fail_recovery_audit()");
    assert.deepEqual(await current(), beforeRollback.state); assert.equal(await challenges(), beforeRollback.challengeCount); assert.deepEqual(await ledger(), beforeRollback.ledger);
    await owner.end(); owner = null;
    return async () => {
      const afterRestartReply = await gateway(exchange(finalKey, finalDer, finalDigest, pending));
      assert.equal(verifyDeviceResponse(afterRestartReply, { keys: new Map([["isolated", serverKey.publicKey]]), expected: { device_id: id, credential_id: finalState.credential_id, device_key_sha256: finalDigest, mac: "02:00:00:00:00:91", realm, challenge_id: pending.id, client_nonce: pending.client_nonce, nonce: pending.nonce, minimum_revision: 6, last_server_time: 0, elapsed_seconds: 0 } }).status.state, "revoked", "rollback left the pending new-key challenge usable after restart");
      const inspect = new pg.Client({ ...connection, user: "ota_test_owner" }); inspect.on("error", () => {}); await inspect.connect();
      try {
        assert.equal(Number((await inspect.query("SELECT revision FROM public.ota_device_licenses WHERE device_id=$1", [id])).rows[0].revision), 6);
        await inspect.query("BEGIN"); await inspect.query("SET LOCAL ROLE authenticated"); await inspect.query("SELECT set_config('request.jwt.claim.sub',$1,true)", [user]);
        const replay = (await inspect.query("SELECT public.ota_admin_license($1,$2,$3::jsonb) AS data", [id, revokeRequest,
          JSON.stringify({ action: "revoke_credential", expected_revision: 1, expected_credential_id: oldCredential, reason: "lost" })])).rows[0].data;
        await inspect.query("COMMIT"); assert.deepEqual(replay, revoked, "historical receipt survives restart without mutation");
      }
      finally { await inspect.end(); }
      process.stdout.write("Credential recovery PostgreSQL: revocation, replacement, ledger isolation, CAS, rollback and restart passed.\n");
    };
  } finally { if (owner) { try { await owner.query("ROLLBACK"); } finally { await owner.end(); } } }
}
