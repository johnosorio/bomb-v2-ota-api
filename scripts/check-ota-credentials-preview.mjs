// Explicit Preview integration runner for OTA-03.  It uses only synthetic Auth
// identities and device material generated in RAM.  Never add this to npm test.
import { readFileSync, lstatSync } from "node:fs";
import { execFile } from "node:child_process";
import { createPublicKey, generateKeyPairSync, randomBytes, randomUUID, sign } from "node:crypto";
import { fileURLToPath } from "node:url";
import { deviceProofInput, sha256 } from "../lib/ota/device-proof.js";
import { verifyDeviceResponse } from "../lib/ota/device-response.js";

const backend = fileURLToPath(new URL("../", import.meta.url));
const {
  SUPABASE_URL: base,
  SUPABASE_PUBLISHABLE_KEY: key,
  OTA_PREVIEW_URL: preview,
  OTA_PREVIEW_FIXTURE: fixturePath,
  OTA_DEVICE_REALM: realm,
  OTA_PREVIEW_SIGNING_PUBLIC_KEY: signingPublicKeyPem,
  OTA_LICENSE_SIGNING_KID: signingKid
} = process.env;

if (base !== "https://cdurakjehpvcwmvsgire.supabase.co" || !/^sb_publishable_/.test(key || ""))
  throw Error("Expected approved development Supabase project");
if (!/^https:\/\/bomb-v2-ota-[a-z0-9-]+-johnosorios-projects\.vercel\.app$/.test(preview || ""))
  throw Error("Expected explicit Preview URL, never production");
if (!/^[a-z0-9][a-z0-9_-]{0,39}$/.test(realm || "") || !/^[A-Za-z0-9_-]{1,40}$/.test(signingKid || ""))
  throw Error("Expected gateway realm and signing key id");
if (!fixturePath || !lstatSync(fixturePath).isFile() || (lstatSync(fixturePath).mode & 0o777) !== 0o600)
  throw Error("Private fixture required (0600)");

let signingPublicKey;
try {
  signingPublicKey = createPublicKey(signingPublicKeyPem);
  if (signingPublicKey.asymmetricKeyType !== "ec" || signingPublicKey.asymmetricKeyDetails?.namedCurve !== "prime256v1") throw Error();
} catch { throw Error("Expected P-256 Preview signing public key"); }

const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));
if (fixture.projectRef !== "cdurakjehpvcwmvsgire" || fixture.closed || !fixture.provisioned)
  throw Error("Fixture is not active for this project");
const sessions = {};
// Each invocation owns a fresh synthetic device; retries cannot revoke an older run.
const executionId = randomBytes(8).toString("hex");
let passed = 0;
let deviceId = null;
let failureName = "credential Preview runner";
let lastServerTime = 0;
const expect = (condition, name) => {
  failureName = name;
  if (!condition) throw Error(name);
  passed++;
  console.log(`PASS ${name}`);
};

async function rest(path, { token, method = "GET", body, object = false } = {}) {
  const response = await fetch(base + path, {
    method,
    headers: {
      apikey: key,
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      "Content-Type": "application/json",
      Accept: object ? "application/vnd.pgrst.object+json" : "application/json"
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    redirect: "error",
    signal: AbortSignal.timeout(15000)
  });
  const text = await response.text();
  let data;
  try { data = JSON.parse(text); } catch { data = null; }
  return { status: response.status, data };
}

function http(path, { role, method = "GET", body, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    // Headers arrive by stdin rather than command arguments or logs.
    const values = { ...headers, ...(role ? { Authorization: `Bearer ${sessions[role]}` } : {}) };
    const lines = [`request = ${JSON.stringify(method)}`, ...Object.entries(values)
      .map(([name, value]) => `header = ${JSON.stringify(`${name}: ${value}`)}`)];
    if (body !== undefined) {
      lines.push('header = "Content-Type: application/json"');
      lines.push(`data = ${JSON.stringify(typeof body === "string" ? body : JSON.stringify(body))}`);
    }
    const child = execFile("npx", ["--yes", "vercel@59.23.2", "curl", path, "--deployment", preview,
      "--", "--silent", "--show-error", "--max-time", "25", "--write-out", "\n_OTA_HTTP_%{http_code}", "--config", "-"],
    { cwd: backend, timeout: 45000, maxBuffer: 1024 * 1024 }, (error, stdout) => {
      if (error) return reject(Error("Preview transport failed"));
      const match = stdout.match(/\n_OTA_HTTP_(\d{3})\s*$/);
      if (!match) return reject(Error("Preview status marker missing"));
      const text = stdout.slice(0, match.index);
      let data;
      try { data = JSON.parse(text); } catch { data = null; }
      resolve({ status: Number(match[1]), data });
    });
    child.stdin.end(`${lines.join("\n")}\n`);
  });
}

function deviceKey() {
  const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const der = pair.publicKey.export({ type: "spki", format: "der" });
  return { privateKey: pair.privateKey, der, digest: sha256(der) };
}

function signedDeviceRequest(pair, body) {
  return {
    ...body,
    signature: sign("sha256", deviceProofInput(body, realm, pair.digest),
      { key: pair.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url")
  };
}

// Keep the signer names aligned with the installed-device protocol boundary.
function signDeviceChallengeRequest(pair, mac) {
  return signedDeviceRequest(pair, {
    action: "challenge", mac, public_key: pair.der.toString("base64url"), client_nonce: randomBytes(32).toString("hex")
  });
}

function signDeviceExchange(pair, challenge) {
  return signedDeviceRequest(pair, {
    action: "exchange", device_id: challenge.device_id, credential_id: challenge.credential_id,
    mac: challenge.mac, public_key: pair.der.toString("base64url"), client_nonce: challenge.client_nonce,
    challenge_id: challenge.id, nonce: challenge.nonce
  });
}

const credentialsPath = "/api/ota/licenses";
const gatewayPath = "/api/ota/device-license";
const command = (action, extra = {}) => ({ device_id: deviceId, request_id: randomUUID(), action, ...extra });
const mutate = (body, role = "adminA") => http(credentialsPath, { role, method: "POST", body });
const credentialState = () => http(`${credentialsPath}?device_id=${deviceId}`, { role: "adminA" });
const stateIdentity = (response) => {
  const state = response.data?.license;
  if (response.status !== 200 || !state || !Number.isInteger(state.revision) || typeof state.credential_id !== "string")
    throw Error("State read failed");
  return [state.credential_id, state.device_key_sha256, state.license_id, state.revision,
    state.status, state.credential_status, state.not_before, state.expires_at].join("|");
};
function verify(response, challenge, pair, minimumRevision, challengeStarted) {
  failureName = "signed device response verification";
  const verified = verifyDeviceResponse(response, {
    keys: new Map([[signingKid, signingPublicKey]]),
    expected: {
      device_id: challenge.device_id, credential_id: challenge.credential_id, device_key_sha256: pair.digest,
      mac: challenge.mac, realm, challenge_id: challenge.id, client_nonce: challenge.client_nonce, nonce: challenge.nonce,
      minimum_revision: minimumRevision, last_server_time: lastServerTime,
      elapsed_seconds: (performance.now() - challengeStarted) / 1000
    }
  });
  lastServerTime = verified.status.server_time;
  return verified;
}

function syntheticMac() {
  return Buffer.concat([Buffer.from([0x02]), randomBytes(5)]).toString("hex").match(/../g).join(":").toUpperCase();
}

async function revokeActiveCredential() {
  if (!deviceId || !sessions.adminA) return;
  try {
    const state = await credentialState();
    if (state.status !== 200 || !state.data?.license) throw Error("cleanup state");
    const current = state.data.license;
    if (current.credential_status !== "active") return;
    const result = await mutate(command("revoke_credential", {
      expected_revision: current.revision, expected_credential_id: current.credential_id, reason: "maintenance"
    }));
    if (result.status === 200 && result.data?.receipt?.snapshot?.credential_status === "revoked")
      console.log(`PASS cleanup revoked active credential ${deviceId}`);
    else throw Error("cleanup revoke");
  } catch {
    // Cleanup is best effort. Do not disclose a response, token, or transport details.
    console.log(`CLEANUP_INCOMPLETE ${deviceId}`);
    process.exitCode = 1;
  }
}

try {
  for (const [role, user] of Object.entries(fixture.users)) {
    const result = await rest("/auth/v1/token?grant_type=password", { method: "POST", body: { email: user.email, password: user.password } });
    if (result.status !== 200 || !result.data?.access_token || result.data.user?.id !== user.id)
      throw Error("Auth login failed");
    sessions[role] = result.data.access_token;
  }
  expect(Boolean(sessions.adminA && sessions.viewerA && sessions.adminB), "real Auth admin viewer and foreign sessions established");

  const registration = await http("/api/ota/devices", { role: "adminA", method: "POST", body: {
    scope_id: fixture.scopeA, device_id: `CREDENTIAL-PREVIEW-${executionId}`, label: "Synthetic credential Preview"
  } });
  expect(registration.status === 200 && typeof registration.data?.device?.id === "string", "synthetic credential device registered");
  deviceId = registration.data.device.id;
  const mac = syntheticMac();
  const oldKey = deviceKey();
  const newKey = deviceKey();
  const revokedKey = deviceKey();

  const approved = await mutate(command("approve_identity", { mac, device_key_sha256: oldKey.digest }));
  expect(approved.status === 200 && approved.data?.receipt?.snapshot?.revision === 0, "admin approves synthetic device identity");
  const grantExpiry = Math.floor(Date.now() / 1000) + 3600;
  const granted = await mutate(command("grant", { expected_revision: 0, not_before: 1, expires_at: grantExpiry }));
  expect(granted.status === 200 && granted.data?.receipt?.snapshot?.revision === 1 && granted.data.receipt.snapshot.status === "granted", "admin grant committed");
  const grantSnapshot = granted.data.receipt.snapshot;

  failureName = "approved device challenge";
  const firstStarted = performance.now();
  const firstRequest = signDeviceChallengeRequest(oldKey, mac);
  const firstChallenge = await http(gatewayPath, { method: "POST", body: firstRequest });
  expect(firstChallenge.status === 200 && firstChallenge.data?.challenge?.credential_id === grantSnapshot.credential_id, "approved device challenge issued");
  const sameChallenge = await http(gatewayPath, { method: "POST", body: firstRequest });
  expect(sameChallenge.status === 200 && sameChallenge.data?.challenge?.id === firstChallenge.data.challenge.id, "challenge retry is idempotent");
  const firstExchange = await http(gatewayPath, { method: "POST", body: signDeviceExchange(oldKey, firstChallenge.data.challenge) });
  const valid = verify(firstExchange.data, firstChallenge.data.challenge, oldKey, 1, firstStarted);
  expect(firstExchange.status === 200 && valid.status.state === "valid", "exchange returns verified valid license");
  expect((await http(gatewayPath, { method: "POST", body: signDeviceExchange(oldKey, firstChallenge.data.challenge) })).status === 409, "exchange replay rejected without state change");

  failureName = "old credential pending challenge";
  const pending = await http(gatewayPath, { method: "POST", body: signDeviceChallengeRequest(oldKey, mac) });
  expect(pending.status === 200, "old credential pending challenge issued");
  const credentialRevocation = await mutate(command("revoke_credential", {
    expected_revision: 1, expected_credential_id: grantSnapshot.credential_id, reason: "lost"
  }));
  expect(credentialRevocation.status === 200 && credentialRevocation.data?.receipt?.snapshot?.credential_status === "revoked", "credential revocation committed");
  expect((await http(gatewayPath, { method: "POST", body: signDeviceChallengeRequest(oldKey, mac) })).status === 403, "old credential challenge rejected after revocation");
  expect((await http(gatewayPath, { method: "POST", body: signDeviceExchange(oldKey, pending.data.challenge) })).status === 403, "old pending exchange rejected after credential revocation");

  const replaced = await mutate(command("replace_credential", {
    expected_revision: 2, expected_credential_id: grantSnapshot.credential_id, reason: "lost", device_key_sha256: newKey.digest
  }));
  const replacement = replaced.data?.receipt?.snapshot;
  expect(replaced.status === 200 && replacement?.credential_status === "active" && replacement.credential_id !== grantSnapshot.credential_id &&
    replacement.license_id === grantSnapshot.license_id && replacement.not_before === grantSnapshot.not_before &&
    replacement.expires_at === grantSnapshot.expires_at && replacement.status === grantSnapshot.status && replacement.revision === 3,
  "replacement preserves grant fields and rotates credential UUID with CAS");
  failureName = "replacement credential challenge";
  const newStarted = performance.now();
  const newChallenge = await http(gatewayPath, { method: "POST", body: signDeviceChallengeRequest(newKey, mac) });
  expect(newChallenge.status === 200 && newChallenge.data?.challenge?.credential_id === replacement.credential_id, "replacement key challenge issued");
  const newExchange = await http(gatewayPath, { method: "POST", body: signDeviceExchange(newKey, newChallenge.data.challenge) });
  expect(newExchange.status === 200 && verify(newExchange.data, newChallenge.data.challenge, newKey, 3, newStarted).status.state === "valid", "replacement key receives verified valid license");
  expect((await http(gatewayPath, { method: "POST", body: signDeviceChallengeRequest(oldKey, mac) })).status === 403, "old credential challenge rejected after replacement");
  const beforeOldHashReuse = await credentialState();
  const oldHashReuse = await mutate(command("replace_credential", {
    expected_revision: 3, expected_credential_id: replacement.credential_id, reason: "lost", device_key_sha256: oldKey.digest
  }));
  const afterOldHashReuse = await credentialState();
  expect(oldHashReuse.status === 409 && stateIdentity(beforeOldHashReuse) === stateIdentity(afterOldHashReuse), "historical device key hash rejected without state change");

  const entitlementRevocation = await mutate(command("revoke", { expected_revision: 3 }));
  expect(entitlementRevocation.status === 200 && entitlementRevocation.data?.receipt?.snapshot?.revision === 4 &&
    entitlementRevocation.data.receipt.snapshot.status === "revoked", "grant revocation committed");
  const revokedReplacement = await mutate(command("replace_credential", {
    expected_revision: 4, expected_credential_id: replacement.credential_id, reason: "maintenance", device_key_sha256: revokedKey.digest
  }));
  const revokedSnapshot = revokedReplacement.data?.receipt?.snapshot;
  expect(revokedReplacement.status === 200 && revokedSnapshot?.status === "revoked" && revokedSnapshot.credential_status === "active" &&
    revokedSnapshot.license_id === grantSnapshot.license_id && revokedSnapshot.not_before === grantSnapshot.not_before &&
    revokedSnapshot.expires_at === grantSnapshot.expires_at && revokedSnapshot.revision === 5,
  "replacement retains revoked entitlement without license changes");
  failureName = "revoked replacement challenge";
  const revokedStarted = performance.now();
  const revokedChallenge = await http(gatewayPath, { method: "POST", body: signDeviceChallengeRequest(revokedKey, mac) });
  expect(revokedChallenge.status === 200 && revokedChallenge.data?.challenge?.credential_id === revokedSnapshot.credential_id, "revoked replacement challenge issued");
  const revokedExchange = await http(gatewayPath, { method: "POST", body: signDeviceExchange(revokedKey, revokedChallenge.data.challenge) });
  expect(revokedExchange.status === 200 &&
    verify(revokedExchange.data, revokedChallenge.data.challenge, revokedKey, 5, revokedStarted).status.state === "revoked" && revokedExchange.data.license_document === null,
  "revoked replacement response is signed and has no license document");
  const beforeRejectedWrites = await credentialState();
  const staleCas = await mutate(command("replace_credential", {
    expected_revision: 4, expected_credential_id: replacement.credential_id, reason: "lost", device_key_sha256: deviceKey().digest
  }));
  const viewerDenied = await mutate(command("revoke_credential", {
    expected_revision: 5, expected_credential_id: revokedSnapshot.credential_id, reason: "lost"
  }), "viewerA");
  const foreignDenied = await mutate(command("revoke_credential", {
    expected_revision: 5, expected_credential_id: revokedSnapshot.credential_id, reason: "lost"
  }), "adminB");
  const afterRejectedWrites = await credentialState();
  expect(staleCas.status === 409 && stateIdentity(beforeRejectedWrites) === stateIdentity(afterRejectedWrites), "stale replacement CAS rejected without state change");
  expect(viewerDenied.status === 403 && stateIdentity(beforeRejectedWrites) === stateIdentity(afterRejectedWrites), "viewer credential mutation denied without state change");
  expect(foreignDenied.status === 403 && stateIdentity(beforeRejectedWrites) === stateIdentity(afterRejectedWrites), "foreign admin credential mutation denied without state change");

  console.log(JSON.stringify({ passed, preview, projectRef: fixture.projectRef, deviceId, scopeId: fixture.scopeA, executionId }));
} catch {
  console.log(`FAIL ${failureName}`);
  process.exitCode = 1;
} finally {
  await revokeActiveCredential();
}
