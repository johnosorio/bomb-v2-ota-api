import test from 'node:test';
import assert from 'node:assert/strict';
import { IncomingMessage } from 'node:http';
import { Socket } from 'node:net';
import { generateKeyPairSync, sign } from 'node:crypto';
import { createHandler } from "../api/ota/pin.js";
import { proofInput } from "../lib/ota/pin-recovery.js";
import { sha256 } from "../lib/ota/device-proof.js";

const realm = 'production';
const mac = 'A1:B2:C3:D4:E5:F6';
const requestId = '12'.repeat(32);
const nonce = '34'.repeat(32);
const deviceId = '11111111-1111-4111-8111-111111111111';
const credentialId = '22222222-2222-4222-8222-222222222222';
const issuedAt = 1_800_000_000;
const baseRow = {
  request_id: requestId,
  device_id: deviceId,
  credential_id: credentialId,
  realm,
  status: 'pending',
  issued_at: issuedAt,
  expires_at: issuedAt + 600
};
const adminEnv = {
  OTA_PIN_RECOVERY_ENABLED: 'true',
  OTA_ADMIN_ENABLED: 'true',
  OTA_DEVICE_REALM: realm,
  SUPABASE_URL: 'https://fixture-project.supabase.co',
  SUPABASE_PUBLISHABLE_KEY: 'sb_publishable_synthetic_fixture'
};

function makeRequest(method, query, headers, body) {
  const req = new IncomingMessage(new Socket());
  req.method = method;
  req.url = `/api/ota/pin${query ? `?${query}` : ''}`;
  req.query = query ? Object.fromEntries(new URLSearchParams(query)) : {};
  req.body = body;
  req.headers = headers;
  assert.equal(req.headers['content-type'], headers['content-type']);
  return req;
}

function responseRecorder() {
  const result = { status: 200, headers: {}, body: undefined };
  const res = {
    setHeader(name, value) { result.headers[name.toLowerCase()] = value; return this; },
    status(code) { result.status = code; return this; },
    json(body) { result.body = body; return this; }
  };
  return { result, res };
}

function jsonReply(body) {
  return { ok: true, status: 200, json: async () => body };
}

test('POST device proof reaches its transaction and returns the bound recovery', async () => {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const der = publicKey.export({ format: 'der', type: 'spki' });
  const input = {
    action: 'create', mac,
    public_key: der.toString('base64url'),
    request_id: requestId,
    nonce,
    signature: ''
  };
  input.signature = sign('sha256', proofInput(input, realm, sha256(der)), {
    key: privateKey, dsaEncoding: 'ieee-p1363'
  }).toString('base64url');

  let calls = 0;
  const handler = createHandler({
    env: adminEnv,
    transaction: async callback => callback(async (sql, values) => {
      calls++;
      assert.match(sql, /ota_pin_device/);
      assert.equal(values[1], 'create');
      assert.equal(values[2], requestId);
      assert.equal(values[3], nonce);
      const identity = JSON.parse(values[0]);
      assert.deepEqual(identity, { mac, device_key_sha256: sha256(der), realm });
      return { rows: [{ data: { ...baseRow, nonce } }] };
    })
  });
  const req = makeRequest('POST', '', { 'content-type': 'application/json' }, input);
  const { result, res } = responseRecorder();
  try {
    await handler(req, res);
    assert.equal(result.status, 200);
    assert.deepEqual(result.body, { schema_version: 1, recovery: { ...baseRow, nonce } });
    assert.equal(calls, 1);
  } finally { req.socket.destroy(); }
});

test('POST admin approval authenticates the JWT and calls the user-scoped RPC', async () => {
  const calls = [];
  const handler = createHandler({
    env: adminEnv,
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      if (url.endsWith('/auth/v1/user')) return jsonReply({ id: '33333333-3333-4333-8333-333333333333', is_anonymous: false });
      if (url.endsWith('/rest/v1/rpc/ota_pin_admin')) return jsonReply({ ...baseRow, status: 'approved' });
      throw new Error(`Unexpected fixture URL: ${url}`);
    }
  });
  const req = makeRequest('POST', '', {
    'content-type': 'application/json',
    authorization: 'Bearer synthetic.user.jwt'
  }, { request_id: requestId, action: 'approve' });
  const { result, res } = responseRecorder();
  try {
    await handler(req, res);
    assert.equal(result.status, 200);
    assert.deepEqual(result.body, { schema_version: 1, recovery: { ...baseRow, status: 'approved' } });
    assert.equal(calls.length, 2);
    assert.match(calls[0].url, /\/auth\/v1\/user$/);
    assert.equal(calls[0].options.headers.Authorization, 'Bearer synthetic.user.jwt');
    assert.match(calls[1].url, /\/rest\/v1\/rpc\/ota_pin_admin$/);
    assert.deepEqual(JSON.parse(calls[1].options.body), { p_request_id: requestId, p_action: 'approve' });
  } finally { req.socket.destroy(); }
});

test('invalid JSON content type is rejected before device transaction', async () => {
  let calls = 0;
  const handler = createHandler({
    env: adminEnv,
    transaction: async () => { calls++; throw new Error('must not reach transaction'); }
  });
  const req = makeRequest('POST', '', { 'content-type': 'text/plain' }, {});
  const { result, res } = responseRecorder();
  try {
    await handler(req, res);
    assert.equal(result.status, 415);
    assert.deepEqual(result.body, { error: 'JSON_REQUIRED' });
    assert.equal(calls, 0);
  } finally { req.socket.destroy(); }
});
