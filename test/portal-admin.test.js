import test from 'node:test';
import assert from 'node:assert/strict';
import { portal } from './portal-helper.js';

const scopeId = '10000000-0000-0000-0000-000000000001';
const deviceId = '30000000-0000-0000-0000-000000000001';
const credentialId = '40000000-0000-0000-0000-000000000001';
const device = { id: deviceId, label: 'Equipo uno', model: 'CoreS3', device_id: 'CORES3-01' };
const license = { device_id: deviceId, credential_id: credentialId, mac: 'AA:BB:CC:DD:EE:FF',
  device_key_sha256: 'a'.repeat(64), license_id: '50000000-0000-0000-0000-000000000001', revision: 7,
  status: 'granted', credential_status: 'active', issued_at: 1900000000, not_before: 1900000000,
  expires_at: 2000000000, updated_by: '60000000-0000-0000-0000-000000000001', updated_at: '2026-10-01T00:00:00Z' };

async function signedIn({ role = 'admin', scopes = [{ id: scopeId, name: 'Ámbito seguro', role }], devices = [device], deviceReply, reply } = {}) {
  const p = await portal({ reply: async (url, options, calls) => {
    if (url.includes('grant_type=password')) return { access_token: 'session-token', user: { id: 'user', is_anonymous: false } };
    if (url.includes('action=context')) return { scopes };
    if (url.startsWith('/api/ota/devices?scope_id=')) return deviceReply ? deviceReply(url, options, calls) : { devices };
    return reply ? reply(url, options, calls) : {};
  } });
  p.elements.get('email').value = 'operator@example.org'; p.elements.get('password').value = 'password';
  await p.submit('login-form');
  return p;
}

async function openLicense(p) {
  await p.elements.get('devices').children[0].children[1].onclick(); await p.idle();
}

async function prepareGrant(p) {
  p.elements.get('license-action').value = 'grant'; await p.click('action-open');
  p.elements.get('edit-start').value = '2030-01-01T00:00';
  p.elements.get('edit-end').value = '2030-02-01T00:00';
  await p.submit('operation-form');
}

test('session opens the context dashboard and logout clears it even when Auth logout fails', async () => {
  const p = await signedIn({ reply: url => url.includes('/logout') ? { failure: 503 } : {} });
  assert.equal(p.elements.get('workspace').hidden, false);
  assert.equal(p.elements.get('workspace-title').textContent, 'Dispositivos');
  assert.equal(p.calls.some(call => call.url.includes('action=context')), true);
  await p.click('logout');
  assert.equal(p.elements.get('workspace').hidden, true);
  assert.equal(p.elements.get('login').hidden, false);
  assert.equal(p.elements.get('status').textContent, 'Sesión cerrada en este navegador.');
});

test('viewer context shows a valid license but no mutation controls', async () => {
  const p = await signedIn({ role: 'viewer', reply: url => url.startsWith('/api/ota/licenses?') ? { license } : {} });
  assert.equal(p.elements.get('register-open').hidden, true);
  assert.equal(p.elements.get('scope-role').textContent, 'Sólo lectura');
  await openLicense(p);
  assert.equal(p.elements.get('license-actions').hidden, true);
});

test('scope and device read failures show a retryable error without opening a mutation flow', async () => {
  let contexts = 0, devicesCalls = 0;
  const p = await portal({ reply: url => {
    if (url.includes('grant_type=password')) return { access_token: 'session-token', user: { id: 'user' } };
    if (url.includes('action=context')) return ++contexts === 1 ? { failure: 503 } : { scopes: [{ id: scopeId, name: 'Ámbito', role: 'admin' }] };
    if (url.startsWith('/api/ota/devices?scope_id=')) return ++devicesCalls === 1 ? { failure: 503 } : { devices: [] };
    return {};
  } });
  p.elements.get('email').value = 'operator@example.org'; p.elements.get('password').value = 'password'; await p.submit('login-form');
  assert.match(p.elements.get('status').textContent, /No se pudo completar/);
  assert.equal(p.elements.get('operation').hidden, true);
  assert.equal(p.elements.get('register-open').hidden, true);
  await p.click('refresh-devices');
  assert.equal(p.elements.get('register-open').hidden, true);
  await p.click('refresh-devices');
  assert.equal(p.elements.get('register-open').hidden, false);
  assert.equal(p.elements.get('devices-empty').hidden, false);
});

test('grant is prepared exactly and sends no write until confirmation', async () => {
  const p = await signedIn({ reply: url => url.startsWith('/api/ota/licenses?') ? { license } : { license } });
  await openLicense(p); await prepareGrant(p);
  assert.equal(p.calls.filter(call => call.url === '/api/ota/licenses' && call.options.method === 'POST').length, 0);
  assert.match(p.elements.get('operation-summary').children.map(node => node.textContent).join(' '), /Revisión que se modificará: 7/);
  await p.click('operation-confirm');
  const post = p.calls.find(call => call.url === '/api/ota/licenses' && call.options.method === 'POST');
  assert.deepEqual(JSON.parse(post.options.body), { device_id: deviceId, request_id: '00000000-0000-4000-8000-000000000001', action: 'grant', expected_revision: 7,
    not_before: Math.floor(new Date('2030-01-01T00:00').getTime() / 1000), expires_at: Math.floor(new Date('2030-02-01T00:00').getTime() / 1000) });
});

test('503 retries the exact same license command, including request UUID and body', async () => {
  let posts = 0;
  const p = await signedIn({ reply: (url, options) => {
    if (url.startsWith('/api/ota/licenses?')) return { license };
    if (url === '/api/ota/licenses' && options.method === 'POST') return ++posts === 1 ? { failure: 503 } : { receipt: true };
    return { license };
  } });
  await openLicense(p); await prepareGrant(p); await p.click('operation-confirm'); await p.click('operation-confirm');
  const writes = p.calls.filter(call => call.url === '/api/ota/licenses' && call.options.method === 'POST').map(call => call.options.body);
  assert.equal(writes.length, 2); assert.equal(writes[0], writes[1]);
});

test('409 hides confirmation and never retries a rejected command automatically', async () => {
  const p = await signedIn({ reply: (url, options) => {
    if (url.startsWith('/api/ota/licenses?')) return { license };
    if (url === '/api/ota/licenses' && options.method === 'POST') return { failure: 409 };
    return {};
  } });
  await openLicense(p); await prepareGrant(p); await p.click('operation-confirm'); await p.idle();
  assert.equal(p.elements.get('operation-confirm').hidden, true);
  assert.equal(p.calls.filter(call => call.url === '/api/ota/licenses' && call.options.method === 'POST').length, 1);
});

test('after 409, returning refreshes and a newly prepared command uses a new UUID only after confirmation', async () => {
  let posts = 0;
  const p = await signedIn({ reply: (url, options) => {
    if (url.startsWith('/api/ota/licenses?')) return { license };
    if (url === '/api/ota/licenses' && options.method === 'POST') return ++posts === 1 ? { failure: 409 } : { receipt: true };
    return {};
  } });
  await openLicense(p); await prepareGrant(p); await p.click('operation-confirm');
  await p.click('operation-return');
  assert.equal(p.calls.filter(call => call.url === '/api/ota/licenses' && call.options.method === 'POST').length, 1);
  p.elements.get('license-action').value = 'grant'; await p.click('action-open');
  p.elements.get('edit-start').value = '2030-01-01T00:00'; p.elements.get('edit-end').value = '2030-02-01T00:00';
  await p.submit('operation-form');
  assert.equal(p.calls.filter(call => call.url === '/api/ota/licenses' && call.options.method === 'POST').length, 1);
  await p.click('operation-confirm');
  const writes = p.calls.filter(call => call.url === '/api/ota/licenses' && call.options.method === 'POST').map(call => JSON.parse(call.options.body));
  assert.equal(writes.length, 2); assert.notEqual(writes[0].request_id, writes[1].request_id);
});

test('after a successful POST and failed refresh, retry reads only and does not duplicate the write', async () => {
  let reads = 0;
  const p = await signedIn({ reply: (url, options) => {
    if (url.startsWith('/api/ota/licenses?')) return ++reads === 1 ? { license } : reads === 2 ? { failure: 503 } : { license };
    if (url === '/api/ota/licenses' && options.method === 'POST') return { receipt: true };
    return {};
  } });
  await openLicense(p); await prepareGrant(p); await p.click('operation-confirm'); await p.click('operation-confirm');
  assert.equal(p.calls.filter(call => call.url === '/api/ota/licenses' && call.options.method === 'POST').length, 1);
  assert.equal(reads, 3);
});

test('registered device POST is not repeated when its following list refresh fails', async () => {
  let deviceReads = 0;
  const p = await signedIn({ devices: [], deviceReply: () => ++deviceReads === 2 ? { failure: 503 } : { devices: [] }, reply: (url, options) => {
    if (url === '/api/ota/devices' && options.method === 'POST') return { device };
    return {};
  } });
  await p.click('register-open');
  p.elements.get('edit-code').value = 'CORES3-NEW'; p.elements.get('edit-label').value = 'Nuevo equipo';
  await p.submit('operation-form'); await p.click('operation-confirm');
  assert.equal(p.calls.filter(call => call.url === '/api/ota/devices' && call.options.method === 'POST').length, 1);
  await p.click('operation-confirm');
  assert.equal(p.calls.filter(call => call.url === '/api/ota/devices' && call.options.method === 'POST').length, 1);
  assert.equal(deviceReads, 3);
});

test('PIN navigation compares the displayed code and uses only the canonical PIN route for approve and reject', async () => {
  const request = { request_id: 'abcdef1234567890abcdef1234567890', status: 'pending', device_label: 'Equipo PIN',
    device_code: 'CORES3-PIN', expires_at: 2000000000 };
  const methods = [];
  const p = await signedIn({ reply: (url, options) => {
    if (url === '/api/ota/pin') { methods.push(options.method || 'GET'); return options.method === 'POST' ? {} : { recoveries: [request] }; }
    return {};
  } });
  await p.click('nav-pin');
  const card = p.elements.get('requests').children[0]; await card.children[5].onclick(); await p.idle();
  p.elements.get('code').value = 'wrong-code'; await p.submit('decision-form');
  assert.equal(methods.filter(method => method === 'POST').length, 0);
  p.elements.get('code').value = request.request_id.slice(0, 12); await p.submit('decision-form');
  const approve = p.calls.find(call => call.url === '/api/ota/pin' && call.options.method === 'POST');
  assert.deepEqual(JSON.parse(approve.options.body), { request_id: request.request_id, action: 'approve' });
  await p.click('nav-pin');
  const rejectedCard = p.elements.get('requests').children[0]; await rejectedCard.children[7].onclick(); await p.idle();
  const writes = p.calls.filter(call => call.url === '/api/ota/pin' && call.options.method === 'POST').map(call => JSON.parse(call.options.body));
  assert.deepEqual(writes, [{ request_id: request.request_id, action: 'approve' }, { request_id: request.request_id, action: 'reject' }]);
  assert.equal(p.calls.every(call => !call.url.includes('scope_id=') || !call.url.includes('/api/ota/pin')), true);
});

test('scope and device labels remain textContent, never inserted as HTML', async () => {
  const payload = '<img src=x onerror=alert(1)>';
  const p = await signedIn({ scopes: [{ id: scopeId, name: payload, role: 'admin' }], devices: [{ ...device, label: payload }] });
  assert.equal(p.elements.get('scope-select').children[0].textContent, payload);
  const title = p.elements.get('devices').children[0].children[0].children[0];
  assert.equal(title.textContent, payload);
  assert.equal(title.innerHTML, undefined);
});

test('credential replacement includes CAS revision, credential id, and selected reason', async () => {
  const p = await signedIn({ reply: (url, options) => {
    if (url.startsWith('/api/ota/licenses?')) return { license };
    if (url === '/api/ota/licenses' && options.method === 'POST') return { receipt: true };
    return {};
  } });
  await openLicense(p);
  p.elements.get('license-action').value = 'replace_credential'; await p.click('action-open');
  p.elements.get('edit-fingerprint').value = 'b'.repeat(64); p.elements.get('edit-reason').value = 'compromised';
  await p.submit('operation-form'); await p.click('operation-confirm');
  const post = p.calls.find(call => call.url === '/api/ota/licenses' && call.options.method === 'POST');
  assert.deepEqual(JSON.parse(post.options.body), { device_id: deviceId, request_id: '00000000-0000-4000-8000-000000000001', action: 'replace_credential', expected_revision: 7, device_key_sha256: 'b'.repeat(64), expected_credential_id: credentialId, reason: 'compromised' });
});
