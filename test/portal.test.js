import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { auth, portal } from './portal-helper.js';

test('forgot password sends only email to Auth with same-origin return and no account disclosure', async () => {
  const p = await portal();
  p.elements.get('email').value = 'operator@example.org';
  p.elements.get('password').value = 'must-be-cleared';
  await p.click('forgot-password');
  assert.equal(p.elements.get('password').value, '');
  assert.equal(p.elements.get('login').hidden, true);
  assert.equal(p.elements.get('password-recovery').hidden, false);
  await p.submit('recovery-form');
  const request = p.calls.at(-1);
  assert.equal(request.url, `${auth}/auth/v1/recover?redirect_to=https%3A%2F%2Fportal.example%2Fadmin%2F`);
  assert.deepEqual(JSON.parse(request.options.body), { email: 'operator@example.org' });
  assert.equal(request.options.headers.Authorization, undefined);
  assert.equal(request.options.redirect, 'error');
  assert.match(p.elements.get('status').textContent, /^Si la cuenta/);
  assert.equal(p.elements.get('workspace').hidden, true);
  await p.click('recovery-back');
  assert.equal(p.elements.get('login').hidden, false);
  assert.equal(p.elements.get('password-recovery').hidden, true);
});

test('recovery transport error permits retry and back without granting access', async () => {
  let attempts = 0;
  const p = await portal({ reply: () => { if (++attempts === 1) throw new Error('Offline'); return {}; } });
  await p.click('forgot-password');
  p.elements.get('recovery-email').value = 'operator@example.org';
  await p.submit('recovery-form');
  assert.equal(p.elements.get('status').textContent, 'Offline');
  assert.equal(p.elements.get('recovery-back').disabled, false);
  await p.submit('recovery-form');
  assert.equal(attempts, 2);
  assert.equal(p.elements.get('workspace').hidden, true);
});

test('verified recovery updates password then requires fresh login without listing PIN requests', async () => {
  const p = await portal({ hash: '#type=recovery&access_token=fixture-token&refresh_token=never-use',
    reply: () => ({ id: 'user', is_anonymous: false }) });
  assert.equal(p.historyCalls[0][2], '/admin/');
  assert.equal(vm.runInContext('incoming.size', p.context), 0);
  assert.equal(p.elements.get('activation').hidden, false);
  assert.equal(p.elements.get('workspace').hidden, true);
  p.elements.get('new-password').value = 'synthetic-password';
  p.elements.get('repeat-password').value = 'different-password';
  await p.submit('activation-form');
  assert.equal(p.calls.length, 2);
  p.elements.get('repeat-password').value = 'synthetic-password';
  await p.submit('activation-form');
  assert.equal(p.calls.at(-1).options.method, 'PUT');
  assert.equal(p.calls.at(-1).options.headers.Authorization, 'Bearer fixture-token');
  assert.equal(p.elements.get('new-password').value, '');
  assert.equal(p.elements.get('login').hidden, false);
  assert.equal(vm.runInContext('token', p.context), '');
  assert.equal(p.calls.some(c => c.url === '/api/ota/pin'), false);
});

test('expired or invalid links leave login available and release URL tokens', async () => {
  for (const hash of ['#error=access_denied&error_code=otp_expired', '#type=recovery&access_token=bad&refresh_token=discard']) {
    const p = await portal({ hash, reply: () => ({ failure: 401 }) });
    assert.equal(p.elements.get('login').hidden, false);
    assert.equal(p.elements.get('workspace').hidden, true);
    assert.equal(vm.runInContext('incoming.size', p.context), 0);
    assert.equal(vm.runInContext('token', p.context), '');
    await p.click('forgot-password');
    assert.equal(p.elements.get('password-recovery').hidden, false);
  }
});

test('cancel verified link clears session and never changes password', async () => {
  const p = await portal({ hash: '#type=recovery&access_token=fixture-token', reply: () => ({ id: 'user' }) });
  await p.click('activation-back');
  assert.equal(vm.runInContext('token', p.context), '');
  assert.equal(p.elements.get('login').hidden, false);
  assert.equal(p.calls.filter(c => c.options.method === 'PUT').length, 0);
});

test('anonymous or malformed users never open recovery or retain a token', async () => {
  for (const user of [{ id: 'user', is_anonymous: true }, {}, null]) {
    const p = await portal({ hash: '#type=recovery&access_token=fixture-token', reply: () => user });
    assert.equal(p.elements.get('activation').hidden, true);
    assert.equal(p.elements.get('workspace').hidden, true);
    assert.equal(p.elements.get('login').hidden, false);
    assert.equal(vm.runInContext('token', p.context), '');
    assert.equal(vm.runInContext('incoming.size', p.context), 0);
  }
});

test('password update rejected by Auth clears session and returns to login', async () => {
  const p = await portal({ hash: '#type=recovery&access_token=fixture-token',
    reply: (_url, options) => options.method === 'PUT' ? { failure: 401 } : { id: 'user' } });
  p.elements.get('new-password').value = p.elements.get('repeat-password').value = 'synthetic-password';
  await p.submit('activation-form');
  assert.equal(p.elements.get('workspace').hidden, true);
  assert.equal(p.elements.get('activation').hidden, true);
  assert.equal(p.elements.get('login').hidden, false);
  assert.equal(vm.runInContext('token', p.context), '');
  assert.equal(p.elements.get('new-password').value, '');
});

test('invitation still verifies, sets password and loads authorized device context', async () => {
  const scope = '10000000-0000-0000-0000-000000000001';
  const p = await portal({ hash: '#type=invite&access_token=fixture-token', reply: url => {
    if (url.includes('action=context')) return { scopes: [{ id: scope, name: 'Fixture', role: 'admin' }] };
    if (url.startsWith('/api/ota/devices?scope_id=')) return { devices: [] };
    return { id: 'user' };
  } });
  p.elements.get('new-password').value = p.elements.get('repeat-password').value = 'synthetic-password';
  await p.submit('activation-form');
  assert.equal(p.elements.get('workspace').hidden, false);
  assert.match(p.calls.at(-1).url, /^\/api\/ota\/devices\?scope_id=/);
});
