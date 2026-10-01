import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { immutableOtaInventory, isOtaAsset, verifyBackendRemote } from '../scripts/lib/release-backend.mjs';
const sha = x => createHash('sha256').update(x).digest('hex');
test('OTA inventory rejects changes, additions and removals', () => {
  const records = { base: { 'release.json': 'm', 'releases/x.json': 'd', 'public/firmware/x.bin': 'b' }, next: { 'release.json': 'm', 'releases/x.json': 'd', 'public/firmware/x.bin': 'b', 'api/a.js': 'code' } };
  const w = { entries: ref => Object.keys(records[ref]).map(file => ({ file, type: 'blob', mode: '100644' })), object: (ref, file) => Buffer.from(records[ref][file]) };
  assert.equal(immutableOtaInventory(w, 'base', 'next').length, 3); records.next['release.json'] = 'changed'; assert.throws(() => immutableOtaInventory(w, 'base', 'next'));
  assert.equal(isOtaAsset('public/firmware/x.bin'), true); assert.equal(isOtaAsset('api/x.js'), false);
});
test('remote verifier checks same-origin manifest and all binaries', async () => {
  const bin = Buffer.from('bin'), manifest = { product: 'bomb-manager', channel: 'stable', version: '1.0.0', sha256: sha(bin), size: 3, firmware_url: '/firmware/x.bin' };
  const entry = { path: 'release.json', body: manifest };
  await verifyBackendRemote('https://candidate.test', [entry], [{ path: 'public/firmware/x.bin', size: 3, sha256: sha(bin) }], { fetchImpl: async url => new Response(String(url).includes('/api/') ? JSON.stringify(manifest) : bin, { status: 200 }), timeoutMs: 100 });
  await assert.rejects(verifyBackendRemote('https://candidate.test', [entry], [{ path: 'public/firmware/x.bin', size: 3, sha256: sha(bin) }], { fetchImpl: async url => new Response(String(url).includes('/api/') ? JSON.stringify({ ...manifest, firmware_url: 'https://other.test/x' }) : bin, { status: 200 }) }), /same origin/);
});
test('remote verifier rejects transformed manifests and bounded failures', async () => {
  const bin = Buffer.from('bin'), body = { product: 'bomb-manager', channel: 'stable', version: '1.0.0', sha256: sha(bin), size: 3, catalog_schema_version: 1, firmware_url: '/firmware/x.bin' }, entry = { path: 'release.json', body };
  const binaries = [{ path: 'public/firmware/x.bin', size: 3, sha256: sha(bin) }];
  for (const actual of [{ ...body, firmware_url: '/firmware/other.bin' }, { ...body, catalog_schema_version: 2 }, { ...body, extra: true }]) {
    let calls = 0;
    await assert.rejects(verifyBackendRemote('https://candidate.test', [entry], binaries, { fetchImpl: async url => { calls++; return new Response(String(url).includes('/api/') ? JSON.stringify(actual) : bin); }, timeoutMs: 20 }));
    assert.equal(calls, 1);
  }
  const stalled = new ReadableStream({ pull: () => new Promise(() => {}) });
  await assert.rejects(verifyBackendRemote('https://candidate.test', [entry], binaries, { fetchImpl: async url => new Response(String(url).includes('/api/') ? stalled : bin), timeoutMs: 20 }), /timed out/);
});
test('inventory freezes all OTA paths and denies empty sets', () => {
  assert.equal(isOtaAsset('release-custom.json'), true);
  const w = { entries: () => [], object: () => Buffer.alloc(0) };
  assert.throws(() => immutableOtaInventory(w, 'base', 'next'));
});

function remoteFixture() {
  const bytes = Buffer.from('bin');
  const body = { product: 'bomb-manager', channel: 'stable', version: '1.0.0',
    sha256: sha(bytes), size: bytes.length, catalog_schema_version: 1, firmware_url: '/firmware/x.bin' };
  return { bytes, manifests: [{ path: 'release.json', body }],
    binaries: [{ path: 'public/firmware/x.bin', size: bytes.length, sha256: sha(bytes) }] };
}

test('header deadline aborts even when transport ignores the AbortSignal', async () => {
  const f = remoteFixture(); let signal;
  await assert.rejects(verifyBackendRemote('https://candidate.test', f.manifests, f.binaries, {
    timeoutMs: 20, fetchImpl: (_url, options) => { signal = options.signal; return new Promise(() => {}); }
  }), /timed out/);
  assert.equal(signal.aborted, true);
});

test('oversized streaming response is cancelled before buffering subsequent chunks', async () => {
  const f = remoteFixture(); let cancelled = false;
  const stream = new ReadableStream({ start(controller) { controller.enqueue(new Uint8Array(65537)); },
    cancel() { cancelled = true; } });
  await assert.rejects(verifyBackendRemote('https://candidate.test', f.manifests, f.binaries, {
    timeoutMs: 100, fetchImpl: async () => new Response(stream)
  }), /exceeds allowed size/);
  assert.equal(cancelled, true);
});

test('redirect responses fail without following or requesting another origin', async () => {
  const f = remoteFixture(); let calls = 0;
  await assert.rejects(verifyBackendRemote('https://candidate.test', f.manifests, f.binaries, {
    fetchImpl: async (_url, options) => {
      ++calls; assert.equal(options.redirect, 'error');
      return new Response('', { status: 302, headers: { location: 'https://other.test/secret' } });
    }
  }), /failed or redirected/);
  assert.equal(calls, 1);
});

test('all historical binaries are downloaded and corrupt bytes cannot pass', async () => {
  const f = remoteFixture(), history = Buffer.from('older');
  f.binaries.push({ path: 'public/firmware/history.bin', size: history.length, sha256: sha(history) });
  const requested = [];
  const fetchImpl = async url => {
    const path = new URL(url).pathname; requested.push(path);
    return new Response(path.startsWith('/api/') ? JSON.stringify(f.manifests[0].body) : path.endsWith('history.bin') ? history : f.bytes);
  };
  await verifyBackendRemote('https://candidate.test', f.manifests, f.binaries, { fetchImpl });
  assert.deepEqual(requested, ['/api/releases/stable', '/firmware/x.bin', '/firmware/history.bin']);
  await assert.rejects(verifyBackendRemote('https://candidate.test', f.manifests, f.binaries, {
    fetchImpl: async url => String(url).endsWith('history.bin') ? new Response('wrong') : fetchImpl(url)
  }), /artifact does not match/);
});

test('inventory detects added, removed, mode-changed and unknown-channel OTA files', () => {
  const original = { 'release.json': 'm', 'release-custom.json': 'custom', 'releases/x.json': 'provenance', 'public/firmware/x.bin': 'bin' };
  for (const file of Object.keys(original)) {
    for (const kind of ['add', 'remove', 'change', 'mode']) {
      const next = { ...original };
      if (kind === 'add') next['public/firmware/new.bin'] = 'new';
      if (kind === 'remove') delete next[file];
      if (kind === 'change') next[file] += 'x';
      const w = { entries: ref => Object.keys(ref === 'base' ? original : next).map(name => ({ file: name, type: 'blob',
        mode: ref === 'next' && name === file && kind === 'mode' ? '100755' : '100644' })),
        object: (ref, name) => Buffer.from((ref === 'base' ? original : next)[name]) };
      assert.throws(() => immutableOtaInventory(w, 'base', 'next'), /changes OTA assets/);
    }
  }
});

test('the exact legacy inactive beta marker is preserved without requesting a fabricated binary', async () => {
  const f = remoteFixture();
  const beta = { product: 'bomb-manager', channel: 'beta', version: '0.0.0',
    firmware_url: '/firmware/bomb-manager-beta-placeholder.bin', sha256: 'REPLACE_WITH_PUBLISH_SCRIPT',
    size: 0, catalog_schema_version: 1 };
  f.manifests.push({ path: 'release-beta.json', body: beta });
  const requests = [];
  const fetchImpl = async url => {
    const path = new URL(url).pathname; requests.push(path);
    const body = path.endsWith('/beta') ? beta : f.manifests[0].body;
    return new Response(path.startsWith('/api/') ? JSON.stringify(body) : f.bytes);
  };
  await verifyBackendRemote('https://candidate.test', f.manifests, f.binaries, { fetchImpl });
  assert.deepEqual(requests, ['/api/releases/stable', '/api/releases/beta', '/firmware/x.bin']);
  for (const change of [{ version: '1.0.0' }, { sha256: '0'.repeat(64) }, { size: 1 }]) {
    await assert.rejects(verifyBackendRemote('https://candidate.test',
      [{ path: 'release-beta.json', body: { ...beta, ...change } }], f.binaries, { fetchImpl }), /not backed/);
  }
});
