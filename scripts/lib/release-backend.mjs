import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const assert = (value, message) => { if (!value) throw new Error(message); };
const manifestPath = /^release(?:-(?:beta|dev))?\.json$/;
export const isOtaAsset = file => /^release[^/]*\.json$/.test(file) || /^(?:releases|public\/firmware)\/.+/.test(file);

export function immutableOtaInventory(workflow, base, commit) {
  const read = ref => workflow.entries(ref).filter(entry => isOtaAsset(entry.file)).map(entry => {
    assert(entry.type === 'blob' && /^100(644|755)$/.test(entry.mode), 'Unsafe OTA asset');
    const bytes = workflow.object(ref, entry.file);
    return { path: entry.file, mode: entry.mode, size: bytes.length, sha256: hash(bytes) };
  }).sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  const before = read(base), after = read(commit);
  assert(before.some(e => manifestPath.test(e.path)) && before.some(e => e.path.startsWith('public/firmware/')), 'Empty OTA manifest or binary inventory');
  assert(isDeepStrictEqual(before, after), 'Backend-only commit changes OTA assets');
  return before;
}

// One deadline covers headers and streaming body. Never allocate an unbounded
// arrayBuffer before checking size; abort and cancel the reader on every error.
async function readRemote(fetchImpl, url, limit, timeoutMs) {
  const controller = new AbortController();
  let timer, reader;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      controller.abort(); reject(new Error('Remote verification timed out'));
    }, timeoutMs);
  });
  try {
    const response = await Promise.race([fetchImpl(url, { redirect: 'error', cache: 'no-store', signal: controller.signal }), timeout]);
    assert(response.ok && !response.redirected, 'Remote response failed or redirected');
    if (response.url) assert(new URL(response.url).href === url.href, 'Remote response URL changed');
    const length = response.headers.get('content-length');
    assert(length === null || (/^\d+$/.test(length) && Number(length) <= limit), 'Remote response exceeds allowed size');
    assert(response.body?.getReader, 'Remote response has no bounded stream');
    reader = response.body.getReader();
    let count = 0;
    const chunks = [];
    while (true) {
      const { done, value } = await Promise.race([reader.read(), timeout]);
      if (done) break;
      count += value.byteLength;
      assert(count <= limit, 'Remote response exceeds allowed size');
      chunks.push(Buffer.from(value));
    }
    if (length !== null) assert(count === Number(length), 'Remote response length mismatch');
    return Buffer.concat(chunks, count);
  } finally {
    clearTimeout(timer); controller.abort();
    if (reader) { try { Promise.resolve(reader.cancel()).catch(() => {}); } catch {} }
  }
}

function sameOrigin(base, value) {
  assert(typeof value === 'string', 'Invalid remote URL');
  const target = new URL(value, base);
  assert(target.protocol === 'https:' && target.origin === base.origin && !target.username && !target.password && !target.hash && !target.search, 'Remote URL must have the same origin and no credentials/query/fragment');
  return target;
}

export async function verifyBackendRemote(baseUrl, manifests, binaries, { fetchImpl = fetch, timeoutMs = 30000 } = {}) {
  const base = new URL(baseUrl);
  assert(base.protocol === 'https:' && !base.username && !base.password && base.pathname === '/' && !base.search && !base.hash, 'Remote verification requires HTTPS origin');
  assert(Number.isSafeInteger(timeoutMs) && timeoutMs > 0 && timeoutMs <= 300000, 'Invalid verification timeout');
  assert(Array.isArray(manifests) && manifests.length > 0 && manifests.length <= 3 &&
    Array.isArray(binaries) && binaries.length > 0, 'Empty or invalid remote inventory');
  const files = new Map();
  for (const binary of binaries) {
    assert(/^public\/firmware\/[A-Za-z0-9_-][A-Za-z0-9_.-]*\.bin$/.test(binary.path) &&
      Number.isSafeInteger(binary.size) && binary.size > 0 && binary.size <= 16 * 1024 * 1024 &&
      /^[a-f0-9]{64}$/.test(binary.sha256) && !files.has(binary.path), 'Invalid binary inventory');
    files.set(binary.path, binary);
  }
  const channels = new Set();
  for (const manifest of manifests) {
    assert(manifestPath.test(manifest.path) && manifest.body && typeof manifest.body === 'object' &&
      !Array.isArray(manifest.body) && !channels.has(manifest.path), 'Invalid public manifest inventory');
    channels.add(manifest.path);
    const channel = manifest.path === 'release.json' ? 'stable' : manifest.path.slice(8, -5);
    const expected = manifest.body;
    assert(expected.channel === channel && expected.product === 'bomb-manager', 'Invalid manifest channel/product');
    const expectedUrl = sameOrigin(base, expected.firmware_url);
    const binary = files.get(`public${expectedUrl.pathname}`);
    // This exact inactive beta marker exists in the public base. Preserving a
    // backend deployment must neither invent its missing binary nor enable beta.
    const inactiveBeta = isDeepStrictEqual(expected, { product: 'bomb-manager', channel: 'beta',
      version: '0.0.0', firmware_url: '/firmware/bomb-manager-beta-placeholder.bin',
      sha256: 'REPLACE_WITH_PUBLISH_SCRIPT', size: 0, catalog_schema_version: 1 });
    assert(inactiveBeta || (binary && binary.sha256 === expected.sha256 && binary.size === expected.size), 'Manifest is not backed by preserved artifact');
    const bytes = await readRemote(fetchImpl, sameOrigin(base, `/api/releases/${channel}`), 65536, timeoutMs);
    let actual;
    try { actual = JSON.parse(bytes); } catch { throw new Error('Invalid remote manifest JSON'); }
    assert(actual && typeof actual === 'object' && !Array.isArray(actual), 'Invalid remote manifest');
    const actualUrl = sameOrigin(base, actual.firmware_url);
    assert(actualUrl.href === expectedUrl.href && isDeepStrictEqual(
      { ...actual, firmware_url: actualUrl.href }, { ...expected, firmware_url: expectedUrl.href }), 'Remote manifest does not match');
  }
  for (const binary of binaries) {
    const bytes = await readRemote(fetchImpl, sameOrigin(base, `/${binary.path.slice(7)}`), binary.size, timeoutMs);
    assert(bytes.length === binary.size && hash(bytes) === binary.sha256, 'Remote artifact does not match');
  }
  return { manifests: manifests.length, artifacts: binaries.length };
}
