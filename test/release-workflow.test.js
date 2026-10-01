import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { ReleaseWorkflow, parseEnvironmentNames, serviceFile, checkTarget, run } from '../scripts/lib/release-workflow.mjs';
import { verifyRemote } from '../scripts/lib/release-artifact.mjs';

const sha = b => createHash('sha256').update(b).digest('hex');
const target = { project_id: 'prj_fixture', team_id: 'team_fixture', public_url: 'https://ota.example.test', previous_deployment: 'dpl_previous', base_ref: 'refs/tags/public-base' };
const git = (dir, ...args) => execFileSync('git', args, { cwd: dir, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
function repoAt(dir) {
  fs.mkdirSync(dir); git(dir, 'init'); git(dir, 'config', 'user.email', 'fixture@example.test'); git(dir, 'config', 'user.name', 'Fixture');
}

async function backendFixture(t) {
  const f = await fixture(t, { backend: true });
  f.id = `backend-${f.head}`;
  git(f.repo, 'tag', 'backend-source'); git(f.repo, 'push', 'origin', 'refs/tags/backend-source');
  return f;
}

test('backend-only uses immutable source commit, preserves all OTA bytes and working edits', async t => {
  const f = await backendFixture(t), w = f.workflow;
  fs.writeFileSync(path.join(f.repo, 'staged.txt'), 'keep'); git(f.repo, 'add', 'staged.txt');
  const before = git(f.repo, 'status', '--porcelain');
  const first = await w.prepareBackend(f.head, 'backend-source', target);
  assert.equal(first.mode, 'backend'); assert.equal(first.descriptor, undefined);
  assert.equal((await w.prepareBackend(f.head, 'backend-source', target)).input_hash, first.input_hash);
  const result = await w.gitPublish(first.id);
  assert.equal(result.commit, f.head);
  assert.equal(git(f.repo, 'rev-parse', 'HEAD'), f.head);
  assert.equal(git(f.repo, 'status', '--porcelain').replace('?? .ota-release/\n', ''), before);
  assert.equal((await w.gitPublish(first.id)).commit, result.commit);
  assert.ok(result.ota_inventory.some(e => e.path === 'releases/stable/old.json'));
  await w.deploy(first.id);
  assert.equal(w.load(first.id).package.find(e => e.path === 'release.json').sha256,
    result.ota_inventory.find(e => e.path === 'release.json').sha256);
});

test('backend-only rejects changed, added, deleted OTA files before creating state or release refs', async t => {
  for (const mutation of ['manifest', 'binary', 'provenance', 'added', 'deleted']) {
    const f = await backendFixture(t), w = f.workflow;
    const file = path.join(f.repo, mutation === 'manifest' ? 'release.json' : mutation === 'provenance' ? 'releases/stable/old.json' : mutation === 'added' ? 'public/firmware/new.bin' : 'public/firmware/old.bin');
    if (mutation === 'deleted') fs.unlinkSync(file); else fs.writeFileSync(file, 'different');
    git(f.repo, 'add', 'release.json', 'releases', 'public'); git(f.repo, 'commit', '-m', mutation);
    const changed = git(f.repo, 'rev-parse', 'HEAD'); git(f.repo, 'tag', 'changed-source');
    await assert.rejects(w.prepareBackend(changed, 'changed-source', target));
    assert.equal(fs.existsSync(w.root), false);
    assert.equal(w.remoteRef(`refs/tags/backend/${changed}`), null);
  }
});

test('backend-only reconciles uncertain deployment, verifies protected and public bytes without a firmware receipt', async t => {
  const f = await backendFixture(t), w = f.workflow;
  await w.prepareBackend(f.head, 'backend-source', target); await w.gitPublish(f.id);
  f.failDeploy = true; await assert.rejects(w.deploy(f.id), /response lost/);
  await assert.rejects(w.deploy(f.id), /reconcile/); assert.equal(f.deploys, 1);
  await w.reconcile(f.id, 'dpl_candidate');
  const requests = [];
  const fetcher = async (url, options) => {
    const u = new URL(url); requests.push({ origin: u.origin, headers: new Headers(options?.headers) });
    return new Response(u.pathname.startsWith('/api/releases/') ?
      w.object(f.head, 'release.json') : w.object(f.head, 'public/firmware/old.bin'));
  };
  w.candidateBypass = 'synthetic-bypass'; w.fetchImpl = fetcher;
  await w.verifyCandidate(f.id);
  const priorFetch = globalThis.fetch; globalThis.fetch = fetcher;
  try {
    f.failPromote = true; await assert.rejects(w.promote(f.id), /promotion response lost/);
    assert.equal((await w.promote(f.id)).phase, 'public-verified');
  } finally { globalThis.fetch = priorFetch; }
  assert.equal(f.promotions, 1); assert.equal(f.deploys, 1);
  for (const request of requests) assert.equal(request.headers.get('x-vercel-protection-bypass'),
    request.origin === 'https://candidate.vercel.app' ? 'synthetic-bypass' : null);
  await assert.rejects(w.accept(f.id, {}), /no firmware installation receipt/);
});

test('bypass secret is removed from every subprocess including explicit Git environments', t => {
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), 'ota-secret-env-'));
  t.after(() => fs.rmSync(repo, { recursive: true, force: true }));
  const prior = process.env.BOMB_OTA_CANDIDATE_BYPASS;
  process.env.BOMB_OTA_CANDIDATE_BYPASS = 'synthetic-private-value';
  try {
    let count = 0;
    const w = new ReleaseWorkflow({ repo, command: (_file, _args, options) => {
      assert.equal(options.env.BOMB_OTA_CANDIDATE_BYPASS, undefined); ++count; return '';
    } });
    w.git(['status']); w.command('vercel', ['deploy']);
    w.git(['read-tree'], { env: { ...process.env, GIT_INDEX_FILE: '/tmp/fixture-index' } });
    assert.equal(count, 3);
  } finally {
    if (prior === undefined) delete process.env.BOMB_OTA_CANDIDATE_BYPASS;
    else process.env.BOMB_OTA_CANDIDATE_BYPASS = prior;
  }
});

test('backend CLI can plan without a firmware checkout and requires a remotely verified source tag', async t => {
  const f = await backendFixture(t), w = f.workflow;
  const targetFile = path.join(f.repo, 'target-fixture.json');
  fs.writeFileSync(targetFile, JSON.stringify(target));
  const result = JSON.parse(execFileSync(process.execPath, [fileURLToPath(new URL('../scripts/ota-release.mjs', import.meta.url)),
    'plan-backend', '--repo', f.repo, '--commit', f.head, '--source-tag', 'backend-source', '--target', targetFile], { encoding: 'utf8' }));
  assert.equal(result.id, f.id); assert.equal(fs.existsSync(w.root), false);
  await w.prepareBackend(f.head, 'backend-source', target);
  git(f.repo, 'push', 'origin', ':refs/tags/backend-source');
  await assert.rejects(w.gitPublish(f.id), /source tag is not verified remotely/);
  assert.equal(w.remoteRef(`refs/tags/backend/${f.head}`), null);
  assert.equal(w.load(f.id).phase, 'prepared');
});

test('environment metadata parsing failures cannot expose provider values', async t => {
  const f = await fixture(t), w = f.workflow;
  w.api = () => { throw new Error('provider malformed JSON includes synthetic-env-secret'); };
  assert.throws(() => w.assertEnvironment({ target }), error =>
    /metadata is unavailable/.test(error.message) && !error.message.includes('synthetic-env-secret'));
});
async function fixture(t, { backend = false } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ota-workflow-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const repo = path.join(root, 'backend'), firmware = path.join(root, 'firmware');
  repoAt(repo); repoAt(firmware);
  fs.writeFileSync(path.join(repo, 'package.json'), '{}'); fs.writeFileSync(path.join(repo, 'vercel.json'), '{}');
  fs.mkdirSync(path.join(repo, 'api')); fs.writeFileSync(path.join(repo, 'api/health.js'), 'export default {};');
  fs.writeFileSync(path.join(repo, '.env.local'), 'PRIVATE_FIXTURE');
  if (backend) {
    const bytes = Buffer.from('preserved old firmware');
    fs.mkdirSync(path.join(repo, 'public/firmware'), { recursive: true });
    fs.writeFileSync(path.join(repo, 'public/firmware/old.bin'), bytes);
    fs.writeFileSync(path.join(repo, 'release.json'), JSON.stringify({ product: 'bomb-manager',
      channel: 'stable', version: '1.2.2', firmware_url: '/firmware/old.bin', sha256: sha(bytes), size: bytes.length, catalog_schema_version: 1 }));
    fs.mkdirSync(path.join(repo, 'releases/stable'), { recursive: true });
    fs.writeFileSync(path.join(repo, 'releases/stable/old.json'), '{"provenance":"unchanged"}');
    git(repo, 'add', 'release.json', 'public', 'releases');
  }
  git(repo, 'add', 'package.json', 'vercel.json', 'api'); git(repo, 'commit', '-m', 'public base');
  const base = git(repo, 'rev-parse', 'HEAD');
  git(repo, 'tag', 'public-base');
  // Current feature branch contains an API not approved for production.
  fs.writeFileSync(path.join(repo, 'api/feature.js'), 'export default {};'); git(repo, 'add', 'api'); git(repo, 'commit', '-m', 'feature');
  fs.writeFileSync(path.join(repo, 'user-work.txt'), 'preserve');
  fs.writeFileSync(path.join(firmware, 'source.cpp'), 'source'); git(firmware, 'add', '.'); git(firmware, 'commit', '-m', 'source');
  const source = git(firmware, 'rev-parse', 'HEAD'); git(firmware, 'tag', 'fixture-v1');
  for (const [local, name] of [[repo, 'remote.git'], [firmware, 'firmware.git']]) {
    git(root, 'init', '--bare', name); git(local, 'remote', 'add', 'origin', path.join(root, name)); git(local, 'push', 'origin', 'HEAD');
  }
  git(firmware, 'push', 'origin', 'refs/tags/fixture-v1');
  git(repo, 'push', 'origin', 'refs/tags/public-base');
  const bytes = Buffer.from('test image bytes');
  const provenance = { schema_version: 1, product: 'bomb-manager', model: 'cores3', version: '1.2.3', environment: 'core_s3', compiled_channel: 'stable',
    source: { commit: source, dirty: false }, artifact: { size: bytes.length, sha256: sha(bytes) }, compatibility: { partition_sha256: 'b'.repeat(64), catalog_schema_version: 1 }, build: { radio_provisioned: false, pin_recovery: false } };
  const pb = JSON.stringify(provenance);
  fs.writeFileSync(path.join(root, 'firmware.bin'), bytes); fs.writeFileSync(path.join(root, 'provenance.json'), pb);
  const descriptor = { ...provenance, channel: 'stable', source: { commit: source, tag: 'fixture-v1' }, backend: { base_commit: base },
    artifact: { ...provenance.artifact, path: 'firmware.bin' }, provenance: { path: 'provenance.json', sha256: sha(pb) }, evidence: { build: 'fixture', tests: 'fixture' } };
  const descriptorPath = path.join(root, 'descriptor.json'); fs.writeFileSync(descriptorPath, JSON.stringify(descriptor));
  const f = { repo, firmware, descriptorPath, descriptor, head: git(repo, 'rev-parse', 'HEAD'), current: 'dpl_previous', deploys: 0, promotions: 0, verified: [], failDeploy: false, failPromote: false,
    environment: { envs: ['OTA_ADMIN_ENABLED', 'OTA_DEVICE_REALM', 'OTA_GATEWAY_DATABASE_CA', 'OTA_GATEWAY_DATABASE_URL', 'OTA_PIN_RECOVERY_ENABLED', 'SUPABASE_PUBLISHABLE_KEY', 'SUPABASE_URL'].map(key => ({ key, target: ['production'] })) } };
  f.command = (file, args, options) => {
    if (file === 'git') {
      const result = run(file, args, options);
      if (f.failUnlock && args[0] === 'push' && args.some(a => a.startsWith(':refs/tags/ota-lock-'))) {
        f.failUnlock = false; throw new Error('unlock response lost');
      }
      return result;
    }
    assert.equal(file, 'vercel-fixture');
    if (args[0] === 'api' && args[1].startsWith('/v10/projects/')) {
      f.environmentChecks = (f.environmentChecks || 0) + 1;
      assert.match(args[1], /\/env\?decrypt=false&teamId=team_fixture$/);
      return JSON.stringify(f.environment);
    }
    const s = f.workflow.load(f.id || 'stable-1.2.3');
    const deployed = { id: 'dpl_candidate', projectId: s.target.project_id, url: 'candidate.vercel.app', target: 'production', readyState: 'READY', meta: { bombRelease: s.input_hash, bombCommit: s.commit } };
    if (args[0] === 'api') {
      if (args[1].includes('ota.example.test')) return JSON.stringify(f.current === 'dpl_candidate' ? deployed : { id: f.current, projectId: s.target.project_id, meta: { bombCommit: f.wrongBase ? f.head : base } });
      return JSON.stringify(deployed);
    }
    if (args[0] === 'deploy') {
      f.deploys++; assert(args.includes('--skip-domain'));
      assert(!fs.existsSync(path.join(options.cwd, '.env.local')));
      assert.equal(fs.existsSync(path.join(options.cwd, 'api/feature.js')), backend);
      if (f.failDeploy) throw new Error('response lost');
      return JSON.stringify({ deployment: { id: 'dpl_candidate' } });
    }
    if (args[0] === 'promote') { f.promotions++; f.current = 'dpl_candidate'; if (f.failPromote) throw new Error('promotion response lost'); return ''; }
    throw new Error('Unexpected command');
  };
  f.workflow = new ReleaseWorkflow({ repo, firmwareRepo: firmware, vercel: 'vercel-fixture', command: f.command, verify: async url => { f.verified.push(url); return {}; } });
  return f;
}

test('prepare and Git preserve current branch, staged user edits and feature API; retries retain commit', async t => {
  const f = await fixture(t), w = f.workflow;
  fs.writeFileSync(path.join(f.repo, 'staged.txt'), 'keep'); git(f.repo, 'add', 'staged.txt');
  const before = git(f.repo, 'status', '--porcelain');
  const first = await w.prepare(f.descriptorPath, target);
  assert.equal((await w.prepare(f.descriptorPath, target)).input_hash, first.input_hash);
  const pushed = await w.gitPublish(first.id);
  assert.equal(git(f.repo, 'rev-parse', 'HEAD'), f.head);
  assert.equal(git(f.repo, 'diff', '--cached', '--name-only'), 'staged.txt');
  assert.equal(fs.readFileSync(path.join(f.repo, 'user-work.txt'), 'utf8'), 'preserve');
  assert(!w.entries(pushed.commit).some(e => e.file === 'api/feature.js'));
  assert.equal((await w.gitPublish(first.id)).commit, pushed.commit);
  assert.equal(git(f.repo, 'status', '--porcelain').replace('?? .ota-release/\n', ''), before);
});

test('deployment response loss never triggers another deployment; reconcile and promote exact candidate', async t => {
  const f = await fixture(t), w = f.workflow;
  const { id } = await w.prepare(f.descriptorPath, target); await w.gitPublish(id);
  f.failDeploy = true; await assert.rejects(w.deploy(id), /response lost/);
  await assert.rejects(w.deploy(id), /reconcile/); assert.equal(f.deploys, 1);
  await w.reconcile(id, 'dpl_candidate'); await w.verifyCandidate(id);
  f.failPromote = true; await assert.rejects(w.promote(id), /response lost/);
  assert.equal(w.load(id).phase, 'promotion-uncertain');
  const final = await w.promote(id); assert.equal(f.promotions, 1); assert.equal(final.phase, 'public-verified');
  assert.equal((await w.gitPublish(id)).phase, 'public-verified');
  assert.equal(w.remoteRef(`refs/tags/ota-lock-${target.project_id}`), null);
  assert.equal(final.installation.length, 0);
  await assert.rejects(w.cancel(id), /cannot revert/);
});

test('another project lock holder or changed public alias blocks deployment', async t => {
  const f = await fixture(t), w = f.workflow;
  const { id } = await w.prepare(f.descriptorPath, target); await w.gitPublish(id);
  git(f.repo, 'push', 'origin', `${f.head}:refs/tags/ota-lock-${target.project_id}`);
  await assert.rejects(w.deploy(id), /Another release/); assert.equal(f.deploys, 0);
  git(f.repo, 'push', 'origin', `:refs/tags/ota-lock-${target.project_id}`);
  f.current = 'dpl_changed'; await assert.rejects(w.deploy(id), /Public deployment changed/); assert.equal(f.deploys, 0);
});

test('failed bytes verification prevents promotion and physical evidence needs explicit checks', async t => {
  const f = await fixture(t), w = f.workflow;
  const { id } = await w.prepare(f.descriptorPath, target); await w.gitPublish(id); await w.deploy(id);
  w.verify = async () => { throw new Error('wrong bytes'); };
  await assert.rejects(w.verifyCandidate(id), /Candidate verification failed/);
  await assert.rejects(w.promote(id), /Verify candidate/); assert.equal(f.promotions, 0);
  await assert.rejects(w.accept(id, {}), /verification required/);
});

test('package allowlist and target reject private paths and ambiguous destinations', () => {
  for (const file of ['api/releases/[channel].js', 'public/admin/index.html', 'public/admin/portal.js', 'public/admin/portal.css']) assert.equal(serviceFile(file), true);
  for (const file of ['public/admin/.env', 'public/admin/token.json', 'public/admin/session.js', 'public/admin/../secrets.js']) assert.equal(serviceFile(file), false);
  for (const file of ['.env.local', '.vercel/project.json', 'config/private.json', 'supabase/migrations/one.sql', 'README.md', 'scripts/secret.js']) assert.equal(serviceFile(file), false);
  assert.throws(() => checkTarget({ ...target, public_url: 'https://user:secret@example.test' }), /HTTPS origin/);
  assert.throws(() => checkTarget({ ...target, token: 'fixture' }), /fields/);
  assert.throws(() => checkTarget({ ...target, required_env: ['OTA_ADMIN_ENABLED'] }), /closed portal/);
  assert.deepEqual([...parseEnvironmentNames({ envs: [{ key: 'OTA_ADMIN_ENABLED', target: ['production'] }, { key: 'SUPABASE_URL', target: ['preview', 'production'] }] })], ['OTA_ADMIN_ENABLED', 'SUPABASE_URL']);
  assert.throws(() => parseEnvironmentNames({ envs: [{ key: 'OTA_ADMIN_ENABLED', target: ['other'] }] }), /unexpected format/);
  assert.deepEqual([...parseEnvironmentNames({ envs: [
    { key: 'OTA_ADMIN_ENABLED', target: 'production' }, { key: 'custom_scope_var', customEnvironmentIds: ['custom'] }
  ] })], ['OTA_ADMIN_ENABLED']);
});

test('every target requires all seven production environment names before deploy intent', async t => {
  const f = await fixture(t), w = f.workflow;
  const names = f.environment.envs.map(entry => entry.key);
  for (const name of names) {
    f.environment = { envs: names.filter(entry => entry !== name).map(key => ({ key, target: ['production'] })) };
    assert.throws(() => w.assertEnvironment({ target }), /Required production environment is incomplete/);
    f.environment = { envs: names.map(key => ({ key, target: [key === name ? 'preview' : 'production'] })) };
    assert.throws(() => w.assertEnvironment({ target }), /Required production environment is incomplete/);
  }
  f.environment = { envs: names.map(key => ({ key, target: ['production'] })) };
  assert.doesNotThrow(() => w.assertEnvironment({ target: { ...target, project_id: 'prj_other' } }));
  const { id } = await w.prepare(f.descriptorPath, target); await w.gitPublish(id);
  f.environment = { envs: names.filter(key => key !== names[0]).map(key => ({ key, target: ['production'] })) };
  await assert.rejects(w.deploy(id), /Required production environment is incomplete/);
  assert.equal(f.deploys, 0); assert.equal(f.environmentChecks, 16);
  const state = w.load(id); assert.equal(state.deploy_intent, undefined); assert.equal(state.phase, 'git-verified');
});

test('candidate bypass uses verifyRemote for protected manifest and artifact only', async t => {
  const f = await fixture(t), w = f.workflow;
  const { id } = await w.prepare(f.descriptorPath, target); await w.gitPublish(id); await w.deploy(id);
  const requests = [];
  w.candidateBypass = 'fixture-secret';
  const bytes = Buffer.from('test image bytes');
  w.fetchImpl = async (url, options) => {
    requests.push({ url: String(url), options });
    if (String(url).includes('/api/releases/stable')) return new Response(JSON.stringify({ product: 'bomb-manager', channel: 'stable', version: '1.2.3', firmware_url: '/firmware/bomb-manager-1.2.3.bin', sha256: sha(bytes), size: bytes.length, catalog_schema_version: 1 }), { status: 200 });
    return new Response(bytes, { status: 200, headers: { 'content-length': String(bytes.length) } });
  };
  w.verify = verifyRemote;
  await w.verifyCandidate(id);
  assert.equal(requests.length, 2);
  for (const request of requests) {
    assert.equal(request.options.headers.get('x-vercel-protection-bypass'), 'fixture-secret');
    assert.equal(request.options.redirect, 'error');
  }
  assert.throws(() => w.candidateFetch(w.load(id))('https://other.example.test/file.bin', {}), /exact deployment origin/);
  f.current = 'dpl_candidate';
  let publicArguments;
  w.verify = async (...arguments_) => { publicArguments = arguments_; };
  await w.verifyPublic(id);
  assert.equal(publicArguments.length, 2);
});

test('candidate verification redacts malformed and secret-marked failures without state mutation', async t => {
  const f = await fixture(t), w = f.workflow;
  const { id } = await w.prepare(f.descriptorPath, target); await w.gitPublish(id); await w.deploy(id);
  w.candidateBypass = 'secret-marker';
  w.fetchImpl = async () => { throw new Error('secret-marker malformed response'); };
  w.verify = verifyRemote;
  await assert.rejects(w.verifyCandidate(id), error => error.message === 'Candidate verification failed');
  const state = w.load(id); assert.equal(state.candidate_verified, undefined); assert.equal(state.phase, 'deployed');
  w.candidateBypass = 'bad\nsecret-marker';
  await assert.rejects(w.verifyCandidate(id), error => error.message === 'Candidate verification failed');
  assert.equal(w.load(id).candidate_verified, undefined);
});

test('unpublished or wrong deployment base is rejected before Git ref creation', async t => {
  const f = await fixture(t), w = f.workflow;
  const { id } = await w.prepare(f.descriptorPath, target);
  f.wrongBase = true; await assert.rejects(w.gitPublish(id), /Deployment provenance/);
  assert.equal(w.load(id).commit, undefined);
  f.wrongBase = false;
  git(f.repo, 'push', 'origin', ':refs/tags/public-base');
  await assert.rejects(w.gitPublish(id), /base tag/);
  assert.equal(w.load(id).commit, undefined);
});

test('lost unlock response resumes public verification without repeat promotion', async t => {
  const f = await fixture(t), w = f.workflow;
  const { id } = await w.prepare(f.descriptorPath, target); await w.gitPublish(id);
  await w.deploy(id); await w.verifyCandidate(id); f.failUnlock = true;
  await assert.rejects(w.promote(id), /unlock response lost/);
  assert.equal(w.load(id).phase, 'public-verified');
  assert.equal((await w.verifyPublic(id)).phase, 'public-verified');
  assert.equal(f.promotions, 1);
  const accepted = await w.accept(id, { device: 'fixture-device', previous: '1.2.2', observed: '1.2.3', source: 'operator', checks: 'version,configuration,identity,functions' });
  assert.equal(accepted.installation.length, 1);
});
