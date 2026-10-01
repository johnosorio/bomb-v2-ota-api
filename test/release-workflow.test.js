import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { ReleaseWorkflow, serviceFile, checkTarget, run } from '../scripts/lib/release-workflow.mjs';

const sha = b => createHash('sha256').update(b).digest('hex');
const target = { project_id: 'prj_fixture', team_id: 'team_fixture', public_url: 'https://ota.example.test', previous_deployment: 'dpl_previous', base_ref: 'refs/tags/public-base' };
const git = (dir, ...args) => execFileSync('git', args, { cwd: dir, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
function repoAt(dir) {
  fs.mkdirSync(dir); git(dir, 'init'); git(dir, 'config', 'user.email', 'fixture@example.test'); git(dir, 'config', 'user.name', 'Fixture');
}
async function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ota-workflow-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const repo = path.join(root, 'backend'), firmware = path.join(root, 'firmware');
  repoAt(repo); repoAt(firmware);
  fs.writeFileSync(path.join(repo, 'package.json'), '{}'); fs.writeFileSync(path.join(repo, 'vercel.json'), '{}');
  fs.mkdirSync(path.join(repo, 'api')); fs.writeFileSync(path.join(repo, 'api/health.js'), 'export default {};');
  fs.writeFileSync(path.join(repo, '.env.local'), 'PRIVATE_FIXTURE');
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
  const f = { repo, firmware, descriptorPath, descriptor, head: git(repo, 'rev-parse', 'HEAD'), current: 'dpl_previous', deploys: 0, promotions: 0, verified: [], failDeploy: false, failPromote: false };
  f.command = (file, args, options) => {
    if (file === 'git') {
      const result = run(file, args, options);
      if (f.failUnlock && args[0] === 'push' && args.some(a => a.startsWith(':refs/tags/ota-lock-'))) {
        f.failUnlock = false; throw new Error('unlock response lost');
      }
      return result;
    }
    assert.equal(file, 'vercel-fixture');
    const s = f.workflow.load('stable-1.2.3');
    const deployed = { id: 'dpl_candidate', projectId: target.project_id, url: 'candidate.vercel.app', target: 'production', readyState: 'READY', meta: { bombRelease: s.input_hash, bombCommit: s.commit } };
    if (args[0] === 'api') {
      if (args[1].includes('ota.example.test')) return JSON.stringify(f.current === 'dpl_candidate' ? deployed : { id: f.current, projectId: target.project_id, meta: { bombCommit: f.wrongBase ? f.head : base } });
      return JSON.stringify(deployed);
    }
    if (args[0] === 'deploy') {
      f.deploys++; assert(args.includes('--skip-domain'));
      assert(!fs.existsSync(path.join(options.cwd, '.env.local')));
      assert(!fs.existsSync(path.join(options.cwd, 'api/feature.js')));
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
  await assert.rejects(w.verifyCandidate(id), /wrong bytes/);
  await assert.rejects(w.promote(id), /Verify candidate/); assert.equal(f.promotions, 0);
  await assert.rejects(w.accept(id, {}), /verification required/);
});

test('package allowlist and target reject private paths and ambiguous destinations', () => {
  for (const file of ['api/releases/[channel].js', 'public/admin/index.html', 'public/admin/portal.js', 'public/admin/portal.css']) assert.equal(serviceFile(file), true);
  for (const file of ['public/admin/.env', 'public/admin/token.json', 'public/admin/session.js', 'public/admin/../secrets.js']) assert.equal(serviceFile(file), false);
  for (const file of ['.env.local', '.vercel/project.json', 'config/private.json', 'supabase/migrations/one.sql', 'README.md', 'scripts/secret.js']) assert.equal(serviceFile(file), false);
  assert.throws(() => checkTarget({ ...target, public_url: 'https://user:secret@example.test' }), /HTTPS origin/);
  assert.throws(() => checkTarget({ ...target, token: 'fixture' }), /fields/);
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
