import { execFileSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { inspectCandidate, prepareRelease, releasePaths, verifyRemote } from './release-artifact.mjs';
import { immutableOtaInventory, verifyBackendRemote } from './release-backend.mjs';

const digest = b => createHash('sha256').update(b).digest('hex');
const json = p => JSON.parse(fs.readFileSync(p, 'utf8'));
const assert = (ok, message) => { if (!ok) throw new Error(message); };
const oid = /^[a-f0-9]{40}$/;
const defaultEnvironment = [
  'OTA_ADMIN_ENABLED', 'OTA_DEVICE_REALM', 'OTA_GATEWAY_DATABASE_CA',
  'OTA_GATEWAY_DATABASE_URL', 'OTA_PIN_RECOVERY_ENABLED',
  'SUPABASE_PUBLISHABLE_KEY', 'SUPABASE_URL'
];
function noSymlinks(file) {
  const absolute = path.resolve(file), parts = absolute.split(path.sep).filter(Boolean);
  let current = path.parse(absolute).root;
  for (const part of parts) {
    current = path.join(current, part);
    if (!fs.existsSync(current)) continue;
    assert(!fs.lstatSync(current).isSymbolicLink(), 'Symlink in workflow path');
  }
}
export function atomicJson(file, data) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${randomUUID()}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  fs.renameSync(tmp, file);
}
export function run(file, args, options = {}) {
  try { return execFileSync(file, args, { encoding: 'utf8', timeout: 60000,
    maxBuffer: 32 * 1024 * 1024, stdio: ['pipe', 'pipe', 'pipe'], ...options }); }
  catch { throw new Error(`${path.basename(file)} ${args[0]} failed or timed out; reconcile before retrying. No raw credentials/logs recorded.`); }
}
export function parseJsonOutput(output) {
  const start = output.indexOf('{');
  assert(start >= 0, 'Command returned no JSON');
  return JSON.parse(output.slice(start));
}
export function serviceFile(file) {
  if (["api/releases/[channel].js", "public/admin/index.html", "public/admin/portal.css", "public/admin/portal.js"].includes(file)) return true;
  return /^(api|lib)\/[a-zA-Z0-9_./-]+\.(js|mjs|json)$/.test(file) ||
    /^public\/firmware\/[a-zA-Z0-9_.-]+\.bin$/.test(file) ||
    /^(package(?:-lock)?\.json|vercel\.json|release(?:-(?:beta|dev))?\.json)$/.test(file);
}
export function checkTarget(t) {
  assert(t && Object.keys(t).every(key => ['base_ref', 'previous_deployment', 'project_id', 'public_url', 'team_id', 'required_env'].includes(key)) &&
    ['base_ref', 'previous_deployment', 'project_id', 'public_url', 'team_id'].every(key => Object.hasOwn(t, key)), 'Invalid target fields');
  assert(/^refs\/tags\/[A-Za-z0-9][A-Za-z0-9_./-]{0,180}$/.test(t.base_ref) && !t.base_ref.includes('..') && !t.base_ref.endsWith('/'), 'Explicit immutable public base tag required');
  assert(/^prj_[a-zA-Z0-9]+$/.test(t.project_id) && /^team_[a-zA-Z0-9]+$/.test(t.team_id), 'Explicit Vercel project/team required');
  assert(/^dpl_[a-zA-Z0-9]+$/.test(t.previous_deployment), 'Previous deployment required');
  const u = new URL(t.public_url);
  assert(u.protocol === 'https:' && !u.username && !u.password && u.pathname === '/' && !u.search && !u.hash, 'Public URL must be an HTTPS origin');
  if (Object.hasOwn(t, 'required_env')) {
    assert(Array.isArray(t.required_env) && t.required_env.length === defaultEnvironment.length &&
      [...t.required_env].sort().join(',') === defaultEnvironment.join(','), 'required_env must be the closed portal environment contract');
  }
  return t;
}
export function parseEnvironmentNames(output) {
  assert(output && typeof output === 'object' && Array.isArray(output.envs), 'Environment metadata has unexpected format');
  const names = new Set();
  for (const environment of output.envs) {
    assert(environment && typeof environment === 'object' && /^[A-Za-z_][A-Za-z0-9_]{0,255}$/.test(environment.key), 'Environment metadata has unexpected format');
    const targets = environment.target === undefined ? [] : Array.isArray(environment.target) ? environment.target : [environment.target];
    assert(targets.every(target => ['development', 'preview', 'production'].includes(target)), 'Environment metadata has unexpected format');
    if (!targets.includes('production')) continue;
    assert(!names.has(environment.key), 'Environment metadata has duplicate production names');
    names.add(environment.key);
  }
  return names;
}

export class ReleaseWorkflow {
  constructor({ repo, firmwareRepo, vercel = 'vercel', command = run, verify = verifyRemote, candidateBypass = process.env.BOMB_OTA_CANDIDATE_BYPASS, fetchImpl = fetch }) {
    this.repo = fs.realpathSync(repo); this.firmwareRepo = firmwareRepo && fs.realpathSync(firmwareRepo);
    this.command = (file, args, options = {}) => {
      const env = { ...process.env, ...options.env };
      delete env.BOMB_OTA_CANDIDATE_BYPASS;
      return command(file, args, { ...options, env });
    };
    this.vercel = vercel; this.verify = verify; this.candidateBypass = candidateBypass; this.fetchImpl = fetchImpl;
    this.root = path.join(this.repo, '.ota-release');
  }
  git(args, options = {}) { return this.command('git', args, { cwd: this.repo, ...options }).toString().trim(); }
  file(id) {
    assert(/^(?:(stable|beta|dev)-\d+\.\d+\.\d+|backend-[a-f0-9]{40})$/.test(id), 'Invalid release id');
    const file = path.join(this.root, id, 'state.json'); noSymlinks(file); return file;
  }
  save(s) { s.updated_at = new Date().toISOString(); atomicJson(this.file(s.id), s); }
  load(id) { const s = json(this.file(id)); assert(s.id === id, 'State id mismatch'); return s; }
  async locked(id, action) {
    this.file(id); fs.mkdirSync(this.root, { recursive: true });
    const lock = path.join(this.root, 'workflow.lock');
    try { fs.mkdirSync(lock); } catch { throw new Error('Another release operation or interrupted local lock exists. Inspect owner.json; never steal an active lock.'); }
    atomicJson(path.join(lock, 'owner.json'), { pid: process.pid, id, at: new Date().toISOString() });
    try { return await action(); } finally { fs.rmSync(lock, { recursive: true }); }
  }
  object(ref, file) { return this.command('git', ['show', `${ref}:${file}`], { cwd: this.repo, encoding: null }); }
  exists(ref, file) { try { this.git(['cat-file', '-e', `${ref}:${file}`]); return true; } catch { return false; } }
  entries(ref) {
    return this.git(['ls-tree', '-r', ref]).split('\n').filter(Boolean).map(line => {
      const m = /^(\d+) (\w+) ([a-f0-9]+)\t(.+)$/.exec(line);
      assert(m, 'Unsupported Git path'); return { mode: m[1], type: m[2], file: m[4] };
    });
  }
  inventory(ref) {
    const all = this.entries(ref), included = [];
    for (const e of all) {
      if (!serviceFile(e.file)) continue;
      assert(e.type === 'blob' && /^100(644|755)$/.test(e.mode) && !e.file.split('/').includes('..'), 'Symlink or unsafe package entry');
      const bytes = this.object(ref, e.file); included.push({ path: e.file, size: bytes.length, sha256: digest(bytes) });
    }
    assert(included.some(e => e.path === 'package.json') && included.some(e => e.path === 'vercel.json'), 'Service package incomplete');
    // Refuse silently omitting service assets outside our narrow packaging contract.
    assert(!all.some(e => /^(api|lib|public)\//.test(e.file) && !serviceFile(e.file)), 'Service contains unsupported assets; review packaging contract');
    return included;
  }
  baseCommit(s) { return s.mode === 'backend' ? s.base_commit : s.descriptor.backend.base_commit; }
  async planBackend(commit, sourceTag, target) {
    checkTarget(target);
    assert(oid.test(commit || ''), 'Exact backend source commit required');
    assert(/^[A-Za-z0-9][A-Za-z0-9_./-]{0,180}$/.test(sourceTag || '') &&
      !sourceTag.includes('..') && !sourceTag.endsWith('/'), 'Immutable backend source tag required');
    this.git(['check-ref-format', `refs/tags/${sourceTag}`]);
    assert(this.git(['rev-parse', `${commit}^{commit}`]) === commit, 'Backend source commit unavailable');
    assert(this.git(['rev-parse', `refs/tags/${sourceTag}^{commit}`]) === commit, 'Backend source tag mismatch');
    const base = this.git(['rev-parse', `${target.base_ref}^{commit}`]);
    assert(oid.test(base), 'Backend public base unavailable');
    this.git(['merge-base', '--is-ancestor', base, commit]);
    const ota_inventory = immutableOtaInventory(this, base, commit);
    assert(!ota_inventory.some(e => /^release[^/]*\.json$/.test(e.path) &&
      !/^release(?:-(?:beta|dev))?\.json$/.test(e.path)), 'Unsupported OTA manifest: review the public verification contract');
    const service_package = this.inventory(commit);
    return { id: `backend-${commit}`, mode: 'backend', source_commit: commit,
      source_tag: sourceTag, base_commit: base, target, ota_inventory, service_package,
      notice: 'Backend-only: existing OTA manifests and firmware bytes are unchanged.' };
  }
  async prepareBackend(commit, sourceTag, target) {
    const p = await this.planBackend(commit, sourceTag, target);
    return this.locked(p.id, async () => {
      if (fs.existsSync(this.file(p.id))) {
        const old = this.load(p.id);
        assert(old.input_hash === digest(JSON.stringify(p)), 'Existing release has different inputs');
        return old;
      }
      const s = { ...p, schema_version: 1, input_hash: digest(JSON.stringify(p)), phase: 'prepared',
        branch: `release/backend-${commit}`, tag: `backend/${commit}`, nonce: randomUUID(), installation: [] };
      this.save(s); return s;
    });
  }
  assertBackendAssets(s) {
    if (s.mode !== 'backend') return;
    const inventory = immutableOtaInventory(this, s.base_commit, s.source_commit);
    assert(JSON.stringify(inventory) === JSON.stringify(s.ota_inventory), 'Backend OTA inventory changed');
    assert(!s.commit || s.commit === s.source_commit, 'Backend release must use exact source commit');
    assert(JSON.stringify(this.inventory(s.source_commit)) === JSON.stringify(s.service_package), 'Backend service inventory changed');
  }
  assertSourceTag(s) {
    const ref = `refs/tags/${s.source_tag}`;
    const rows = this.command('git', ['ls-remote', 'origin', ref, `${ref}^{}`], { cwd: this.repo })
      .toString().trim().split('\n').filter(Boolean).map(row => row.split(/\s+/));
    const resolved = rows.find(row => row[1] === `${ref}^{}`)?.[0] || rows.find(row => row[1] === ref)?.[0];
    assert(resolved === s.source_commit, 'Backend source tag is not verified remotely');
  }
  async gitPublishBackend(s) {
    this.assertBackendAssets(s);
    if (s.deploy_intent) { this.assertRemote(s); return s; }
    this.assertBaseRef(s); this.assertBase(s); this.assertSourceTag(s);
    s.commit = s.source_commit;
    const refs = [`refs/heads/${s.branch}`, `refs/tags/${s.tag}`];
    // Check all refs before creating either, and never move an existing ref.
    const previous = refs.map(ref => {
      let local; try { local = this.git(['rev-parse', '--verify', ref]); } catch { local = null; }
      const remote = this.remoteRef(ref);
      assert((!local || local === s.commit) && (!remote || remote === s.commit), 'Backend release ref conflicts');
      return local;
    });
    this.save(s);
    refs.forEach((ref, i) => { if (!previous[i]) this.git(['update-ref', ref, s.commit, '0'.repeat(40)]); });
    s.phase = 'git-pending'; this.save(s);
    this.git(['push', '--atomic', 'origin', ...refs.map(ref => `${ref}:${ref}`)], { timeout: 120000 });
    this.assertRemote(s); s.phase = 'git-verified'; this.save(s); return s;
  }
  async plan(descriptorPath, target) {
    checkTarget(target);
    const { descriptor: d } = await inspectCandidate(descriptorPath);
    assert(this.git(['rev-parse', `${d.backend.base_commit}^{commit}`]) === d.backend.base_commit, 'Backend base unavailable');
    assert(this.firmwareRepo, 'Firmware repository required to verify source tag');
    const source = this.command('git', ['rev-parse', '--verify', `refs/tags/${d.source.tag}^{commit}`], { cwd: this.firmwareRepo }).toString().trim();
    assert(source === d.source.commit, 'Source tag does not identify build commit');
    const files = this.inventory(d.backend.base_commit);
    return { id: `${d.channel}-${d.version}`, descriptor: d, target, base_package: files,
      installation: 'unconfirmed', notice: 'Preparing a shared channel release does not install it.' };
  }
  async prepare(descriptorPath, target) {
    const p = await this.plan(descriptorPath, target);
    return this.locked(p.id, async () => {
      const file = this.file(p.id);
      if (fs.existsSync(file)) {
        const old = this.load(p.id);
        assert(old.input_hash === digest(JSON.stringify(p)), 'Existing release has different inputs');
        await inspectCandidate(path.join(path.dirname(file), 'stage', old.paths.descriptor));
        return old;
      }
      const paths = releasePaths(p.descriptor), stage = path.join(path.dirname(file), 'stage');
      fs.mkdirSync(stage, { recursive: true });
      for (const f of Object.values(paths)) {
        if (this.exists(p.descriptor.backend.base_commit, f) && !fs.existsSync(path.join(stage, f))) {
          fs.mkdirSync(path.dirname(path.join(stage, f)), { recursive: true });
          fs.writeFileSync(path.join(stage, f), this.object(p.descriptor.backend.base_commit, f), { flag: 'wx' });
        }
      }
      await prepareRelease(stage, descriptorPath);
      const s = { schema_version: 1, id: p.id, input_hash: digest(JSON.stringify(p)),
        descriptor: p.descriptor, target, paths, base_package: p.base_package, phase: 'prepared',
        branch: `release/ota-${p.id}`, tag: `ota/${p.id}`, nonce: randomUUID(), installation: [] };
      this.save(s); return s;
    });
  }
  remoteRef(ref, repo = this.repo) {
    const out = this.command('git', ['ls-remote', '--refs', 'origin', ref], { cwd: repo }).toString().trim();
    if (!out) return null;
    const [hash, name] = out.split(/\s+/); assert(oid.test(hash) && name === ref, 'Unexpected remote reference'); return hash;
  }
  assertRemote(s) {
    assert(s.commit && this.remoteRef(`refs/heads/${s.branch}`) === s.commit && this.remoteRef(`refs/tags/${s.tag}`) === s.commit, 'Release commit/tag not verified remotely');
  }
  assertBaseRef(s) {
    const ref = s.target.base_ref;
    const out = this.command('git', ['ls-remote', 'origin', ref, `${ref}^{}`], { cwd: this.repo }).toString();
    const rows = out.trim().split('\n').filter(Boolean).map(l => l.split(/\s+/));
    const hash = rows.find(r => r[1] === `${ref}^{}`)?.[0] || rows.find(r => r[1] === ref)?.[0];
    assert(hash === this.baseCommit(s), 'Public base tag is not verified remotely');
  }
  async gitPublish(id) {
    return this.locked(id, async () => {
      const s = this.load(id), dir = path.dirname(this.file(id));
      if (s.mode === 'backend') return this.gitPublishBackend(s);
      await inspectCandidate(path.join(dir, 'stage', s.paths.descriptor));
      if (s.deploy_intent) { this.assertRemote(s); return s; }
      this.assertBaseRef(s);
      this.assertBase(s);
      assert(this.firmwareRepo, 'Firmware repository required');
      // Resolve annotated source tags through a read-only remote fetch to FETCH_HEAD.
      const tagRef = `refs/tags/${s.descriptor.source.tag}`;
      const remote = this.command('git', ['ls-remote', 'origin', tagRef, `${tagRef}^{}`], { cwd: this.firmwareRepo }).toString();
      const rows = remote.trim().split('\n').filter(Boolean).map(l => l.split(/\s+/));
      const resolved = rows.find(r => r[1] === `${tagRef}^{}`)?.[0] || rows.find(r => r[1] === tagRef)?.[0];
      assert(resolved === s.descriptor.source.commit, 'Firmware source tag not verified remotely');
      const index = path.join(dir, 'index');
      const env = { ...process.env, GIT_INDEX_FILE: index };
      this.git(['read-tree', s.descriptor.backend.base_commit], { env });
      for (const file of Object.values(s.paths)) {
        const hash = this.git(['hash-object', '-w', '--stdin'], { input: fs.readFileSync(path.join(dir, 'stage', file)) });
        this.git(['update-index', '--add', '--cacheinfo', '100644', hash, file], { env });
      }
      const tree = this.git(['write-tree'], { env });
      const ref = `refs/heads/${s.branch}`;
      let prior;
      try { prior = this.git(['rev-parse', '--verify', ref]); } catch { prior = null; }
      if (s.commit || prior) {
        const commit = s.commit || prior;
        assert(this.git(['rev-parse', `${commit}^{tree}`]) === tree && this.git(['rev-parse', `${commit}^`]) === s.descriptor.backend.base_commit, 'Existing release ref conflicts');
        assert(!prior || prior === commit, 'Release branch moved'); s.commit = commit;
      } else {
        s.commit = this.git(['commit-tree', tree, '-p', s.descriptor.backend.base_commit, '-m', `release(ota): ${id}`]);
        this.save(s);
      }
      if (!prior) this.git(['update-ref', ref, s.commit, '0'.repeat(40)]);
      let tag; try { tag = this.git(['rev-parse', '--verify', `refs/tags/${s.tag}`]); } catch { tag = null; }
      assert(!tag || tag === s.commit, 'Existing tag conflicts');
      if (!tag) this.git(['update-ref', `refs/tags/${s.tag}`, s.commit, '0'.repeat(40)]);
      if (!s.deploy_intent) s.phase = 'git-pending'; this.save(s);
      for (const r of [ref, `refs/tags/${s.tag}`]) {
        const observed = this.remoteRef(r); assert(!observed || observed === s.commit, 'Remote ref conflicts; never force-push');
      }
      this.git(['push', '--atomic', 'origin', `${ref}:${ref}`, `refs/tags/${s.tag}:refs/tags/${s.tag}`], { timeout: 120000 });
      this.assertRemote(s); if (!s.deploy_intent) s.phase = 'git-verified'; this.save(s); return s;
    });
  }
  api(s, endpoint) {
    const join = endpoint.includes('?') ? '&' : '?';
    return parseJsonOutput(this.command(this.vercel, ['api', `${endpoint}${join}teamId=${s.target.team_id}`, '--method', 'GET', '--raw'], { cwd: this.repo }));
  }
  inspect(s, ref) {
    return this.api(s, `/v13/deployments/${encodeURIComponent(ref)}`);
  }
  checkDeployment(s, d) {
    assert(d.id && d.projectId === s.target.project_id && d.meta?.bombRelease === s.input_hash && d.meta?.bombCommit === s.commit, 'Deployment does not belong to this exact release/project');
    assert(d.target === 'production' && d.readyState === 'READY', 'Deployment not ready for production promotion');
    assert(typeof d.url === 'string' && /^[a-zA-Z0-9.-]+\.vercel\.app$/.test(d.url), 'Invalid deployment URL');
    return { id: d.id, url: `https://${d.url}` };
  }
  assertBase(s) {
    const d = this.inspect(s, new URL(s.target.public_url).hostname);
    assert(d.projectId === s.target.project_id && d.id === s.target.previous_deployment, 'Public deployment changed; prepare a new reviewed base/target');
    const commit = d.meta?.bombCommit || d.meta?.githubCommitSha || d.meta?.gitCommitSha || d.gitSource?.sha;
    assert(commit === this.baseCommit(s), 'Deployment provenance does not confirm the selected backend base');
  }
  acquire(s) {
    const ref = `refs/tags/ota-lock-${s.target.project_id}`;
    if (!s.lock_commit) {
      const tree = this.git(['mktree'], { input: '' });
      s.lock_commit = this.git(['commit-tree', tree, '-m', `OTA operation ${s.nonce}`]); this.save(s);
    }
    const remote = this.remoteRef(ref);
    assert(!remote || remote === s.lock_commit, 'Another release holds the project lock; reconcile its owner first');
    if (!remote) this.git(['push', 'origin', `${s.lock_commit}:${ref}`]);
    assert(this.remoteRef(ref) === s.lock_commit, 'Remote project lock uncertain');
  }
  releaseLock(s) {
    const ref = `refs/tags/ota-lock-${s.target.project_id}`;
    const observed = this.remoteRef(ref);
    assert(!observed || observed === s.lock_commit, 'Project lock owner changed');
    if (observed) this.git(['push', `--force-with-lease=${ref}:${s.lock_commit}`, 'origin', `:${ref}`]);
  }
  package(s) {
    this.assertBackendAssets(s);
    const dir = path.join(path.dirname(this.file(s.id)), 'package');
    const files = this.inventory(s.commit);
    if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true });
    fs.mkdirSync(dir, { recursive: true });
    for (const f of files) {
      const dest = path.join(dir, f.path); fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.writeFileSync(dest, this.object(s.commit, f.path));
    }
    atomicJson(path.join(dir, '.vercel/project.json'), { projectId: s.target.project_id, orgId: s.target.team_id });
    // Only the exported committed allowlist and generated project linkage exist here.
    fs.writeFileSync(path.join(dir, '.vercelignore'), '/.vercel/\n');
    s.package = files; this.save(s); return dir;
  }
  requiredEnvironment(s) {
    return s.target.required_env || defaultEnvironment;
  }
  assertEnvironment(s) {
    try {
      const required = this.requiredEnvironment(s);
      const names = parseEnvironmentNames(this.api(s, `/v10/projects/${encodeURIComponent(s.target.project_id)}/env?decrypt=false`));
      assert(required.every(name => names.has(name)), 'Missing environment');
    } catch {
      // Even malformed provider JSON can contain values; never echo it.
      throw new Error('Required production environment is incomplete or metadata is unavailable');
    }
  }
  candidateFetch(s) {
    if (!this.candidateBypass) return undefined;
    assert(typeof this.candidateBypass === 'string' && /^[\x21-\x7e]{1,1024}$/.test(this.candidateBypass), 'Candidate bypass configuration invalid');
    const origin = new URL(s.deployment.url).origin;
    return (url, options = {}) => {
      const target = new URL(url);
      assert(target.protocol === 'https:' && target.origin === origin, 'Candidate verification URL is not the exact deployment origin');
      const headers = new Headers(options.headers);
      headers.set('x-vercel-protection-bypass', this.candidateBypass);
      return this.fetchImpl(target, { ...options, headers, redirect: 'error' });
    };
  }
  async verifyCandidateRemote(s) {
    try {
      await this.verifyRelease(s, s.deployment.url, { fetchImpl: this.candidateFetch(s) });
    } catch {
      throw new Error('Candidate verification failed');
    }
  }
  async verifyRelease(s, origin, options) {
    if (s.mode !== 'backend') return options === undefined ? this.verify(origin, s.descriptor) : this.verify(origin, s.descriptor, options);
    this.assertBackendAssets(s);
    const manifests = s.ota_inventory.filter(entry => /^release(?:-(?:beta|dev))?\.json$/.test(entry.path))
      .map(entry => ({ path: entry.path, body: JSON.parse(this.object(s.source_commit, entry.path).toString()) }));
    const binaries = s.ota_inventory.filter(entry => entry.path.startsWith('public/firmware/'));
    return verifyBackendRemote(origin, manifests, binaries, options);
  }
  async deploy(id) {
    return this.locked(id, async () => {
      const s = this.load(id); this.assertRemote(s); this.assertBackendAssets(s);
      assert(!s.deploy_intent, 'Deployment already attempted; use reconcile with its deployment ID, never retry blindly');
      this.assertEnvironment(s); this.acquire(s); this.assertBaseRef(s); this.assertBase(s);
      const cwd = this.package(s);
      s.deploy_intent = true; s.phase = 'deployment-uncertain'; this.save(s);
      const result = parseJsonOutput(this.command(this.vercel, ['deploy', '--prod', '--skip-domain', '--yes', '--json',
        '--meta', `bombRelease=${s.input_hash}`, '--meta', `bombCommit=${s.commit}`], { cwd, timeout: 300000 }));
      const ref = result.deployment?.id;
      assert(ref, 'Deployment response uncertain: reconcile by deployment ID');
      s.deployment = { id: ref }; this.save(s);
      s.deployment = this.checkDeployment(s, this.inspect(s, ref));
      s.phase = 'deployed'; this.save(s); return s;
    });
  }
  async reconcile(id, deploymentId) {
    return this.locked(id, async () => {
      const s = this.load(id); this.assertRemote(s);
      const ref = deploymentId || s.deployment?.id;
      assert(/^dpl_[a-zA-Z0-9]+$/.test(ref || ''), 'Provide the deployment ID from Vercel; no new deployment will be created');
      assert(!s.deployment?.id || s.deployment.id === ref, 'Cannot replace an already bound deployment');
      s.deployment = this.checkDeployment(s, this.inspect(s, ref)); s.deploy_intent = true;
      if (!s.public_verified_at) s.phase = s.promotion_intent ? 'promotion-uncertain' : 'deployed'; this.save(s); return s;
    });
  }
  async verifyCandidate(id) {
    return this.locked(id, async () => {
      const s = this.load(id); assert(s.deployment?.id, 'No deployment');
      s.deployment = this.checkDeployment(s, this.inspect(s, s.deployment.id));
      await this.verifyCandidateRemote(s);
      s.candidate_verified = true; if (!s.promotion_intent && !s.public_verified_at) s.phase = 'candidate-verified'; this.save(s); return s;
    });
  }
  async promote(id) {
    return this.locked(id, async () => {
      const s = this.load(id); this.assertRemote(s); this.acquire(s);
      assert(s.candidate_verified, 'Verify candidate bytes before promoting');
      const current = this.inspect(s, new URL(s.target.public_url).hostname);
      if (current.id !== s.deployment.id) {
        assert(!s.promotion_intent, 'Promotion outcome uncertain; verify public or reconcile, do not repeat');
        this.assertBase(s);
        this.checkDeployment(s, this.inspect(s, s.deployment.id));
        await this.verifyCandidateRemote(s);
        s.promotion_intent = true; s.phase = 'promotion-uncertain'; this.save(s);
        this.command(this.vercel, ['promote', s.deployment.id, '--yes', '--timeout', '3m', '--scope', s.target.team_id], { cwd: path.join(path.dirname(this.file(id)), 'package'), timeout: 210000 });
      }
      return this.verifyPublicUnlocked(s);
    });
  }
  async verifyPublicUnlocked(s) {
    const current = this.inspect(s, new URL(s.target.public_url).hostname);
    assert(current.id === s.deployment?.id && current.projectId === s.target.project_id, 'Public alias does not reference release deployment');
    await this.verifyRelease(s, s.target.public_url);
    s.phase = 'public-verified'; s.public_verified_at = new Date().toISOString(); this.save(s);
    this.releaseLock(s); return s;
  }
  async verifyPublic(id) { return this.locked(id, () => this.verifyPublicUnlocked(this.load(id))); }
  async cancel(id) {
    return this.locked(id, async () => {
      const s = this.load(id);
      assert(!s.promotion_intent && s.phase !== 'public-verified', 'Already promoted or uncertain; cancel cannot revert publication');
      if (s.deploy_intent) this.assertBase(s);
      if (s.lock_commit) this.releaseLock(s);
      s.phase = 'paused'; this.save(s); return s;
    });
  }
  async accept(id, { device, previous, observed, source, checks }) {
    return this.locked(id, async () => {
      const s = this.load(id); assert(s.phase === 'public-verified', 'Public release verification required');
      assert(s.mode !== 'backend', 'Backend-only publication has no firmware installation receipt');
      assert(/^[a-zA-Z0-9:_-]{1,80}$/.test(device || '') && /^\d+\.\d+\.\d+$/.test(previous || '') && observed === s.descriptor.version, 'Invalid device/version evidence');
      assert(source === 'operator' && checks === 'version,configuration,identity,functions', 'Explicit operator confirmation of all physical checks required');
      const entry = { device, previous, observed, source, checks, at: new Date().toISOString() };
      s.installation = [...s.installation.filter(e => e.device !== device), entry]; this.save(s); return s;
    });
  }
}
