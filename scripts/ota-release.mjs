#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { ReleaseWorkflow, atomicJson } from './lib/release-workflow.mjs';
import { inspectCandidate, validateDescriptor } from './lib/release-artifact.mjs';

const help = `OTA release — preserved artifact, no build or USB operations

describe --provenance FILE --artifact BIN --source-tag TAG --base COMMIT
         --build-evidence REPO_PATH --test-evidence REPO_PATH --out FILE
plan|prepare --descriptor FILE --target FILE [--firmware-repo DIR]
plan-backend|prepare-backend --commit SHA40 --source-tag TAG --target FILE
status --id CHANNEL-X.Y.Z
git|deploy|verify-candidate|promote|verify-public|cancel --id CHANNEL-X.Y.Z
reconcile --id CHANNEL-X.Y.Z [--deployment dpl_ID]
Backend-only IDs are backend-SHA40; use the same git/deploy/verify/promote/reconcile
steps. They preserve every OTA artifact and do not accept installation receipts.
accept --id CHANNEL-X.Y.Z --device ID --previous X.Y.Z --observed X.Y.Z
       --source operator --checks version,configuration,identity,functions

Mutating external actions git/deploy/promote/cancel and physical evidence accept
require --authorize INPUT_HASH from the prepared summary. This confirms the
reviewed target; it does not grant user authorization or bypass sandbox policy.
Global: --repo DIR, --firmware-repo DIR, --vercel PATH. Default action: help.
Target JSON: project_id, team_id, public_url (HTTPS origin), previous_deployment,
base_ref (remote immutable tag identifying the currently deployed backend commit),
and optional required_env (the closed portal variable-name contract). Deploy checks
only variable names in production; no values are accepted in target or local state.
Candidate verification reads BOMB_OTA_CANDIDATE_BYPASS only from this process and
sends it only as an HTTPS header to the exact candidate origin. Public verification
is always anonymous. Local state: .ota-release/. No secrets accepted in descriptor or target.
`;

export async function main(argv) {
  const [action = 'help', ...rest] = argv;
  if (['help', '--help', '-h'].includes(action)) { console.log(help); return; }
  const options = {};
  const allowed = new Set(['repo', 'firmware-repo', 'vercel', 'provenance', 'artifact', 'source-tag', 'commit', 'base', 'build-evidence', 'test-evidence', 'out', 'descriptor', 'target', 'id', 'deployment', 'authorize', 'device', 'previous', 'observed', 'source', 'checks']);
  for (let i = 0; i < rest.length; i += 2) {
    const key = rest[i].replace(/^--/, '');
    if (!rest[i].startsWith('--') || !allowed.has(key) || !rest[i + 1] || Object.hasOwn(options, key)) throw new Error(`Invalid or duplicated option ${rest[i]}`);
    options[key] = rest[i + 1];
  }
  const required = (...names) => { for (const n of names) if (!options[n]) throw new Error(`Missing --${n}`); };
  if (action === 'describe') {
    required('provenance', 'artifact', 'source-tag', 'base', 'build-evidence', 'test-evidence', 'out');
    const out = path.resolve(options.out), bytes = fs.readFileSync(options.provenance);
    const p = JSON.parse(bytes);
    if (p.source?.dirty !== false) throw new Error('Build source is dirty or unknown; create a new candidate from committed build inputs');
    const d = { schema_version: 1, product: p.product, model: p.model, version: p.version,
      channel: p.compiled_channel, compiled_channel: p.compiled_channel, environment: p.environment,
      source: { commit: p.source.commit, tag: options['source-tag'] }, backend: { base_commit: options.base },
      artifact: { ...p.artifact, path: path.relative(path.dirname(out), path.resolve(options.artifact)) },
      provenance: { path: path.relative(path.dirname(out), path.resolve(options.provenance)), sha256: createHash('sha256').update(bytes).digest('hex') },
      compatibility: p.compatibility, build: p.build, evidence: { build: options['build-evidence'], tests: options['test-evidence'] } };
    validateDescriptor(d);
    if (fs.existsSync(out)) throw new Error('Descriptor already exists; inspect it instead of overwriting');
    for (const relative of [d.artifact.path, d.provenance.path]) {
      if (relative === '..' || relative.startsWith(`..${path.sep}`)) throw new Error('Write the descriptor beside or above its candidate files');
    }
    atomicJson(out, d);
    try { await inspectCandidate(out); } catch (error) { fs.unlinkSync(out); throw error; }
    console.log(JSON.stringify({ descriptor: out, action: 'described; not prepared or published' }, null, 2)); return;
  }
  const repo = options.repo || path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const backendOnly = ['plan-backend', 'prepare-backend'].includes(action) || options.id?.startsWith('backend-');
  const workflow = new ReleaseWorkflow({ repo, firmwareRepo: backendOnly ? undefined : options['firmware-repo'] || path.resolve(repo, '../bomb-v2'), vercel: options.vercel });
  let result;
  if (['plan-backend', 'prepare-backend'].includes(action)) {
    required('commit', 'source-tag', 'target');
    result = await workflow[action === 'plan-backend' ? 'planBackend' : 'prepareBackend'](
      options.commit, options['source-tag'], JSON.parse(fs.readFileSync(options.target, 'utf8')));
  } else if (['plan', 'prepare'].includes(action)) {
    required('descriptor', 'target');
    result = await workflow[action](path.resolve(options.descriptor), JSON.parse(fs.readFileSync(options.target, 'utf8')));
  } else {
    required('id');
    const s = workflow.load(options.id);
    if (['git', 'deploy', 'promote', 'cancel', 'accept'].includes(action) && options.authorize !== s.input_hash) throw new Error('Review status and pass --authorize with its exact input_hash');
    switch (action) {
      case 'status': result = s; break;
      case 'git': result = await workflow.gitPublish(options.id); break;
      case 'deploy': result = await workflow.deploy(options.id); break;
      case 'reconcile': result = await workflow.reconcile(options.id, options.deployment); break;
      case 'verify-candidate': result = await workflow.verifyCandidate(options.id); break;
      case 'promote': result = await workflow.promote(options.id); break;
      case 'verify-public': result = await workflow.verifyPublic(options.id); break;
      case 'cancel': result = await workflow.cancel(options.id); break;
      case 'accept': result = await workflow.accept(options.id, options); break;
      default: throw new Error(`Unknown action ${action}`);
    }
  }
  console.log(JSON.stringify(result, null, 2));
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch(error => { console.error(`OTA: ${error.message}`); process.exitCode = 1; });
}
