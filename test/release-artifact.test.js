import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { inspectCandidate, prepareRelease, releasePaths, validateDescriptor, verifyRemote } from "../scripts/lib/release-artifact.mjs";

const hash = (value) => createHash("sha256").update(value).digest("hex");
const commit = "a".repeat(40);
const partition = "b".repeat(64);

async function fixture({ version = "1.2.3", channel = "beta" } = {}) {
  const directory = await mkdtemp(path.join(os.tmpdir(), "release-artifact-"));
  const bytes = Buffer.from(`firmware ${version}`);
  const provenance = {
    schema_version: 1,
    product: "bomb-manager",
    model: "cores3",
    version,
    environment: channel === "stable" ? "core_s3" : `core_s3_ota_${channel}`,
    compiled_channel: channel,
    source: { commit, dirty: false },
    artifact: { size: bytes.length, sha256: hash(bytes) },
    compatibility: { partition_sha256: partition, catalog_schema_version: 1 },
    build: { radio_provisioned: false, pin_recovery: false }
  };
  const provenanceBytes = Buffer.from(`${JSON.stringify(provenance)}\n`);
  const descriptor = {
    schema_version: 1,
    product: "bomb-manager",
    model: "cores3",
    version,
    channel,
    compiled_channel: channel,
    environment: provenance.environment,
    source: { commit, tag: `v${version}` },
    backend: { base_commit: "c".repeat(40) },
    artifact: { path: "candidate.bin", size: bytes.length, sha256: hash(bytes) },
    compatibility: provenance.compatibility,
    build: provenance.build,
    evidence: { build: "validation/build.json", tests: "validation/tests.json" },
    provenance: { path: "provenance.json", sha256: hash(provenanceBytes) }
  };
  const descriptorPath = path.join(directory, "descriptor.json");
  await Promise.all([
    writeFile(path.join(directory, "candidate.bin"), bytes),
    writeFile(path.join(directory, "provenance.json"), provenanceBytes),
    writeFile(descriptorPath, `${JSON.stringify(descriptor, null, 2)}\n`)
  ]);
  return { directory, descriptor, descriptorPath, bytes, provenanceBytes };
}

test("validates a candidate and rejects a symlink artifact before any release write", async () => {
  const item = await fixture();
  const inspected = await inspectCandidate(item.descriptorPath);
  assert.equal(inspected.bytes.toString(), item.bytes.toString());
  await writeFile(path.join(item.directory, "other.bin"), item.bytes);
  await writeFile(item.descriptorPath, JSON.stringify({ ...item.descriptor, artifact: { ...item.descriptor.artifact, path: "link.bin" } }));
  await symlink("other.bin", path.join(item.directory, "link.bin"));
  await assert.rejects(() => inspectCandidate(item.descriptorPath), /Symlink path|non-symlink/);
});

test("prepareRelease is idempotent and normalizes durable descriptor paths", async () => {
  const item = await fixture();
  const repo = await mkdtemp(path.join(os.tmpdir(), "release-repo-"));
  const first = await prepareRelease(repo, item.descriptorPath);
  const second = await prepareRelease(repo, item.descriptorPath);
  assert.equal(first.changed, true);
  assert.equal(second.changed, false);
  assert.deepEqual(first.paths, {
    artifact: "public/firmware/bomb-manager-beta-1.2.3.bin",
    manifest: "release-beta.json",
    descriptor: "releases/beta-1.2.3.json",
    provenance: "releases/beta-1.2.3.provenance.json"
  });
  const durable = JSON.parse(await readFile(path.join(repo, first.paths.descriptor), "utf8"));
  assert.equal(durable.artifact.path, "../public/firmware/bomb-manager-beta-1.2.3.bin");
  assert.equal(durable.provenance.path, "beta-1.2.3.provenance.json");
  assert.equal((await inspectCandidate(path.join(repo, first.paths.descriptor))).bytes.length, item.bytes.length);
});

test('candidate cannot escape its directory or embed arbitrary evidence text', async () => {
  const item = await fixture();
  const nested = path.join(item.directory, 'nested'); await mkdir(nested);
  const escaped = { ...item.descriptor, artifact: { ...item.descriptor.artifact, path: '../candidate.bin' }, provenance: { ...item.descriptor.provenance, path: '../provenance.json' } };
  const descriptorPath = path.join(nested, 'descriptor.json'); await writeFile(descriptorPath, JSON.stringify(escaped));
  await assert.rejects(inspectCandidate(descriptorPath), /escapes/);
  for (const evidence of ['token=fixture', 'ssid=fixture', 'password.txt', 'https://user:secret@example.test', '../outside']) {
    assert.throws(() => validateDescriptor({ ...item.descriptor, evidence: { build: evidence, tests: 'validation/tests.json' } }), /references/);
  }
});

test("rejection for an existing conflicting artifact leaves manifest and descriptor absent", async () => {
  const item = await fixture();
  const repo = await mkdtemp(path.join(os.tmpdir(), "release-conflict-"));
  const paths = releasePaths(item.descriptor);
  await mkdir(path.join(repo, "public", "firmware"), { recursive: true });
  await writeFile(path.join(repo, paths.artifact), "different bytes");
  await assert.rejects(() => prepareRelease(repo, item.descriptorPath), /Artifact already exists/);
  await assert.rejects(() => readFile(path.join(repo, paths.descriptor)), { code: "ENOENT" });
  await assert.rejects(() => readFile(path.join(repo, paths.manifest)), { code: "ENOENT" });
});

test("unknown fields, dirty provenance and partial manifest conflicts fail closed", async () => {
  const item = await fixture();
  assert.throws(() => validateDescriptor({ ...item.descriptor, token: "secret" }), /unknown or missing/);
  const dirty = JSON.parse(await readFile(path.join(item.directory, "provenance.json"), "utf8"));
  dirty.source.dirty = true;
  const dirtyBytes = Buffer.from(JSON.stringify(dirty));
  await writeFile(path.join(item.directory, "provenance.json"), dirtyBytes);
  item.descriptor.provenance.sha256 = hash(dirtyBytes);
  await writeFile(item.descriptorPath, JSON.stringify(item.descriptor));
  await assert.rejects(() => inspectCandidate(item.descriptorPath), /dirty/);

  const clean = await fixture();
  const repo = await mkdtemp(path.join(os.tmpdir(), "release-manifest-"));
  await writeFile(path.join(repo, "release-beta.json"), JSON.stringify({ version: clean.descriptor.version, sha256: "wrong" }));
  await assert.rejects(() => prepareRelease(repo, clean.descriptorPath), /Release manifest conflicts/);
  const paths = releasePaths(clean.descriptor);
  await assert.rejects(() => readFile(path.join(repo, paths.artifact)), { code: "ENOENT" });
});

test("prepareRelease advances a channel manifest only after durable release files exist", async () => {
  const item = await fixture();
  const repo = await mkdtemp(path.join(os.tmpdir(), "release-advance-"));
  await writeFile(path.join(repo, "release-beta.json"), JSON.stringify({ version: "0.0.0", placeholder: true }));
  const result = await prepareRelease(repo, item.descriptorPath);
  const manifest = JSON.parse(await readFile(path.join(repo, result.paths.manifest), "utf8"));
  assert.equal(manifest.version, item.descriptor.version);
  await readFile(path.join(repo, result.paths.artifact));
  await readFile(path.join(repo, result.paths.descriptor));
});

test("rejects provisioned or mismatched provenance, locks and symlinked output parents", async () => {
  const item = await fixture();
  const provenance = JSON.parse(await readFile(path.join(item.directory, "provenance.json"), "utf8"));
  provenance.build.radio_provisioned = true;
  const bytes = Buffer.from(JSON.stringify(provenance));
  item.descriptor.provenance.sha256 = hash(bytes);
  await writeFile(path.join(item.directory, "provenance.json"), bytes);
  await writeFile(item.descriptorPath, JSON.stringify(item.descriptor));
  await assert.rejects(() => inspectCandidate(item.descriptorPath), /build.radio_provisioned/);
  const clean = await fixture();
  const repo = await mkdtemp(path.join(os.tmpdir(), "release-lock-"));
  await mkdir(path.join(repo, ".release-artifact.lock"));
  await assert.rejects(() => prepareRelease(repo, clean.descriptorPath), /already locked/);
  await rm(path.join(repo, ".release-artifact.lock"), { recursive: true });
  await mkdir(path.join(repo, "outside"));
  await symlink("outside", path.join(repo, "public"));
  await assert.rejects(() => prepareRelease(repo, clean.descriptorPath), /Symlink path/);
});

test("verifyRemote checks same-origin URL, exact bytes and local HTTP test origin", async () => {
  const item = await fixture();
  const paths = releasePaths(item.descriptor);
  const manifest = {
    product: item.descriptor.product,
    channel: item.descriptor.channel,
    version: item.descriptor.version,
    firmware_url: `/${paths.artifact.slice("public/".length)}`,
    sha256: item.descriptor.artifact.sha256,
    size: item.descriptor.artifact.size,
    catalog_schema_version: 1
  };
  const fetchImpl = async (url) => String(url).includes("/api/releases/")
    ? new Response(JSON.stringify(manifest), { status: 200 })
    : new Response(item.bytes, { status: 200, headers: { "content-length": String(item.bytes.length) } });
  const evidence = await verifyRemote("http://localhost:3010", item.descriptor, { fetchImpl, timeoutMs: 1000 });
  assert.equal(evidence.sha256, item.descriptor.artifact.sha256);
  const external = async () => new Response(JSON.stringify({ ...manifest, firmware_url: "https://elsewhere.test/file.bin" }), { status: 200 });
  await assert.rejects(() => verifyRemote("http://localhost:3010", item.descriptor, { fetchImpl: external }), /same origin/);
});

test("verifyRemote bounds stalled headers and body reads", async () => {
  const item = await fixture();
  await assert.rejects(() => verifyRemote("http://localhost:3010", item.descriptor, {
    fetchImpl: () => new Promise(() => {}), timeoutMs: 10
  }), /timed out/);
  const stream = new ReadableStream({ pull: () => new Promise(() => {}) });
  await assert.rejects(() => verifyRemote("http://localhost:3010", item.descriptor, {
    fetchImpl: () => new Response(stream, { status: 200 }), timeoutMs: 10
  }), /timed out/);
});
