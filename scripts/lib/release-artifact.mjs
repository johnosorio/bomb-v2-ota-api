import { createHash } from "node:crypto";
import {
  lstat, mkdir, readFile, rename, rmdir, stat, unlink, writeFile
} from "node:fs/promises";
import path from "node:path";

const channels = new Set(["stable", "beta", "dev"]);
const environments = {
  stable: "core_s3",
  beta: "core_s3_ota_beta",
  dev: "core_s3_ota_dev"
};
const hex40 = /^[a-f0-9]{40}$/;
const hex64 = /^[a-f0-9]{64}$/;
const versionPattern = /^\d+\.\d+\.\d+$/;
const tagPattern = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/;
const maximumFirmwareSize = 6_400_000;
const descriptorKeys = ["schema_version", "product", "model", "version", "channel", "compiled_channel", "environment", "source", "backend", "artifact", "compatibility", "build", "evidence", "provenance"];

function fail(message) {
  throw new Error(`Invalid release descriptor: ${message}`);
}

function exactKeys(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail(`${label} has unknown or missing fields`);
  }
}

function string(value, label) {
  if (typeof value !== "string" || value.length === 0) fail(`${label} must be a non-empty string`);
  return value;
}

function relativePath(value, label) {
  string(value, label);
  if (value.includes("\0") || path.isAbsolute(value)) fail(`${label} must be a relative path`);
  const normalized = path.normalize(value);
  if (normalized === "." || normalized === ".." || normalized.startsWith(`..${path.sep}`)) {
    // Artifact paths may deliberately leave releases/ (for ../public/firmware).
    if (!value.startsWith(`..${path.sep}`) && !value.startsWith("../")) fail(`${label} is not a file path`);
  }
  return value;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function parseJson(bytes, label) {
  try {
    return JSON.parse(Buffer.from(bytes).toString("utf8"));
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
}

export function validateDescriptor(descriptor) {
  exactKeys(descriptor, descriptorKeys, "descriptor");
  if (descriptor.schema_version !== 1) fail("schema_version must be 1");
  if (descriptor.product !== "bomb-manager") fail("product must be bomb-manager");
  if (descriptor.model !== "cores3") fail("model must be cores3");
  if (!versionPattern.test(string(descriptor.version, "version"))) fail("version must be X.Y.Z");
  if (!channels.has(descriptor.channel)) fail("channel must be stable, beta or dev");
  if (descriptor.compiled_channel !== descriptor.channel) fail("compiled_channel must equal channel");
  if (descriptor.environment !== environments[descriptor.channel]) fail("environment does not match channel");

  exactKeys(descriptor.source, ["commit", "tag"], "source");
  if (!hex40.test(string(descriptor.source.commit, "source.commit"))) fail("source.commit must be 40 lowercase hex characters");
  string(descriptor.source.tag, "source.tag");
  if (!tagPattern.test(descriptor.source.tag)) fail("source.tag must be a safe git ref");
  exactKeys(descriptor.backend, ["base_commit"], "backend");
  if (!hex40.test(string(descriptor.backend.base_commit, "backend.base_commit"))) fail("backend.base_commit must be 40 lowercase hex characters");

  exactKeys(descriptor.artifact, ["path", "size", "sha256"], "artifact");
  relativePath(descriptor.artifact.path, "artifact.path");
  if (!Number.isSafeInteger(descriptor.artifact.size) || descriptor.artifact.size <= 0 || descriptor.artifact.size > maximumFirmwareSize) fail("artifact.size must be a positive integer within the firmware limit");
  if (!hex64.test(string(descriptor.artifact.sha256, "artifact.sha256"))) fail("artifact.sha256 must be 64 lowercase hex characters");
  exactKeys(descriptor.compatibility, ["partition_sha256", "catalog_schema_version"], "compatibility");
  if (!hex64.test(string(descriptor.compatibility.partition_sha256, "compatibility.partition_sha256"))) fail("compatibility.partition_sha256 must be 64 lowercase hex characters");
  if (descriptor.compatibility.catalog_schema_version !== 1) fail("compatibility.catalog_schema_version must be 1");
  exactKeys(descriptor.build, ["radio_provisioned", "pin_recovery"], "build");
  if (descriptor.build.radio_provisioned !== false || descriptor.build.pin_recovery !== false) fail("build provisioning flags must be false");
  exactKeys(descriptor.evidence, ["build", "tests"], "evidence");
  string(descriptor.evidence.build, "evidence.build");
  string(descriptor.evidence.tests, "evidence.tests");
  for (const reference of Object.values(descriptor.evidence)) {
    if (!/^[A-Za-z0-9][A-Za-z0-9_./-]{0,159}$/.test(reference) || reference.includes('..') || /(?:token|password|secret|ssid|credential)/i.test(reference)) {
      fail('evidence must be bounded repository references, never free text or credentials');
    }
  }
  exactKeys(descriptor.provenance, ["path", "sha256"], "provenance");
  relativePath(descriptor.provenance.path, "provenance.path");
  if (!hex64.test(string(descriptor.provenance.sha256, "provenance.sha256"))) fail("provenance.sha256 must be 64 lowercase hex characters");
  return descriptor;
}

function validateProvenance(provenance) {
  exactKeys(provenance, ["schema_version", "product", "model", "version", "environment", "compiled_channel", "source", "artifact", "compatibility", "build"], "provenance");
  if (provenance.schema_version !== 1) throw new Error("Invalid provenance: schema_version must be 1");
  exactKeys(provenance.source, ["commit", "dirty"], "provenance.source");
  exactKeys(provenance.artifact, ["size", "sha256"], "provenance.artifact");
  exactKeys(provenance.compatibility, ["partition_sha256", "catalog_schema_version"], "provenance.compatibility");
  exactKeys(provenance.build, ["radio_provisioned", "pin_recovery"], "provenance.build");
  return provenance;
}

async function regularFile(filePath, label) {
  await rejectSymlinkAncestors(filePath, true);
  const info = await lstat(filePath);
  if (info.isSymbolicLink() || !info.isFile()) throw new Error(`${label} must be a regular non-symlink file`);
}

async function rejectSymlinkAncestors(filePath, requireLeaf) {
  const absolute = path.resolve(filePath);
  const parsed = path.parse(absolute);
  let current = parsed.root;
  for (const segment of absolute.slice(parsed.root.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    try {
      const entry = await lstat(current);
      // macOS exposes its temporary directory through the system /var symlink.
      // It is outside the candidate/repository authority; all later ancestors are checked.
      if (entry.isSymbolicLink() && current !== "/var") throw new Error(`Symlink path is not allowed: ${current}`);
    } catch (error) {
      if (error.code === "ENOENT" && !requireLeaf) return;
      throw error;
    }
  }
}

export async function inspectCandidate(descriptorPath) {
  await regularFile(descriptorPath, "Descriptor");
  const descriptorBytes = await readFile(descriptorPath);
  const descriptor = validateDescriptor(parseJson(descriptorBytes, "Descriptor"));
  const directory = path.dirname(path.resolve(descriptorPath));
  const artifactPath = path.resolve(directory, descriptor.artifact.path);
  const provenancePath = path.resolve(directory, descriptor.provenance.path);
  const paths = releasePaths(descriptor);
  const durable = path.basename(directory) === 'releases' &&
    path.basename(descriptorPath) === path.basename(paths.descriptor) &&
    descriptor.artifact.path === `../${paths.artifact}` &&
    descriptor.provenance.path === path.basename(paths.provenance);
  const root = durable ? path.dirname(directory) : directory;
  for (const file of [artifactPath, provenancePath]) {
    const relative = path.relative(root, file);
    if (!relative || relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
      throw new Error('Candidate input escapes its directory');
    }
  }
  await regularFile(artifactPath, "Artifact");
  await regularFile(provenancePath, "Provenance");
  const [bytes, provenanceBytes] = await Promise.all([readFile(artifactPath), readFile(provenancePath)]);
  if (bytes.length !== descriptor.artifact.size || sha256(bytes) !== descriptor.artifact.sha256) throw new Error("Artifact bytes do not match descriptor");
  if (sha256(provenanceBytes) !== descriptor.provenance.sha256) throw new Error("Provenance bytes do not match descriptor");
  const provenance = validateProvenance(parseJson(provenanceBytes, "Provenance"));
  for (const field of ["product", "model", "version", "environment", "compiled_channel"]) {
    if (provenance[field] !== descriptor[field]) throw new Error(`Provenance ${field} does not match descriptor`);
  }
  for (const [object, field] of [["source", "commit"], ["artifact", "size"], ["artifact", "sha256"], ["compatibility", "partition_sha256"], ["compatibility", "catalog_schema_version"], ["build", "radio_provisioned"], ["build", "pin_recovery"]]) {
    if (provenance[object][field] !== descriptor[object][field]) throw new Error(`Provenance ${object}.${field} does not match descriptor`);
  }
  if (provenance.source.dirty !== false) throw new Error("Provenance source.dirty must be false");
  return { descriptor, bytes, descriptorPath: path.resolve(descriptorPath), provenanceBytes };
}

export function releasePaths(descriptor) {
  validateDescriptor(descriptor);
  const suffix = descriptor.channel === "stable" ? "" : `-${descriptor.channel}`;
  const filename = `bomb-manager${suffix}-${descriptor.version}.bin`;
  const id = `${descriptor.channel}-${descriptor.version}`;
  return {
    artifact: path.posix.join("public", "firmware", filename),
    manifest: descriptor.channel === "stable" ? "release.json" : `release-${descriptor.channel}.json`,
    descriptor: path.posix.join("releases", `${id}.json`),
    provenance: path.posix.join("releases", `${id}.provenance.json`)
  };
}

function publicManifest(descriptor, paths) {
  return {
    product: descriptor.product,
    channel: descriptor.channel,
    version: descriptor.version,
    firmware_url: `/${paths.artifact.slice("public/".length)}`,
    sha256: descriptor.artifact.sha256,
    size: descriptor.artifact.size,
    catalog_schema_version: descriptor.compatibility.catalog_schema_version
  };
}

async function readExisting(filePath) {
  try { return await readFile(filePath); } catch (error) { if (error.code === "ENOENT") return undefined; throw error; }
}

async function ensureEqualOrAbsent(filePath, bytes, label, structured = false) {
  const existing = await readExisting(filePath);
  if (!existing) return true;
  const matches = structured
    ? canonical(parseJson(existing, label)) === canonical(parseJson(bytes, label))
    : Buffer.compare(existing, bytes) === 0;
  if (!matches) throw new Error(`${label} already exists with different content`);
  return false;
}

async function inspectManifest(filePath, expectedBytes) {
  const existing = await readExisting(filePath);
  if (!existing) return true;
  const expected = parseJson(expectedBytes, "Release manifest");
  const current = parseJson(existing, "Release manifest");
  if (current.version === expected.version && canonical(current) !== canonical(expected)) {
    throw new Error("Release manifest conflicts with the same release version");
  }
  return canonical(current) !== canonical(expected);
}

async function atomicWrite(filePath, bytes) {
  await mkdir(path.dirname(filePath), { recursive: true });
  const temporary = `${filePath}.tmp-${process.pid}-${Date.now()}`;
  try {
    await writeFile(temporary, bytes, { flag: "wx" });
    await rename(temporary, filePath);
  } finally {
    await unlink(temporary).catch(() => {});
  }
}

async function acquireLock(repo) {
  const lockPath = path.join(repo, ".release-artifact.lock");
  try { await mkdir(lockPath); } catch (error) {
    if (error.code === "EEXIST") throw new Error("Release preparation is already locked; do not steal the lock");
    throw error;
  }
  return lockPath;
}

export async function prepareRelease(repo, descriptorPath) {
  const repository = path.resolve(repo);
  await rejectSymlinkAncestors(repository, true);
  if (!(await stat(repository)).isDirectory()) throw new Error("Repository path must be a directory");
  const candidate = await inspectCandidate(descriptorPath);
  const paths = releasePaths(candidate.descriptor);
  const normalized = structuredClone(candidate.descriptor);
  normalized.artifact.path = path.posix.relative(path.posix.dirname(paths.descriptor), paths.artifact);
  normalized.provenance.path = path.posix.relative(path.posix.dirname(paths.descriptor), paths.provenance);
  const descriptorBytes = Buffer.from(`${JSON.stringify(normalized, null, 2)}\n`);
  const manifestBytes = Buffer.from(`${JSON.stringify(publicManifest(normalized, paths), null, 2)}\n`);
  const targets = {
    artifact: path.join(repository, paths.artifact),
    provenance: path.join(repository, paths.provenance),
    descriptor: path.join(repository, paths.descriptor),
    manifest: path.join(repository, paths.manifest)
  };
  for (const target of Object.values(targets)) {
    if (path.relative(repository, target).startsWith("..")) throw new Error("Release target escapes repository");
    await rejectSymlinkAncestors(target, false);
  }
  const lockPath = await acquireLock(repository);
  try {
    const changes = await Promise.all([
      ensureEqualOrAbsent(targets.artifact, candidate.bytes, "Artifact"),
      ensureEqualOrAbsent(targets.provenance, candidate.provenanceBytes, "Provenance"),
      ensureEqualOrAbsent(targets.descriptor, descriptorBytes, "Release descriptor", true),
      inspectManifest(targets.manifest, manifestBytes)
    ]);
    if (changes[0]) await atomicWrite(targets.artifact, candidate.bytes);
    if (changes[1]) await atomicWrite(targets.provenance, candidate.provenanceBytes);
    if (changes[2]) await atomicWrite(targets.descriptor, descriptorBytes);
    if (changes[3]) await atomicWrite(targets.manifest, manifestBytes);
    return { descriptor: normalized, paths, changed: changes.some(Boolean) };
  } finally {
    await rmdir(lockPath).catch(() => {});
  }
}

function allowedRemoteUrl(baseUrl, candidate) {
  const base = new URL(baseUrl);
  if (base.protocol !== "https:" && !(base.protocol === "http:" && (base.hostname === "localhost" || base.hostname === "127.0.0.1" || base.hostname === "[::1]"))) {
    throw new Error("Remote verification requires HTTPS (HTTP is only allowed for localhost tests)");
  }
  const url = new URL(candidate, base);
  if (url.origin !== base.origin) throw new Error("Remote URL must have the same origin");
  return url;
}

async function timedFetch(fetchImpl, url, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try { return { response: await withTimeout(fetchImpl(url, { signal: controller.signal, redirect: "error" }), timeoutMs, "Remote request timed out"), controller, timer }; }
  catch (error) { clearTimeout(timer); throw new Error(`Remote request failed or timed out: ${error.message}`); }
}

function withTimeout(promise, timeoutMs, message) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(message)), timeoutMs);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

async function responseBytes(response, maximumSize, timeoutMs, exactSize = false) {
  const contentLength = response.headers?.get?.("content-length");
  if (contentLength && (!/^\d+$/.test(contentLength) || Number(contentLength) > maximumSize)) throw new Error("Remote response Content-Length exceeds allowed size");
  const deadline = Date.now() + timeoutMs;
  if (!response.body?.getReader) {
    const bytes = Buffer.from(await withTimeout(response.arrayBuffer(), timeoutMs, "Remote artifact stream timed out"));
    if ((exactSize && bytes.length !== maximumSize) || bytes.length > maximumSize) throw new Error("Remote response size does not match allowed size");
    return bytes;
  }
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw new Error("Remote artifact stream timed out");
      const next = await withTimeout(reader.read(), remaining, "Remote artifact stream timed out");
      if (next.done) break;
      const chunk = Buffer.from(next.value);
      size += chunk.length;
      if (size > maximumSize) throw new Error("Remote response exceeds allowed size");
      chunks.push(chunk);
    }
  } catch (error) {
    reader.cancel(error).catch(() => {});
    throw error;
  } finally { reader.releaseLock?.(); }
  const bytes = Buffer.concat(chunks);
  if (exactSize && bytes.length !== maximumSize) throw new Error("Remote artifact size does not match descriptor");
  return bytes;
}

export async function verifyRemote(baseUrl, descriptor, { fetchImpl = fetch, timeoutMs = 30000 } = {}) {
  validateDescriptor(descriptor);
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) throw new Error("timeoutMs must be a positive integer");
  const paths = releasePaths(descriptor);
  const base = allowedRemoteUrl(baseUrl, "/");
  const manifestUrl = allowedRemoteUrl(base, `/api/releases/${descriptor.channel}`);
  const manifestRequest = await timedFetch(fetchImpl, manifestUrl, timeoutMs);
  const manifestResponse = manifestRequest.response;
  if (!manifestResponse.ok) throw new Error(`Remote manifest returned HTTP ${manifestResponse.status}`);
  let manifestBytes;
  try { manifestBytes = await responseBytes(manifestResponse, 65536, timeoutMs); } finally { clearTimeout(manifestRequest.timer); }
  const manifest = parseJson(manifestBytes, "Remote manifest");
  const expected = publicManifest(descriptor, paths);
  for (const key of ["product", "channel", "version", "sha256", "size", "catalog_schema_version"]) {
    if (manifest[key] !== expected[key]) throw new Error(`Remote manifest ${key} does not match descriptor`);
  }
  if (typeof manifest.firmware_url !== "string") throw new Error("Remote manifest firmware_url is invalid");
  const firmwareUrl = allowedRemoteUrl(base, manifest.firmware_url);
  if (firmwareUrl.pathname !== expected.firmware_url) throw new Error("Remote manifest firmware_url does not match descriptor");
  const artifactRequest = await timedFetch(fetchImpl, firmwareUrl, timeoutMs);
  const artifactResponse = artifactRequest.response;
  if (!artifactResponse.ok) throw new Error(`Remote artifact returned HTTP ${artifactResponse.status}`);
  let bytes;
  try { bytes = await responseBytes(artifactResponse, descriptor.artifact.size, timeoutMs, true); } finally { clearTimeout(artifactRequest.timer); }
  const hash = sha256(bytes);
  if (hash !== descriptor.artifact.sha256) throw new Error("Remote artifact hash does not match descriptor");
  return { channel: descriptor.channel, manifest_url: manifestUrl.href, firmware_url: firmwareUrl.href, size: bytes.length, sha256: hash };
}
