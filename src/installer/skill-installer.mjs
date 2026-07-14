import { constants } from 'node:fs';
import { lstat, mkdir, open, realpath, unlink } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join, relative } from 'node:path';

import { canonicalJson } from '../core/canonical.mjs';
import {
  renderFieldManual,
  renderGuidanceShim,
  renderSkillTemplate,
  SHARED_MANUAL_RELATIVE_PATH,
  SKILL_DIRECTORY_NAME,
} from './templates.mjs';

const INSTALL_PLAN_VERSION = 1;
const HOSTS = Object.freeze(['claude', 'codex']);
const SCOPES = new Set(['project', 'global', 'both']);
const SHARING_MODES = new Set(['private', 'shared']);
const PRIVATE_FILE_MODE = 0o600;
const PRIVATE_DIRECTORY_MODE = 0o700;
const SHARED_FILE_MODE = 0o644;
const MAX_EXISTING_ARTIFACT_BYTES = 256 * 1024;
const UNSAFE_DIRECTORY_PERMISSION_MASK = 0o022;
const READ_NOFOLLOW_FLAGS = constants.O_RDONLY | constants.O_NOFOLLOW | (constants.O_NONBLOCK ?? 0);
const APPEND_NOFOLLOW_FLAGS = constants.O_RDWR | constants.O_APPEND | constants.O_NOFOLLOW | (constants.O_NONBLOCK ?? 0);

/**
 * Creates a reviewable, side-effect-free install plan. A project plan is
 * private by default and host choices default to detected/preselected hosts.
 */
export async function planInstall(selection = {}) {
  if (!isPlainObject(selection)) {
    throw new TypeError('Installer selection must be an object.');
  }
  const discovery = selection.discovery;
  if (discovery !== undefined && !isPlainObject(discovery)) {
    throw new TypeError('Installer discovery must be an object.');
  }
  const [projectRoot, homeDirectory] = await Promise.all([
    canonicalDirectory(selection.projectRoot ?? discovery?.projectRoot, 'projectRoot'),
    canonicalDirectory(selection.homeDirectory ?? discovery?.homeDirectory ?? homedir(), 'homeDirectory'),
  ]);
  const scope = selection.scope ?? 'project';
  const sharing = selection.sharing ?? 'private';
  if (!SCOPES.has(scope)) {
    throw new TypeError('Installer scope must be project, global, or both.');
  }
  if (!SHARING_MODES.has(sharing)) {
    throw new TypeError('Installer sharing must be private or shared.');
  }
  if (scope === 'both' && projectRoot === homeDirectory) {
    throw new TypeError('Installer projectRoot and homeDirectory must differ for both scope.');
  }
  const hosts = selectedHosts(selection.hosts, discovery);
  const files = installArtifacts({ homeDirectory, hosts, projectRoot, scope, sharing });
  return deepFreeze({
    files,
    homeDirectory,
    hosts,
    projectRoot,
    requiresConfirmation: true,
    requiresGlobalOptIn: scope === 'global' || scope === 'both',
    scope,
    sharing,
    version: INSTALL_PLAN_VERSION,
  });
}

/**
 * Applies only a plan that still exactly matches the fixed artifact layout.
 * Confirmation is deliberately separate from the preview, and global targets
 * require a second explicit opt-in.
 */
export async function applyInstall(plan, confirmation = {}) {
  if (!isPlainObject(confirmation)) {
    throw new TypeError('Installer confirmation must be an object.');
  }
  const validatedPlan = await validatePlan(plan);
  if (confirmation.confirmed !== true) {
    throw new Error('Installer confirmation is required before writing files.');
  }
  if (validatedPlan.requiresGlobalOptIn && confirmation.globalOptIn !== true) {
    throw new Error('Explicit global opt-in is required before writing global files.');
  }

  const operations = [];
  for (const file of validatedPlan.files) {
    operations.push(await inspectArtifact(file, validatedPlan.sharing));
  }
  const results = [];
  for (const operation of operations) {
    await applyArtifact(operation, validatedPlan.sharing);
    results.push(Object.freeze({ path: operation.file.path, status: operation.status }));
  }
  return deepFreeze({
    files: results,
    hosts: validatedPlan.hosts,
    scope: validatedPlan.scope,
    sharing: validatedPlan.sharing,
    status: 'installed',
  });
}

function selectedHosts(explicitHosts, discovery) {
  const candidates = explicitHosts ?? HOSTS.filter((host) => discovery?.hosts?.[host]?.preselected === true);
  if (!Array.isArray(candidates) || candidates.length === 0) {
    throw new TypeError('Installer requires at least one selected host.');
  }
  const hosts = [...new Set(candidates)].sort();
  if (hosts.some((host) => typeof host !== 'string' || !HOSTS.includes(host))) {
    throw new TypeError('Installer hosts must be Claude Code and/or Codex.');
  }
  return Object.freeze(hosts);
}

function installArtifacts({ homeDirectory, hosts, projectRoot, scope, sharing }) {
  const files = [];
  if (scope === 'project' || scope === 'both') {
    files.push(...scopeArtifacts({ hosts, root: projectRoot, scope: 'project' }));
    if (sharing === 'private') {
      files.push(gitignoreArtifact(projectRoot, hosts));
    }
  }
  if (scope === 'global' || scope === 'both') {
    files.push(...scopeArtifacts({ hosts, root: homeDirectory, scope: 'global' }));
  }
  return Object.freeze(files.map((file) => Object.freeze(file)));
}

function scopeArtifacts({ hosts, root, scope }) {
  const files = [{
    content: renderFieldManual(),
    kind: 'write',
    path: join(root, ...SHARED_MANUAL_RELATIVE_PATH.split('/')),
    root,
    scope,
  }];
  for (const host of hosts) {
    files.push({
      content: renderSkillTemplate(host),
      kind: 'write',
      path: skillPath(root, host),
      root,
      scope,
    });
    if (scope === 'project') {
      files.push({
        content: renderGuidanceShim(host),
        kind: 'write',
        path: join(root, host === 'claude' ? 'CLAUDE.local.md' : 'AGENTS.md'),
        root,
        scope,
      });
    }
  }
  return files;
}

function skillPath(root, host) {
  const segments = host === 'claude'
    ? ['.claude', 'skills', SKILL_DIRECTORY_NAME, 'SKILL.md']
    : ['.agents', 'skills', SKILL_DIRECTORY_NAME, 'SKILL.md'];
  return join(root, ...segments);
}

function gitignoreArtifact(projectRoot, hosts) {
  const entries = [`/.atomical/keyguard/`];
  if (hosts.includes('claude')) {
    entries.push('/.claude/skills/atomical-keyguard/', '/CLAUDE.local.md');
  }
  if (hosts.includes('codex')) {
    entries.push('/.agents/skills/atomical-keyguard/', '/AGENTS.md');
  }
  return {
    entries: Object.freeze(entries.sort()),
    kind: 'gitignore',
    path: join(projectRoot, '.gitignore'),
    root: projectRoot,
    scope: 'project',
  };
}

async function validatePlan(plan) {
  if (!isPlainObject(plan)) {
    throw new TypeError('Install plan is unavailable.');
  }
  let expected;
  try {
    expected = await planInstall({
      homeDirectory: plan.homeDirectory,
      hosts: plan.hosts,
      projectRoot: plan.projectRoot,
      scope: plan.scope,
      sharing: plan.sharing,
    });
  } catch {
    throw new TypeError('Install plan is unavailable.');
  }
  if (canonicalJson(plan) !== canonicalJson(expected)) {
    throw new TypeError('Install plan is unavailable.');
  }
  return expected;
}

async function inspectArtifact(file, sharing) {
  await validateSafeParent(file.path, file.root, false);
  if (file.kind === 'gitignore') {
    return inspectGitignore(file);
  }
  return inspectWrite(file, sharing);
}

async function inspectWrite(file, sharing) {
  const existing = await readExistingFile(file.path);
  if (existing === undefined) {
    return { file, status: 'written' };
  }
  if (existing.contents !== file.content) {
    throw new Error(`Installer will not overwrite existing file: ${file.path}`);
  }
  return {
    existing,
    file,
    status: sharing === 'private' && fileMode(existing.details) !== PRIVATE_FILE_MODE
      ? 'mode_repaired'
      : 'unchanged',
  };
}

async function inspectGitignore(file) {
  const existing = await readExistingFile(file.path);
  if (existing === undefined) {
    return {
      content: `${file.entries.join('\n')}\n`,
      file,
      status: 'written',
    };
  }
  const addition = gitignoreAddition(existing.contents, file.entries);
  return {
    addition,
    existing,
    file,
    status: addition.length === 0 ? 'unchanged' : 'updated',
  };
}

async function applyArtifact(operation, sharing) {
  const { file, status } = operation;
  if (status === 'unchanged') {
    return;
  }
  await ensureSafeParent(file.path, file.root);
  if (status === 'mode_repaired') {
    await repairPrivateFileMode(file, operation.existing);
    return;
  }
  if (file.kind === 'gitignore') {
    if (status === 'written') {
      const identity = await writeExclusive(file.path, operation.content, PRIVATE_FILE_MODE);
      await verifyWrittenArtifact(file.path, file.root, identity, true);
    } else {
      await appendSafe(file, operation.addition, operation.existing);
    }
    return;
  }
  const identity = await writeExclusive(
    file.path,
    file.content,
    sharing === 'private' ? PRIVATE_FILE_MODE : SHARED_FILE_MODE,
  );
  await verifyWrittenArtifact(file.path, file.root, identity, true);
}

async function ensureSafeParent(path, root) {
  await validateSafeParent(path, root, true);
}

async function validateSafeParent(path, root, createMissing) {
  const canonicalRoot = await canonicalDirectory(root, 'installer root');
  if (!isContained(canonicalRoot, path)) {
    throw new Error('Installer destination is outside the selected root.');
  }
  const relativeParent = relative(canonicalRoot, dirname(path));
  const segments = relativeParent.length === 0 ? [] : relativeParent.split(/[\\/]/u);
  let current = canonicalRoot;
  for (const segment of segments) {
    if (segment.length === 0 || segment === '.' || segment === '..') {
      throw new Error('Installer destination is outside the selected root.');
    }
    current = join(current, segment);
    let details;
    try {
      details = await lstat(current);
    } catch (error) {
      if (error?.code !== 'ENOENT') {
        throw error;
      }
      if (!createMissing) {
        return;
      }
      try {
        await mkdir(current, { mode: PRIVATE_DIRECTORY_MODE, recursive: false });
      } catch (mkdirError) {
        if (mkdirError?.code !== 'EEXIST') {
          throw mkdirError;
        }
      }
      details = await lstat(current);
    }
    if (!details.isDirectory() || details.isSymbolicLink()) {
      throw new Error('Installer destination contains a symbolic link or non-directory.');
    }
    assertPrivateDirectory(details, 'Installer destination');
    await assertContainedDirectory(canonicalRoot, current);
  }
}

async function writeExclusive(path, contents, mode) {
  let handle;
  try {
    handle = await open(
      path,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      mode,
    );
    await handle.writeFile(contents, 'utf8');
    return fileIdentity(await handle.stat());
  } finally {
    await handle?.close();
  }
}

async function appendSafe(file, contents, expected) {
  let handle;
  try {
    handle = await open(file.path, APPEND_NOFOLLOW_FLAGS);
    const details = await checkedRegularFile(handle, file.path);
    if (!sameFileIdentity(fileIdentity(details), expected.identity)) {
      throw new Error('Installer .gitignore changed after inspection.');
    }
    if (details.nlink !== 1) {
      throw new Error('Installer will not modify a multiply linked .gitignore.');
    }
    const current = await readBoundedUtf8(handle, details, file.path);
    if (current !== expected.contents) {
      throw new Error('Installer .gitignore changed after inspection.');
    }
    await handle.writeFile(contents, 'utf8');
    await verifyWrittenArtifact(file.path, file.root, fileIdentity(await handle.stat()), false);
  } finally {
    await handle?.close();
  }
}

async function readExistingFile(path) {
  let handle;
  try {
    handle = await open(path, READ_NOFOLLOW_FLAGS);
    const details = await checkedRegularFile(handle, path);
    return Object.freeze({
      contents: await readBoundedUtf8(handle, details, path),
      details: fileIdentity(details),
      identity: fileIdentity(details),
    });
  } catch (error) {
    if (error?.code === 'ENOENT') {
      return undefined;
    }
    throw error;
  } finally {
    await handle?.close();
  }
}

async function repairPrivateFileMode(file, expected) {
  let handle;
  try {
    handle = await open(file.path, READ_NOFOLLOW_FLAGS);
    const details = await checkedRegularFile(handle, file.path);
    if (!sameFileIdentity(fileIdentity(details), expected.identity)) {
      throw new Error(`Installer target changed after inspection: ${file.path}`);
    }
    if (details.nlink !== 1) {
      throw new Error(`Installer will not change mode on a multiply linked file: ${file.path}`);
    }
    if ((await readBoundedUtf8(handle, details, file.path)) !== expected.contents) {
      throw new Error(`Installer target changed after inspection: ${file.path}`);
    }
    await handle.chmod(PRIVATE_FILE_MODE);
    await verifyWrittenArtifact(file.path, file.root, fileIdentity(await handle.stat()), false);
  } finally {
    await handle?.close();
  }
}

async function checkedRegularFile(handle, path) {
  const details = await handle.stat();
  if (!details.isFile()) {
    throw new Error(`Installer target is not a regular file: ${path}`);
  }
  if (details.size > MAX_EXISTING_ARTIFACT_BYTES) {
    throw new Error(`Installer target is too large: ${path}`);
  }
  return details;
}

async function readBoundedUtf8(handle, details, path) {
  const size = details.size;
  const buffer = Buffer.alloc(size);
  let offset = 0;
  while (offset < size) {
    const { bytesRead } = await handle.read(buffer, offset, size - offset, offset);
    if (bytesRead === 0) {
      throw new Error(`Installer target changed while reading: ${path}`);
    }
    offset += bytesRead;
  }
  const extra = Buffer.alloc(1);
  const { bytesRead } = await handle.read(extra, 0, 1, size);
  if (bytesRead !== 0) {
    throw new Error(`Installer target is too large or changed while reading: ${path}`);
  }
  return buffer.toString('utf8');
}

async function verifyWrittenArtifact(path, root, identity, removeOnFailure) {
  try {
    const canonicalRoot = await canonicalDirectory(root, 'installer root');
    const canonicalPath = await realpath(path);
    const details = await lstat(canonicalPath);
    if (!isContained(canonicalRoot, canonicalPath) || !details.isFile() || !sameFileIdentity(fileIdentity(details), identity)) {
      throw new Error('invalid containment');
    }
  } catch {
    if (removeOnFailure) {
      await removeExpectedArtifact(path, identity);
    }
    throw new Error('Installer could not verify that a written artifact remains inside the selected root.');
  }
}

async function removeExpectedArtifact(path, identity) {
  try {
    const details = await lstat(path);
    if (details.isFile() && sameFileIdentity(fileIdentity(details), identity)) {
      await unlink(path);
    }
  } catch {
    // Best effort only: a hostile same-user filesystem race may have changed the path again.
  }
}

function gitignoreAddition(existing, entries) {
  const lines = new Set(existing.replaceAll('\r\n', '\n').split('\n'));
  const missing = entries.filter((entry) => !lines.has(entry));
  if (missing.length === 0) {
    return '';
  }
  return `${existing.length === 0 || existing.endsWith('\n') ? '' : '\n'}${missing.join('\n')}\n`;
}

async function canonicalDirectory(path, name) {
  if (typeof path !== 'string' || path.length === 0 || !isAbsolute(path)) {
    throw new TypeError(`${name} must be an existing absolute directory.`);
  }
  let initialDetails;
  let canonicalPath;
  let details;
  try {
    initialDetails = await lstat(path);
    canonicalPath = await realpath(path);
    details = await lstat(canonicalPath);
  } catch {
    throw new TypeError(`${name} must be an existing absolute directory.`);
  }
  if (!initialDetails.isDirectory() || initialDetails.isSymbolicLink()
    || !details.isDirectory() || details.isSymbolicLink()) {
    throw new TypeError(`${name} must be an existing absolute directory.`);
  }
  assertPrivateDirectory(details, `Installer ${name}`);
  return canonicalPath;
}

function assertPrivateDirectory(details, label) {
  if ((details.mode & UNSAFE_DIRECTORY_PERMISSION_MASK) !== 0) {
    throw new Error(`${label} must not be group- or world-writable.`);
  }
}

async function assertContainedDirectory(root, path) {
  const canonicalPath = await realpath(path);
  if (!isContained(root, canonicalPath)) {
    throw new Error('Installer destination contains a symbolic link or escapes the selected root.');
  }
}

function fileIdentity(details) {
  return Object.freeze({
    dev: details.dev,
    ino: details.ino,
    mode: details.mode,
    nlink: details.nlink,
    size: details.size,
  });
}

function sameFileIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function fileMode(details) {
  return details.mode & 0o777;
}

function isContained(root, candidate) {
  const fromRoot = relative(root, candidate);
  return fromRoot !== ''
    && fromRoot !== '..'
    && !fromRoot.startsWith(`..${String.fromCharCode(47)}`)
    && !fromRoot.startsWith(`..${String.fromCharCode(92)}`)
    && !isAbsolute(fromRoot);
}

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const nested of Object.values(value)) {
      deepFreeze(nested);
    }
  }
  return value;
}
