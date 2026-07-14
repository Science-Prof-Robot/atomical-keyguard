import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import { homedir } from 'node:os';
import { delimiter, dirname, isAbsolute, join } from 'node:path';

import { SKILL_DIRECTORY_NAME, hostInvocation } from './templates.mjs';

const HOSTS = Object.freeze({
  claude: Object.freeze({
    configurationDirectories: ['.claude'],
    executable: 'claude',
    globalSkillDirectory: ['.claude', 'skills', SKILL_DIRECTORY_NAME],
    projectSkillDirectory: ['.claude', 'skills', SKILL_DIRECTORY_NAME],
  }),
  codex: Object.freeze({
    configurationDirectories: ['.codex', '.agents'],
    executable: 'codex',
    globalSkillDirectory: ['.agents', 'skills', SKILL_DIRECTORY_NAME],
    projectSkillDirectory: ['.agents', 'skills', SKILL_DIRECTORY_NAME],
  }),
});

const MCP_CONFIGURATION_PATHS = Object.freeze([
  ['.mcp.json'],
  ['.claude.json'],
  ['.claude', 'settings.json'],
  ['.codex', 'config.toml'],
]);
const PROJECT_POLICY_PATHS = Object.freeze([
  ['.atomical', 'keyguard', 'policy.json'],
  ['keyguard.policy.json'],
]);
const MAX_CONFIGURATION_BYTES = 256 * 1024;
const READ_NOFOLLOW_FLAGS = constants.O_RDONLY | constants.O_NOFOLLOW | (constants.O_NONBLOCK ?? 0);

/**
 * Performs filesystem-only environment discovery. The result intentionally
 * contains presence/status data rather than configuration contents, credential
 * material, or a command to execute.
 */
export async function discoverEnvironment(projectRoot, options = {}) {
  if (!isPlainObject(options)) {
    throw new TypeError('Environment discovery options must be an object.');
  }
  const [canonicalProjectRoot, canonicalHomeDirectory] = await Promise.all([
    canonicalDirectory(projectRoot, 'projectRoot'),
    canonicalDirectory(options.homeDirectory ?? homedir(), 'homeDirectory'),
  ]);
  const environment = normalizedEnvironment(options.environment);
  const [repository, hosts, mcp, policy, atomicCli] = await Promise.all([
    discoverRepository(canonicalProjectRoot),
    discoverHosts(canonicalProjectRoot, canonicalHomeDirectory, environment),
    discoverMcpRegistration(canonicalProjectRoot, canonicalHomeDirectory),
    discoverPolicy(canonicalProjectRoot, options),
    discoverExecutable('atomic', environment),
  ]);
  const result = {
    atomicCli,
    homeDirectory: canonicalHomeDirectory,
    hosts,
    identity: identityStatus(options.identity),
    mcp,
    policy,
    projectRoot: canonicalProjectRoot,
    repository,
  };
  return deepFreeze(result);
}

async function discoverRepository(projectRoot) {
  let candidate = projectRoot;
  for (;;) {
    if (await gitMarkerExists(join(candidate, '.git'))) {
      return Object.freeze({ detected: true, root: candidate });
    }
    const parent = dirname(candidate);
    if (parent === candidate) {
      return Object.freeze({ detected: false, root: null });
    }
    candidate = parent;
  }
}

async function discoverHosts(projectRoot, homeDirectory, environment) {
  const entries = await Promise.all(Object.entries(HOSTS).map(async ([host, details]) => {
    const [executable, globalSkill, projectSkill, configurationPresent] = await Promise.all([
      discoverExecutable(details.executable, environment),
      directoryExists(join(homeDirectory, ...details.globalSkillDirectory)),
      directoryExists(join(projectRoot, ...details.projectSkillDirectory)),
      hostConfigurationExists(details.configurationDirectories, projectRoot, homeDirectory),
    ]);
    const detected = executable.detected || configurationPresent || globalSkill || projectSkill;
    return [host, Object.freeze({
      detected,
      globalSkill,
      invocation: hostInvocation(host),
      preselected: detected,
      projectSkill,
    })];
  }));
  return Object.freeze(Object.fromEntries(entries));
}

async function hostConfigurationExists(paths, projectRoot, homeDirectory) {
  const candidates = [];
  for (const path of paths) {
    candidates.push(join(homeDirectory, path), join(projectRoot, path));
  }
  const values = await Promise.all(candidates.map((candidate) => directoryExists(candidate)));
  return values.some(Boolean);
}

async function discoverMcpRegistration(projectRoot, homeDirectory) {
  const candidates = [];
  for (const segments of MCP_CONFIGURATION_PATHS) {
    candidates.push(join(projectRoot, ...segments), join(homeDirectory, ...segments));
  }
  const registered = (await Promise.all(candidates.map(configurationMentionsKeyguard))).some(Boolean);
  return Object.freeze({ registered });
}

async function discoverPolicy(projectRoot, options) {
  const suppliedVersion = policyVersion(options);
  for (const segments of PROJECT_POLICY_PATHS) {
    const path = join(projectRoot, ...segments);
    const contents = await readSafeText(path);
    if (contents === undefined) {
      continue;
    }
    return Object.freeze({
      active: true,
      path,
      version: versionFromPolicy(contents) ?? suppliedVersion,
    });
  }
  return Object.freeze({
    active: suppliedVersion !== null,
    path: null,
    version: suppliedVersion,
  });
}

function policyVersion(options) {
  const value = options.policy?.version
    ?? options.policy?.policyVersion
    ?? options.policyVersion
    ?? options.actionRegistry?.policyVersion;
  return Number.isInteger(value) && value >= 0 ? value : null;
}

function versionFromPolicy(contents) {
  try {
    const policy = JSON.parse(contents);
    const version = policy?.version ?? policy?.policyVersion;
    return Number.isInteger(version) && version >= 0 ? version : null;
  } catch {
    return null;
  }
}

function identityStatus(identity) {
  const fingerprint = identity?.fingerprint;
  if (typeof fingerprint === 'string' && /^[a-f0-9]{64}$/u.test(fingerprint)) {
    return Object.freeze({ available: true, fingerprint });
  }
  return Object.freeze({ available: false, fingerprint: null });
}

async function discoverExecutable(name, environment) {
  const path = await executablePath(name, environment.PATH);
  return Object.freeze({ detected: path !== null, path });
}

async function executablePath(name, pathValue) {
  if (typeof pathValue !== 'string' || pathValue.length === 0) {
    return null;
  }
  for (const directory of pathValue.split(delimiter)) {
    if (!isAbsolute(directory)) {
      continue;
    }
    const candidate = join(directory, name);
    try {
      const details = await lstat(candidate);
      if (
        details.isFile()
        && !details.isSymbolicLink()
        && (details.mode & 0o111) !== 0
      ) {
        return candidate;
      }
    } catch (error) {
      if (error?.code !== 'ENOENT' && error?.code !== 'ENOTDIR') {
        return null;
      }
    }
  }
  return null;
}

function normalizedEnvironment(environment) {
  if (environment === undefined) {
    return process.env;
  }
  if (!isPlainObject(environment)) {
    throw new TypeError('Environment discovery environment must be an object.');
  }
  return environment;
}

async function canonicalDirectory(path, name) {
  if (typeof path !== 'string' || path.length === 0 || !isAbsolute(path)) {
    throw new TypeError(`${name} must be an existing absolute directory.`);
  }
  try {
    const initialDetails = await lstat(path);
    if (!initialDetails.isDirectory() || initialDetails.isSymbolicLink()) {
      throw new Error('invalid directory');
    }
    const canonicalPath = await realpath(path);
    const details = await lstat(canonicalPath);
    if (!details.isDirectory() || details.isSymbolicLink()) {
      throw new Error('invalid directory');
    }
    return canonicalPath;
  } catch {
    throw new TypeError(`${name} must be an existing absolute directory.`);
  }
}

async function gitMarkerExists(path) {
  try {
    const details = await lstat(path);
    return !details.isSymbolicLink() && (details.isDirectory() || details.isFile());
  } catch (error) {
    if (error?.code === 'ENOENT' || error?.code === 'ENOTDIR') {
      return false;
    }
    return false;
  }
}

async function directoryExists(path) {
  try {
    const details = await lstat(path);
    return details.isDirectory() && !details.isSymbolicLink();
  } catch (error) {
    if (error?.code === 'ENOENT' || error?.code === 'ENOTDIR') {
      return false;
    }
    return false;
  }
}

async function configurationMentionsKeyguard(path) {
  const contents = await readSafeText(path);
  return contents?.includes('atomical-keyguard') === true;
}

async function readSafeText(path) {
  let handle;
  try {
    handle = await open(path, READ_NOFOLLOW_FLAGS);
    const details = await handle.stat();
    if (details.isSymbolicLink() || !details.isFile() || details.size > MAX_CONFIGURATION_BYTES) {
      return undefined;
    }
    return await readBoundedText(handle, details);
  } catch {
    return undefined;
  } finally {
    await handle?.close();
  }
}

async function readBoundedText(handle, details) {
  const size = details.size;
  const buffer = Buffer.alloc(size);
  let offset = 0;
  while (offset < size) {
    const { bytesRead } = await handle.read(buffer, offset, size - offset, offset);
    if (bytesRead === 0) {
      throw new Error('configuration changed while reading');
    }
    offset += bytesRead;
  }
  const extra = Buffer.alloc(1);
  const { bytesRead } = await handle.read(extra, 0, 1, size);
  if (bytesRead !== 0) {
    throw new Error('configuration grew while reading');
  }
  return buffer.toString('utf8');
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
