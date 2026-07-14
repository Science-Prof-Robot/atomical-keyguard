import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstat, readFile, readlink, realpath } from 'node:fs/promises';
import { devNull } from 'node:os';
import { isAbsolute, relative, resolve } from 'node:path';
import { promisify } from 'node:util';

import { sha256 } from '../core/canonical.mjs';

const execFileAsync = promisify(execFile);
const GIT_OUTPUT_LIMIT = 2 * 1024 * 1024;
const UNAVAILABLE_MESSAGE = 'Git project inspection is unavailable.';

/**
 * Derives the current repository state with fixed Git commands. Callers may
 * nominate a directory to inspect, but cannot supply a repository identity,
 * commit, or dirty-worktree state.
 */
export class GitInspector {
  async inspect(projectRoot) {
    try {
      const requestedRoot = await canonicalDirectory(projectRoot);
      const reportedRoot = requiredLine(await runGit(requestedRoot, [
        'rev-parse',
        '--show-toplevel',
      ]));
      const root = await canonicalDirectory(reportedRoot);
      const commit = requiredLine(await runGit(root, ['rev-parse', 'HEAD']));

      if (!/^[a-f0-9]{40,64}$/u.test(commit)) {
        throw unavailable();
      }

      const [remoteOutput, status, diff, untrackedOutput] = await Promise.all([
        runGit(root, ['config', '--get', 'remote.origin.url'], { optional: true }),
        runGit(root, ['status', '--porcelain=v1', '--untracked-files=all', '-z']),
        runGit(root, ['diff', '--no-ext-diff', '--binary', 'HEAD', '--']),
        runGit(root, ['ls-files', '--others', '--exclude-standard', '-z']),
      ]);
      const untracked = await fingerprintUntrackedFiles(root, untrackedOutput);
      const remote = remoteOutput === undefined ? undefined : requiredLine(remoteOutput);

      return Object.freeze({
        commit,
        dirty: status.length > 0,
        dirtyFingerprint: fingerprintDirtyWorktree({ diff, status, untracked }),
        repositoryFingerprint: fingerprintRepository(root, remote),
        root,
      });
    } catch {
      throw unavailable();
    }
  }
}

async function canonicalDirectory(projectRoot) {
  if (typeof projectRoot !== 'string' || projectRoot.length === 0 || !isAbsolute(projectRoot)) {
    throw unavailable();
  }

  const resolved = await realpath(projectRoot);
  const details = await lstat(resolved);
  if (!details.isDirectory() || details.isSymbolicLink()) {
    throw unavailable();
  }
  return resolved;
}

async function runGit(cwd, args, { optional = false } = {}) {
  try {
    const { stdout } = await execFileAsync('git', ['-C', cwd, ...args], {
      encoding: 'buffer',
      env: gitEnvironment(),
      maxBuffer: GIT_OUTPUT_LIMIT,
      shell: false,
      windowsHide: true,
    });
    return Buffer.from(stdout);
  } catch (error) {
    if (optional && error?.code === 1) {
      return undefined;
    }
    throw unavailable();
  }
}

function gitEnvironment() {
  const environment = {
    GIT_CONFIG_GLOBAL: devNull,
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_OPTIONAL_LOCKS: '0',
    GIT_TERMINAL_PROMPT: '0',
    LANG: 'C',
    LC_ALL: 'C',
    PATH: process.env.PATH ?? '',
  };

  if (process.platform === 'win32' && process.env.SystemRoot !== undefined) {
    environment.SystemRoot = process.env.SystemRoot;
  }

  return environment;
}

function requiredLine(output) {
  const text = output.toString('utf8');
  if (!text.endsWith('\n')) {
    throw unavailable();
  }

  const line = text.slice(0, -1).replace(/\r$/u, '');
  if (line.length === 0 || line.includes('\n') || line.includes('\u0000')) {
    throw unavailable();
  }
  return line;
}

function fingerprintRepository(root, remote) {
  return fingerprint({
    kind: remote === undefined ? 'local-worktree' : 'origin-remote',
    value: remote === undefined ? root : remote,
  });
}

function fingerprintDirtyWorktree({ diff, status, untracked }) {
  return fingerprint({
    diff: diff.toString('base64'),
    status: status.toString('base64'),
    untracked,
    version: 1,
  });
}

async function fingerprintUntrackedFiles(root, output) {
  const paths = output
    .toString('utf8')
    .split('\u0000')
    .filter((candidate) => candidate.length > 0)
    .sort();
  const fingerprints = [];

  for (const path of paths) {
    if (path.includes('\u0000')) {
      throw unavailable();
    }

    const candidate = resolve(root, path);
    if (!isContained(root, candidate)) {
      throw unavailable();
    }

    const details = await lstat(candidate);
    if (details.isSymbolicLink()) {
      fingerprints.push({
        kind: 'symlink',
        path,
        value: digest(await readlink(candidate)),
      });
      continue;
    }
    if (!details.isFile()) {
      throw unavailable();
    }
    fingerprints.push({
      kind: 'file',
      path,
      value: digest(await readFile(candidate)),
    });
  }

  return fingerprints;
}

function isContained(root, candidate) {
  const pathFromRoot = relative(root, candidate);
  return pathFromRoot !== ''
    && pathFromRoot !== '..'
    && !pathFromRoot.startsWith(`..${String.fromCharCode(47)}`)
    && !pathFromRoot.startsWith(`..${String.fromCharCode(92)}`)
    && !isAbsolute(pathFromRoot);
}

function fingerprint(value) {
  return sha256(value);
}

function digest(value) {
  return createHash('sha256').update(value).digest('hex');
}

function unavailable() {
  return new Error(UNAVAILABLE_MESSAGE);
}
