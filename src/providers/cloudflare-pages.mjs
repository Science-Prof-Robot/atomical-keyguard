import { execFile } from 'node:child_process';
import { lstat, realpath } from 'node:fs/promises';
import { isAbsolute, relative } from 'node:path';
import { promisify } from 'node:util';

import { redactSensitiveOutput } from '../core/redaction.mjs';

const DEFAULT_TIMEOUT_MILLISECONDS = 120_000;
const MAX_TIMEOUT_MILLISECONDS = 5 * 60 * 1000;
const OUTPUT_LIMIT = 64 * 1024;
const PROJECT_SLUG = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;

const defaultRunner = promisify(execFile);

/**
 * The only provider adapter in the MVP. The executable and every argument
 * other than daemon-validated target values are fixed in this module.
 */
export class CloudflarePagesAdapter {
  #runner;
  #timeoutMilliseconds;

  constructor(options = {}) {
    if (options === null || typeof options !== 'object' || Array.isArray(options)) {
      throw new TypeError('Cloudflare Pages adapter options must be an object.');
    }
    this.#runner = options.runner ?? defaultRunner;
    if (typeof this.#runner !== 'function') {
      throw new TypeError('runner must be a function.');
    }
    this.#timeoutMilliseconds = options.timeoutMilliseconds ?? DEFAULT_TIMEOUT_MILLISECONDS;
    if (
      !Number.isInteger(this.#timeoutMilliseconds)
      || this.#timeoutMilliseconds <= 0
      || this.#timeoutMilliseconds > MAX_TIMEOUT_MILLISECONDS
    ) {
      throw new TypeError('timeoutMilliseconds must be a bounded positive integer.');
    }
  }

  async execute({ projectRoot, directory, project, secret } = {}) {
    validateExecutionInput({ directory, project, projectRoot, secret });
    await revalidateFilesystemTarget({ directory, projectRoot });
    const args = Object.freeze([
      'wrangler',
      'pages',
      'deploy',
      directory,
      '--project-name',
      project,
    ]);
    const options = Object.freeze({
      cwd: projectRoot,
      encoding: 'utf8',
      env: childEnvironment(secret),
      maxBuffer: OUTPUT_LIMIT,
      shell: false,
      timeout: this.#timeoutMilliseconds,
      windowsHide: true,
    });

    try {
      const result = await this.#runner('npx', args, options);
      return providerResult({
        exitCode: 0,
        status: 'succeeded',
        stderr: safeOutput(result?.stderr, secret),
        stdout: safeOutput(result?.stdout, secret),
      });
    } catch (error) {
      return providerResult({
        exitCode: numericExitCode(error?.code),
        status: 'failed',
        stderr: firstNonEmptySafeOutput(error, secret),
        stdout: safeOutput(error?.stdout, secret),
      });
    }
  }
}

function validateExecutionInput({ directory, project, projectRoot, secret }) {
  if (
    typeof projectRoot !== 'string'
    || !isAbsolute(projectRoot)
    || typeof directory !== 'string'
    || !isAbsolute(directory)
    || !isContained(projectRoot, directory)
  ) {
    throw new TypeError('Provider target must be an absolute directory inside the project root.');
  }
  if (typeof project !== 'string' || !PROJECT_SLUG.test(project)) {
    throw new TypeError('Provider project must be a slug.');
  }
  if (typeof secret !== 'string' || secret.length === 0) {
    throw new TypeError('Provider credential is unavailable.');
  }
}

function childEnvironment(secret) {
  const environment = {
    CLOUDFLARE_API_TOKEN: secret,
    PATH: process.env.PATH ?? '',
  };
  if (process.platform === 'win32' && process.env.SystemRoot !== undefined) {
    environment.SystemRoot = process.env.SystemRoot;
  }
  return Object.freeze(environment);
}

async function revalidateFilesystemTarget({ directory, projectRoot }) {
  try {
    const resolvedRoot = await realpath(projectRoot);
    const rootDetails = await lstat(projectRoot);
    const resolvedDirectory = await realpath(directory);
    const directoryDetails = await lstat(directory);
    if (
      resolvedRoot !== projectRoot
      || !rootDetails.isDirectory()
      || rootDetails.isSymbolicLink()
      || resolvedDirectory !== directory
      || !isContained(resolvedRoot, resolvedDirectory)
      || !directoryDetails.isDirectory()
      || directoryDetails.isSymbolicLink()
    ) {
      throw new TypeError('Provider target must remain a real directory inside the project root.');
    }
  } catch (error) {
    if (error instanceof TypeError) {
      throw error;
    }
    throw new TypeError('Provider target must remain a real directory inside the project root.');
  }
}

function providerResult({ exitCode, status, stderr, stdout }) {
  return Object.freeze({ exitCode, status, stderr, stdout });
}

function firstNonEmptySafeOutput(error, secret) {
  for (const value of [error?.stderr, error?.message]) {
    const output = safeOutput(value, secret);
    if (output.length > 0) {
      return output;
    }
  }
  return '';
}

function safeOutput(value, secret) {
  const text = typeof value === 'string' ? value : '';
  if (text.length === 0) {
    return '';
  }
  try {
    return redactSensitiveOutput(text, secret);
  } catch {
    return '[REDACTED]';
  }
}

function numericExitCode(value) {
  return Number.isInteger(value) && value >= 0 ? value : null;
}

function isContained(root, candidate) {
  const fromRoot = relative(root, candidate);
  return fromRoot !== ''
    && fromRoot !== '..'
    && !fromRoot.startsWith(`..${String.fromCharCode(47)}`)
    && !fromRoot.startsWith(`..${String.fromCharCode(92)}`)
    && !isAbsolute(fromRoot);
}
