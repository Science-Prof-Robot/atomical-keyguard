import { lstat, realpath, stat } from 'node:fs/promises';
import { isAbsolute, relative, resolve } from 'node:path';

const SLUG = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const WINDOWS_ABSOLUTE_PATH = /^(?:[A-Za-z]:[\\/]|[\\/]{1,2})/u;

/**
 * Validates the typed inputs for the optional Cloudflare Pages adapter. A
 * directory is returned both as a normalized relative value and as the
 * checked real path used only by that adapter's fixed runner.
 */
export async function validateCloudflarePagesParams(params, projectRoot) {
  const root = await canonicalRoot(projectRoot);
  const values = readParams(params);
  const directory = await validateDirectory(values.directory, root);
  const project = validateSlug(values.project);

  return Object.freeze({
    directory: relative(root, directory),
    directoryPath: directory,
    project,
  });
}

async function canonicalRoot(projectRoot) {
  if (typeof projectRoot !== 'string' || projectRoot.length === 0 || !isAbsolute(projectRoot)) {
    throw new Error('Project root is unavailable.');
  }

  try {
    const root = await realpath(projectRoot);
    const details = await lstat(root);
    if (!details.isDirectory() || details.isSymbolicLink()) {
      throw new Error('Project root is unavailable.');
    }
    return root;
  } catch (error) {
    if (error?.message === 'Project root is unavailable.') {
      throw error;
    }
    throw new Error('Project root is unavailable.');
  }
}

function readParams(params) {
  if (!isPlainObject(params)) {
    throw new Error('Action parameters are invalid.');
  }
  const keys = Object.keys(params).sort();
  if (keys.length !== 2 || keys[0] !== 'directory' || keys[1] !== 'project') {
    throw new Error('Action parameters are invalid.');
  }

  return {
    directory: ownDataValue(params, 'directory'),
    project: ownDataValue(params, 'project'),
  };
}

async function validateDirectory(value, root) {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.includes('\u0000')
    || isAbsolute(value)
    || WINDOWS_ABSOLUTE_PATH.test(value)
    || value.includes('\\')
  ) {
    throw new Error('Directory must be a relative path inside the project root.');
  }

  const segments = value.split('/');
  if (segments.some((segment) => segment === '' || segment === '.' || segment === '..')) {
    throw new Error('Directory must be a relative path inside the project root.');
  }

  const lexicalPath = resolve(root, value);
  if (!isContained(root, lexicalPath)) {
    throw new Error('Directory must be a relative path inside the project root.');
  }

  let resolvedDirectory;
  try {
    resolvedDirectory = await realpath(lexicalPath);
  } catch (error) {
    if (error?.code === 'ENOENT') {
      throw new Error('Relative path does not exist.');
    }
    throw new Error('Relative path is unavailable.');
  }
  if (!isContained(root, resolvedDirectory)) {
    throw new Error('Directory must resolve inside the project root.');
  }

  try {
    if (!(await stat(resolvedDirectory)).isDirectory()) {
      throw new Error('Relative path must resolve to a directory.');
    }
  } catch (error) {
    if (error?.message === 'Relative path must resolve to a directory.') {
      throw error;
    }
    throw new Error('Relative path is unavailable.');
  }

  return resolvedDirectory;
}

function validateSlug(value) {
  if (typeof value !== 'string' || !SLUG.test(value)) {
    throw new Error('Project must be a slug.');
  }
  return value;
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

function ownDataValue(object, key) {
  const descriptor = Object.getOwnPropertyDescriptor(object, key);
  if (descriptor === undefined || !Object.hasOwn(descriptor, 'value')) {
    throw new Error('Action parameters are invalid.');
  }
  return descriptor.value;
}
