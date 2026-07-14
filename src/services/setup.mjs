import { join, resolve } from 'node:path';

import { JsonStore } from '../storage/json-store.mjs';
import { defaultDataDirectory } from '../storage/sealed-vault.mjs';

const STORE_VERSION = 1;
const SETUP_SCOPES = new Set(['project', 'global', 'both']);

/**
 * Persists the small, nonsecret local setup decision. The private JsonStore
 * keeps this state local without making setup status a browser-only flag.
 */
export class SetupService {
  #ready;
  #snapshot;
  #storagePath;
  #store;

  constructor(options = {}) {
    if (!isPlainObject(options)) {
      throw new TypeError('Setup service options must be an object.');
    }
    const dataDirectory = options.dataDirectory ?? defaultDataDirectory();
    if (typeof dataDirectory !== 'string' || dataDirectory.length === 0) {
      throw new TypeError('dataDirectory must be a non-empty string.');
    }
    this.#storagePath = resolve(options.storagePath ?? join(dataDirectory, 'setup.json'));
    this.#store = options.store ?? new JsonStore(this.#storagePath);
    if (
      this.#store === null
      || typeof this.#store !== 'object'
      || typeof this.#store.initialize !== 'function'
      || typeof this.#store.update !== 'function'
    ) {
      throw new TypeError('setup store must implement initialize and update.');
    }
    this.#snapshot = project(emptyState());
    this.#ready = this.#store.initialize(emptyState()).then((state) => {
      validateState(state);
      this.#snapshot = project(state);
    });
  }

  static async open(options = {}) {
    const service = new SetupService(options);
    await service.#ready;
    return service;
  }

  get storagePath() {
    return this.#storagePath;
  }

  status() {
    return this.#snapshot;
  }

  async complete(scope) {
    const normalizedScope = requiredScope(scope);
    await this.#ready;
    const next = await this.#store.update((state) => {
      validateState(state);
      state.complete = true;
      state.scope = normalizedScope;
      return state;
    });
    validateState(next);
    this.#snapshot = project(next);
    return this.#snapshot;
  }
}

export function isSetupScope(value) {
  return typeof value === 'string' && SETUP_SCOPES.has(value);
}

function emptyState() {
  return { complete: false, scope: null, version: STORE_VERSION };
}

function requiredScope(value) {
  if (!isSetupScope(value)) {
    throw new TypeError('Setup scope must be project, global, or both.');
  }
  return value;
}

function validateState(state) {
  if (!isPlainObject(state)) {
    throw unavailable();
  }
  assertExactKeys(state, ['complete', 'scope', 'version']);
  if (state.version !== STORE_VERSION || typeof state.complete !== 'boolean') {
    throw unavailable();
  }
  if (state.complete) {
    requiredScopeForState(state.scope);
    return;
  }
  if (state.scope !== null) {
    throw unavailable();
  }
}

function requiredScopeForState(value) {
  if (!isSetupScope(value)) {
    throw unavailable();
  }
}

function project(state) {
  return Object.freeze(state.complete
    ? { complete: true, scope: state.scope }
    : { complete: false });
}

function assertExactKeys(value, expected) {
  const actual = Object.keys(value).sort();
  const keys = [...expected].sort();
  if (actual.length !== keys.length || actual.some((key, index) => key !== keys[index])) {
    throw unavailable();
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !Object.hasOwn(descriptor, 'value')) {
      throw unavailable();
    }
  }
}

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function unavailable() {
  return new Error('Setup state is unavailable.');
}
