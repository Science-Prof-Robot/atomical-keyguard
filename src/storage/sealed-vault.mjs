import { Buffer } from 'node:buffer';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';

import { canonicalJson } from '../core/canonical.mjs';
import { JsonStore } from './json-store.mjs';

const ACTIVE = 'active';
const REVOKED = 'revoked';
const PRIVATE_FILE_MODE = 0o600;
const PRIVATE_DIRECTORY_MODE = 0o700;
const VAULT_VERSION = 1;
const GCM_IV_BYTES = 12;
const GCM_TAG_BYTES = 16;
const MASTER_KEY_BYTES = 32;
const CREDENTIAL_INSTANCE_ID_BYTES = 24;

export function defaultDataDirectory() {
  return join(homedir(), '.atomical-keyguard');
}

/**
 * Stores credentials as authenticated AES-256-GCM envelopes. Its public methods
 * intentionally return reconstructed projections, never stored records.
 */
export class SealedVault {
  #clock;
  #dataDirectory;
  #masterKey;
  #masterKeyPath;
  #ready;
  #storagePath;
  #store;

  constructor(options = {}) {
    const normalizedOptions = typeof options === 'string' ? { dataDirectory: options } : options;
    if (normalizedOptions === null || typeof normalizedOptions !== 'object') {
      throw new TypeError('SealedVault options must be an object.');
    }

    const dataDirectory = normalizedOptions.dataDirectory ?? defaultDataDirectory();
    if (typeof dataDirectory !== 'string' || dataDirectory.length === 0) {
      throw new TypeError('dataDirectory must be a non-empty string.');
    }

    this.#dataDirectory = resolve(dataDirectory);
    this.#masterKeyPath = resolve(
      normalizedOptions.masterKeyPath ?? join(this.#dataDirectory, 'master.key'),
    );
    this.#storagePath = resolve(
      normalizedOptions.storagePath ?? join(this.#dataDirectory, 'credentials.json'),
    );
    if (this.#masterKeyPath === this.#storagePath) {
      throw new TypeError('masterKeyPath and storagePath must be different.');
    }

    this.#clock = normalizedOptions.clock ?? { now: () => new Date() };
    if (typeof this.#clock.now !== 'function') {
      throw new TypeError('clock.now must be a function.');
    }

    this.#store = new JsonStore(this.#storagePath);
    this.#ready = this.#initialize();
  }

  static async open(options = {}) {
    const vault = new SealedVault(options);
    await vault.#ready;
    return vault;
  }

  get masterKeyPath() {
    return this.#masterKeyPath;
  }

  get storagePath() {
    return this.#storagePath;
  }

  async put(metadata, secret) {
    await this.#ready;
    const normalizedMetadata = normalizeMetadata(metadata);
    const normalizedSecret = normalizeSecret(secret);
    const label = normalizedMetadata.label;
    const now = this.#timestamp();
    let projection;

    await this.#store.update((state) => {
      validateState(state);
      if (state.credentials.some((record) => record.label === label)) {
        throw new Error('Credential label is already in use.');
      }

      const record = this.#seal({
        createdAt: now,
        instanceId: newCredentialInstanceId(),
        label,
        metadata: normalizedMetadata,
        secret: normalizedSecret,
        status: ACTIVE,
        updatedAt: now,
      });
      state.credentials.push(record);
      projection = project(record);
      return state;
    });

    return projection;
  }

  /**
   * Atomically seals a new credential only when the caller's previously read
   * public instance is still current. The caller's possession of that exact
   * public instance ID is the explicit replacement intent; a delayed handoff
   * cannot overwrite an intervening active or revoked replacement.
   */
  async putIfCurrentInstance(metadata, secret, expectedInstanceId) {
    await this.#ready;
    const normalizedMetadata = normalizeMetadata(metadata);
    const normalizedSecret = normalizeSecret(secret);
    const normalizedExpectedInstanceId = normalizeExpectedInstanceId(expectedInstanceId);
    const label = normalizedMetadata.label;
    const now = this.#timestamp();
    let projection;

    await this.#store.update((state) => {
      validateState(state);
      const index = state.credentials.findIndex((record) => record.label === label);
      if (normalizedExpectedInstanceId === null) {
        if (index !== -1) {
          throw credentialUnavailable();
        }
      } else {
        if (index === -1) {
          throw credentialUnavailable();
        }
        const existing = state.credentials[index];
        if (existing.instanceId !== normalizedExpectedInstanceId) {
          throw credentialUnavailable();
        }
        this.#unseal(existing);
      }

      const replacement = this.#seal({
        createdAt: now,
        instanceId: newCredentialInstanceId(),
        label,
        metadata: normalizedMetadata,
        secret: normalizedSecret,
        status: ACTIVE,
        updatedAt: now,
      });
      if (index === -1) {
        state.credentials.push(replacement);
      } else {
        state.credentials[index] = replacement;
      }
      projection = project(replacement);
      return state;
    });

    return projection;
  }

  async list() {
    await this.#ready;
    const state = await this.#readVerifiedState();
    return state.credentials.map(project);
  }

  /**
   * Returns the active opaque credential instance only when the caller's
   * reviewed `{ label, provider }` binding matches the sealed metadata. This
   * lets policy and approval services test a binding without reading a secret.
   */
  async getActiveCredentialBinding(binding) {
    await this.#ready;
    const normalizedBinding = normalizeExecutionBinding(binding, { providerRequired: true });
    const state = await this.#readState();
    const record = state.credentials.find((candidate) => candidate.label === normalizedBinding.label);
    if (record === undefined || record.status !== ACTIVE) {
      return undefined;
    }
    const payload = this.#unseal(record);
    if (payload.metadata.provider !== normalizedBinding.provider) {
      return undefined;
    }
    return Object.freeze({
      instanceId: record.instanceId,
      label: normalizedBinding.label,
      provider: normalizedBinding.provider,
    });
  }

  async readForExecution(binding) {
    await this.#ready;
    const normalizedBinding = normalizeExecutionBinding(binding);
    const state = await this.#readState();
    const record = state.credentials.find((candidate) => candidate.label === normalizedBinding.label);

    if (record === undefined || record.status !== ACTIVE) {
      throw credentialUnavailable();
    }

    const payload = this.#unseal(record);
    if (
      normalizedBinding.provider !== undefined
      && payload.metadata.provider !== normalizedBinding.provider
    ) {
      throw credentialUnavailable();
    }
    return payload.secret;
  }

  async revoke(label) {
    await this.#ready;
    const normalizedLabel = normalizeLabel(label);
    let projection;

    await this.#store.update((state) => {
      validateState(state);
      const index = state.credentials.findIndex((record) => record.label === normalizedLabel);
      if (index === -1) {
        throw credentialUnavailable();
      }

      const existing = state.credentials[index];
      const payload = this.#unseal(existing);
      if (existing.status === REVOKED) {
        projection = project(existing);
        return state;
      }

      const replacement = this.#seal({
        createdAt: existing.createdAt,
        instanceId: existing.instanceId,
        label: existing.label,
        metadata: payload.metadata,
        secret: payload.secret,
        status: REVOKED,
        updatedAt: this.#timestamp(),
      });
      state.credentials[index] = replacement;
      projection = project(replacement);
      return state;
    });

    return projection;
  }

  async delete(label) {
    await this.#ready;
    const normalizedLabel = normalizeLabel(label);
    let deleted = false;

    await this.#store.update((state) => {
      validateState(state);
      const index = state.credentials.findIndex((record) => record.label === normalizedLabel);
      if (index === -1) {
        return state;
      }

      this.#unseal(state.credentials[index]);
      state.credentials.splice(index, 1);
      deleted = true;
      return state;
    });

    return deleted;
  }

  async #initialize() {
    await ensurePrivateDirectory(this.#dataDirectory);
    this.#masterKey = await loadOrCreateMasterKey(this.#masterKeyPath);
    const state = await this.#store.initialize(emptyState());
    validateState(state);
    for (const record of state.credentials) {
      this.#unseal(record);
    }
  }

  async #readState() {
    const state = await this.#store.read();
    try {
      validateState(state);
      return state;
    } catch {
      throw credentialUnavailable();
    }
  }

  async #readVerifiedState() {
    const state = await this.#readState();
    for (const record of state.credentials) {
      this.#unseal(record);
    }
    return state;
  }

  #seal({ createdAt, instanceId, label, metadata, secret, status, updatedAt }) {
    decodeBase64url(instanceId, CREDENTIAL_INSTANCE_ID_BYTES);
    const record = {
      createdAt,
      instanceId,
      label,
      sealed: {},
      status,
      updatedAt,
      version: VAULT_VERSION,
    };
    const plaintext = Buffer.from(canonicalJson({ metadata, secret }), 'utf8');
    const iv = randomBytes(GCM_IV_BYTES);

    try {
      const cipher = createCipheriv('aes-256-gcm', this.#masterKey, iv);
      cipher.setAAD(Buffer.from(canonicalJson(authenticatedFields(record)), 'utf8'));
      const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      record.sealed = {
        authTag: cipher.getAuthTag().toString('base64url'),
        ciphertext: ciphertext.toString('base64url'),
        iv: iv.toString('base64url'),
      };
      return record;
    } catch {
      throw credentialUnavailable();
    }
  }

  #unseal(record) {
    try {
      validateRecord(record);
      const iv = decodeBase64url(record.sealed.iv, GCM_IV_BYTES);
      const authTag = decodeBase64url(record.sealed.authTag, GCM_TAG_BYTES);
      const ciphertext = decodeBase64url(record.sealed.ciphertext);
      const decipher = createDecipheriv('aes-256-gcm', this.#masterKey, iv);
      decipher.setAAD(Buffer.from(canonicalJson(authenticatedFields(record)), 'utf8'));
      decipher.setAuthTag(authTag);
      const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      const payload = JSON.parse(plaintext.toString('utf8'));
      const metadata = normalizeMetadata(payload?.metadata);
      const secret = normalizeSecret(payload?.secret);

      if (metadata.label !== record.label) {
        throw credentialUnavailable();
      }

      return { metadata, secret };
    } catch {
      throw credentialUnavailable();
    }
  }

  #timestamp() {
    try {
      const now = this.#clock.now();
      if (!(now instanceof Date) || Number.isNaN(now.valueOf())) {
        throw new TypeError('clock.now must return a valid Date.');
      }
      return now.toISOString();
    } catch {
      throw new Error('Credential clock is unavailable.');
    }
  }
}

function emptyState() {
  return { credentials: [], version: VAULT_VERSION };
}

function authenticatedFields(record) {
  return {
    createdAt: record.createdAt,
    instanceId: record.instanceId,
    label: record.label,
    status: record.status,
    updatedAt: record.updatedAt,
    version: record.version,
  };
}

function project(record) {
  return Object.freeze({
    createdAt: record.createdAt,
    instanceId: record.instanceId,
    label: record.label,
    status: record.status,
    updatedAt: record.updatedAt,
  });
}

function normalizeMetadata(metadata) {
  if (!isPlainObject(metadata)) {
    throw new TypeError('Credential metadata must be a plain object.');
  }

  const label = normalizeLabel(metadata.label);
  try {
    const normalized = JSON.parse(canonicalJson(metadata));
    if (normalized.label !== label) {
      throw new TypeError('Credential metadata label is invalid.');
    }
    return normalized;
  } catch (error) {
    if (error instanceof TypeError && error.message === 'Credential metadata label is invalid.') {
      throw error;
    }
    throw new TypeError('Credential metadata must contain canonical JSON data.');
  }
}

function normalizeLabel(label) {
  if (
    typeof label !== 'string'
    || label.length === 0
    || label.length > 128
    || label !== label.trim()
    || /[\u0000-\u001f]/u.test(label)
  ) {
    throw new TypeError('Credential label must be a non-empty printable string.');
  }
  return label;
}

function normalizeExecutionBinding(value, { providerRequired = false } = {}) {
  if (typeof value === 'string') {
    if (providerRequired) {
      throw new TypeError('Credential provider binding is required.');
    }
    return Object.freeze({ label: normalizeLabel(value), provider: undefined });
  }
  if (!isPlainObject(value)) {
    throw new TypeError('Credential execution binding must be a label or binding object.');
  }
  const keys = Object.keys(value).sort();
  if (keys.length !== 2 || keys[0] !== 'label' || keys[1] !== 'provider') {
    throw new TypeError('Credential execution binding is invalid.');
  }
  const label = normalizeLabel(value.label);
  const provider = value.provider;
  if (typeof provider !== 'string' || !/^[a-z0-9][a-z0-9-]{0,63}$/u.test(provider)) {
    throw new TypeError('Credential execution binding is invalid.');
  }
  return Object.freeze({ label, provider });
}

function normalizeSecret(secret) {
  if (typeof secret !== 'string' || secret.length === 0) {
    throw new TypeError('Credential secret must be a non-empty string.');
  }
  return secret;
}

function normalizeExpectedInstanceId(value) {
  if (value === null) {
    return null;
  }
  decodeBase64url(value, CREDENTIAL_INSTANCE_ID_BYTES);
  return value;
}

function validateState(state) {
  if (!isPlainObject(state) || state.version !== VAULT_VERSION || !Array.isArray(state.credentials)) {
    throw credentialUnavailable();
  }

  const labels = new Set();
  for (const record of state.credentials) {
    validateRecord(record);
    if (labels.has(record.label)) {
      throw credentialUnavailable();
    }
    labels.add(record.label);
  }
}

function validateRecord(record) {
  if (!isPlainObject(record)) {
    throw credentialUnavailable();
  }
  normalizeLabel(record.label);
  if (record.version !== VAULT_VERSION || ![ACTIVE, REVOKED].includes(record.status)) {
    throw credentialUnavailable();
  }
  if (typeof record.createdAt !== 'string' || typeof record.updatedAt !== 'string') {
    throw credentialUnavailable();
  }
  decodeBase64url(record.instanceId, CREDENTIAL_INSTANCE_ID_BYTES);
  if (!isPlainObject(record.sealed)) {
    throw credentialUnavailable();
  }
  decodeBase64url(record.sealed.iv, GCM_IV_BYTES);
  decodeBase64url(record.sealed.authTag, GCM_TAG_BYTES);
  decodeBase64url(record.sealed.ciphertext);
}

function newCredentialInstanceId() {
  return randomBytes(CREDENTIAL_INSTANCE_ID_BYTES).toString('base64url');
}

function decodeBase64url(value, expectedLength) {
  if (typeof value !== 'string' || value.length === 0 || !/^[A-Za-z0-9_-]+$/u.test(value)) {
    throw credentialUnavailable();
  }

  const decoded = Buffer.from(value, 'base64url');
  if (decoded.length === 0 || decoded.toString('base64url') !== value) {
    throw credentialUnavailable();
  }
  if (expectedLength !== undefined && decoded.length !== expectedLength) {
    throw credentialUnavailable();
  }
  return decoded;
}

function isPlainObject(value) {
  if (value === null || typeof value !== 'object') {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

async function ensurePrivateDirectory(directoryPath) {
  try {
    await mkdir(directoryPath, { mode: PRIVATE_DIRECTORY_MODE, recursive: true });
    const details = await lstat(directoryPath);
    if (
      !details.isDirectory()
      || details.isSymbolicLink()
      || (details.mode & 0o022) !== 0
    ) {
      throw credentialUnavailable();
    }
  } catch {
    throw credentialUnavailable();
  }
}

async function loadOrCreateMasterKey(masterKeyPath) {
  await ensurePrivateDirectory(dirname(masterKeyPath));

  let handle;
  try {
    handle = await open(
      masterKeyPath,
      constants.O_RDONLY | constants.O_NOFOLLOW,
    );
    const details = await handle.stat();
    if (!details.isFile()) {
      throw credentialUnavailable();
    }
    await handle.chmod(PRIVATE_FILE_MODE);
    const key = await handle.readFile();
    if (key.length !== MASTER_KEY_BYTES) {
      throw credentialUnavailable();
    }
    return key;
  } catch (error) {
    if (error?.code !== 'ENOENT') {
      throw credentialUnavailable();
    }
  } finally {
    await handle?.close().catch(() => undefined);
  }

  const key = randomBytes(MASTER_KEY_BYTES);
  try {
    handle = await open(
      masterKeyPath,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      PRIVATE_FILE_MODE,
    );
    await handle.chmod(PRIVATE_FILE_MODE);
    await handle.writeFile(key);
    await handle.sync();
    return key;
  } catch (error) {
    if (error?.code === 'EEXIST') {
      return loadOrCreateMasterKey(masterKeyPath);
    }
    throw credentialUnavailable();
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

function credentialUnavailable() {
  return new Error('Credential is not available for execution.');
}
