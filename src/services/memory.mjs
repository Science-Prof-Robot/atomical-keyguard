import { randomUUID } from 'node:crypto';
import { join, resolve } from 'node:path';

import { canonicalJson, sha256 } from '../core/canonical.mjs';
import { JsonStore } from '../storage/json-store.mjs';
import { defaultDataDirectory } from '../storage/sealed-vault.mjs';

const STORE_VERSION = 1;
const MEMORY_STATUSES = new Set(['candidate', 'saved', 'dismissed']);
const MAX_ACTION_DATA_LENGTH = 32 * 1024;

/**
 * Stores only deterministic, receipt-derived project memories. A candidate is
 * not automatically saved: callers must explicitly choose Save or Dismiss.
 */
export class MemoryService {
  #clock;
  #idGenerator;
  #identity;
  #ready;
  #storagePath;
  #store;

  constructor(options = {}) {
    if (options === null || typeof options !== 'object' || Array.isArray(options)) {
      throw new TypeError('Memory service options must be an object.');
    }
    const dataDirectory = options.dataDirectory ?? defaultDataDirectory();
    if (typeof dataDirectory !== 'string' || dataDirectory.length === 0) {
      throw new TypeError('dataDirectory must be a non-empty string.');
    }
    this.#identity = options.identity;
    if (
      this.#identity === null
      || typeof this.#identity !== 'object'
      || typeof this.#identity.fingerprint !== 'string'
      || typeof this.#identity.signCanonical !== 'function'
      || typeof this.#identity.verifyCanonical !== 'function'
    ) {
      throw new TypeError('Memory service requires a local identity.');
    }
    this.#storagePath = resolve(options.storagePath ?? join(dataDirectory, 'memory.json'));
    this.#clock = options.clock ?? { now: () => new Date() };
    if (typeof this.#clock.now !== 'function') {
      throw new TypeError('clock.now must be a function.');
    }
    this.#idGenerator = options.idGenerator ?? randomUUID;
    if (typeof this.#idGenerator !== 'function') {
      throw new TypeError('idGenerator must be a function.');
    }
    this.#store = options.store ?? new JsonStore(this.#storagePath);
    if (
      this.#store === null
      || typeof this.#store.initialize !== 'function'
      || typeof this.#store.read !== 'function'
      || typeof this.#store.update !== 'function'
    ) {
      throw new TypeError('store must implement initialize, read, and update.');
    }
    this.#ready = this.#store.initialize(emptyState()).then((state) => {
      validateState(state, this.#identity);
    });
  }

  static async open(options = {}) {
    const service = new MemoryService(options);
    await service.#ready;
    return service;
  }

  get storagePath() {
    return this.#storagePath;
  }

  async createVerifiedCandidate(receipt) {
    await this.#ready;
    const verifiedReceipt = verifiedReceiptProvenance(receipt, this.#identity);
    if (verifiedReceipt === undefined) {
      return undefined;
    }
    const now = this.#timestamp();
    const body = {
      createdAt: now,
      id: this.#newId(),
      scope: {
        kind: 'project',
        repositoryFingerprint: verifiedReceipt.body.repository.fingerprint,
      },
      sourceReceiptHash: verifiedReceipt.hash,
      sourceReceiptId: verifiedReceipt.body.id,
      sourceSignerFingerprint: verifiedReceipt.signerFingerprint,
      status: 'candidate',
      text: `Verified ${verifiedReceipt.body.action} action at ${verifiedReceipt.body.commit.slice(0, 12)}.`,
      updatedAt: now,
    };
    const record = { ...body, signature: this.#identity.signCanonical(body) };
    validateMemory(record, this.#identity);
    let result;

    await this.#store.update((state) => {
      validateState(state, this.#identity);
      state.memories.push(record);
      result = deepFreeze(cloneJson(record));
      return state;
    });
    return result;
  }

  async save(id) {
    return this.#setStatus(id, 'saved');
  }

  async dismiss(id) {
    return this.#setStatus(id, 'dismissed');
  }

  async list() {
    await this.#ready;
    const state = await this.#store.read();
    validateState(state, this.#identity);
    return Object.freeze(state.memories.map((record) => deepFreeze(cloneJson(record))));
  }

  async #setStatus(id, nextStatus) {
    await this.#ready;
    if (typeof id !== 'string' || !/^memory_[A-Za-z0-9_-]{8,128}$/u.test(id)) {
      throw memoryUnavailable();
    }
    let result;
    await this.#store.update((state) => {
      validateState(state, this.#identity);
      const record = state.memories.find((candidate) => candidate.id === id);
      if (record === undefined) {
        throw memoryUnavailable();
      }
      if (record.status === 'candidate') {
        record.status = nextStatus;
        record.updatedAt = this.#timestamp();
        record.signature = this.#identity.signCanonical(memoryBody(record));
      }
      validateMemory(record, this.#identity);
      result = deepFreeze(cloneJson(record));
      return state;
    });
    return result;
  }

  #newId() {
    const value = this.#idGenerator();
    if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{8,128}$/u.test(value)) {
      throw memoryUnavailable();
    }
    return `memory_${value}`;
  }

  #timestamp() {
    let now;
    try {
      now = this.#clock.now();
    } catch {
      throw memoryUnavailable();
    }
    if (!(now instanceof Date) || Number.isNaN(now.valueOf())) {
      throw memoryUnavailable();
    }
    return now.toISOString();
  }
}

function emptyState() {
  return { memories: [], version: STORE_VERSION };
}

function verifiedReceiptProvenance(receipt, identity) {
  try {
    if (!isPlainObject(receipt)) {
      return undefined;
    }
    const receiptKeys = RECEIPT_KEYS.filter((key) => (
      (key !== 'actionVersion' || Object.hasOwn(receipt, 'actionVersion'))
      && (key !== 'credentialProvider' || Object.hasOwn(receipt, 'credentialProvider'))
    ));
    assertExactKeys(receipt, receiptKeys);
    const body = receiptBody(receipt);
    validateReceiptBody(body);
    validateSignature(receipt.signature, identity);
    if (identity.verifyCanonical(body, receipt.signature) !== true) {
      return undefined;
    }
    if (
      body.provider.status !== 'succeeded'
      || body.verification.status !== 'verified'
      || body.secretExposedToModel !== false
      || body.agent.identity !== identity.fingerprint
    ) {
      return undefined;
    }
    return {
      body: cloneJson(body),
      hash: sha256(receipt),
      signerFingerprint: receipt.signature.fingerprint,
    };
  } catch {
    return undefined;
  }
}

const RECEIPT_KEYS = [
  'action',
  'actionVersion',
  'agent',
  'approval',
  'commit',
  'credentialLabel',
  'credentialProvider',
  'dirtyTreeAllowed',
  'id',
  'provider',
  'repository',
  'request',
  'retryOf',
  'secretExposedToModel',
  'signature',
  'target',
  'timestamps',
  'verification',
  'verificationOf',
];

function validateReceiptBody(body) {
  if (!isPlainObject(body)) {
    throw memoryUnavailable();
  }
  const keys = RECEIPT_KEYS.filter((key) => key !== 'signature');
  const expected = keys.filter((key) => (
    (key !== 'actionVersion' || Object.hasOwn(body, 'actionVersion'))
    && (key !== 'credentialProvider' || Object.hasOwn(body, 'credentialProvider'))
  ));
  assertExactKeys(body, expected);
  if (
    !validActionName(body.action)
    || !validId(body.id, 'receipt')
    || !validId(body.approval?.id, 'approval')
    || body.approval.status !== 'consumed'
    || !validId(body.request?.id, 'approval')
    || typeof body.request.envelopeHash !== 'string'
    || !/^[a-f0-9]{64}$/u.test(body.request.envelopeHash)
    || !validRequestSignature(body.request.signature)
    || typeof body.commit !== 'string'
    || !/^[a-f0-9]{40,64}$/u.test(body.commit)
    || !validCredentialLabel(body.credentialLabel)
    || typeof body.dirtyTreeAllowed !== 'boolean'
    || body.secretExposedToModel !== false
    || (body.retryOf !== null && !validId(body.retryOf, 'receipt'))
    || (body.verificationOf !== null && !validId(body.verificationOf, 'receipt'))
  ) {
    throw memoryUnavailable();
  }
  if (Object.hasOwn(body, 'actionVersion') && !validActionVersion(body.actionVersion)) {
    throw memoryUnavailable();
  }
  if (Object.hasOwn(body, 'credentialProvider') && !validCredentialProvider(body.credentialProvider)) {
    throw memoryUnavailable();
  }
  validateAgent(body.agent);
  validateRepository(body.repository);
  validateTarget(body.target);
  validateTimestampPair(body.timestamps);
  validateStatusRecord(body.provider, ['succeeded', 'failed', 'not_started']);
  validateStatusRecord(body.verification, ['verified', 'failed', 'not_run']);
}

function validateMemory(record, identity) {
  if (!isPlainObject(record)) {
    throw memoryUnavailable();
  }
  assertExactKeys(record, MEMORY_KEYS);
  const body = memoryBody(record);
  if (
    !validId(body.id, 'memory')
    || !validId(body.sourceReceiptId, 'receipt')
    || typeof body.sourceReceiptHash !== 'string'
    || !/^[a-f0-9]{64}$/u.test(body.sourceReceiptHash)
    || typeof body.sourceSignerFingerprint !== 'string'
    || !/^[a-f0-9]{64}$/u.test(body.sourceSignerFingerprint)
    || !MEMORY_STATUSES.has(body.status)
    || typeof body.createdAt !== 'string'
    || typeof body.updatedAt !== 'string'
    || typeof body.text !== 'string'
    || !validMemoryText(body.text)
  ) {
    throw memoryUnavailable();
  }
  timestampMilliseconds(body.createdAt);
  timestampMilliseconds(body.updatedAt);
  if (!isPlainObject(body.scope)) {
    throw memoryUnavailable();
  }
  assertExactKeys(body.scope, ['kind', 'repositoryFingerprint']);
  if (
    body.scope.kind !== 'project'
    || typeof body.scope.repositoryFingerprint !== 'string'
    || !/^[a-f0-9]{64}$/u.test(body.scope.repositoryFingerprint)
  ) {
    throw memoryUnavailable();
  }
  validateSignature(record.signature, identity);
  if (identity.verifyCanonical(body, record.signature) !== true) {
    throw memoryUnavailable();
  }
}

const MEMORY_KEYS = [
  'createdAt',
  'id',
  'scope',
  'signature',
  'sourceReceiptHash',
  'sourceReceiptId',
  'sourceSignerFingerprint',
  'status',
  'text',
  'updatedAt',
];

function validateState(state, identity) {
  if (!isPlainObject(state)) {
    throw memoryUnavailable();
  }
  assertExactKeys(state, ['memories', 'version']);
  if (state.version !== STORE_VERSION || !Array.isArray(state.memories)) {
    throw memoryUnavailable();
  }
  const ids = new Set();
  for (const memory of state.memories) {
    validateMemory(memory, identity);
    if (ids.has(memory.id)) {
      throw memoryUnavailable();
    }
    ids.add(memory.id);
  }
}

function validateAgent(agent) {
  if (!isPlainObject(agent)) {
    throw memoryUnavailable();
  }
  assertExactKeys(agent, ['id', 'identity']);
  if (
    typeof agent.id !== 'string'
    || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(agent.id)
    || typeof agent.identity !== 'string'
    || !/^[a-f0-9]{64}$/u.test(agent.identity)
  ) {
    throw memoryUnavailable();
  }
}

function validateRepository(repository) {
  if (!isPlainObject(repository)) {
    throw memoryUnavailable();
  }
  assertExactKeys(repository, ['fingerprint', 'root']);
  if (
    typeof repository.root !== 'string'
    || !repository.root.startsWith('/')
    || typeof repository.fingerprint !== 'string'
    || !/^[a-f0-9]{64}$/u.test(repository.fingerprint)
  ) {
    throw memoryUnavailable();
  }
}

function validateTarget(target) {
  validateActionData(target);
}

function validateTimestampPair(timestamps) {
  if (!isPlainObject(timestamps)) {
    throw memoryUnavailable();
  }
  assertExactKeys(timestamps, ['executedAt', 'requestedAt']);
  timestampMilliseconds(timestamps.executedAt);
  timestampMilliseconds(timestamps.requestedAt);
}

function validateStatusRecord(value, allowedStatuses) {
  if (!isPlainObject(value)) {
    throw memoryUnavailable();
  }
  assertExactKeys(value, ['status']);
  if (!allowedStatuses.includes(value.status)) {
    throw memoryUnavailable();
  }
}

function validateActionData(value) {
  if (!isPlainObject(value)) {
    throw memoryUnavailable();
  }
  try {
    if (canonicalJson(value).length > MAX_ACTION_DATA_LENGTH) {
      throw new Error('Action data is too large.');
    }
  } catch {
    throw memoryUnavailable();
  }
}

function validActionName(value) {
  return typeof value === 'string' && /^[a-z][a-z0-9_]{2,127}$/u.test(value);
}

function validActionVersion(value) {
  return Number.isInteger(value) && value >= 1 && value <= 1_000_000;
}

function validCredentialLabel(value) {
  return typeof value === 'string'
    && value.length > 0
    && value.length <= 128
    && value === value.trim()
    && !/[\u0000-\u001f]/u.test(value);
}

function validCredentialProvider(value) {
  return typeof value === 'string' && /^[a-z0-9][a-z0-9-]{0,63}$/u.test(value);
}

function validMemoryText(value) {
  return typeof value === 'string' && (
    /^Verified [a-z][a-z0-9_]{2,127} action at [a-f0-9]{12}\.$/u.test(value)
    // Legacy signed memories remain readable after the switch to generic
    // action wording; new records always use the first pattern.
    || /^Verified [A-Za-z0-9 _-]{1,128} deployment for [a-z0-9-]+ at [a-f0-9]{12}\.$/u.test(value)
  );
}

function validRequestSignature(value) {
  if (!isPlainObject(value)) {
    return false;
  }
  const keys = Object.keys(value).sort();
  return keys.length === 3
    && keys[0] === 'algorithm'
    && keys[1] === 'fingerprint'
    && keys[2] === 'signature'
    && value.algorithm === 'ed25519'
    && typeof value.fingerprint === 'string'
    && /^[a-f0-9]{64}$/u.test(value.fingerprint)
    && typeof value.signature === 'string'
    && /^[A-Za-z0-9_-]+$/u.test(value.signature);
}

function validateRequestSignature(value) {
  if (!isPlainObject(value)) {
    return false;
  }
  const keys = Object.keys(value).sort();
  return keys.length === 3
    && keys[0] === 'algorithm'
    && keys[1] === 'fingerprint'
    && keys[2] === 'signature'
    && value.algorithm === 'ed25519'
    && typeof value.fingerprint === 'string'
    && /^[a-f0-9]{64}$/u.test(value.fingerprint)
    && typeof value.signature === 'string'
    && /^[A-Za-z0-9_-]+$/u.test(value.signature);
}

function validateSignature(value, identity) {
  if (!isPlainObject(value)) {
    throw memoryUnavailable();
  }
  assertExactKeys(value, ['algorithm', 'fingerprint', 'signature']);
  if (
    value.algorithm !== 'ed25519'
    || value.fingerprint !== identity.fingerprint
    || typeof value.signature !== 'string'
    || !/^[A-Za-z0-9_-]+$/u.test(value.signature)
  ) {
    throw memoryUnavailable();
  }
}

function validId(value, prefix) {
  return typeof value === 'string' && new RegExp(`^${prefix}_[A-Za-z0-9_-]{8,128}$`, 'u').test(value);
}

function receiptBody(receipt) {
  const { signature, ...body } = receipt;
  return body;
}

function memoryBody(memory) {
  const { signature, ...body } = memory;
  return body;
}

function timestampMilliseconds(value) {
  if (typeof value !== 'string') {
    throw memoryUnavailable();
  }
  const timestamp = new Date(value);
  if (Number.isNaN(timestamp.valueOf()) || timestamp.toISOString() !== value) {
    throw memoryUnavailable();
  }
  return timestamp.valueOf();
}

function assertExactKeys(value, expected) {
  if (!isPlainObject(value)) {
    throw memoryUnavailable();
  }
  const actual = Object.keys(value).sort();
  const keys = [...expected].sort();
  if (actual.length !== keys.length || actual.some((key, index) => key !== keys[index])) {
    throw memoryUnavailable();
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !Object.hasOwn(descriptor, 'value')) {
      throw memoryUnavailable();
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

function cloneJson(value) {
  return JSON.parse(JSON.stringify(value));
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

function memoryUnavailable() {
  return new Error('Memory is unavailable.');
}
