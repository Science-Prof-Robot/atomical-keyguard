import { randomUUID } from 'node:crypto';
import { lstat, realpath, stat } from 'node:fs/promises';
import { isAbsolute, join, relative, resolve } from 'node:path';

import { sha256 } from '../core/canonical.mjs';
import { redactSensitiveOutput } from '../core/redaction.mjs';
import { ACTION_NAME } from '../policy/action-registry.mjs';
import { GitInspector } from '../project/git-inspector.mjs';
import { JsonStore } from '../storage/json-store.mjs';
import { defaultDataDirectory } from '../storage/sealed-vault.mjs';

const STORE_VERSION = 1;
const PROVIDER_STATUSES = new Set(['succeeded', 'failed', 'not_started']);
const VERIFICATION_STATUSES = new Set(['verified', 'failed', 'not_run']);

/**
 * Consumes exactly one approval, performs a second just-before-launch project
 * check, and produces a signed, output-free receipt for every provider path.
 */
export class ExecutionService {
  #activity;
  #approvals;
  #clock;
  #gitInspector;
  #idGenerator;
  #identity;
  #memory;
  #provider;
  #ready;
  #storagePath;
  #store;
  #vault;
  #verifier;

  constructor(options = {}) {
    if (options === null || typeof options !== 'object' || Array.isArray(options)) {
      throw new TypeError('Execution service options must be an object.');
    }
    const dataDirectory = options.dataDirectory ?? defaultDataDirectory();
    if (typeof dataDirectory !== 'string' || dataDirectory.length === 0) {
      throw new TypeError('dataDirectory must be a non-empty string.');
    }
    this.#approvals = requiredDependency(options.approvals, 'consume', 'approval service');
    this.#vault = requiredDependency(options.vault, 'readForExecution', 'vault');
    this.#activity = requiredDependency(options.activity, 'append', 'activity service');
    this.#memory = requiredDependency(options.memory, 'createVerifiedCandidate', 'memory service');
    this.#provider = requiredDependency(options.provider, 'execute', 'provider');
    this.#identity = options.identity;
    if (
      this.#identity === null
      || typeof this.#identity !== 'object'
      || typeof this.#identity.fingerprint !== 'string'
      || typeof this.#identity.signCanonical !== 'function'
      || typeof this.#identity.verifyCanonical !== 'function'
    ) {
      throw new TypeError('Execution service requires a local identity.');
    }
    this.#gitInspector = options.gitInspector ?? new GitInspector();
    if (this.#gitInspector === null || typeof this.#gitInspector.inspect !== 'function') {
      throw new TypeError('gitInspector.inspect must be a function.');
    }
    this.#clock = options.clock ?? { now: () => new Date() };
    if (typeof this.#clock.now !== 'function') {
      throw new TypeError('clock.now must be a function.');
    }
    this.#verifier = options.verifier ?? (async () => false);
    if (typeof this.#verifier !== 'function') {
      throw new TypeError('verifier must be a function.');
    }
    this.#idGenerator = options.idGenerator ?? randomUUID;
    if (typeof this.#idGenerator !== 'function') {
      throw new TypeError('idGenerator must be a function.');
    }
    this.#storagePath = resolve(options.storagePath ?? join(dataDirectory, 'receipts.json'));
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
    const service = new ExecutionService(options);
    await service.#ready;
    return service;
  }

  get storagePath() {
    return this.#storagePath;
  }

  async listReceipts() {
    await this.#ready;
    const state = await this.#store.read();
    validateState(state, this.#identity);
    return Object.freeze(state.receipts.map((receipt) => deepFreeze(cloneJson(receipt))));
  }

  async executeApproved(requestId) {
    await this.#ready;
    let consumed;
    try {
      consumed = await this.#approvals.consume(requestId);
    } catch {
      return rejectedExecution();
    }

    let envelope;
    try {
      envelope = normalizeConsumedEnvelope(consumed, requestId, this.#identity);
    } catch {
      return rejectedExecution();
    }

    const receiptId = this.#newReceiptId();
    const context = { envelope, receiptId, requestId };
    await this.#recordActivity({
      action: envelope.body.action,
      receiptId,
      requestId,
      stage: 'preparing',
      status: 'started',
    });

    if (!(await finalRevalidation(envelope.body, this.#gitInspector))) {
      return this.#preparationFailure(context);
    }

    let secret;
    try {
      secret = await this.#vault.readForExecution(envelope.body.credentialLabel);
    } catch {
      return this.#preparationFailure(context);
    }

    if (!(await finalRevalidation(envelope.body, this.#gitInspector))) {
      secret = undefined;
      return this.#preparationFailure(context);
    }

    await this.#recordActivity({
      action: envelope.body.action,
      receiptId,
      requestId,
      stage: 'executing',
      status: 'started',
    });
    let providerResult;
    try {
      providerResult = await this.#provider.execute({
        directory: envelope.body.target.directory,
        project: envelope.body.target.project,
        projectRoot: envelope.body.project.root,
        secret,
      });
    } catch (error) {
      providerResult = thrownProviderResult(error, secret);
    }
    const output = safeProviderOutput(providerResult, secret);
    secret = undefined;

    if (providerResult?.status !== 'succeeded') {
      const receipt = this.#createReceipt({
        envelope,
        id: receiptId,
        providerStatus: 'failed',
        requestId,
        retryOf: null,
        verificationOf: null,
        verificationStatus: 'not_run',
      });
      await this.#persistReceipt(receipt);
      return executionResult({
        attention: 'needs_attention',
        output,
        receipt,
        status: 'provider_failed',
      });
    }

    const providerAttemptReceipt = this.#createReceipt({
      envelope,
      id: receiptId,
      providerStatus: 'succeeded',
      requestId,
      retryOf: null,
      verificationOf: null,
      verificationStatus: 'not_run',
    });
    await this.#persistReceipt(providerAttemptReceipt);
    const verificationReceiptId = this.#newReceiptId();
    await this.#recordActivity({
      action: envelope.body.action,
      receiptId: verificationReceiptId,
      requestId,
      stage: 'verifying',
      status: 'started',
    });
    const verified = await this.#verify(providerAttemptReceipt);
    const receipt = this.#createReceipt({
      envelope,
      id: verificationReceiptId,
      providerStatus: 'succeeded',
      requestId,
      retryOf: null,
      verificationOf: providerAttemptReceipt.id,
      verificationStatus: verified ? 'verified' : 'failed',
    });
    await this.#persistReceipt(receipt);
    const memoryCandidate = verified
      ? await this.#createMemoryCandidate(receipt)
      : undefined;
    return executionResult({
      attention: verified ? 'none' : 'needs_attention',
      memoryCandidate,
      output,
      receipt,
      status: verified ? 'verified' : 'verification_failed',
    });
  }

  async retryVerification(receiptId) {
    await this.#ready;
    let previous;
    try {
      previous = await this.#receiptById(receiptId);
    } catch {
      return verificationRetryUnavailable();
    }
    if (
      previous.provider.status !== 'succeeded'
      || previous.verification.status !== 'failed'
    ) {
      return verificationRetryUnavailable();
    }

    const retryId = this.#newReceiptId();
    await this.#recordActivity({
      action: previous.action,
      receiptId: retryId,
      requestId: previous.request.id,
      stage: 'verifying',
      status: 'started',
    });
    const provisionalReceipt = this.#retryReceipt(previous, retryId, 'not_run');
    const verified = await this.#verify(provisionalReceipt);
    const receipt = this.#retryReceipt(previous, retryId, verified ? 'verified' : 'failed');
    await this.#persistReceipt(receipt);
    const memoryCandidate = verified
      ? await this.#createMemoryCandidate(receipt)
      : undefined;
    return executionResult({
      attention: verified ? 'none' : 'needs_attention',
      memoryCandidate,
      output: emptyOutput(),
      receipt,
      status: verified ? 'verified' : 'verification_failed',
    });
  }

  async #preparationFailure({ envelope, receiptId, requestId }) {
    const receipt = this.#createReceipt({
      envelope,
      id: receiptId,
      providerStatus: 'not_started',
      requestId,
      retryOf: null,
      verificationOf: null,
      verificationStatus: 'not_run',
    });
    await this.#persistReceipt(receipt);
    await this.#recordActivity({
      action: envelope.body.action,
      receiptId,
      requestId,
      stage: 'preparing',
      status: 'failed',
    });
    return executionResult({
      attention: 'needs_attention',
      output: emptyOutput(),
      receipt,
      status: 'preparation_failed',
    });
  }

  #createReceipt({
    envelope,
    id,
    providerStatus,
    requestId,
    retryOf,
    verificationOf,
    verificationStatus,
  }) {
    const body = {
      action: envelope.body.action,
      agent: {
        id: envelope.body.agent.id,
        identity: envelope.body.agent.identity,
      },
      approval: {
        id: requestId,
        status: 'consumed',
      },
      commit: envelope.body.project.commit,
      credentialLabel: envelope.body.credentialLabel,
      dirtyTreeAllowed: envelope.body.project.dirty,
      id,
      provider: {
        status: providerStatus,
      },
      repository: {
        fingerprint: envelope.body.project.repositoryFingerprint,
        root: envelope.body.project.root,
      },
      request: {
        envelopeHash: envelope.bodyHash,
        id: requestId,
        signature: cloneJson(envelope.signature),
      },
      retryOf,
      secretExposedToModel: false,
      target: {
        directory: envelope.body.target.directory,
        project: envelope.body.target.project,
      },
      timestamps: {
        executedAt: this.#timestamp(),
        requestedAt: envelope.body.requestedAt,
      },
      verification: {
        status: verificationStatus,
      },
      verificationOf,
    };
    const receipt = { ...body, signature: this.#identity.signCanonical(body) };
    validateReceipt(receipt, this.#identity);
    return deepFreeze(receipt);
  }

  #retryReceipt(previous, id, verificationStatus) {
    const body = {
      ...receiptBody(previous),
      id,
      retryOf: previous.id,
      timestamps: {
        executedAt: this.#timestamp(),
        requestedAt: previous.timestamps.requestedAt,
      },
      verification: {
        status: verificationStatus,
      },
    };
    const receipt = { ...body, signature: this.#identity.signCanonical(body) };
    validateReceipt(receipt, this.#identity);
    return deepFreeze(receipt);
  }

  async #persistReceipt(receipt) {
    await this.#store.update((state) => {
      validateState(state, this.#identity);
      state.receipts.push(receipt);
      return state;
    });
  }

  async #recordActivity(milestone) {
    try {
      await this.#activity.append(milestone);
    } catch {
      // The durable signed receipt remains the execution source of truth.
    }
  }

  async #receiptById(id) {
    if (typeof id !== 'string' || !validId(id, 'receipt')) {
      throw executionUnavailable();
    }
    const state = await this.#store.read();
    validateState(state, this.#identity);
    const receipt = state.receipts.find((candidate) => candidate.id === id);
    if (receipt === undefined) {
      throw executionUnavailable();
    }
    return deepFreeze(cloneJson(receipt));
  }

  async #verify(receipt) {
    try {
      const response = await this.#verifier(deepFreeze({ receipt: cloneJson(receipt) }));
      return response === true || response?.verified === true || response?.status === 'verified';
    } catch {
      return false;
    }
  }

  async #createMemoryCandidate(receipt) {
    try {
      return await this.#memory.createVerifiedCandidate(receipt);
    } catch {
      return undefined;
    }
  }

  #newReceiptId() {
    const value = this.#idGenerator();
    if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{8,128}$/u.test(value)) {
      throw executionUnavailable();
    }
    return `receipt_${value}`;
  }

  #timestamp() {
    let now;
    try {
      now = this.#clock.now();
    } catch {
      throw executionUnavailable();
    }
    if (!(now instanceof Date) || Number.isNaN(now.valueOf())) {
      throw executionUnavailable();
    }
    return now.toISOString();
  }
}

function emptyState() {
  return { receipts: [], version: STORE_VERSION };
}

function requiredDependency(value, method, name) {
  if (value === null || typeof value !== 'object' || typeof value[method] !== 'function') {
    throw new TypeError(`Execution service requires a ${name}.`);
  }
  return value;
}

function normalizeConsumedEnvelope(consumed, requestId, identity) {
  if (!isPlainObject(consumed)) {
    throw executionUnavailable();
  }
  assertExactKeys(consumed, ['envelope', 'id', 'status']);
  if (consumed.status !== 'approved' || consumed.id !== requestId || !validId(requestId, 'approval')) {
    throw executionUnavailable();
  }
  const envelope = cloneJson(consumed.envelope);
  assertExactKeys(envelope, ['body', 'bodyHash', 'signature']);
  if (
    typeof envelope.bodyHash !== 'string'
    || !/^[a-f0-9]{64}$/u.test(envelope.bodyHash)
    || sha256(envelope.body) !== envelope.bodyHash
  ) {
    throw executionUnavailable();
  }
  validateEnvelopeBody(envelope.body, identity);
  validateSignature(envelope.signature, identity);
  if (identity.verifyCanonical(envelope.body, envelope.signature) !== true) {
    throw executionUnavailable();
  }
  return envelope;
}

function validateEnvelopeBody(body, identity) {
  if (!isPlainObject(body)) {
    throw executionUnavailable();
  }
  assertExactKeys(body, [
    'action',
    'agent',
    'credentialLabel',
    'expiresAt',
    'nonce',
    'params',
    'policyVersion',
    'project',
    'requestedAt',
    'target',
  ]);
  if (
    body.action !== ACTION_NAME
    || body.credentialLabel !== 'cloudflare-api-token'
    || typeof body.requestedAt !== 'string'
    || typeof body.expiresAt !== 'string'
  ) {
    throw executionUnavailable();
  }
  timestampMilliseconds(body.requestedAt);
  timestampMilliseconds(body.expiresAt);
  validateAgent(body.agent, identity);
  validateProject(body.project);
  validateTarget(body.target);
}

function validateAgent(agent, identity) {
  if (!isPlainObject(agent)) {
    throw executionUnavailable();
  }
  assertExactKeys(agent, ['id', 'identity']);
  if (
    typeof agent.id !== 'string'
    || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(agent.id)
    || agent.identity !== identity.fingerprint
  ) {
    throw executionUnavailable();
  }
}

function validateProject(project) {
  if (!isPlainObject(project)) {
    throw executionUnavailable();
  }
  assertExactKeys(project, ['commit', 'dirty', 'dirtyFingerprint', 'repositoryFingerprint', 'root']);
  if (
    typeof project.root !== 'string'
    || !isAbsolute(project.root)
    || typeof project.commit !== 'string'
    || !/^[a-f0-9]{40,64}$/u.test(project.commit)
    || typeof project.repositoryFingerprint !== 'string'
    || !/^[a-f0-9]{64}$/u.test(project.repositoryFingerprint)
    || typeof project.dirty !== 'boolean'
    || typeof project.dirtyFingerprint !== 'string'
    || !/^[a-f0-9]{64}$/u.test(project.dirtyFingerprint)
  ) {
    throw executionUnavailable();
  }
}

function validateTarget(target) {
  if (!isPlainObject(target)) {
    throw executionUnavailable();
  }
  assertExactKeys(target, ['directory', 'project']);
  if (
    typeof target.directory !== 'string'
    || !isAbsolute(target.directory)
    || typeof target.project !== 'string'
    || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(target.project)
  ) {
    throw executionUnavailable();
  }
}

async function finalRevalidation(body, gitInspector) {
  try {
    const snapshot = await gitInspector.inspect(body.project.root);
    if (
      snapshot.root !== body.project.root
      || snapshot.commit !== body.project.commit
      || snapshot.repositoryFingerprint !== body.project.repositoryFingerprint
      || snapshot.dirty !== body.project.dirty
      || snapshot.dirtyFingerprint !== body.project.dirtyFingerprint
    ) {
      return false;
    }
    return await targetStillMatches(body.project.root, body.target.directory);
  } catch {
    return false;
  }
}

async function targetStillMatches(canonicalRoot, signedTarget) {
  try {
    const resolvedRoot = await realpath(canonicalRoot);
    const rootDetails = await lstat(canonicalRoot);
    if (
      resolvedRoot !== canonicalRoot
      || !rootDetails.isDirectory()
      || rootDetails.isSymbolicLink()
    ) {
      return false;
    }
    const resolvedTarget = await realpath(signedTarget);
    const targetDetails = await lstat(signedTarget);
    return resolvedTarget === signedTarget
      && isContained(canonicalRoot, resolvedTarget)
      && targetDetails.isDirectory()
      && !targetDetails.isSymbolicLink()
      && (await stat(resolvedTarget)).isDirectory();
  } catch {
    return false;
  }
}

function thrownProviderResult(error, secret) {
  return {
    status: 'failed',
    stderr: safeOutput(error?.stderr ?? error?.message, secret),
    stdout: safeOutput(error?.stdout, secret),
  };
}

function safeProviderOutput(providerResult, secret) {
  return deepFreeze({
    stderr: safeOutput(providerResult?.stderr, secret),
    stdout: safeOutput(providerResult?.stdout, secret),
  });
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

function emptyOutput() {
  return deepFreeze({ stderr: '', stdout: '' });
}

function executionResult({ attention, memoryCandidate, output, receipt, status }) {
  const result = { attention, output, receipt, status };
  if (memoryCandidate !== undefined) {
    result.memoryCandidate = memoryCandidate;
  }
  return deepFreeze(result);
}

function rejectedExecution() {
  return deepFreeze({ attention: 'needs_attention', status: 'approval_not_granted' });
}

function verificationRetryUnavailable() {
  return deepFreeze({ attention: 'needs_attention', status: 'verification_retry_not_available' });
}

function validateState(state, identity) {
  if (!isPlainObject(state)) {
    throw executionUnavailable();
  }
  assertExactKeys(state, ['receipts', 'version']);
  if (state.version !== STORE_VERSION || !Array.isArray(state.receipts)) {
    throw executionUnavailable();
  }
  const ids = new Set();
  for (const receipt of state.receipts) {
    validateReceipt(receipt, identity);
    if (ids.has(receipt.id)) {
      throw executionUnavailable();
    }
    ids.add(receipt.id);
  }
}

const RECEIPT_KEYS = [
  'action',
  'agent',
  'approval',
  'commit',
  'credentialLabel',
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

function validateReceipt(receipt, identity) {
  if (!isPlainObject(receipt)) {
    throw executionUnavailable();
  }
  assertExactKeys(receipt, RECEIPT_KEYS);
  const body = receiptBody(receipt);
  if (
    body.action !== ACTION_NAME
    || !validId(body.id, 'receipt')
    || !validId(body.approval?.id, 'approval')
    || body.approval.status !== 'consumed'
    || !validId(body.request?.id, 'approval')
    || typeof body.request.envelopeHash !== 'string'
    || !/^[a-f0-9]{64}$/u.test(body.request.envelopeHash)
    || !validRequestSignature(body.request.signature)
    || typeof body.commit !== 'string'
    || !/^[a-f0-9]{40,64}$/u.test(body.commit)
    || body.credentialLabel !== 'cloudflare-api-token'
    || typeof body.dirtyTreeAllowed !== 'boolean'
    || body.secretExposedToModel !== false
    || (body.retryOf !== null && !validId(body.retryOf, 'receipt'))
    || (body.verificationOf !== null && !validId(body.verificationOf, 'receipt'))
  ) {
    throw executionUnavailable();
  }
  validateAgent(body.agent, identity);
  validateRepository(body.repository);
  validateTarget(body.target);
  validateReceiptTimestamps(body.timestamps);
  validateStatus(body.provider, PROVIDER_STATUSES);
  validateStatus(body.verification, VERIFICATION_STATUSES);
  validateSignature(receipt.signature, identity);
  if (identity.verifyCanonical(body, receipt.signature) !== true) {
    throw executionUnavailable();
  }
}

function validateRepository(repository) {
  if (!isPlainObject(repository)) {
    throw executionUnavailable();
  }
  assertExactKeys(repository, ['fingerprint', 'root']);
  if (
    typeof repository.root !== 'string'
    || !isAbsolute(repository.root)
    || typeof repository.fingerprint !== 'string'
    || !/^[a-f0-9]{64}$/u.test(repository.fingerprint)
  ) {
    throw executionUnavailable();
  }
}

function validateReceiptTimestamps(timestamps) {
  if (!isPlainObject(timestamps)) {
    throw executionUnavailable();
  }
  assertExactKeys(timestamps, ['executedAt', 'requestedAt']);
  timestampMilliseconds(timestamps.executedAt);
  timestampMilliseconds(timestamps.requestedAt);
}

function validateStatus(value, allowed) {
  if (!isPlainObject(value)) {
    throw executionUnavailable();
  }
  assertExactKeys(value, ['status']);
  if (!allowed.has(value.status)) {
    throw executionUnavailable();
  }
}

function validateSignature(signature, identity) {
  if (!isPlainObject(signature)) {
    throw executionUnavailable();
  }
  assertExactKeys(signature, ['algorithm', 'fingerprint', 'signature']);
  if (
    signature.algorithm !== 'ed25519'
    || signature.fingerprint !== identity.fingerprint
    || typeof signature.signature !== 'string'
    || !/^[A-Za-z0-9_-]+$/u.test(signature.signature)
  ) {
    throw executionUnavailable();
  }
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

function validId(value, prefix) {
  return typeof value === 'string' && new RegExp(`^${prefix}_[A-Za-z0-9_-]{8,128}$`, 'u').test(value);
}

function receiptBody(receipt) {
  const { signature, ...body } = receipt;
  return body;
}

function timestampMilliseconds(value) {
  if (typeof value !== 'string') {
    throw executionUnavailable();
  }
  const timestamp = new Date(value);
  if (Number.isNaN(timestamp.valueOf()) || timestamp.toISOString() !== value) {
    throw executionUnavailable();
  }
  return timestamp.valueOf();
}

function assertExactKeys(value, expected) {
  if (!isPlainObject(value)) {
    throw executionUnavailable();
  }
  const actual = Object.keys(value).sort();
  const keys = [...expected].sort();
  if (actual.length !== keys.length || actual.some((key, index) => key !== keys[index])) {
    throw executionUnavailable();
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !Object.hasOwn(descriptor, 'value')) {
      throw executionUnavailable();
    }
  }
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

function executionUnavailable() {
  return new Error('Execution is unavailable.');
}
