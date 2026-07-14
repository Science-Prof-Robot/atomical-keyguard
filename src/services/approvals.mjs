import { randomUUID } from 'node:crypto';
import { isAbsolute, join, resolve } from 'node:path';

import { canonicalJson, sha256 } from '../core/canonical.mjs';
import { POLICY_VERSION } from '../policy/action-registry.mjs';
import { GitInspector } from '../project/git-inspector.mjs';
import { JsonStore } from '../storage/json-store.mjs';
import { defaultDataDirectory } from '../storage/sealed-vault.mjs';

const STORE_VERSION = 1;
const MAX_APPROVAL_TTL_MILLISECONDS = 10 * 60 * 1000;
const DEFAULT_SCOPE_TTL_MILLISECONDS = 5 * 60 * 1000;
const MAX_ACTION_DATA_LENGTH = 32 * 1024;
const RECORD_STATUSES = new Set([
  'pending',
  'approved_once',
  'approved_scope',
  'denied',
  'expired',
  'consumed',
  'invalidated',
]);

/**
 * Persists signed approval envelopes and makes every consume transition under
 * JsonStore's process-safe update lock. It never treats a caller-provided
 * commit as authoritative: consume re-inspects the stored worktree itself.
 */
export class ApprovalService {
  #actionRegistry;
  #clock;
  #credentialVerifier;
  #gitInspector;
  #idGenerator;
  #identity;
  #ready;
  #scopeTtlMilliseconds;
  #storagePath;
  #store;
  #vault;

  constructor(options = {}) {
    if (options === null || typeof options !== 'object' || Array.isArray(options)) {
      throw new TypeError('Approval service options must be an object.');
    }

    const dataDirectory = options.dataDirectory ?? defaultDataDirectory();
    if (typeof dataDirectory !== 'string' || dataDirectory.length === 0) {
      throw new TypeError('dataDirectory must be a non-empty string.');
    }
    this.#storagePath = resolve(options.storagePath ?? join(dataDirectory, 'approvals.json'));
    this.#actionRegistry = options.actionRegistry;
    if (
      this.#actionRegistry !== undefined
      && (
        this.#actionRegistry === null
        || typeof this.#actionRegistry !== 'object'
        || typeof this.#actionRegistry.get !== 'function'
        || typeof this.#actionRegistry.prepare !== 'function'
      )
    ) {
      throw new TypeError('actionRegistry must provide get and prepare methods.');
    }
    this.#clock = options.clock ?? { now: () => new Date() };
    if (typeof this.#clock.now !== 'function') {
      throw new TypeError('clock.now must be a function.');
    }
    this.#identity = options.identity;
    if (
      this.#identity === null
      || typeof this.#identity !== 'object'
      || typeof this.#identity.fingerprint !== 'string'
      || typeof this.#identity.verifyCanonical !== 'function'
    ) {
      throw new TypeError('Approval service requires a local identity.');
    }
    this.#gitInspector = options.gitInspector ?? new GitInspector();
    if (this.#gitInspector === null || typeof this.#gitInspector.inspect !== 'function') {
      throw new TypeError('gitInspector.inspect must be a function.');
    }
    this.#vault = options.vault;
    this.#credentialVerifier = options.credentialVerifier;
    if (this.#credentialVerifier !== undefined && typeof this.#credentialVerifier !== 'function') {
      throw new TypeError('credentialVerifier must be a function.');
    }
    this.#idGenerator = options.idGenerator ?? randomUUID;
    if (typeof this.#idGenerator !== 'function') {
      throw new TypeError('idGenerator must be a function.');
    }
    this.#scopeTtlMilliseconds = options.scopeTtlMilliseconds ?? DEFAULT_SCOPE_TTL_MILLISECONDS;
    if (
      !Number.isInteger(this.#scopeTtlMilliseconds)
      || this.#scopeTtlMilliseconds <= 0
      || this.#scopeTtlMilliseconds > MAX_APPROVAL_TTL_MILLISECONDS
    ) {
      throw new TypeError('scopeTtlMilliseconds must be a short positive integer.');
    }

    this.#store = options.store ?? new JsonStore(this.#storagePath);
    if (
      this.#store === null
      || typeof this.#store.initialize !== 'function'
      || typeof this.#store.update !== 'function'
    ) {
      throw new TypeError('store must implement initialize and update.');
    }
    this.#ready = this.#store.initialize(emptyState()).then((state) => {
      validateState(state, this.#identity, this.#scopeTtlMilliseconds);
    });
  }

  static async open(options = {}) {
    const service = new ApprovalService(options);
    await service.#ready;
    return service;
  }

  get storagePath() {
    return this.#storagePath;
  }

  async request(envelope) {
    await this.#ready;
    const now = this.#timestamp();
    const normalizedEnvelope = normalizeEnvelope(envelope, this.#identity, now);
    if (!this.#isRegisteredAction(normalizedEnvelope.body)) {
      throw approvalUnavailable();
    }
    const credentialRevision = await this.#credentialRevision(
      normalizedEnvelope.body.credentialLabel,
      normalizedEnvelope.body.credentialProvider,
    );
    if (credentialRevision === undefined) {
      throw approvalUnavailable();
    }
    let result;

    await this.#store.update((state) => {
      validateState(state, this.#identity, this.#scopeTtlMilliseconds);
      const existing = state.approvals.find(
        (record) => record.envelopeHash === normalizedEnvelope.bodyHash,
      );
      if (existing !== undefined) {
        refreshRecord(state, existing, now);
        result = project(existing);
        return state;
      }

      const record = {
        consumedAt: null,
        createdAt: now,
        credentialRevision,
        dirtyTreeAcknowledged: false,
        envelope: normalizedEnvelope,
        envelopeHash: normalizedEnvelope.bodyHash,
        id: this.#newId('approval'),
        invalidatedReason: null,
        scopeId: null,
        scopeProposal: scopeForBody(
          normalizedEnvelope.body,
          earlierTimestamp(
            normalizedEnvelope.body.expiresAt,
            addMilliseconds(now, this.#scopeTtlMilliseconds),
          ),
          credentialRevision,
        ),
        status: isExpired(normalizedEnvelope.body.expiresAt, now) ? 'expired' : 'pending',
        updatedAt: now,
      };
      const matchingScope = findMatchingScope(
        state.scopes,
        normalizedEnvelope.body,
        credentialRevision,
        now,
      );
      if (record.status === 'pending' && matchingScope !== undefined) {
        record.scopeId = matchingScope.id;
        record.status = 'approved_scope';
      }
      state.approvals.push(record);
      result = project(record);
      return state;
    });

    return result;
  }

  /**
   * Returns only the compact, secret-free approval information the local
   * control UI needs. Signed envelopes, scope records, filesystem paths, and
   * credential revisions remain internal to the approval service.
   */
  async list() {
    await this.#ready;
    const now = this.#timestamp();
    let result;

    await this.#store.update((state) => {
      validateState(state, this.#identity, this.#scopeTtlMilliseconds);
      for (const record of state.approvals) {
        refreshRecord(state, record, now);
      }
      validateState(state, this.#identity, this.#scopeTtlMilliseconds);
      result = Object.freeze(state.approvals.map(projectForControlUi));
      return state;
    });

    return result;
  }

  async approveOnce(id, options = undefined) {
    await this.#ready;
    const now = this.#timestamp();
    const dirtyTreeAcknowledged = acknowledgementFrom(options);
    let result;

    await this.#store.update((state) => {
      validateState(state, this.#identity, this.#scopeTtlMilliseconds);
      const record = requiredRecord(state, id);
      refreshRecord(state, record, now);
      if (record.status !== 'pending') {
        result = project(record);
        return state;
      }
      if (record.envelope.body.project.dirty && !dirtyTreeAcknowledged) {
        result = withReason(project(record), 'dirty_tree_acknowledgement_required');
        return state;
      }

      record.dirtyTreeAcknowledged = record.envelope.body.project.dirty;
      record.status = 'approved_once';
      record.updatedAt = now;
      result = project(record);
      return state;
    });

    return result;
  }

  async approveScope(id, scope) {
    return this.#approveScope(id, scope, false);
  }

  /**
   * Approves the exact, daemon-stored scope proposal without accepting a
   * caller-provided scope object. The compact result deliberately omits the
   * stored scope because it contains canonical filesystem paths.
   */
  async approveExactScope(id) {
    return this.#approveScope(id, undefined, true);
  }

  async #approveScope(id, scope, exactScope) {
    await this.#ready;
    const now = this.#timestamp();
    let result;
    const projectResult = exactScope ? projectWithoutScope : project;

    await this.#store.update((state) => {
      validateState(state, this.#identity, this.#scopeTtlMilliseconds);
      const record = requiredRecord(state, id);
      refreshRecord(state, record, now);
      if (record.status !== 'pending') {
        result = projectResult(record);
        return state;
      }
      if (record.envelope.body.project.dirty) {
        result = withReason(projectResult(record), 'dirty_tree_scope_not_allowed');
        return state;
      }
      if (isExpired(record.scopeProposal.expiresAt, now)) {
        result = withReason(projectResult(record), 'scope_expired');
        return state;
      }
      if (!exactScope && !sameCanonicalValue(scope, record.scopeProposal)) {
        result = withReason(projectResult(record), 'scope_mismatch');
        return state;
      }

      const scopeRecord = {
        createdAt: now,
        envelopeHash: record.envelopeHash,
        expiresAt: record.scopeProposal.expiresAt,
        id: this.#newId('scope'),
        scope: cloneJson(record.scopeProposal),
      };
      state.scopes.push(scopeRecord);
      record.scopeId = scopeRecord.id;
      record.status = 'approved_scope';
      record.updatedAt = now;
      result = projectResult(record);
      return state;
    });

    return result;
  }

  async deny(id) {
    await this.#ready;
    const now = this.#timestamp();
    let result;

    await this.#store.update((state) => {
      validateState(state, this.#identity, this.#scopeTtlMilliseconds);
      const record = requiredRecord(state, id);
      refreshRecord(state, record, now);
      if (['pending', 'approved_once', 'approved_scope'].includes(record.status)) {
        revokeScopesForOrigin(state, record, now);
        record.status = 'denied';
        record.updatedAt = now;
      }
      result = project(record);
      return state;
    });

    return result;
  }

  async consume(id, currentCommit) {
    void currentCommit;
    await this.#ready;
    let result;

    await this.#store.update(async (state) => {
      validateState(state, this.#identity, this.#scopeTtlMilliseconds);
      const now = this.#timestamp();
      const record = requiredRecord(state, id);
      refreshRecord(state, record, now);
      const terminal = terminalConsumeResult(record);
      if (terminal !== undefined) {
        result = terminal;
        return state;
      }
      if (record.envelope.body.project.dirty && !record.dirtyTreeAcknowledged) {
        invalidate(state, record, 'dirty_tree_acknowledgement_required', now);
        result = invalidated(record, 'dirty_tree_acknowledgement_required');
        return state;
      }
      if (!this.#isRegisteredAction(record.envelope.body)) {
        invalidate(state, record, 'action_unavailable', now);
        result = invalidated(record, 'action_unavailable');
        return state;
      }

      let currentSnapshot;
      try {
        currentSnapshot = await this.#gitInspector.inspect(record.envelope.body.project.root);
      } catch {
        invalidate(state, record, 'project_unavailable', now);
        result = invalidated(record, 'project_unavailable');
        return state;
      }
      const changedReason = snapshotChangeReason(record.envelope.body.project, currentSnapshot);
      if (changedReason !== undefined) {
        invalidate(state, record, changedReason, now);
        result = invalidated(record, changedReason);
        return state;
      }
      if (!(await this.#targetStillMatches(record.envelope.body, currentSnapshot))) {
        invalidate(state, record, 'target_changed', now);
        result = invalidated(record, 'target_changed');
        return state;
      }
      const credentialRevision = await this.#credentialRevision(
        record.envelope.body.credentialLabel,
        record.envelope.body.credentialProvider,
      );
      if (credentialRevision === undefined) {
        invalidate(state, record, 'credential_unavailable', now);
        result = invalidated(record, 'credential_unavailable');
        return state;
      }
      if (credentialRevision !== record.credentialRevision) {
        invalidate(state, record, 'credential_changed', now);
        result = invalidated(record, 'credential_changed');
        return state;
      }
      record.consumedAt = now;
      record.status = 'consumed';
      record.updatedAt = now;
      result = deepFreeze({
        envelope: cloneJson(record.envelope),
        id: record.id,
        status: 'approved',
      });
      return state;
    });

    return result;
  }

  async #credentialRevision(label, provider) {
    try {
      if (this.#credentialVerifier !== undefined) {
        return (await this.#credentialVerifier({ label, provider })) === true
          ? sha256({ kind: 'credential-verifier', label, provider: provider ?? null })
          : undefined;
      }
      if (this.#vault === null || typeof this.#vault !== 'object') {
        return undefined;
      }
      if (provider !== undefined && typeof this.#vault.getActiveCredentialBinding === 'function') {
        const credential = await this.#vault.getActiveCredentialBinding({ label, provider });
        if (
          credential === undefined
          || credential.label !== label
          || credential.provider !== provider
          || typeof credential.instanceId !== 'string'
          || !/^[A-Za-z0-9_-]{32}$/u.test(credential.instanceId)
        ) {
          return undefined;
        }
        return sha256({
          instanceId: credential.instanceId,
          label,
          provider,
        });
      }
      if (typeof this.#vault.list !== 'function') {
        return undefined;
      }
      const credentials = await this.#vault.list();
      const credential = Array.isArray(credentials)
        ? credentials.find((candidate) => (
          candidate?.label === label
          && candidate?.provider === provider
          && candidate?.status === 'active'
        ))
        : undefined;
      if (
        credential === undefined
        || typeof credential.instanceId !== 'string'
        || !/^[A-Za-z0-9_-]{32}$/u.test(credential.instanceId)
      ) {
        return undefined;
      }
      return sha256({
        instanceId: credential.instanceId,
        label,
        provider: provider ?? null,
      });
    } catch {
      return undefined;
    }
  }

  #isRegisteredAction(body) {
    if (this.#actionRegistry === undefined) {
      return true;
    }
    try {
      const action = this.#actionRegistry.get(body.action);
      return action !== undefined
        && action.version === body.actionVersion
        && action.credentialLabel === body.credentialLabel
        && action.credential?.provider === body.credentialProvider;
    } catch {
      return false;
    }
  }

  async #targetStillMatches(body, snapshot) {
    if (this.#actionRegistry === undefined || typeof this.#actionRegistry.prepare !== 'function') {
      return true;
    }
    try {
      const prepared = await this.#actionRegistry.prepare(body.action, body.params, snapshot);
      return sameCanonicalValue(prepared.params, body.params)
        && sameCanonicalValue(prepared.target, body.target);
    } catch {
      return false;
    }
  }

  #newId(prefix) {
    const value = this.#idGenerator();
    if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{8,128}$/u.test(value)) {
      throw approvalUnavailable();
    }
    return `${prefix}_${value}`;
  }

  #timestamp() {
    let value;
    try {
      value = this.#clock.now();
    } catch {
      throw approvalUnavailable();
    }
    if (!(value instanceof Date) || Number.isNaN(value.valueOf())) {
      throw approvalUnavailable();
    }
    return value.toISOString();
  }
}

function emptyState() {
  return { approvals: [], scopes: [], version: STORE_VERSION };
}

function normalizeEnvelope(envelope, identity, now) {
  if (!isPlainObject(envelope)) {
    throw invalidEnvelope();
  }
  assertExactKeys(envelope, ['body', 'bodyHash', 'signature'], invalidEnvelope);
  const body = cloneCanonical(envelope.body, invalidEnvelope);
  const signature = cloneCanonical(envelope.signature, invalidEnvelope);
  if (typeof envelope.bodyHash !== 'string' || !/^[a-f0-9]{64}$/u.test(envelope.bodyHash)) {
    throw invalidEnvelope();
  }
  if (sha256(body) !== envelope.bodyHash) {
    throw invalidEnvelope();
  }
  validateBody(body, identity);
  validateSignature(signature, identity);
  if (identity.verifyCanonical(body, signature) !== true) {
    throw invalidEnvelope();
  }

  const requestedAt = timestampMilliseconds(body.requestedAt, invalidEnvelope);
  const expiresAt = timestampMilliseconds(body.expiresAt, invalidEnvelope);
  if (
    expiresAt <= requestedAt
    || expiresAt - requestedAt > MAX_APPROVAL_TTL_MILLISECONDS
    || requestedAt > timestampMilliseconds(now, invalidEnvelope)
  ) {
    throw invalidEnvelope();
  }

  return Object.freeze({ body, bodyHash: envelope.bodyHash, signature });
}

function validateState(state, identity, scopeTtlMilliseconds) {
  if (!isPlainObject(state)) {
    throw approvalUnavailable();
  }
  assertExactKeys(state, ['approvals', 'scopes', 'version'], approvalUnavailable);
  if (state.version !== STORE_VERSION || !Array.isArray(state.approvals) || !Array.isArray(state.scopes)) {
    throw approvalUnavailable();
  }

  const approvalIds = new Set();
  const envelopeHashes = new Set();
  const approvalsByEnvelopeHash = new Map();
  for (const record of state.approvals) {
    if (!isPlainObject(record)) {
      throw approvalUnavailable();
    }
    assertExactKeys(record, [
      'consumedAt',
      'createdAt',
      'credentialRevision',
      'dirtyTreeAcknowledged',
      'envelope',
      'envelopeHash',
      'id',
      'invalidatedReason',
      'scopeId',
      'scopeProposal',
      'status',
      'updatedAt',
    ], approvalUnavailable);
    if (
      typeof record.id !== 'string'
      || !record.id.startsWith('approval_')
      || approvalIds.has(record.id)
      || typeof record.credentialRevision !== 'string'
      || !/^[a-f0-9]{64}$/u.test(record.credentialRevision)
      || typeof record.envelopeHash !== 'string'
      || !/^[a-f0-9]{64}$/u.test(record.envelopeHash)
      || envelopeHashes.has(record.envelopeHash)
      || !RECORD_STATUSES.has(record.status)
      || typeof record.dirtyTreeAcknowledged !== 'boolean'
      || !optionalTimestamp(record.consumedAt)
      || !optionalString(record.invalidatedReason)
      || !optionalString(record.scopeId)
    ) {
      throw approvalUnavailable();
    }
    timestampMilliseconds(record.createdAt, approvalUnavailable);
    timestampMilliseconds(record.updatedAt, approvalUnavailable);
    const normalizedEnvelope = normalizeStoredEnvelope(record.envelope, identity);
    if (normalizedEnvelope.bodyHash !== record.envelopeHash) {
      throw approvalUnavailable();
    }
    validateScope(record.scopeProposal, approvalUnavailable);
    const expectedScope = scopeForBody(
      normalizedEnvelope.body,
      earlierTimestamp(
        normalizedEnvelope.body.expiresAt,
        addMilliseconds(record.createdAt, scopeTtlMilliseconds),
      ),
      record.credentialRevision,
    );
    if (!sameCanonicalValue(record.scopeProposal, expectedScope)) {
      throw approvalUnavailable();
    }
    approvalIds.add(record.id);
    envelopeHashes.add(record.envelopeHash);
    approvalsByEnvelopeHash.set(record.envelopeHash, record);
  }

  const scopeIds = new Set();
  for (const scopeRecord of state.scopes) {
    if (!isPlainObject(scopeRecord)) {
      throw approvalUnavailable();
    }
    assertExactKeys(scopeRecord, ['createdAt', 'envelopeHash', 'expiresAt', 'id', 'scope'], approvalUnavailable);
    if (
      typeof scopeRecord.id !== 'string'
      || !scopeRecord.id.startsWith('scope_')
      || scopeIds.has(scopeRecord.id)
      || typeof scopeRecord.envelopeHash !== 'string'
      || !/^[a-f0-9]{64}$/u.test(scopeRecord.envelopeHash)
    ) {
      throw approvalUnavailable();
    }
    timestampMilliseconds(scopeRecord.createdAt, approvalUnavailable);
    timestampMilliseconds(scopeRecord.expiresAt, approvalUnavailable);
    validateScope(scopeRecord.scope, approvalUnavailable);
    const originatingApproval = approvalsByEnvelopeHash.get(scopeRecord.envelopeHash);
    if (
      originatingApproval === undefined
      || !['approved_scope', 'consumed'].includes(originatingApproval.status)
      || originatingApproval.scopeId !== scopeRecord.id
      || originatingApproval.envelope.body.project.dirty
      || scopeRecord.expiresAt !== originatingApproval.scopeProposal.expiresAt
      || !sameCanonicalValue(scopeRecord.scope, originatingApproval.scopeProposal)
    ) {
      throw approvalUnavailable();
    }
    scopeIds.add(scopeRecord.id);
  }

  for (const record of state.approvals) {
    if (
      (record.status === 'approved_scope' && record.scopeId === null)
      || (record.scopeId !== null && !scopeIds.has(record.scopeId))
      || (!['approved_scope', 'consumed'].includes(record.status) && record.scopeId !== null)
    ) {
      throw approvalUnavailable();
    }
  }
}

function normalizeStoredEnvelope(envelope, identity) {
  try {
    if (!isPlainObject(envelope)) {
      throw approvalUnavailable();
    }
    assertExactKeys(envelope, ['body', 'bodyHash', 'signature'], approvalUnavailable);
    if (typeof envelope.bodyHash !== 'string' || sha256(envelope.body) !== envelope.bodyHash) {
      throw approvalUnavailable();
    }
    validateBody(envelope.body, identity);
    validateSignature(envelope.signature, identity);
    if (identity.verifyCanonical(envelope.body, envelope.signature) !== true) {
      throw approvalUnavailable();
    }
    return envelope;
  } catch {
    throw approvalUnavailable();
  }
}

function validateBody(body, identity) {
  if (!isPlainObject(body)) {
    throw invalidEnvelope();
  }
  assertBodyKeys(body);
  if (
    !validActionName(body.action)
    || !validCredentialLabel(body.credentialLabel)
    || body.policyVersion !== POLICY_VERSION
    || typeof body.nonce !== 'string'
    || !/^[A-Za-z0-9_-]{16,128}$/u.test(body.nonce)
  ) {
    throw invalidEnvelope();
  }
  if (Object.hasOwn(body, 'actionVersion') && !validActionVersion(body.actionVersion)) {
    throw invalidEnvelope();
  }
  if (Object.hasOwn(body, 'credentialProvider') && !validCredentialProvider(body.credentialProvider)) {
    throw invalidEnvelope();
  }
  validateAgent(body.agent, identity);
  validateActionData(body.params);
  validateProjectSnapshot(body.project);
  validateActionData(body.target);
  timestampMilliseconds(body.requestedAt, invalidEnvelope);
  timestampMilliseconds(body.expiresAt, invalidEnvelope);
}

function assertBodyKeys(body) {
  const legacyKeys = [
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
  ];
  const keys = [
    ...legacyKeys,
    ...(Object.hasOwn(body, 'actionVersion') ? ['actionVersion'] : []),
    ...(Object.hasOwn(body, 'credentialProvider') ? ['credentialProvider'] : []),
  ];
  assertExactKeys(body, keys, invalidEnvelope);
}

function validateAgent(agent, identity) {
  if (!isPlainObject(agent)) {
    throw invalidEnvelope();
  }
  assertExactKeys(agent, ['id', 'identity'], invalidEnvelope);
  if (
    typeof agent.id !== 'string'
    || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(agent.id)
    || agent.identity !== identity.fingerprint
  ) {
    throw invalidEnvelope();
  }
}

function validateProjectSnapshot(project) {
  if (!isPlainObject(project)) {
    throw invalidEnvelope();
  }
  assertExactKeys(project, ['commit', 'dirty', 'dirtyFingerprint', 'repositoryFingerprint', 'root'], invalidEnvelope);
  if (
    typeof project.root !== 'string'
    || !isAbsolute(project.root)
    || typeof project.repositoryFingerprint !== 'string'
    || !/^[a-f0-9]{64}$/u.test(project.repositoryFingerprint)
    || typeof project.commit !== 'string'
    || !/^[a-f0-9]{40,64}$/u.test(project.commit)
    || typeof project.dirty !== 'boolean'
    || typeof project.dirtyFingerprint !== 'string'
    || !/^[a-f0-9]{64}$/u.test(project.dirtyFingerprint)
  ) {
    throw invalidEnvelope();
  }
}

function validateSignature(signature, identity) {
  if (!isPlainObject(signature)) {
    throw invalidEnvelope();
  }
  assertExactKeys(signature, ['algorithm', 'fingerprint', 'signature'], invalidEnvelope);
  if (
    signature.algorithm !== 'ed25519'
    || signature.fingerprint !== identity.fingerprint
    || typeof signature.signature !== 'string'
    || !/^[A-Za-z0-9_-]+$/u.test(signature.signature)
  ) {
    throw invalidEnvelope();
  }
}

function scopeForBody(body, expiresAt, credentialRevision) {
  const scope = {
    action: body.action,
    commit: body.project.commit,
    credentialLabel: body.credentialLabel,
    credentialRevision,
    expiresAt,
    repositoryFingerprint: body.project.repositoryFingerprint,
    root: body.project.root,
    target: cloneJson(body.target),
  };
  if (Object.hasOwn(body, 'actionVersion')) {
    scope.actionVersion = body.actionVersion;
  }
  if (Object.hasOwn(body, 'credentialProvider')) {
    scope.credentialProvider = body.credentialProvider;
  }
  return scope;
}

function validateScope(scope, failure) {
  if (!isPlainObject(scope)) {
    throw failure();
  }
  const legacyKeys = [
    'action',
    'commit',
    'credentialLabel',
    'credentialRevision',
    'expiresAt',
    'repositoryFingerprint',
    'root',
    'target',
  ];
  const keys = [
    ...legacyKeys,
    ...(Object.hasOwn(scope, 'actionVersion') ? ['actionVersion'] : []),
    ...(Object.hasOwn(scope, 'credentialProvider') ? ['credentialProvider'] : []),
  ];
  assertExactKeys(scope, keys, failure);
  if (
    !validActionName(scope.action)
    || !validCredentialLabel(scope.credentialLabel)
    || typeof scope.credentialRevision !== 'string'
    || !/^[a-f0-9]{64}$/u.test(scope.credentialRevision)
    || typeof scope.commit !== 'string'
    || !/^[a-f0-9]{40,64}$/u.test(scope.commit)
    || typeof scope.repositoryFingerprint !== 'string'
    || !/^[a-f0-9]{64}$/u.test(scope.repositoryFingerprint)
    || typeof scope.root !== 'string'
    || !isAbsolute(scope.root)
  ) {
    throw failure();
  }
  if (Object.hasOwn(scope, 'actionVersion') && !validActionVersion(scope.actionVersion)) {
    throw failure();
  }
  if (Object.hasOwn(scope, 'credentialProvider') && !validCredentialProvider(scope.credentialProvider)) {
    throw failure();
  }
  timestampMilliseconds(scope.expiresAt, failure);
  validateActionData(scope.target, failure);
}

function findMatchingScope(scopes, body, credentialRevision, now) {
  return scopes.find((scopeRecord) => {
    if (isExpired(scopeRecord.expiresAt, now) || body.project.dirty) {
      return false;
    }
    const scope = scopeRecord.scope;
    return (
      scope.action === body.action
      && scope.actionVersion === body.actionVersion
      && scope.credentialLabel === body.credentialLabel
      && scope.credentialProvider === body.credentialProvider
      && scope.credentialRevision === credentialRevision
      && scope.repositoryFingerprint === body.project.repositoryFingerprint
      && scope.root === body.project.root
      && sameCanonicalValue(scope.target, body.target)
      && scope.commit === body.project.commit
    );
  });
}

function refreshRecord(state, record, now) {
  if (
    ['pending', 'approved_once', 'approved_scope'].includes(record.status)
    && isExpired(record.envelope.body.expiresAt, now)
  ) {
    revokeScopesForOrigin(state, record, now);
    record.status = 'expired';
    record.updatedAt = now;
  }
}

function terminalConsumeResult(record) {
  switch (record.status) {
    case 'consumed':
      return denied(record, 'already_consumed');
    case 'denied':
      return denied(record, 'approval_denied');
    case 'expired':
      return Object.freeze({ id: record.id, reason: 'approval_expired', status: 'expired' });
    case 'invalidated':
      return invalidated(record, record.invalidatedReason ?? 'approval_invalidated');
    case 'pending':
      return denied(record, 'approval_not_approved');
    default:
      return undefined;
  }
}

function snapshotChangeReason(expected, current) {
  if (current.commit !== expected.commit) {
    return 'commit_changed';
  }
  if (
    current.root !== expected.root
    || current.repositoryFingerprint !== expected.repositoryFingerprint
  ) {
    return 'repository_changed';
  }
  if (
    current.dirty !== expected.dirty
    || current.dirtyFingerprint !== expected.dirtyFingerprint
  ) {
    return 'worktree_changed';
  }
  return undefined;
}

function invalidate(state, record, reason, now) {
  revokeScopesForOrigin(state, record, now);
  record.invalidatedReason = reason;
  record.status = 'invalidated';
  record.updatedAt = now;
}

function revokeScopesForOrigin(state, record, now) {
  const revokedScopeIds = new Set();
  state.scopes = state.scopes.filter((scopeRecord) => {
    if (scopeRecord.envelopeHash !== record.envelopeHash) {
      return true;
    }
    revokedScopeIds.add(scopeRecord.id);
    return false;
  });

  for (const candidate of state.approvals) {
    if (candidate === record || !revokedScopeIds.has(candidate.scopeId)) {
      continue;
    }
    candidate.scopeId = null;
    candidate.updatedAt = now;
    if (candidate.status === 'approved_scope') {
      candidate.invalidatedReason = 'scope_revoked';
      candidate.status = 'invalidated';
    }
  }
  record.scopeId = null;
}

function project(record) {
  const body = record.envelope.body;
  const projection = {
    action: body.action,
    credentialLabel: body.credentialLabel,
    dirtyTreeAcknowledged: record.dirtyTreeAcknowledged,
    envelopeHash: record.envelopeHash,
    expiresAt: body.expiresAt,
    id: record.id,
    requiresDirtyTreeAcknowledgement: body.project.dirty && !record.dirtyTreeAcknowledged,
    status: record.status,
  };
  if (!body.project.dirty) {
    projection.scope = cloneJson(record.scopeProposal);
  }
  return Object.freeze(projection);
}

function projectWithoutScope(record) {
  const projection = project(record);
  const { scope, ...withoutScope } = projection;
  void scope;
  return Object.freeze(withoutScope);
}

function projectForControlUi(record) {
  const body = record.envelope.body;
  return deepFreeze({
    action: body.action,
    credentialLabel: body.credentialLabel,
    dirtyTreeAcknowledged: record.dirtyTreeAcknowledged,
    expiresAt: body.expiresAt,
    id: record.id,
    project: {
      commit: body.project.commit,
      dirty: body.project.dirty,
      repositoryFingerprint: body.project.repositoryFingerprint,
    },
    requiresDirtyTreeAcknowledgement: body.project.dirty && !record.dirtyTreeAcknowledged,
    status: record.status,
  });
}

function denied(record, reason) {
  return Object.freeze({ id: record.id, reason, status: 'denied' });
}

function invalidated(record, reason) {
  return Object.freeze({ id: record.id, reason, status: 'invalidated' });
}

function withReason(value, reason) {
  return Object.freeze({ ...value, reason });
}

function requiredRecord(state, id) {
  if (typeof id !== 'string' || id.length === 0) {
    throw approvalUnavailable();
  }
  const record = state.approvals.find((candidate) => candidate.id === id);
  if (record === undefined) {
    throw approvalUnavailable();
  }
  return record;
}

function acknowledgementFrom(options) {
  if (options === undefined) {
    return false;
  }
  if (!isPlainObject(options)) {
    return false;
  }
  const descriptor = Object.getOwnPropertyDescriptor(options, 'dirtyTreeAcknowledged');
  return descriptor !== undefined && Object.hasOwn(descriptor, 'value') && descriptor.value === true;
}

function sameCanonicalValue(left, right) {
  try {
    return canonicalJson(left) === canonicalJson(right);
  } catch {
    return false;
  }
}

function validateActionData(value, failure = invalidEnvelope) {
  if (!isPlainObject(value)) {
    throw failure();
  }
  try {
    if (canonicalJson(value).length > MAX_ACTION_DATA_LENGTH) {
      throw new Error('Action data is too large.');
    }
  } catch {
    throw failure();
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

function cloneCanonical(value, failure) {
  try {
    return JSON.parse(canonicalJson(value));
  } catch {
    throw failure();
  }
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

function addMilliseconds(timestamp, milliseconds) {
  return new Date(timestampMilliseconds(timestamp, approvalUnavailable) + milliseconds).toISOString();
}

function earlierTimestamp(first, second) {
  return timestampMilliseconds(first, approvalUnavailable) <= timestampMilliseconds(second, approvalUnavailable)
    ? first
    : second;
}

function isExpired(timestamp, now) {
  return timestampMilliseconds(timestamp, approvalUnavailable)
    <= timestampMilliseconds(now, approvalUnavailable);
}

function timestampMilliseconds(value, failure) {
  if (typeof value !== 'string') {
    throw failure();
  }
  const date = new Date(value);
  if (Number.isNaN(date.valueOf()) || date.toISOString() !== value) {
    throw failure();
  }
  return date.valueOf();
}

function optionalTimestamp(value) {
  if (value === null) {
    return true;
  }
  try {
    timestampMilliseconds(value, approvalUnavailable);
    return true;
  } catch {
    return false;
  }
}

function optionalString(value) {
  return value === null || typeof value === 'string';
}

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertExactKeys(value, expectedKeys, failure) {
  const actualKeys = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (
    actualKeys.length !== expected.length
    || actualKeys.some((key, index) => key !== expected[index])
  ) {
    throw failure();
  }
  for (const key of expected) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !Object.hasOwn(descriptor, 'value')) {
      throw failure();
    }
  }
}

function invalidEnvelope() {
  return new Error('Approval envelope is invalid.');
}

function approvalUnavailable() {
  return new Error('Approval is unavailable.');
}
