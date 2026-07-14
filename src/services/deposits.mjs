import { Buffer } from 'node:buffer';
import { randomUUID, timingSafeEqual } from 'node:crypto';
import { join, resolve } from 'node:path';

import { canonicalJson } from '../core/canonical.mjs';
import { KeyguardError } from '../core/errors.mjs';
import { JsonStore } from '../storage/json-store.mjs';
import { SealedVault, defaultDataDirectory } from '../storage/sealed-vault.mjs';

const STORE_VERSION = 2;
const DEFAULT_DEPOSIT_TTL_MILLISECONDS = 10 * 60 * 1000;
const DEFAULT_MAX_WEBHOOK_AGE_MILLISECONDS = 5 * 60 * 1000;
const MAX_SHORT_TTL_MILLISECONDS = 10 * 60 * 1000;
const MAX_SECRET_LENGTH = 64 * 1024;
const MAX_URL_LENGTH = 4 * 1024;
const MAX_WEBHOOK_TOKEN_LENGTH = 1024;
const HANDOFF_ID_PATTERN = /^deposit_[A-Za-z0-9_-]{8,128}$/u;
const AGENT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{16,512}$/u;
const CREDENTIAL_INSTANCE_ID_PATTERN = /^[A-Za-z0-9_-]{32}$/u;
const HANDOFF_STATUSES = new Set(['pending', 'claimed']);
const VAULT_CREDENTIAL_STATUSES = new Set(['active', 'revoked']);
const SUPPORTED_METADATA = Object.freeze({
  label: 'cloudflare-api-token',
  provider: 'cloudflare',
});

/**
 * Seals a one-time, signed credential handoff without retaining either its
 * external URL or credential value. The only supported current credential is
 * the daemon-owned Cloudflare Pages token mapping.
 */
export class DepositService {
  #atomicalGateway;
  #clock;
  #depositTtlMilliseconds;
  #handoffIdGenerator;
  #maxWebhookAgeMilliseconds;
  #ready;
  #storagePath;
  #store;
  #trustedPublicKeyVerifier;
  #vault;
  #webhookToken;

  constructor(options = {}) {
    if (!isPlainObject(options)) {
      throw new TypeError('Deposit service options must be a plain object.');
    }

    const dataDirectory = options.dataDirectory ?? defaultDataDirectory();
    if (typeof dataDirectory !== 'string' || dataDirectory.length === 0) {
      throw new TypeError('dataDirectory must be a non-empty string.');
    }
    this.#storagePath = resolve(options.storagePath ?? join(dataDirectory, 'deposits.json'));

    this.#clock = options.clock ?? { now: () => new Date() };
    if (this.#clock === null || typeof this.#clock.now !== 'function') {
      throw new TypeError('clock.now must be a function.');
    }

    this.#vault = options.vault;
    if (
      this.#vault === null
      || typeof this.#vault !== 'object'
      || typeof this.#vault.list !== 'function'
      || typeof this.#vault.putIfCurrentInstance !== 'function'
    ) {
      throw new TypeError('Deposit service requires a sealed vault.');
    }

    this.#atomicalGateway = options.atomicalGateway;
    this.#trustedPublicKeyVerifier = options.trustedPublicKeyVerifier;
    if (
      this.#trustedPublicKeyVerifier !== undefined
      && typeof this.#trustedPublicKeyVerifier !== 'function'
    ) {
      throw new TypeError('trustedPublicKeyVerifier must be a function.');
    }

    this.#webhookToken = options.webhookToken;
    if (
      this.#webhookToken !== undefined
      && (
        typeof this.#webhookToken !== 'string'
        || this.#webhookToken.length === 0
        || this.#webhookToken.length > MAX_WEBHOOK_TOKEN_LENGTH
      )
    ) {
      throw new TypeError('webhookToken must be a bounded non-empty string.');
    }

    this.#depositTtlMilliseconds = normalizeShortDuration(
      options.depositTtlMilliseconds,
      DEFAULT_DEPOSIT_TTL_MILLISECONDS,
      'depositTtlMilliseconds',
    );
    this.#maxWebhookAgeMilliseconds = normalizeShortDuration(
      options.maxWebhookAgeMilliseconds,
      DEFAULT_MAX_WEBHOOK_AGE_MILLISECONDS,
      'maxWebhookAgeMilliseconds',
    );

    this.#handoffIdGenerator = options.handoffIdGenerator ?? randomUUID;
    if (typeof this.#handoffIdGenerator !== 'function') {
      throw new TypeError('handoffIdGenerator must be a function.');
    }

    this.#store = options.store ?? new JsonStore(this.#storagePath);
    if (
      this.#store === null
      || typeof this.#store.initialize !== 'function'
      || typeof this.#store.update !== 'function'
    ) {
      throw new TypeError('store must implement initialize and update.');
    }
    this.#ready = this.#store.initialize(emptyState()).then(validateState);
  }

  static async open(options = {}) {
    if (!isPlainObject(options)) {
      throw new TypeError('Deposit service options must be a plain object.');
    }
    const vault = options.vault ?? await SealedVault.open({
      clock: options.clock,
      dataDirectory: options.dataDirectory,
    });
    const service = new DepositService({ ...options, vault });
    try {
      await service.#ready;
      await service.#reconcileHandoffs();
      return service;
    } catch {
      throw unavailable();
    }
  }

  get storagePath() {
    return this.#storagePath;
  }

  async create(metadata) {
    try {
      await this.#ready;
      await this.#reconcileHandoffs();
      const normalizedMetadata = normalizeMetadata(metadata);
      const expectedInstanceId = await this.#captureExpectedInstanceId(normalizedMetadata.label);
      const now = this.#now();
      const record = {
        createdAt: now.toISOString(),
        expectedInstanceId,
        expiresAt: new Date(now.valueOf() + this.#depositTtlMilliseconds).toISOString(),
        id: this.#newHandoffId(),
        metadata: normalizedMetadata,
        status: 'pending',
      };
      const depositUrl = await this.#createDepositLink(record);
      let result;

      await this.#store.update((state) => {
        validateState(state);
        purgeExpiredHandoffs(state, now.valueOf());
        if (state.handoffs.some((handoff) => handoff.metadata.label === record.metadata.label)) {
          throw unavailable();
        }
        state.handoffs.push(record);
        result = projectHandoff(record, depositUrl);
        return state;
      });

      return result;
    } catch {
      throw unavailable();
    }
  }

  async receiveSigned(event, headers) {
    try {
      await this.#ready;
      const normalizedEvent = normalizeEvent(event);
      const normalizedHeaders = normalizeHeaders(headers);
      const receivedAt = this.#now();
      assertFreshSignatureTime(
        normalizedHeaders.signatureTime,
        receivedAt,
        this.#maxWebhookAgeMilliseconds,
      );
      assertWebhookToken(normalizedHeaders.webhookToken, this.#webhookToken);
      await this.#verifySignature(normalizedEvent, normalizedHeaders);
      const { handoff, vaultProjection } = await this.#sealPendingHandoff(normalizedEvent);
      return projectCredential(vaultProjection, handoff.metadata.label);
    } catch {
      throw unavailable();
    }
  }

  async list() {
    try {
      await this.#ready;
      await this.#reconcileHandoffs();
      const now = this.#now();
      let projections;
      await this.#store.update((state) => {
        validateState(state);
        purgeExpiredHandoffs(state, now.valueOf());
        projections = Object.freeze(
          state.handoffs
            .filter((handoff) => handoff.status === 'pending')
            .map((handoff) => projectHandoff(handoff)),
        );
        return state;
      });
      return projections;
    } catch {
      throw unavailable();
    }
  }

  async #captureExpectedInstanceId(label) {
    const credentialsByLabel = await this.#vaultCredentialStates();
    return credentialsByLabel.get(label)?.instanceId ?? null;
  }

  async #vaultCredentialStates() {
    const credentials = await this.#vault.list();
    if (!Array.isArray(credentials)) {
      throw unavailable();
    }
    const credentialsByLabel = new Map();
    for (const credential of credentials) {
      const normalized = normalizeVaultCredentialState(credential);
      if (credentialsByLabel.has(normalized.label)) {
        throw unavailable();
      }
      credentialsByLabel.set(normalized.label, normalized);
    }
    return credentialsByLabel;
  }

  async #reconcileHandoffs() {
    const credentialsByLabel = await this.#vaultCredentialStates();
    const now = this.#now();

    await this.#store.update((state) => {
      validateState(state);
      purgeExpiredHandoffs(state, now.valueOf());
      // A durable claim is a one-way tombstone until expiry. Vault absence
      // cannot prove that a prior seal did not happen, so reconciliation must
      // never make it pending again.
      const claimedLabels = new Set(
        state.handoffs
          .filter((handoff) => handoff.status === 'claimed')
          .map((handoff) => handoff.metadata.label),
      );
      state.handoffs = state.handoffs.filter((handoff) => {
        if (handoff.status === 'claimed') {
          return true;
        }
        return !claimedLabels.has(handoff.metadata.label)
          && expectedCredentialIsStillCurrent(handoff, credentialsByLabel);
      });
      return state;
    });
  }

  async #createDepositLink(record) {
    const gateway = this.#atomicalGateway;
    if (
      !isPlainObject(gateway)
      || gateway.configured !== true
      || !['atomical-cli', 'sealed-local-test-demo'].includes(gateway.kind)
      || typeof gateway.createDepositLink !== 'function'
      || (
        gateway.kind === 'sealed-local-test-demo'
        && gateway.isPublicDepositBox !== false
      )
    ) {
      throw unavailable();
    }

    const response = await gateway.createDepositLink(Object.freeze({
      expiresAt: record.expiresAt,
      handoffId: record.id,
      label: record.metadata.label,
    }));
    return normalizeDepositUrl(response);
  }

  async #verifySignature(event, headers) {
    if (typeof this.#trustedPublicKeyVerifier !== 'function') {
      throw unavailable();
    }
    const signedPayload = canonicalJson({
      agentId: headers.agentId,
      event,
      signatureTime: headers.signatureTime,
    });
    const verifierEvent = deepFreeze(cloneJson(event));
    const verified = await this.#trustedPublicKeyVerifier(Object.freeze({
      agentId: headers.agentId,
      event: verifierEvent,
      signature: headers.signature,
      signatureTime: headers.signatureTime,
      signedPayload,
    }));
    if (verified !== true) {
      throw unavailable();
    }
  }

  async #sealPendingHandoff(event) {
    const handoff = await this.#claimPendingHandoff(event);
    const vaultProjection = await this.#vault.putIfCurrentInstance(
      handoff.metadata,
      event.secret,
      handoff.expectedInstanceId,
    );

    try {
      await this.#store.update((state) => {
        validateState(state);
        const now = this.#now();
        purgeExpiredHandoffs(state, now.valueOf());
        const index = state.handoffs.findIndex((candidate) => candidate.id === handoff.id);
        if (index === -1) {
          return state;
        }
        if (state.handoffs[index].status !== 'claimed') {
          throw unavailable();
        }
        state.handoffs.splice(index, 1);
        return state;
      });
    } catch {
      // A failed final discard is deliberately retained as a durable claim.
      // The vault write has completed, but retrying the receipt would be
      // unsafe if that failure was ambiguous or persists across a restart.
    }

    return { handoff, vaultProjection };
  }

  async #claimPendingHandoff(event) {
    let handoff;
    await this.#store.update((state) => {
      validateState(state);
      const now = this.#now();
      purgeExpiredHandoffs(state, now.valueOf());
      const index = state.handoffs.findIndex((candidate) => candidate.id === event.handoffId);
      if (
        index === -1
        || state.handoffs[index].status !== 'pending'
        || state.handoffs[index].metadata.label !== event.label
      ) {
        throw unavailable();
      }
      handoff = {
        expectedInstanceId: state.handoffs[index].expectedInstanceId,
        id: state.handoffs[index].id,
        metadata: cloneJson(state.handoffs[index].metadata),
      };
      // This commit precedes all vault I/O. If either step is ambiguous, the
      // claimed tombstone remains until expiry instead of reopening the URL.
      state.handoffs[index].status = 'claimed';
      return state;
    });
    return handoff;
  }

  #newHandoffId() {
    const generated = this.#handoffIdGenerator();
    if (typeof generated !== 'string' || !/^[A-Za-z0-9_-]{8,128}$/u.test(generated)) {
      throw unavailable();
    }
    const handoffId = `deposit_${generated}`;
    if (!HANDOFF_ID_PATTERN.test(handoffId)) {
      throw unavailable();
    }
    return handoffId;
  }

  #now() {
    const now = this.#clock.now();
    if (!(now instanceof Date) || Number.isNaN(now.valueOf())) {
      throw unavailable();
    }
    return new Date(now.valueOf());
  }
}

function emptyState() {
  return { handoffs: [], version: STORE_VERSION };
}

function normalizeMetadata(value) {
  assertPlainObject(value);
  assertAllowedKeys(value, ['label', 'provider']);
  const label = ownDataProperty(value, 'label');
  const provider = Object.hasOwn(value, 'provider') ? ownDataProperty(value, 'provider') : SUPPORTED_METADATA.provider;
  if (label !== SUPPORTED_METADATA.label || provider !== SUPPORTED_METADATA.provider) {
    throw unavailable();
  }
  return Object.freeze({ label, provider });
}

function normalizeEvent(value) {
  assertPlainObject(value);
  assertExactKeys(value, ['handoffId', 'label', 'secret', 'type']);
  const handoffId = ownDataProperty(value, 'handoffId');
  const label = ownDataProperty(value, 'label');
  const secret = ownDataProperty(value, 'secret');
  const type = ownDataProperty(value, 'type');
  if (
    !HANDOFF_ID_PATTERN.test(handoffId)
    || label !== SUPPORTED_METADATA.label
    || typeof secret !== 'string'
    || secret.length === 0
    || secret.length > MAX_SECRET_LENGTH
    || type !== 'deposit.received'
  ) {
    throw unavailable();
  }
  return { handoffId, label, secret, type };
}

function normalizeHeaders(value) {
  assertPlainObject(value);
  const normalized = new Map();
  for (const key of Object.keys(value)) {
    const headerValue = ownDataProperty(value, key);
    const normalizedKey = key.toLowerCase();
    if (normalized.has(normalizedKey) || Array.isArray(headerValue)) {
      throw unavailable();
    }
    normalized.set(normalizedKey, headerValue);
  }

  const agentId = normalized.get('x-agent-id');
  const signature = normalized.get('x-agent-sig');
  const signatureTime = normalized.get('x-agent-sig-time');
  const webhookToken = normalized.get('x-webhook-token');
  if (
    typeof agentId !== 'string'
    || !AGENT_ID_PATTERN.test(agentId)
    || typeof signature !== 'string'
    || !SIGNATURE_PATTERN.test(signature)
    || typeof signatureTime !== 'string'
    || (webhookToken !== undefined && typeof webhookToken !== 'string')
  ) {
    throw unavailable();
  }
  return { agentId, signature, signatureTime, webhookToken };
}

function normalizeDepositUrl(value) {
  if (!isPlainObject(value)) {
    throw unavailable();
  }
  const url = ownDataProperty(value, 'url');
  if (typeof url !== 'string' || url.length === 0 || url.length > MAX_URL_LENGTH) {
    throw unavailable();
  }
  try {
    const parsed = new URL(url);
    if (
      parsed.protocol !== 'https:'
      || parsed.username.length !== 0
      || parsed.password.length !== 0
    ) {
      throw unavailable();
    }
  } catch {
    throw unavailable();
  }
  return url;
}

function assertFreshSignatureTime(value, now, maxAgeMilliseconds) {
  const signedAt = timestampMilliseconds(value);
  if (Math.abs(now.valueOf() - signedAt) > maxAgeMilliseconds) {
    throw unavailable();
  }
}

function assertWebhookToken(value, configuredToken) {
  if (configuredToken === undefined) {
    return;
  }
  if (typeof value !== 'string') {
    throw unavailable();
  }
  const actual = Buffer.from(value, 'utf8');
  const expected = Buffer.from(configuredToken, 'utf8');
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
    throw unavailable();
  }
}

function projectHandoff(record, depositUrl = undefined) {
  const projection = {
    expiresAt: record.expiresAt,
    label: record.metadata.label,
    status: 'pending',
  };
  if (depositUrl !== undefined) {
    projection.depositUrl = depositUrl;
  }
  return Object.freeze(projection);
}

function projectCredential(value, expectedLabel) {
  if (!isPlainObject(value)) {
    throw unavailable();
  }
  const projection = {
    createdAt: ownDataProperty(value, 'createdAt'),
    instanceId: ownDataProperty(value, 'instanceId'),
    label: ownDataProperty(value, 'label'),
    status: ownDataProperty(value, 'status'),
    updatedAt: ownDataProperty(value, 'updatedAt'),
  };
  if (
    projection.label !== expectedLabel
    || projection.status !== 'active'
    || typeof projection.instanceId !== 'string'
    || !/^[A-Za-z0-9_-]{16,128}$/u.test(projection.instanceId)
  ) {
    throw unavailable();
  }
  timestampMilliseconds(projection.createdAt);
  timestampMilliseconds(projection.updatedAt);
  return Object.freeze(projection);
}

function purgeExpiredHandoffs(state, nowMilliseconds) {
  state.handoffs = state.handoffs.filter((handoff) => (
    timestampMilliseconds(handoff.expiresAt) > nowMilliseconds
  ));
}

function validateState(state) {
  assertPlainObject(state);
  assertExactKeys(state, ['handoffs', 'version']);
  if (state.version !== STORE_VERSION || !Array.isArray(state.handoffs)) {
    throw unavailable();
  }
  const ids = new Set();
  const pendingLabels = new Set();
  for (const handoff of state.handoffs) {
    validateHandoff(handoff);
    if (ids.has(handoff.id)) {
      throw unavailable();
    }
    ids.add(handoff.id);
    if (handoff.status === 'pending') {
      if (pendingLabels.has(handoff.metadata.label)) {
        throw unavailable();
      }
      pendingLabels.add(handoff.metadata.label);
    }
  }
}

function validateHandoff(value) {
  assertPlainObject(value);
  assertExactKeys(value, ['createdAt', 'expectedInstanceId', 'expiresAt', 'id', 'metadata', 'status']);
  const createdAt = ownDataProperty(value, 'createdAt');
  const expectedInstanceId = ownDataProperty(value, 'expectedInstanceId');
  const expiresAt = ownDataProperty(value, 'expiresAt');
  const id = ownDataProperty(value, 'id');
  const metadata = ownDataProperty(value, 'metadata');
  const status = ownDataProperty(value, 'status');
  const createdAtMilliseconds = timestampMilliseconds(createdAt);
  const expiresAtMilliseconds = timestampMilliseconds(expiresAt);
  if (
    !HANDOFF_ID_PATTERN.test(id)
    || (
      expectedInstanceId !== null
      && (
        typeof expectedInstanceId !== 'string'
        || !CREDENTIAL_INSTANCE_ID_PATTERN.test(expectedInstanceId)
      )
    )
    || !HANDOFF_STATUSES.has(status)
    || expiresAtMilliseconds <= createdAtMilliseconds
    || expiresAtMilliseconds - createdAtMilliseconds > MAX_SHORT_TTL_MILLISECONDS
  ) {
    throw unavailable();
  }
  normalizeMetadata(metadata);
}

function normalizeVaultCredentialState(value) {
  assertPlainObject(value);
  const label = ownDataProperty(value, 'label');
  const instanceId = ownDataProperty(value, 'instanceId');
  const status = ownDataProperty(value, 'status');
  if (
    typeof label !== 'string'
    || label.length === 0
    || label.length > 128
    || label !== label.trim()
    || /[\u0000-\u001f]/u.test(label)
    || typeof instanceId !== 'string'
    || !CREDENTIAL_INSTANCE_ID_PATTERN.test(instanceId)
    || !VAULT_CREDENTIAL_STATUSES.has(status)
  ) {
    throw unavailable();
  }
  return Object.freeze({ instanceId, label, status });
}

function expectedCredentialIsStillCurrent(handoff, credentialsByLabel) {
  const current = credentialsByLabel.get(handoff.metadata.label);
  if (handoff.expectedInstanceId === null) {
    return current === undefined;
  }
  return current?.instanceId === handoff.expectedInstanceId;
}

function normalizeShortDuration(value, defaultValue, name) {
  const normalized = value ?? defaultValue;
  if (
    !Number.isInteger(normalized)
    || normalized <= 0
    || normalized > MAX_SHORT_TTL_MILLISECONDS
  ) {
    throw new TypeError(`${name} must be a short positive integer.`);
  }
  return normalized;
}

function timestampMilliseconds(value) {
  if (typeof value !== 'string') {
    throw unavailable();
  }
  const timestamp = new Date(value);
  if (Number.isNaN(timestamp.valueOf()) || timestamp.toISOString() !== value) {
    throw unavailable();
  }
  return timestamp.valueOf();
}

function assertAllowedKeys(value, allowed) {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) {
      throw unavailable();
    }
    ownDataProperty(value, key);
  }
  if (!Object.hasOwn(value, 'label')) {
    throw unavailable();
  }
}

function assertExactKeys(value, expected) {
  const actual = Object.keys(value).sort();
  const expectedKeys = [...expected].sort();
  if (
    actual.length !== expectedKeys.length
    || actual.some((key, index) => key !== expectedKeys[index])
  ) {
    throw unavailable();
  }
  for (const key of expectedKeys) {
    ownDataProperty(value, key);
  }
}

function ownDataProperty(value, key) {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (descriptor === undefined || !Object.hasOwn(descriptor, 'value')) {
    throw unavailable();
  }
  return descriptor.value;
}

function assertPlainObject(value) {
  if (!isPlainObject(value)) {
    throw unavailable();
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

function unavailable() {
  return new KeyguardError({
    code: 'deposit_unavailable',
    retryable: false,
    safeMessage: 'Deposit is unavailable.',
  });
}
