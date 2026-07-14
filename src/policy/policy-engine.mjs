import { randomBytes } from 'node:crypto';

import { sha256 } from '../core/canonical.mjs';
import { GitInspector } from '../project/git-inspector.mjs';
import { createActionRegistry, POLICY_VERSION } from './action-registry.mjs';

const DEFAULT_APPROVAL_TTL_MILLISECONDS = 10 * 60 * 1000;

/**
 * Creates signed, secret-free action envelopes from a daemon-derived Git
 * snapshot. Request fields select only an allowlisted action and typed data;
 * they never control execution configuration or credential mapping.
 */
export class PolicyEngine {
  #approvalService;
  #approvalTtlMilliseconds;
  #clock;
  #gitInspector;
  #identity;
  #nonceGenerator;
  #registry;
  #vault;

  constructor(options = {}) {
    if (options === null || typeof options !== 'object' || Array.isArray(options)) {
      throw new TypeError('Policy engine options must be an object.');
    }

    this.#registry = options.registry ?? createActionRegistry({
      approvedProjectRoots: options.approvedProjectRoots,
    });
    if (this.#registry === null || typeof this.#registry.get !== 'function') {
      throw new TypeError('registry.get must be a function.');
    }
    this.#approvalService = options.approvalService;
    if (
      this.#approvalService === null
      || typeof this.#approvalService !== 'object'
      || typeof this.#approvalService.request !== 'function'
    ) {
      throw new TypeError('Policy engine requires an approval service.');
    }
    this.#identity = options.identity;
    if (
      this.#identity === null
      || typeof this.#identity !== 'object'
      || typeof this.#identity.fingerprint !== 'string'
      || typeof this.#identity.signCanonical !== 'function'
    ) {
      throw new TypeError('Policy engine requires a local identity.');
    }
    this.#vault = options.vault;
    this.#gitInspector = options.gitInspector ?? new GitInspector();
    if (this.#gitInspector === null || typeof this.#gitInspector.inspect !== 'function') {
      throw new TypeError('gitInspector.inspect must be a function.');
    }
    this.#clock = options.clock ?? { now: () => new Date() };
    if (typeof this.#clock.now !== 'function') {
      throw new TypeError('clock.now must be a function.');
    }
    this.#approvalTtlMilliseconds = options.approvalTtlMilliseconds
      ?? DEFAULT_APPROVAL_TTL_MILLISECONDS;
    if (
      !Number.isInteger(this.#approvalTtlMilliseconds)
      || this.#approvalTtlMilliseconds <= 0
      || this.#approvalTtlMilliseconds > DEFAULT_APPROVAL_TTL_MILLISECONDS
    ) {
      throw new TypeError('approvalTtlMilliseconds must be a short positive integer.');
    }
    this.#nonceGenerator = options.nonceGenerator ?? defaultNonce;
    if (typeof this.#nonceGenerator !== 'function') {
      throw new TypeError('nonceGenerator must be a function.');
    }
  }

  async evaluate(request) {
    const actionName = requestValue(request, 'action');
    const action = typeof actionName === 'string' ? this.#registry.get(actionName) : undefined;
    if (action === undefined) {
      return denied('unknown_action');
    }

    const projectRoot = requestValue(request, 'projectRoot');
    const agentId = requestValue(request, 'agentId');
    const requestParams = requestValue(request, 'params');
    if (typeof projectRoot !== 'string' || !validAgentId(agentId)) {
      return denied('invalid_request');
    }

    let snapshot;
    try {
      snapshot = await this.#gitInspector.inspect(projectRoot);
    } catch {
      return denied('project_unavailable');
    }
    if (!action.approvedProjectRoots.includes(snapshot.root)) {
      return denied('project_not_allowed');
    }

    let prepared;
    try {
      prepared = await this.#registry.prepare(action.name, requestParams, snapshot);
    } catch {
      return denied('invalid_parameters');
    }
    if (!(await this.#credentialAvailable(action.credential))) {
      return Object.freeze({
        action: action.name,
        credentialLabel: action.credentialLabel,
        status: 'credential_needed',
      });
    }

    let envelope;
    try {
      envelope = this.#createEnvelope(action, agentId, prepared, snapshot);
    } catch {
      return denied('identity_unavailable');
    }

    let approval;
    try {
      approval = await this.#approvalService.request(envelope);
    } catch {
      return denied('approval_unavailable');
    }

    const decision = {
      envelope,
      requestId: approval.id,
      requiresDirtyTreeAcknowledgement: approval.requiresDirtyTreeAcknowledgement === true,
      scope: approval.scope,
    };
    if (approval.status === 'approved_scope') {
      return Object.freeze({ ...decision, status: 'approved' });
    }
    if (approval.status === 'pending') {
      return Object.freeze({ ...decision, status: 'approval_required' });
    }
    return denied('approval_unavailable');
  }

  async #credentialAvailable(binding) {
    try {
      if (this.#vault === null || typeof this.#vault !== 'object') {
        return false;
      }
      if (typeof this.#vault.getActiveCredentialBinding === 'function') {
        return (await this.#vault.getActiveCredentialBinding(binding)) !== undefined;
      }
      if (typeof this.#vault.list !== 'function') {
        return false;
      }
      const credentials = await this.#vault.list();
      return Array.isArray(credentials) && credentials.some(
        (credential) => credential?.label === binding.label
          && credential?.provider === binding.provider
          && credential?.status === 'active',
      );
    } catch {
      return false;
    }
  }

  #createEnvelope(action, agentId, prepared, snapshot) {
    const requestedAt = this.#timestamp();
    const nonce = this.#nonceGenerator();
    if (typeof nonce !== 'string' || !/^[A-Za-z0-9_-]{16,128}$/u.test(nonce)) {
      throw new Error('Nonce is unavailable.');
    }
    const body = deepFreeze({
      action: action.name,
      actionVersion: action.version,
      agent: {
        id: agentId,
        identity: this.#identity.fingerprint,
      },
      credentialLabel: action.credentialLabel,
      credentialProvider: action.credential.provider,
      expiresAt: new Date(
        Date.parse(requestedAt) + this.#approvalTtlMilliseconds,
      ).toISOString(),
      nonce,
      params: prepared.params,
      policyVersion: POLICY_VERSION,
      project: {
        commit: snapshot.commit,
        dirty: snapshot.dirty,
        dirtyFingerprint: snapshot.dirtyFingerprint,
        repositoryFingerprint: snapshot.repositoryFingerprint,
        root: snapshot.root,
      },
      requestedAt,
      target: prepared.target,
    });
    const signature = this.#identity.signCanonical(body);

    return Object.freeze({
      body,
      bodyHash: sha256(body),
      signature,
    });
  }

  #timestamp() {
    const now = this.#clock.now();
    if (!(now instanceof Date) || Number.isNaN(now.valueOf())) {
      throw new Error('Policy clock is unavailable.');
    }
    return now.toISOString();
  }
}

function defaultNonce() {
  return randomBytes(24).toString('base64url');
}

function denied(code) {
  return Object.freeze({ code, status: 'denied' });
}

function requestValue(request, key) {
  if (!isPlainObject(request)) {
    return undefined;
  }
  const descriptor = Object.getOwnPropertyDescriptor(request, key);
  return descriptor !== undefined && Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined;
}

function validAgentId(value) {
  return typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value);
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
