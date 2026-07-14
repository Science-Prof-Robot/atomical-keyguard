import { realpathSync, statSync } from 'node:fs';
import { isAbsolute, parse } from 'node:path';

import { canonicalJson } from '../core/canonical.mjs';

export const POLICY_VERSION = 1;

/**
 * Builds the daemon-owned capability registry. Integrations are trusted code
 * supplied only at application startup; an agent request can select an
 * installed action but can never add an executable, command, or credential
 * mapping. A registry with no integrations is the normal default.
 */
export function createActionRegistry(options = {}) {
  if (!isPlainObject(options)) {
    throw new TypeError('Action registry options must be an object.');
  }
  assertAllowedKeys(options, ['approvedProjectRoots', 'integrations']);

  const approvedProjectRoots = normalizeApprovedRoots(
    options.approvedProjectRoots ?? [process.cwd()],
  );
  const integrations = options.integrations ?? [];
  if (!Array.isArray(integrations)) {
    throw new TypeError('Action registry integrations must be an array.');
  }

  const actions = new Map();
  const credentialBindings = new Map();
  const credentialLabels = new Map();
  for (const integration of integrations) {
    const action = normalizeIntegration(integration, approvedProjectRoots);
    if (actions.has(action.name)) {
      throw new TypeError('Action registry contains a duplicate action name.');
    }
    const credentialKey = credentialBindingKey(action.credential);
    const existingLabelBinding = credentialLabels.get(action.credential.label);
    if (
      existingLabelBinding !== undefined
      && existingLabelBinding.provider !== action.credential.provider
    ) {
      throw new TypeError('Action registry contains a credential label bound to multiple providers.');
    }
    if (!credentialBindings.has(credentialKey)) {
      credentialBindings.set(credentialKey, action.credential);
    }
    credentialLabels.set(action.credential.label, action.credential);
    actions.set(action.name, action);
  }

  const listedActions = Object.freeze(
    [...actions.values()]
      .map((action) => freezeDeep({
        approval: action.approval,
        name: action.name,
        params: cloneCanonical(action.params, 'Action parameter descriptor'),
        version: action.version,
      }))
      .sort((left, right) => left.name.localeCompare(right.name)),
  );

  return Object.freeze({
    async execute(envelope, secret) {
      const actionName = actionNameFromEnvelope(envelope);
      const action = actions.get(actionName);
      if (action === undefined) {
        throw new Error('Action is not allowed.');
      }
      assertEnvelopeBinding(envelope, action);
      return action.execute({ envelope, secret });
    },
    get(actionName) {
      return typeof actionName === 'string' ? actions.get(actionName) : undefined;
    },
    getCredentialBinding(metadata) {
      const credential = normalizeCredentialBinding(metadata, false);
      if (credential === undefined) {
        return undefined;
      }
      return credentialBindings.get(credentialBindingKey(credential));
    },
    list() {
      return listedActions;
    },
    async prepare(actionName, params, snapshot) {
      const action = actions.get(actionName);
      if (action === undefined) {
        throw new Error('Action is not allowed.');
      }
      const normalizedSnapshot = normalizeSnapshot(snapshot, approvedProjectRoots);
      const prepared = await action.prepare({
        params: cloneCanonical(params, 'Action parameters'),
        projectRoot: normalizedSnapshot.root,
        snapshot: normalizedSnapshot,
      });
      return normalizePreparedAction(prepared);
    },
    policyVersion: POLICY_VERSION,
  });
}

function normalizeIntegration(value, approvedProjectRoots) {
  if (!isPlainObject(value)) {
    throw new TypeError('Each integration must be a plain object.');
  }
  assertExactKeys(value, ['action', 'execute', 'prepare'], 'Integration');
  if (typeof value.prepare !== 'function' || typeof value.execute !== 'function') {
    throw new TypeError('Each integration must provide prepare and execute functions.');
  }
  const action = value.action;
  if (!isPlainObject(action)) {
    throw new TypeError('Integration action must be a plain object.');
  }
  assertExactKeys(action, ['approval', 'credential', 'name', 'params', 'version'], 'Integration action');
  if (action.approval !== 'always') {
    throw new TypeError('Integration action approval must be always.');
  }
  if (typeof action.name !== 'string' || !/^[a-z][a-z0-9_]{2,127}$/u.test(action.name)) {
    throw new TypeError('Integration action name is invalid.');
  }
  if (!Number.isInteger(action.version) || action.version < 1 || action.version > 1_000_000) {
    throw new TypeError('Integration action version is invalid.');
  }
  const credential = normalizeCredentialBinding(action.credential, true);
  const params = cloneCanonical(action.params, 'Integration action params');
  if (!isPlainObject(params)) {
    throw new TypeError('Integration action params must be a plain object.');
  }
  return freezeDeep({
    approval: action.approval,
    approvedProjectRoots,
    credential,
    credentialLabel: credential.label,
    execute: value.execute,
    name: action.name,
    params,
    prepare: value.prepare,
    version: action.version,
  });
}

function normalizePreparedAction(value) {
  if (!isPlainObject(value)) {
    throw new TypeError('Integration preparation must be a plain object.');
  }
  assertExactKeys(value, ['params', 'target'], 'Integration preparation');
  const params = cloneCanonical(value.params, 'Prepared action params');
  const target = cloneCanonical(value.target, 'Prepared action target');
  if (!isPlainObject(params) || !isPlainObject(target)) {
    throw new TypeError('Prepared action params and target must be plain objects.');
  }
  return freezeDeep({ params, target });
}

function normalizeSnapshot(value, approvedProjectRoots) {
  const snapshot = cloneCanonical(value, 'Project snapshot');
  if (!isPlainObject(snapshot) || typeof snapshot.root !== 'string' || !approvedProjectRoots.includes(snapshot.root)) {
    throw new Error('Project root is not approved for this action.');
  }
  return freezeDeep(snapshot);
}

function normalizeCredentialBinding(value, required) {
  try {
    if (!isPlainObject(value)) {
      throw new TypeError();
    }
    assertExactKeys(value, ['label', 'provider'], 'Credential binding');
    const label = value.label;
    const provider = value.provider;
    if (
      typeof label !== 'string'
      || label.length === 0
      || label.length > 128
      || label !== label.trim()
      || /[\u0000-\u001f]/u.test(label)
      || typeof provider !== 'string'
      || !/^[a-z0-9][a-z0-9-]{0,63}$/u.test(provider)
    ) {
      throw new TypeError();
    }
    return freezeDeep({ label, provider });
  } catch {
    if (required) {
      throw new TypeError('Integration credential binding is invalid.');
    }
    return undefined;
  }
}

function actionNameFromEnvelope(envelope) {
  if (isPlainObject(envelope) && typeof envelope.action === 'string') {
    return envelope.action;
  }
  if (isPlainObject(envelope) && isPlainObject(envelope.body) && typeof envelope.body.action === 'string') {
    return envelope.body.action;
  }
  throw new Error('Action envelope is invalid.');
}

function assertEnvelopeBinding(envelope, action) {
  if (!isPlainObject(envelope) || !isPlainObject(envelope.body)) {
    return;
  }
  const body = envelope.body;
  if (
    body.action !== action.name
    || body.actionVersion !== action.version
    || body.credentialLabel !== action.credentialLabel
    || body.credentialProvider !== action.credential.provider
  ) {
    throw new Error('Action envelope is not bound to the installed action.');
  }
}

function credentialBindingKey({ label, provider }) {
  return `${provider}\u0000${label}`;
}

function normalizeApprovedRoots(roots) {
  if (!Array.isArray(roots) || roots.length === 0) {
    throw new TypeError('At least one approved project root is required.');
  }

  const canonicalRoots = new Set();
  for (const root of roots) {
    if (
      typeof root !== 'string'
      || root.length === 0
      || root.includes('*')
      || !isAbsolute(root)
    ) {
      throw new TypeError('Each approved project root must be an explicit absolute directory.');
    }

    let canonicalRoot;
    try {
      canonicalRoot = realpathSync(root);
      if (!statSync(canonicalRoot).isDirectory()) {
        throw new Error('not a directory');
      }
    } catch {
      throw new TypeError('Each approved project root must be an existing directory.');
    }
    if (canonicalRoot === parse(canonicalRoot).root) {
      throw new TypeError('An approved project root must not be a filesystem root.');
    }
    canonicalRoots.add(canonicalRoot);
  }

  return Object.freeze([...canonicalRoots].sort());
}

function cloneCanonical(value, name) {
  try {
    return JSON.parse(canonicalJson(value));
  } catch {
    throw new TypeError(`${name} must contain canonical JSON data.`);
  }
}

function assertAllowedKeys(value, allowed) {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) {
      throw new TypeError('Action registry options contain an unsupported field.');
    }
  }
}

function assertExactKeys(value, expected, name) {
  const actual = Object.keys(value).sort();
  const keys = [...expected].sort();
  if (actual.length !== keys.length || actual.some((key, index) => key !== keys[index])) {
    throw new TypeError(`${name} contains unsupported fields.`);
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !Object.hasOwn(descriptor, 'value')) {
      throw new TypeError(`${name} contains unsupported fields.`);
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

function freezeDeep(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const item of Object.values(value)) {
      freezeDeep(item);
    }
  }
  return value;
}
