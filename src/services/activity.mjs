import { randomUUID } from 'node:crypto';
import { join, resolve } from 'node:path';

import { ACTION_NAME } from '../policy/action-registry.mjs';
import { JsonStore } from '../storage/json-store.mjs';
import { defaultDataDirectory } from '../storage/sealed-vault.mjs';

const STORE_VERSION = 1;
const STAGES = new Set(['preparing', 'executing', 'verifying']);
const STATUSES = new Set(['started', 'completed', 'failed', 'blocked']);

/**
 * An append-only audit of typed milestones. It deliberately has no message,
 * output, error, or arbitrary metadata field.
 */
export class ActivityService {
  #clock;
  #idGenerator;
  #ready;
  #storagePath;
  #store;

  constructor(options = {}) {
    if (options === null || typeof options !== 'object' || Array.isArray(options)) {
      throw new TypeError('Activity service options must be an object.');
    }
    const dataDirectory = options.dataDirectory ?? defaultDataDirectory();
    if (typeof dataDirectory !== 'string' || dataDirectory.length === 0) {
      throw new TypeError('dataDirectory must be a non-empty string.');
    }
    this.#storagePath = resolve(options.storagePath ?? join(dataDirectory, 'activity.json'));
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
    this.#ready = this.#store.initialize(emptyState()).then(validateState);
  }

  static async open(options = {}) {
    const service = new ActivityService(options);
    await service.#ready;
    return service;
  }

  get storagePath() {
    return this.#storagePath;
  }

  async append(milestone) {
    await this.#ready;
    const record = normalizeMilestone(milestone, this.#newId(), this.#timestamp());
    let result;

    await this.#store.update((state) => {
      validateState(state);
      state.activities.push(record);
      result = deepFreeze(cloneJson(record));
      return state;
    });
    return result;
  }

  async list() {
    await this.#ready;
    const state = await this.#store.read();
    validateState(state);
    return Object.freeze(state.activities.map((record) => deepFreeze(cloneJson(record))));
  }

  #newId() {
    const value = this.#idGenerator();
    if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{8,128}$/u.test(value)) {
      throw activityUnavailable();
    }
    return `activity_${value}`;
  }

  #timestamp() {
    let now;
    try {
      now = this.#clock.now();
    } catch {
      throw activityUnavailable();
    }
    if (!(now instanceof Date) || Number.isNaN(now.valueOf())) {
      throw activityUnavailable();
    }
    return now.toISOString();
  }
}

function emptyState() {
  return { activities: [], version: STORE_VERSION };
}

function normalizeMilestone(value, id, timestamp) {
  try {
    assertExactKeys(value, ['action', 'receiptId', 'requestId', 'stage', 'status']);
    const record = {
      action: value.action,
      id,
      receiptId: value.receiptId,
      requestId: value.requestId,
      stage: value.stage,
      status: value.status,
      timestamp,
    };
    validateRecord(record);
    return record;
  } catch {
    throw activityUnavailable();
  }
}

function validateState(state) {
  if (!isPlainObject(state)) {
    throw activityUnavailable();
  }
  assertExactKeys(state, ['activities', 'version']);
  if (state.version !== STORE_VERSION || !Array.isArray(state.activities)) {
    throw activityUnavailable();
  }
  const ids = new Set();
  for (const record of state.activities) {
    validateRecord(record);
    if (ids.has(record.id)) {
      throw activityUnavailable();
    }
    ids.add(record.id);
  }
}

function validateRecord(record) {
  if (!isPlainObject(record)) {
    throw activityUnavailable();
  }
  assertExactKeys(record, ['action', 'id', 'receiptId', 'requestId', 'stage', 'status', 'timestamp']);
  if (
    record.action !== ACTION_NAME
    || typeof record.id !== 'string'
    || !/^activity_[A-Za-z0-9_-]{8,128}$/u.test(record.id)
    || typeof record.requestId !== 'string'
    || !/^approval_[A-Za-z0-9_-]{8,128}$/u.test(record.requestId)
    || (record.receiptId !== null && (
      typeof record.receiptId !== 'string'
      || !/^receipt_[A-Za-z0-9_-]{8,128}$/u.test(record.receiptId)
    ))
    || !STAGES.has(record.stage)
    || !STATUSES.has(record.status)
  ) {
    throw activityUnavailable();
  }
  timestampMilliseconds(record.timestamp);
}

function timestampMilliseconds(value) {
  if (typeof value !== 'string') {
    throw activityUnavailable();
  }
  const timestamp = new Date(value);
  if (Number.isNaN(timestamp.valueOf()) || timestamp.toISOString() !== value) {
    throw activityUnavailable();
  }
  return timestamp.valueOf();
}

function assertExactKeys(value, expected) {
  if (!isPlainObject(value)) {
    throw activityUnavailable();
  }
  const actual = Object.keys(value).sort();
  const keys = [...expected].sort();
  if (actual.length !== keys.length || actual.some((key, index) => key !== keys[index])) {
    throw activityUnavailable();
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !Object.hasOwn(descriptor, 'value')) {
      throw activityUnavailable();
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

function activityUnavailable() {
  return new Error('Activity is unavailable.');
}
