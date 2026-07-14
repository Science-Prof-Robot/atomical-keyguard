import { randomUUID } from 'node:crypto';
import { homedir } from 'node:os';
import { isAbsolute, relative, win32 } from 'node:path';

import { canonicalJson } from '../core/canonical.mjs';
import { discoverEnvironment as defaultDiscoverEnvironment } from '../installer/discovery.mjs';
import {
  applyInstall as defaultApplyInstall,
  planInstall as defaultPlanInstall,
} from '../installer/skill-installer.mjs';

const DEFAULT_PLAN_TTL_MILLISECONDS = 2 * 60 * 1000;
const MAX_PLAN_TTL_MILLISECONDS = 10 * 60 * 1000;
const MAX_PENDING_PLANS = 64;
const HOSTS = new Set(['claude', 'codex']);
const SCOPES = new Set(['project', 'global', 'both']);
const SHARING_MODES = new Set(['private', 'shared']);
const APPLY_STATUSES = new Set(['written', 'updated', 'unchanged', 'mode_repaired']);

/**
 * Local-only control boundary for the installer. It fixes roots when opened,
 * keeps full plans in memory, and gives HTTP callers only opaque IDs and
 * relative destinations. No request can supply a root or rendered artifact.
 */
export class InstallerControlService {
  #applyInstall;
  #clock;
  #discoverEnvironment;
  #discoveryOptions;
  #fixedHomeDirectory;
  #fixedProjectRoot;
  #planIdGenerator;
  #planInstall;
  #plans;
  #planTtlMilliseconds;
  #ready;
  #requestedHomeDirectory;
  #requestedProjectRoot;

  constructor(options = {}) {
    if (!isPlainObject(options)) {
      throw new TypeError('Installer control options must be an object.');
    }
    this.#requestedProjectRoot = options.projectRoot ?? process.cwd();
    this.#requestedHomeDirectory = options.homeDirectory ?? homedir();
    if (
      typeof this.#requestedProjectRoot !== 'string'
      || this.#requestedProjectRoot.length === 0
      || !isAbsolute(this.#requestedProjectRoot)
      || typeof this.#requestedHomeDirectory !== 'string'
      || this.#requestedHomeDirectory.length === 0
      || !isAbsolute(this.#requestedHomeDirectory)
    ) {
      throw new TypeError('Installer control requires absolute project and home directories.');
    }
    this.#discoverEnvironment = options.discoverEnvironment ?? defaultDiscoverEnvironment;
    this.#planInstall = options.planInstall ?? defaultPlanInstall;
    this.#applyInstall = options.applyInstall ?? defaultApplyInstall;
    if (typeof this.#discoverEnvironment !== 'function') {
      throw new TypeError('discoverEnvironment must be a function.');
    }
    if (typeof this.#planInstall !== 'function') {
      throw new TypeError('planInstall must be a function.');
    }
    if (typeof this.#applyInstall !== 'function') {
      throw new TypeError('applyInstall must be a function.');
    }
    this.#clock = options.clock ?? { now: () => new Date() };
    if (this.#clock === null || typeof this.#clock !== 'object' || typeof this.#clock.now !== 'function') {
      throw new TypeError('clock.now must be a function.');
    }
    this.#planIdGenerator = options.planIdGenerator ?? randomUUID;
    if (typeof this.#planIdGenerator !== 'function') {
      throw new TypeError('planIdGenerator must be a function.');
    }
    this.#planTtlMilliseconds = options.planTtlMilliseconds ?? DEFAULT_PLAN_TTL_MILLISECONDS;
    if (
      !Number.isInteger(this.#planTtlMilliseconds)
      || this.#planTtlMilliseconds <= 0
      || this.#planTtlMilliseconds > MAX_PLAN_TTL_MILLISECONDS
    ) {
      throw new TypeError('planTtlMilliseconds must be a short positive integer.');
    }
    this.#discoveryOptions = discoveryOptions(options);
    this.#plans = new Map();
    this.#fixedHomeDirectory = undefined;
    this.#fixedProjectRoot = undefined;
    this.#ready = this.#initialize();
  }

  static async open(options = {}) {
    const service = new InstallerControlService(options);
    await service.#ready;
    return service;
  }

  async status() {
    await this.#ready;
    const discovery = await this.#currentDiscovery();
    return projectDiscovery(discovery);
  }

  async plan(selection = {}) {
    await this.#ready;
    const choices = normalizeSelection(selection);
    const discovery = await this.#currentDiscovery();
    const scope = choices.scope ?? 'project';
    const sharing = choices.sharing ?? 'private';
    const hosts = choices.hosts ?? selectedHosts(discovery);
    const expected = Object.freeze({
      homeDirectory: this.#fixedHomeDirectory,
      hosts,
      projectRoot: this.#fixedProjectRoot,
      scope,
      sharing,
    });
    let plan;
    try {
      plan = await this.#planInstall({
        homeDirectory: expected.homeDirectory,
        hosts,
        projectRoot: expected.projectRoot,
        scope,
        sharing,
      });
      plan = snapshotPlan(plan);
    } catch {
      throw installerUnavailable();
    }
    const safePlan = projectPlan(plan, expected);
    const now = this.#now();
    this.#purgeExpired(now.valueOf());
    if (this.#plans.size >= MAX_PENDING_PLANS) {
      throw installerUnavailable();
    }
    const planId = this.#newPlanId();
    const expiresAtMilliseconds = now.valueOf() + this.#planTtlMilliseconds;
    const expiresAt = new Date(expiresAtMilliseconds).toISOString();
    const projection = deepFreeze({
      ...safePlan,
      expiresAt,
      planId,
      status: 'planned',
    });
    this.#plans.set(planId, Object.freeze({
      expected,
      expiresAtMilliseconds,
      plan,
      projection,
      safePlan,
    }));
    return projection;
  }

  async apply(planId, confirmation = {}) {
    await this.#ready;
    const normalizedPlanId = requiredPlanId(planId);
    const normalizedConfirmation = normalizeConfirmation(confirmation);
    this.#purgeExpired(this.#now().valueOf());
    const record = this.#plans.get(normalizedPlanId);
    if (record === undefined) {
      throw planUnavailable();
    }
    const safePlan = projectPlan(record.plan, record.expected);
    if (!sameSafePlan(safePlan, record.safePlan)) {
      throw installerUnavailable();
    }
    if (safePlan.requiresGlobalOptIn && normalizedConfirmation.globalOptIn !== true) {
      throw globalOptInRequired();
    }

    // Consume before applying so retries cannot replay a locally authorized
    // filesystem plan if a caller races or repeats the request.
    this.#plans.delete(normalizedPlanId);
    let result;
    try {
      result = await this.#applyInstall(record.plan, normalizedConfirmation);
    } catch {
      throw installerUnavailable();
    }
    return projectApplied(result, safePlan, record.plan);
  }

  async #initialize() {
    await this.#currentDiscovery();
  }

  async #currentDiscovery() {
    const projectRoot = this.#fixedProjectRoot ?? this.#requestedProjectRoot;
    const homeDirectory = this.#fixedHomeDirectory ?? this.#requestedHomeDirectory;
    let discovery;
    try {
      discovery = await this.#discoverEnvironment(projectRoot, {
        ...this.#discoveryOptions,
        homeDirectory,
      });
    } catch {
      throw installerUnavailable();
    }
    const roots = discoveryRoots(discovery);
    if (this.#fixedProjectRoot === undefined) {
      this.#fixedProjectRoot = roots.projectRoot;
      this.#fixedHomeDirectory = roots.homeDirectory;
    } else if (
      roots.projectRoot !== this.#fixedProjectRoot
      || roots.homeDirectory !== this.#fixedHomeDirectory
    ) {
      throw installerUnavailable();
    }
    return discovery;
  }

  #now() {
    let value;
    try {
      value = this.#clock.now();
    } catch {
      throw installerUnavailable();
    }
    if (!(value instanceof Date) || Number.isNaN(value.valueOf())) {
      throw installerUnavailable();
    }
    return new Date(value);
  }

  #newPlanId() {
    const value = this.#planIdGenerator();
    if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{8,128}$/u.test(value)) {
      throw installerUnavailable();
    }
    const id = `install_${value}`;
    if (this.#plans.has(id)) {
      throw installerUnavailable();
    }
    return id;
  }

  #purgeExpired(now) {
    for (const [id, record] of this.#plans) {
      if (record.expiresAtMilliseconds <= now) {
        this.#plans.delete(id);
      }
    }
  }
}

function discoveryOptions(options) {
  const result = {};
  for (const key of ['actionRegistry', 'environment', 'identity', 'policy', 'policyVersion']) {
    if (options[key] !== undefined) {
      result[key] = options[key];
    }
  }
  return Object.freeze(result);
}

function normalizeSelection(value) {
  if (!isPlainObject(value)) {
    throw invalidSelection();
  }
  const allowed = new Set(['hosts', 'scope', 'sharing']);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key) || !hasValueProperty(value, key)) {
      throw invalidSelection();
    }
  }
  const result = {};
  if (Object.hasOwn(value, 'hosts')) {
    if (!Array.isArray(value.hosts) || value.hosts.length === 0 || value.hosts.length > HOSTS.size) {
      throw invalidSelection();
    }
    const hosts = [...value.hosts];
    if (
      hosts.some((host) => typeof host !== 'string' || !HOSTS.has(host))
      || new Set(hosts).size !== hosts.length
    ) {
      throw invalidSelection();
    }
    result.hosts = Object.freeze(hosts.sort());
  }
  if (Object.hasOwn(value, 'scope')) {
    if (typeof value.scope !== 'string' || !SCOPES.has(value.scope)) {
      throw invalidSelection();
    }
    result.scope = value.scope;
  }
  if (Object.hasOwn(value, 'sharing')) {
    if (typeof value.sharing !== 'string' || !SHARING_MODES.has(value.sharing)) {
      throw invalidSelection();
    }
    result.sharing = value.sharing;
  }
  return Object.freeze(result);
}

function selectedHosts(discovery) {
  const hosts = projectHosts(discovery.hosts);
  const selected = Object.entries(hosts)
    .filter(([, details]) => details.preselected)
    .map(([host]) => host)
    .sort();
  if (selected.length === 0) {
    throw installerUnavailable();
  }
  return Object.freeze(selected);
}

function discoveryRoots(value) {
  if (!isPlainObject(value)) {
    throw installerUnavailable();
  }
  assertValueKeys(value, ['homeDirectory', 'projectRoot']);
  if (
    typeof value.homeDirectory !== 'string'
    || !isAbsolute(value.homeDirectory)
    || typeof value.projectRoot !== 'string'
    || !isAbsolute(value.projectRoot)
  ) {
    throw installerUnavailable();
  }
  return Object.freeze({ homeDirectory: value.homeDirectory, projectRoot: value.projectRoot });
}

function projectDiscovery(value) {
  if (!isPlainObject(value)) {
    throw installerUnavailable();
  }
  assertValueKeys(value, ['atomicCli', 'hosts', 'identity', 'mcp', 'policy', 'repository']);
  const hosts = projectHosts(value.hosts);
  if (!isPlainObject(value.atomicCli) || !hasValueProperty(value.atomicCli, 'detected') || typeof value.atomicCli.detected !== 'boolean') {
    throw installerUnavailable();
  }
  if (!isPlainObject(value.identity) || !hasValueProperty(value.identity, 'available') || typeof value.identity.available !== 'boolean') {
    throw installerUnavailable();
  }
  if (!isPlainObject(value.mcp) || !hasValueProperty(value.mcp, 'registered') || typeof value.mcp.registered !== 'boolean') {
    throw installerUnavailable();
  }
  if (!isPlainObject(value.policy) || !hasValueProperty(value.policy, 'active') || !hasValueProperty(value.policy, 'version')) {
    throw installerUnavailable();
  }
  if (
    typeof value.policy.active !== 'boolean'
    || (value.policy.version !== null && (!Number.isInteger(value.policy.version) || value.policy.version < 0))
  ) {
    throw installerUnavailable();
  }
  if (!isPlainObject(value.repository) || !hasValueProperty(value.repository, 'detected') || typeof value.repository.detected !== 'boolean') {
    throw installerUnavailable();
  }
  return deepFreeze({
    atomicCli: { detected: value.atomicCli.detected },
    hosts,
    identity: { available: value.identity.available },
    mcp: { registered: value.mcp.registered },
    policy: { active: value.policy.active, version: value.policy.version },
    repository: { detected: value.repository.detected },
  });
}

function projectHosts(value) {
  if (!isPlainObject(value)) {
    throw installerUnavailable();
  }
  const projected = {};
  for (const host of [...HOSTS].sort()) {
    const details = value[host];
    if (!isPlainObject(details)) {
      throw installerUnavailable();
    }
    assertValueKeys(details, ['detected', 'globalSkill', 'preselected', 'projectSkill']);
    if (
      typeof details.detected !== 'boolean'
      || typeof details.globalSkill !== 'boolean'
      || typeof details.preselected !== 'boolean'
      || typeof details.projectSkill !== 'boolean'
    ) {
      throw installerUnavailable();
    }
    projected[host] = {
      detected: details.detected,
      globalSkill: details.globalSkill,
      preselected: details.preselected,
      projectSkill: details.projectSkill,
    };
  }
  return deepFreeze(projected);
}

function projectPlan(plan, expected) {
  if (!isPlainObject(plan)) {
    throw installerUnavailable();
  }
  assertValueKeys(plan, [
    'files',
    'homeDirectory',
    'hosts',
    'projectRoot',
    'requiresConfirmation',
    'requiresGlobalOptIn',
    'scope',
    'sharing',
  ]);
  if (
    plan.homeDirectory !== expected.homeDirectory
    || plan.projectRoot !== expected.projectRoot
    || plan.scope !== expected.scope
    || plan.sharing !== expected.sharing
    || plan.requiresConfirmation !== true
    || plan.requiresGlobalOptIn !== (expected.scope === 'global' || expected.scope === 'both')
    || !sameStringArray(plan.hosts, expected.hosts)
    || !Array.isArray(plan.files)
    || plan.files.length === 0
  ) {
    throw installerUnavailable();
  }
  const destinations = [];
  const destinationKeys = new Set();
  const destinationScopes = new Set();
  for (const file of plan.files) {
    const destination = projectPlannedDestination(file, expected);
    const key = `${destination.scope}:${destination.destination}`;
    if (destinationKeys.has(key)) {
      throw installerUnavailable();
    }
    destinationKeys.add(key);
    destinationScopes.add(destination.scope);
    destinations.push(destination);
  }
  if (!hasExpectedArtifactScopes(expected.scope, destinationScopes)) {
    throw installerUnavailable();
  }
  return deepFreeze({
    destinations,
    hosts: [...expected.hosts],
    requiresConfirmation: true,
    requiresGlobalOptIn: plan.requiresGlobalOptIn,
    scope: expected.scope,
    sharing: expected.sharing,
  });
}

function projectPlannedDestination(file, expected) {
  if (!isPlainObject(file)) {
    throw installerUnavailable();
  }
  assertValueKeys(file, ['path', 'root', 'scope']);
  if (!artifactScopeMatchesPlanScope(expected.scope, file.scope)) {
    throw installerUnavailable();
  }
  const root = file.scope === 'project' ? expected.projectRoot : expected.homeDirectory;
  if (file.root !== root) {
    throw installerUnavailable();
  }
  return Object.freeze({
    destination: relativeDestination(root, file.path),
    scope: file.scope,
  });
}

function normalizeConfirmation(value) {
  if (!isPlainObject(value)) {
    throw confirmationRequired();
  }
  const allowed = new Set(['confirmed', 'globalOptIn']);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key) || !hasValueProperty(value, key)) {
      throw confirmationRequired();
    }
  }
  if (value.confirmed !== true) {
    throw confirmationRequired();
  }
  if (Object.hasOwn(value, 'globalOptIn') && typeof value.globalOptIn !== 'boolean') {
    throw confirmationRequired();
  }
  return Object.freeze({ confirmed: true, globalOptIn: value.globalOptIn === true });
}

function projectApplied(value, safePlan, rawPlan) {
  if (!isPlainObject(value)) {
    throw installerUnavailable();
  }
  assertValueKeys(value, ['files', 'hosts', 'scope', 'sharing', 'status']);
  if (
    value.status !== 'installed'
    || value.scope !== safePlan.scope
    || value.sharing !== safePlan.sharing
    || !sameStringArray(value.hosts, safePlan.hosts)
    || !Array.isArray(value.files)
    || value.files.length !== rawPlan.files.length
  ) {
    throw installerUnavailable();
  }
  const statusesByPath = new Map();
  for (const result of value.files) {
    if (!isPlainObject(result)) {
      throw installerUnavailable();
    }
    assertValueKeys(result, ['path', 'status']);
    if (typeof result.path !== 'string' || !APPLY_STATUSES.has(result.status) || statusesByPath.has(result.path)) {
      throw installerUnavailable();
    }
    statusesByPath.set(result.path, result.status);
  }
  const destinations = safePlan.destinations.map((destination, index) => {
    const planned = rawPlan.files[index];
    const status = statusesByPath.get(planned.path);
    if (status === undefined) {
      throw installerUnavailable();
    }
    return { ...destination, status };
  });
  return deepFreeze({
    destinations,
    hosts: [...safePlan.hosts],
    scope: safePlan.scope,
    sharing: safePlan.sharing,
    status: 'installed',
  });
}

function relativeDestination(root, path) {
  if (typeof path !== 'string' || !isAbsolute(path)) {
    throw installerUnavailable();
  }
  const destination = relative(root, path);
  if (!safeRelativeDestination(destination)) {
    throw installerUnavailable();
  }
  return destination.replaceAll('\\', '/');
}

function safeRelativeDestination(value) {
  return typeof value === 'string'
    && value.length > 0
    && !isAbsolute(value)
    && !win32.isAbsolute(value)
    && !/^[A-Za-z]:/u.test(value)
    && !value.split(/[\\/]/u).some((segment) => segment.length === 0 || segment === '.' || segment === '..')
    && !/[\u0000-\u001f]/u.test(value);
}

function artifactScopeMatchesPlanScope(planScope, artifactScope) {
  if (artifactScope !== 'project' && artifactScope !== 'global') {
    return false;
  }
  return planScope === 'both' || artifactScope === planScope;
}

function hasExpectedArtifactScopes(planScope, artifactScopes) {
  if (planScope === 'both') {
    return artifactScopes.size === 2
      && artifactScopes.has('project')
      && artifactScopes.has('global');
  }
  return artifactScopes.size === 1 && artifactScopes.has(planScope);
}

function snapshotPlan(value) {
  try {
    return deepFreeze(JSON.parse(canonicalJson(value)));
  } catch {
    throw installerUnavailable();
  }
}

function sameSafePlan(left, right) {
  try {
    return canonicalJson(left) === canonicalJson(right);
  } catch {
    return false;
  }
}

function sameStringArray(actual, expected) {
  return Array.isArray(actual)
    && actual.length === expected.length
    && actual.every((item, index) => item === expected[index]);
}

function requiredPlanId(value) {
  if (typeof value !== 'string' || !/^install_[A-Za-z0-9_-]{8,128}$/u.test(value)) {
    throw planUnavailable();
  }
  return value;
}

function assertValueKeys(value, keys) {
  if (!isPlainObject(value)) {
    throw installerUnavailable();
  }
  for (const key of keys) {
    if (!hasValueProperty(value, key)) {
      throw installerUnavailable();
    }
  }
}

function hasValueProperty(value, key) {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  return descriptor !== undefined && Object.hasOwn(descriptor, 'value');
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

function invalidSelection() {
  return new TypeError('Installer selection is invalid.');
}

function confirmationRequired() {
  return new Error('Installer confirmation is required.');
}

function globalOptInRequired() {
  return new Error('Explicit global opt-in is required.');
}

function planUnavailable() {
  return new Error('Install plan is unavailable.');
}

function installerUnavailable() {
  return new Error('Installer control is unavailable.');
}
