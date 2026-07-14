import { randomBytes, timingSafeEqual } from 'node:crypto';
import { win32 } from 'node:path';

export const MAX_REQUEST_BODY_BYTES = 16 * 1024;

const DELETE_CONFIRMATION = 'DELETE';
const INSTALL_CONFIRMATION = 'INSTALL';
const REVOKE_CONFIRMATION = 'REVOKE';
const SESSION_COOKIE = 'keyguard_session';
const CSRF_COOKIE = 'keyguard_csrf';
const SESSION_TOKEN_PATTERN = /^[A-Za-z0-9_-]{32,128}$/u;
const MUTATING_METHODS = new Set(['DELETE', 'PATCH', 'POST', 'PUT']);
const SETUP_SCOPES = new Set(['project', 'global', 'both']);
const INSTALL_HOSTS = new Set(['claude', 'codex']);
const INSTALL_SCOPES = new Set(['project', 'global', 'both']);
const INSTALL_SHARING_MODES = new Set(['private', 'shared']);
const EXECUTION_STATUSES = new Set([
  'approval_not_granted',
  'preparation_failed',
  'provider_failed',
  'verification_failed',
  'verified',
]);
const PROVIDER_STATUSES = new Set(['succeeded', 'failed', 'not_started']);
const VERIFICATION_STATUSES = new Set(['verified', 'failed', 'not_run']);
const INSTALL_APPLY_STATUSES = new Set(['written', 'updated', 'unchanged', 'mode_repaired']);

/**
 * Builds the secret-free HTTP API handler. Service output is projected through
 * explicit allowlists before it can become an HTTP response.
 */
export function createApiRouter(options = {}) {
  if (options === null || typeof options !== 'object' || Array.isArray(options)) {
    throw new TypeError('Router options must be an object.');
  }
  const app = options.app;
  if (app === null || typeof app !== 'object' || typeof app.status !== 'function') {
    throw new TypeError('Router requires an application status function.');
  }
  const services = options.services ?? app.services;
  if (services === null || typeof services !== 'object') {
    throw new TypeError('Router requires application services.');
  }
  const originProvider = options.originProvider ?? (() => 'http://127.0.0.1:4545');
  if (typeof originProvider !== 'function') {
    throw new TypeError('originProvider must be a function.');
  }
  const session = createSession(options.sessionTokenGenerator);

  return async function route(request, response) {
    try {
      if (!isLoopbackRequest(request)) {
        throw httpError(403, 'forbidden');
      }
      const method = request.method ?? '';
      const pathname = requestPathname(request);
      if (method === 'OPTIONS') {
        throw httpError(405, 'method_not_allowed');
      }
      const webhook = method === 'POST' && pathname === '/atomic/events';
      if (!webhook && MUTATING_METHODS.has(method)) {
        const expectedOrigin = expectedLocalOrigin(originProvider);
        session.requireMutation(request, expectedOrigin);
      }

      const result = await dispatch({ app, method, pathname, request, services });
      const cookies = method === 'GET' && !webhook ? session.cookies() : undefined;
      writeJson(response, result.status, result.body, cookies);
    } catch (error) {
      writeError(response, error);
    }
  };
}

async function dispatch({ app, method, pathname, request, services }) {
  if (method === 'GET' && pathname === '/api/status') {
    return { body: projectStatus(await app.status()), status: 200 };
  }
  if (method === 'POST' && pathname === '/api/setup/complete') {
    const body = await readJsonObject(request);
    assertExactKeys(body, ['scope']);
    if (typeof body.scope !== 'string' || !SETUP_SCOPES.has(body.scope)) {
      throw httpError(400, 'invalid_request');
    }
    const setup = await invoke(services.setup, 'complete', body.scope);
    return { body: { setup: projectSetup(setup) }, status: 200 };
  }
  if (method === 'GET' && pathname === '/api/credentials') {
    const credentials = await invoke(services.vault, 'list');
    return { body: { items: ensureArray(credentials).map(projectCredential) }, status: 200 };
  }
  if (method === 'POST' && pathname === '/api/deposit-link') {
    const metadata = depositMetadata(await readJsonObject(request));
    const deposit = await invoke(services.depositService, 'create', metadata);
    return { body: { deposit: projectDeposit(deposit) }, status: 201 };
  }
  if (method === 'POST' && pathname === '/atomic/events') {
    const event = await readJsonObject(request);
    const credential = await invoke(services.depositService, 'receiveSigned', event, webhookHeaders(request));
    return { body: { credential: projectCredential(credential) }, status: 202 };
  }
  if (method === 'GET' && pathname === '/api/approvals') {
    const approvals = await invoke(services.approvals, 'list');
    return { body: { items: ensureArray(approvals).map(projectApproval) }, status: 200 };
  }
  if (method === 'GET' && pathname === '/api/activity') {
    const activity = await invoke(services.activity, 'list');
    return { body: { items: ensureArray(activity).map(projectActivity) }, status: 200 };
  }
  if (method === 'GET' && pathname === '/api/actions') {
    const actions = await invoke(services.actionRegistry, 'list');
    return { body: { items: ensureArray(actions).map(projectAction) }, status: 200 };
  }
  if (method === 'GET' && pathname === '/api/memory') {
    const memory = await invoke(services.memory, 'list');
    return { body: { items: ensureArray(memory).map(projectMemory) }, status: 200 };
  }
  if (method === 'GET' && pathname === '/api/skill/status') {
    const skill = await invoke(services.installerControl, 'status');
    return { body: projectSkillStatus(skill), status: 200 };
  }
  if (method === 'POST' && pathname === '/api/skill/install-plan') {
    const selection = installSelection(await readJsonObject(request));
    const plan = await invoke(services.installerControl, 'plan', selection);
    return { body: { plan: projectInstallPlan(plan) }, status: 201 };
  }
  if (method === 'POST' && pathname === '/api/skill/install') {
    const install = installRequest(await readJsonObject(request));
    const result = await invoke(
      services.installerControl,
      'apply',
      install.planId,
      { confirmed: true, globalOptIn: install.globalOptIn },
    );
    return { body: { install: projectInstallResult(result) }, status: 200 };
  }

  const credentialRevokePath = matchPath(pathname, /^\/api\/credentials\/([^/]+)\/revoke$/u);
  if (method === 'POST' && credentialRevokePath !== undefined) {
    const body = await readJsonObject(request);
    assertExactKeys(body, ['confirmation']);
    if (body.confirmation !== REVOKE_CONFIRMATION) {
      throw httpError(400, 'confirmation_required');
    }
    const [rawCredentialLabel] = credentialRevokePath;
    const label = safePathValue(rawCredentialLabel, 'label');
    const credential = await invoke(services.vault, 'revoke', label);
    return { body: { credential: projectCredential(credential) }, status: 200 };
  }

  const credentialPath = matchPath(pathname, /^\/api\/credentials\/([^/]+)$/u);
  if (method === 'DELETE' && credentialPath !== undefined) {
    const body = await readJsonObject(request);
    assertExactKeys(body, ['confirmation']);
    if (body.confirmation !== DELETE_CONFIRMATION) {
      throw httpError(400, 'confirmation_required');
    }
    const [rawCredentialLabel] = credentialPath;
    const label = safePathValue(rawCredentialLabel, 'label');
    const deleted = await invoke(services.vault, 'delete', label);
    if (typeof deleted !== 'boolean') {
      throw httpError(503, 'service_unavailable');
    }
    return { body: { deleted, label }, status: 200 };
  }

  const approvalAction = matchPath(
    pathname,
    /^\/api\/approvals\/([^/]+)\/(approve|approve-scope|deny)$/u,
  );
  if (method === 'POST' && approvalAction !== undefined) {
    const [rawId, action] = approvalAction;
    const id = safePathValue(rawId, 'approval id');
    const body = await readJsonObject(request);
    if (action === 'approve') {
      assertExactKeys(body, ['dirtyTreeAcknowledged']);
      if (typeof body.dirtyTreeAcknowledged !== 'boolean') {
        throw httpError(400, 'invalid_request');
      }
      const approval = await invoke(
        services.approvals,
        'approveOnce',
        id,
        { dirtyTreeAcknowledged: body.dirtyTreeAcknowledged },
      );
      return approvalExecutionResponse(services, id, approval);
    }
    if (action === 'approve-scope') {
      assertExactKeys(body, []);
      const approval = await invoke(services.approvals, 'approveExactScope', id);
      return approvalExecutionResponse(services, id, approval);
    }
    assertExactKeys(body, []);
    const approval = await invoke(services.approvals, 'deny', id);
    return { body: { approval: projectApproval(approval) }, status: 200 };
  }

  const memoryAction = matchPath(
    pathname,
    /^\/api\/memory\/([^/]+)\/(approve|forget)$/u,
  );
  if (method === 'POST' && memoryAction !== undefined) {
    const [rawId, action] = memoryAction;
    const id = safePathValue(rawId, 'memory id');
    const body = await readJsonObject(request);
    assertExactKeys(body, []);
    const memory = await invoke(services.memory, action === 'approve' ? 'save' : 'dismiss', id);
    return { body: { memory: projectMemory(memory) }, status: 200 };
  }

  if (knownPath(pathname)) {
    throw httpError(405, 'method_not_allowed');
  }
  throw httpError(404, 'not_found');
}

function knownPath(pathname) {
  return pathname === '/api/status'
    || pathname === '/api/setup/complete'
    || pathname === '/api/credentials'
    || pathname === '/api/deposit-link'
    || pathname === '/atomic/events'
    || pathname === '/api/approvals'
    || pathname === '/api/activity'
    || pathname === '/api/actions'
    || pathname === '/api/memory'
    || pathname === '/api/skill/status'
    || pathname === '/api/skill/install-plan'
    || pathname === '/api/skill/install'
    || /^\/api\/credentials\/[^/]+$/u.test(pathname)
    || /^\/api\/credentials\/[^/]+\/revoke$/u.test(pathname)
    || /^\/api\/approvals\/[^/]+\/(approve|approve-scope|deny)$/u.test(pathname)
    || /^\/api\/memory\/[^/]+\/(approve|forget)$/u.test(pathname);
}

function createSession(tokenGenerator = defaultSessionToken) {
  if (typeof tokenGenerator !== 'function') {
    throw new TypeError('sessionTokenGenerator must be a function.');
  }
  const sessionToken = validatedSessionToken(tokenGenerator());
  const csrfToken = validatedSessionToken(tokenGenerator());

  return Object.freeze({
    cookies() {
      return [
        `${SESSION_COOKIE}=${sessionToken}; Path=/; HttpOnly; SameSite=Strict`,
        `${CSRF_COOKIE}=${csrfToken}; Path=/; SameSite=Strict`,
      ];
    },
    requireMutation(request, expectedOrigin) {
      const origin = requestHeader(request, 'origin');
      const cookies = cookieMap(requestHeader(request, 'cookie'));
      const csrfHeader = requestHeader(request, 'x-keyguard-csrf');
      if (
        origin !== expectedOrigin
        || !sameToken(cookies.get(SESSION_COOKIE), sessionToken)
        || !sameToken(cookies.get(CSRF_COOKIE), csrfToken)
        || !sameToken(csrfHeader, csrfToken)
      ) {
        throw httpError(403, 'forbidden');
      }
    },
  });
}

function defaultSessionToken() {
  return randomBytes(32).toString('base64url');
}

function validatedSessionToken(value) {
  if (typeof value !== 'string' || !SESSION_TOKEN_PATTERN.test(value)) {
    throw new TypeError('Session token generator returned an invalid value.');
  }
  return value;
}

function sameToken(actual, expected) {
  if (typeof actual !== 'string' || actual.length !== expected.length) {
    return false;
  }
  return timingSafeEqual(Buffer.from(actual, 'utf8'), Buffer.from(expected, 'utf8'));
}

async function readJsonObject(request) {
  const contentLength = requestHeader(request, 'content-length');
  if (contentLength !== undefined) {
    if (!/^\d{1,9}$/u.test(contentLength)) {
      throw httpError(400, 'invalid_request');
    }
    if (Number(contentLength) > MAX_REQUEST_BODY_BYTES) {
      request.resume();
      throw httpError(413, 'payload_too_large');
    }
  }
  const chunks = [];
  let total = 0;
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += bytes.length;
    if (total > MAX_REQUEST_BODY_BYTES) {
      request.resume();
      throw httpError(413, 'payload_too_large');
    }
    chunks.push(bytes);
  }
  if (total === 0) {
    return {};
  }
  const contentType = requestHeader(request, 'content-type');
  if (contentType === undefined || !/^application\/json(?:\s*;|$)/iu.test(contentType)) {
    throw httpError(415, 'unsupported_media_type');
  }
  let value;
  try {
    value = JSON.parse(Buffer.concat(chunks, total).toString('utf8'));
  } catch {
    throw httpError(400, 'invalid_json');
  }
  if (!isPlainObject(value)) {
    throw httpError(400, 'invalid_request');
  }
  return value;
}

function depositMetadata(value) {
  assertExactKeys(value, ['label', 'provider']);
  const label = safeLabel(value.label);
  if (typeof value.provider !== 'string' || !/^[a-z0-9][a-z0-9-]{0,63}$/u.test(value.provider)) {
    throw httpError(400, 'invalid_request');
  }
  return Object.freeze({ label, provider: value.provider });
}

function installSelection(value) {
  assertAllowedKeys(value, ['hosts', 'scope', 'sharing']);
  const selection = {};
  if (Object.hasOwn(value, 'hosts')) {
    if (
      !Array.isArray(value.hosts)
      || value.hosts.length === 0
      || value.hosts.length > INSTALL_HOSTS.size
      || value.hosts.some((host) => typeof host !== 'string' || !INSTALL_HOSTS.has(host))
      || new Set(value.hosts).size !== value.hosts.length
    ) {
      throw httpError(400, 'invalid_request');
    }
    selection.hosts = [...value.hosts].sort();
  }
  if (Object.hasOwn(value, 'scope')) {
    if (!validInstallScope(value.scope)) {
      throw httpError(400, 'invalid_request');
    }
    selection.scope = value.scope;
  }
  if (Object.hasOwn(value, 'sharing')) {
    if (!validInstallSharing(value.sharing)) {
      throw httpError(400, 'invalid_request');
    }
    selection.sharing = value.sharing;
  }
  return Object.freeze(selection);
}

function installRequest(value) {
  assertAllowedKeys(value, ['confirmation', 'globalOptIn', 'planId']);
  if (value.confirmation !== INSTALL_CONFIRMATION) {
    throw httpError(400, 'confirmation_required');
  }
  if (typeof value.planId !== 'string' || !/^install_[A-Za-z0-9_-]{8,128}$/u.test(value.planId)) {
    throw httpError(400, 'invalid_request');
  }
  if (Object.hasOwn(value, 'globalOptIn') && typeof value.globalOptIn !== 'boolean') {
    throw httpError(400, 'invalid_request');
  }
  return Object.freeze({
    globalOptIn: value.globalOptIn === true,
    planId: value.planId,
  });
}

function validInstallScope(value) {
  return typeof value === 'string' && INSTALL_SCOPES.has(value);
}

function validInstallSharing(value) {
  return typeof value === 'string' && INSTALL_SHARING_MODES.has(value);
}

function validTimestamp(value) {
  if (typeof value !== 'string') {
    return false;
  }
  const date = new Date(value);
  return !Number.isNaN(date.valueOf()) && date.toISOString() === value;
}

function safeRelativeDestination(value) {
  return typeof value === 'string'
    && value.length > 0
    && value.length <= 512
    && !value.startsWith('/')
    && !value.startsWith('\\')
    && !win32.isAbsolute(value)
    && !/^[A-Za-z]:/u.test(value)
    && !value.split(/[\\/]/u).some((segment) => segment.length === 0 || segment === '.' || segment === '..')
    && !/[\u0000-\u001f]/u.test(value);
}

function projectStatus(value) {
  if (!isPlainObject(value) || !isPlainObject(value.server)) {
    throw httpError(503, 'service_unavailable');
  }
  assertValueKeys(value, ['identity', 'server', 'setup', 'state']);
  const { server } = value;
  if (
    server.host !== '127.0.0.1'
    || !Number.isInteger(server.port)
    || server.port < 0
    || server.port > 65_535
    || server.url !== `http://127.0.0.1:${server.port}`
    || !['running', 'stopped'].includes(value.state)
  ) {
    throw httpError(503, 'service_unavailable');
  }
  const identity = projectIdentity(value.identity);
  const setup = projectSetup(value.setup);
  return {
    identity,
    server: { host: server.host, port: server.port, url: server.url },
    setup,
    state: value.state,
  };
}

function projectIdentity(value) {
  if (!isPlainObject(value)) {
    throw httpError(503, 'service_unavailable');
  }
  assertValueKeys(value, ['fingerprint']);
  if (typeof value.fingerprint !== 'string' || !/^[a-f0-9]{64}$/u.test(value.fingerprint)) {
    throw httpError(503, 'service_unavailable');
  }
  return { fingerprint: value.fingerprint };
}

function projectSetup(value) {
  if (!isPlainObject(value)) {
    throw httpError(503, 'service_unavailable');
  }
  assertValueKeys(value, ['complete']);
  if (typeof value.complete !== 'boolean') {
    throw httpError(503, 'service_unavailable');
  }
  if (!value.complete) {
    return { complete: false };
  }
  assertValueKeys(value, ['scope']);
  if (typeof value.scope !== 'string' || !SETUP_SCOPES.has(value.scope)) {
    throw httpError(503, 'service_unavailable');
  }
  return { complete: true, scope: value.scope };
}

async function approvalExecutionResponse(services, id, approval) {
  const projectedApproval = projectApproval(approval);
  if (
    !['approved_once', 'approved_scope'].includes(projectedApproval.status)
    || (
      projectedApproval.requiresDirtyTreeAcknowledgement
      && !projectedApproval.dirtyTreeAcknowledged
    )
  ) {
    return { body: { approval: projectedApproval }, status: 200 };
  }
  const execution = await invoke(services.execution, 'executeApproved', id);
  return {
    body: {
      approval: projectedApproval,
      execution: projectExecution(execution),
    },
    status: 200,
  };
}

function projectExecution(value) {
  if (!isPlainObject(value)) {
    throw httpError(503, 'service_unavailable');
  }
  assertValueKeys(value, ['status']);
  if (typeof value.status !== 'string' || !EXECUTION_STATUSES.has(value.status)) {
    throw httpError(503, 'service_unavailable');
  }
  if (value.status === 'approval_not_granted') {
    return { status: value.status };
  }
  assertValueKeys(value, ['receipt']);
  return {
    receipt: projectExecutionReceipt(value.receipt),
    status: value.status,
  };
}

function projectExecutionReceipt(value) {
  if (!isPlainObject(value)) {
    throw httpError(503, 'service_unavailable');
  }
  assertValueKeys(value, ['action', 'id', 'provider', 'verification']);
  if (
    typeof value.action !== 'string'
    || !/^[a-z][a-z0-9_]{2,127}$/u.test(value.action)
    || typeof value.id !== 'string'
    || !/^receipt_[A-Za-z0-9_-]{8,128}$/u.test(value.id)
    || !isPlainObject(value.provider)
    || !isPlainObject(value.verification)
  ) {
    throw httpError(503, 'service_unavailable');
  }
  assertValueKeys(value.provider, ['status']);
  assertValueKeys(value.verification, ['status']);
  if (
    typeof value.provider.status !== 'string'
    || !PROVIDER_STATUSES.has(value.provider.status)
    || typeof value.verification.status !== 'string'
    || !VERIFICATION_STATUSES.has(value.verification.status)
  ) {
    throw httpError(503, 'service_unavailable');
  }
  return {
    action: value.action,
    id: value.id,
    providerStatus: value.provider.status,
    verificationStatus: value.verification.status,
  };
}

function projectSkillStatus(value) {
  if (!isPlainObject(value)) {
    throw httpError(503, 'service_unavailable');
  }
  assertValueKeys(value, ['atomicCli', 'hosts', 'identity', 'mcp', 'policy', 'repository']);
  if (!isPlainObject(value.atomicCli) || !isPlainObject(value.identity) || !isPlainObject(value.mcp)
    || !isPlainObject(value.policy) || !isPlainObject(value.repository)) {
    throw httpError(503, 'service_unavailable');
  }
  assertValueKeys(value.atomicCli, ['detected']);
  assertValueKeys(value.identity, ['available']);
  assertValueKeys(value.mcp, ['registered']);
  assertValueKeys(value.policy, ['active', 'version']);
  assertValueKeys(value.repository, ['detected']);
  if (
    typeof value.atomicCli.detected !== 'boolean'
    || typeof value.identity.available !== 'boolean'
    || typeof value.mcp.registered !== 'boolean'
    || typeof value.policy.active !== 'boolean'
    || (value.policy.version !== null && (!Number.isInteger(value.policy.version) || value.policy.version < 0))
    || typeof value.repository.detected !== 'boolean'
  ) {
    throw httpError(503, 'service_unavailable');
  }
  return {
    atomicCli: { detected: value.atomicCli.detected },
    hosts: projectSkillHosts(value.hosts),
    identity: { available: value.identity.available },
    mcp: { registered: value.mcp.registered },
    policy: { active: value.policy.active, version: value.policy.version },
    repository: { detected: value.repository.detected },
  };
}

function projectSkillHosts(value) {
  if (!isPlainObject(value)) {
    throw httpError(503, 'service_unavailable');
  }
  const hosts = {};
  for (const host of ['claude', 'codex']) {
    const details = value[host];
    if (!isPlainObject(details)) {
      throw httpError(503, 'service_unavailable');
    }
    assertValueKeys(details, ['detected', 'globalSkill', 'preselected', 'projectSkill']);
    if (
      typeof details.detected !== 'boolean'
      || typeof details.globalSkill !== 'boolean'
      || typeof details.preselected !== 'boolean'
      || typeof details.projectSkill !== 'boolean'
    ) {
      throw httpError(503, 'service_unavailable');
    }
    hosts[host] = {
      detected: details.detected,
      globalSkill: details.globalSkill,
      preselected: details.preselected,
      projectSkill: details.projectSkill,
    };
  }
  return hosts;
}

function projectInstallPlan(value) {
  if (!isPlainObject(value)) {
    throw httpError(503, 'service_unavailable');
  }
  assertValueKeys(value, [
    'destinations',
    'expiresAt',
    'hosts',
    'planId',
    'requiresConfirmation',
    'requiresGlobalOptIn',
    'scope',
    'sharing',
    'status',
  ]);
  if (
    value.status !== 'planned'
    || value.requiresConfirmation !== true
    || typeof value.requiresGlobalOptIn !== 'boolean'
    || !validInstallScope(value.scope)
    || !validInstallSharing(value.sharing)
    || value.requiresGlobalOptIn !== (value.scope === 'global' || value.scope === 'both')
    || !validTimestamp(value.expiresAt)
    || typeof value.planId !== 'string'
    || !/^install_[A-Za-z0-9_-]{8,128}$/u.test(value.planId)
  ) {
    throw httpError(503, 'service_unavailable');
  }
  return {
    destinations: projectInstallDestinations(value.destinations, false, value.scope),
    expiresAt: value.expiresAt,
    hosts: projectInstallHosts(value.hosts),
    planId: value.planId,
    requiresConfirmation: true,
    requiresGlobalOptIn: value.requiresGlobalOptIn,
    scope: value.scope,
    sharing: value.sharing,
    status: 'planned',
  };
}

function projectInstallResult(value) {
  if (!isPlainObject(value)) {
    throw httpError(503, 'service_unavailable');
  }
  assertValueKeys(value, ['destinations', 'hosts', 'scope', 'sharing', 'status']);
  if (
    value.status !== 'installed'
    || !validInstallScope(value.scope)
    || !validInstallSharing(value.sharing)
  ) {
    throw httpError(503, 'service_unavailable');
  }
  return {
    destinations: projectInstallDestinations(value.destinations, true, value.scope),
    hosts: projectInstallHosts(value.hosts),
    scope: value.scope,
    sharing: value.sharing,
    status: 'installed',
  };
}

function projectInstallDestinations(value, installed, planScope) {
  if (!Array.isArray(value) || value.length === 0 || value.length > 64) {
    throw httpError(503, 'service_unavailable');
  }
  const keys = new Set();
  const scopes = new Set();
  const projected = value.map((destination) => {
    if (!isPlainObject(destination)) {
      throw httpError(503, 'service_unavailable');
    }
    assertValueKeys(destination, installed ? ['destination', 'scope', 'status'] : ['destination', 'scope']);
    if (
      !safeRelativeDestination(destination.destination)
      || !validInstallScope(destination.scope)
      || !installDestinationScopeMatchesPlanScope(planScope, destination.scope)
      || (installed && (typeof destination.status !== 'string' || !INSTALL_APPLY_STATUSES.has(destination.status)))
    ) {
      throw httpError(503, 'service_unavailable');
    }
    const key = `${destination.scope}:${destination.destination}`;
    if (keys.has(key)) {
      throw httpError(503, 'service_unavailable');
    }
    keys.add(key);
    scopes.add(destination.scope);
    return installed
      ? { destination: destination.destination, scope: destination.scope, status: destination.status }
      : { destination: destination.destination, scope: destination.scope };
  });
  if (!hasExpectedInstallDestinationScopes(planScope, scopes)) {
    throw httpError(503, 'service_unavailable');
  }
  return projected;
}

function installDestinationScopeMatchesPlanScope(planScope, destinationScope) {
  return planScope === 'both' || destinationScope === planScope;
}

function hasExpectedInstallDestinationScopes(planScope, scopes) {
  if (planScope === 'both') {
    return scopes.size === 2 && scopes.has('project') && scopes.has('global');
  }
  return scopes.size === 1 && scopes.has(planScope);
}

function projectInstallHosts(value) {
  if (!Array.isArray(value) || value.length === 0 || value.length > INSTALL_HOSTS.size) {
    throw httpError(503, 'service_unavailable');
  }
  if (
    value.some((host) => typeof host !== 'string' || !INSTALL_HOSTS.has(host))
    || new Set(value).size !== value.length
  ) {
    throw httpError(503, 'service_unavailable');
  }
  return [...value];
}

function projectCredential(value) {
  if (!isPlainObject(value)) {
    throw httpError(503, 'service_unavailable');
  }
  const label = safeLabel(value.label);
  if (
    typeof value.createdAt !== 'string'
    || typeof value.updatedAt !== 'string'
    || typeof value.instanceId !== 'string'
    || !/^[A-Za-z0-9_-]{32}$/u.test(value.instanceId)
    || !['active', 'revoked'].includes(value.status)
  ) {
    throw httpError(503, 'service_unavailable');
  }
  return {
    createdAt: value.createdAt,
    instanceId: value.instanceId,
    label,
    status: value.status,
    updatedAt: value.updatedAt,
  };
}

function projectDeposit(value) {
  if (!isPlainObject(value)) {
    throw httpError(503, 'service_unavailable');
  }
  const label = safeLabel(value.label);
  if (
    typeof value.expiresAt !== 'string'
    || value.status !== 'pending'
    || typeof value.depositUrl !== 'string'
  ) {
    throw httpError(503, 'service_unavailable');
  }
  try {
    const parsed = new URL(value.depositUrl);
    if (parsed.protocol !== 'https:' || parsed.username.length > 0 || parsed.password.length > 0) {
      throw new Error('invalid deposit URL');
    }
  } catch {
    throw httpError(503, 'service_unavailable');
  }
  return {
    depositUrl: value.depositUrl,
    expiresAt: value.expiresAt,
    label,
    status: value.status,
  };
}

function projectApproval(value) {
  if (!isPlainObject(value)) {
    throw httpError(503, 'service_unavailable');
  }
  const keys = [
    'action',
    'credentialLabel',
    'dirtyTreeAcknowledged',
    'expiresAt',
    'id',
    'requiresDirtyTreeAcknowledgement',
    'status',
  ];
  const result = {};
  for (const key of keys) {
    if (!Object.hasOwn(value, key)) {
      throw httpError(503, 'service_unavailable');
    }
    result[key] = value[key];
  }
  if (
    typeof result.action !== 'string'
    || typeof result.credentialLabel !== 'string'
    || typeof result.expiresAt !== 'string'
    || typeof result.id !== 'string'
    || typeof result.status !== 'string'
    || typeof result.dirtyTreeAcknowledged !== 'boolean'
    || typeof result.requiresDirtyTreeAcknowledgement !== 'boolean'
  ) {
    throw httpError(503, 'service_unavailable');
  }
  if (Object.hasOwn(value, 'project')) {
    result.project = projectApprovalSummary(value.project);
  }
  return result;
}

function projectApprovalSummary(value) {
  if (!isPlainObject(value)) {
    throw httpError(503, 'service_unavailable');
  }
  const keys = ['commit', 'dirty', 'repositoryFingerprint', 'targetProject'];
  assertValueKeys(value, keys);
  if (
    typeof value.commit !== 'string'
    || !/^[a-f0-9]{40,64}$/u.test(value.commit)
    || typeof value.dirty !== 'boolean'
    || typeof value.repositoryFingerprint !== 'string'
    || !/^[a-f0-9]{64}$/u.test(value.repositoryFingerprint)
    || typeof value.targetProject !== 'string'
    || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(value.targetProject)
  ) {
    throw httpError(503, 'service_unavailable');
  }
  return {
    commit: value.commit,
    dirty: value.dirty,
    repositoryFingerprint: value.repositoryFingerprint,
    targetProject: value.targetProject,
  };
}

function projectActivity(value) {
  if (!isPlainObject(value)) {
    throw httpError(503, 'service_unavailable');
  }
  const keys = ['action', 'id', 'receiptId', 'requestId', 'stage', 'status', 'timestamp'];
  assertValueKeys(value, keys);
  if (
    typeof value.action !== 'string'
    || typeof value.id !== 'string'
    || typeof value.requestId !== 'string'
    || typeof value.stage !== 'string'
    || typeof value.status !== 'string'
    || typeof value.timestamp !== 'string'
    || (value.receiptId !== null && typeof value.receiptId !== 'string')
  ) {
    throw httpError(503, 'service_unavailable');
  }
  return objectFromKeys(value, keys);
}

function projectAction(value) {
  if (!isPlainObject(value) || !isPlainObject(value.params)) {
    throw httpError(503, 'service_unavailable');
  }
  assertValueKeys(value.params, ['directory', 'project']);
  if (
    typeof value.approval !== 'string'
    || typeof value.name !== 'string'
    || typeof value.params.directory !== 'string'
    || typeof value.params.project !== 'string'
  ) {
    throw httpError(503, 'service_unavailable');
  }
  return {
    approval: value.approval,
    name: value.name,
    params: { directory: value.params.directory, project: value.params.project },
  };
}

function projectMemory(value) {
  if (!isPlainObject(value) || !isPlainObject(value.scope)) {
    throw httpError(503, 'service_unavailable');
  }
  const keys = ['createdAt', 'id', 'sourceReceiptId', 'status', 'text', 'updatedAt'];
  assertValueKeys(value, keys);
  assertValueKeys(value.scope, ['kind', 'repositoryFingerprint']);
  if (
    typeof value.createdAt !== 'string'
    || typeof value.id !== 'string'
    || typeof value.sourceReceiptId !== 'string'
    || typeof value.status !== 'string'
    || typeof value.text !== 'string'
    || typeof value.updatedAt !== 'string'
    || value.scope.kind !== 'project'
    || typeof value.scope.repositoryFingerprint !== 'string'
    || !/^[a-f0-9]{64}$/u.test(value.scope.repositoryFingerprint)
  ) {
    throw httpError(503, 'service_unavailable');
  }
  return {
    createdAt: value.createdAt,
    id: value.id,
    scope: {
      kind: value.scope.kind,
      repositoryFingerprint: value.scope.repositoryFingerprint,
    },
    sourceReceiptId: value.sourceReceiptId,
    status: value.status,
    text: value.text,
    updatedAt: value.updatedAt,
  };
}

async function invoke(service, method, ...args) {
  if (service === null || typeof service !== 'object' || typeof service[method] !== 'function') {
    throw httpError(503, 'service_unavailable');
  }
  try {
    return await service[method](...args);
  } catch (error) {
    if (error instanceof HttpError) {
      throw error;
    }
    throw httpError(500, 'request_failed');
  }
}

function ensureArray(value) {
  if (!Array.isArray(value)) {
    throw httpError(503, 'service_unavailable');
  }
  return value;
}

function matchPath(pathname, expression) {
  const match = expression.exec(pathname);
  if (match === null) {
    return undefined;
  }
  try {
    return match.slice(1).map((part) => decodeURIComponent(part));
  } catch {
    throw httpError(400, 'invalid_request');
  }
}

function safePathValue(value, name) {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > 128
    || value.includes('/')
    || value.includes('\\')
    || /[\u0000-\u001f]/u.test(value)
  ) {
    throw httpError(400, 'invalid_request');
  }
  return name === 'label' ? safeLabel(value) : value;
}

function safeLabel(value) {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > 128
    || value !== value.trim()
    || /[\u0000-\u001f]/u.test(value)
  ) {
    throw httpError(400, 'invalid_request');
  }
  return value;
}

function requestPathname(request) {
  try {
    return new URL(request.url ?? '/', 'http://127.0.0.1').pathname;
  } catch {
    throw httpError(400, 'invalid_request');
  }
}

function expectedLocalOrigin(originProvider) {
  let origin;
  try {
    origin = originProvider();
  } catch {
    throw httpError(503, 'service_unavailable');
  }
  if (typeof origin !== 'string' || !/^http:\/\/127\.0\.0\.1(?::\d{1,5})?$/u.test(origin)) {
    throw httpError(503, 'service_unavailable');
  }
  return origin;
}

function webhookHeaders(request) {
  return Object.freeze({
    'X-Agent-Id': requestHeader(request, 'x-agent-id'),
    'X-Agent-Sig': requestHeader(request, 'x-agent-sig'),
    'X-Agent-Sig-Time': requestHeader(request, 'x-agent-sig-time'),
    'X-Webhook-Token': requestHeader(request, 'x-webhook-token'),
  });
}

function requestHeader(request, name) {
  const value = request.headers?.[name];
  if (Array.isArray(value)) {
    return undefined;
  }
  return typeof value === 'string' ? value : undefined;
}

function cookieMap(value) {
  const cookies = new Map();
  if (typeof value !== 'string' || value.length > 4 * 1024) {
    return cookies;
  }
  for (const part of value.split(';')) {
    const separator = part.indexOf('=');
    if (separator <= 0) {
      continue;
    }
    const name = part.slice(0, separator).trim();
    const token = part.slice(separator + 1).trim();
    if (!cookies.has(name)) {
      cookies.set(name, token);
    }
  }
  return cookies;
}

function isLoopbackRequest(request) {
  const address = request.socket?.remoteAddress;
  return address === undefined
    || address === '127.0.0.1'
    || address === '::1'
    || address === '::ffff:127.0.0.1';
}

function assertExactKeys(value, expected) {
  if (!isPlainObject(value)) {
    throw httpError(400, 'invalid_request');
  }
  const actual = Object.keys(value).sort();
  const keys = [...expected].sort();
  if (actual.length !== keys.length || actual.some((key, index) => key !== keys[index])) {
    throw httpError(400, 'invalid_request');
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !Object.hasOwn(descriptor, 'value')) {
      throw httpError(400, 'invalid_request');
    }
  }
}

function assertAllowedKeys(value, allowed) {
  if (!isPlainObject(value)) {
    throw httpError(400, 'invalid_request');
  }
  const allowedKeys = new Set(allowed);
  for (const key of Object.keys(value)) {
    if (!allowedKeys.has(key)) {
      throw httpError(400, 'invalid_request');
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !Object.hasOwn(descriptor, 'value')) {
      throw httpError(400, 'invalid_request');
    }
  }
}

function assertValueKeys(value, keys) {
  if (!isPlainObject(value)) {
    throw httpError(503, 'service_unavailable');
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !Object.hasOwn(descriptor, 'value')) {
      throw httpError(503, 'service_unavailable');
    }
  }
}

function objectFromKeys(value, keys) {
  const result = {};
  for (const key of keys) {
    result[key] = value[key];
  }
  return result;
}

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

class HttpError extends Error {
  constructor(status, code) {
    super(code);
    this.code = code;
    this.status = status;
  }
}

function httpError(status, code) {
  return new HttpError(status, code);
}

function writeError(response, error) {
  const known = error instanceof HttpError ? error : httpError(500, 'request_failed');
  const safe = SAFE_ERRORS[known.code] ?? SAFE_ERRORS.request_failed;
  writeJson(response, known.status, {
    error: { code: known.code in SAFE_ERRORS ? known.code : 'request_failed', message: safe },
  });
}

const SAFE_ERRORS = Object.freeze({
  confirmation_required: 'Type the required confirmation to continue.',
  forbidden: 'This request is not permitted.',
  invalid_json: 'Request body must be valid JSON.',
  invalid_request: 'Request is invalid.',
  method_not_allowed: 'This method is not supported for this path.',
  not_found: 'The requested resource was not found.',
  payload_too_large: 'Request body is too large.',
  request_failed: 'Request could not be completed.',
  service_unavailable: 'This capability is currently unavailable.',
  unsupported_media_type: 'Request body must use application/json.',
});

function writeJson(response, status, body, cookies = undefined) {
  if (response.headersSent || response.writableEnded) {
    return;
  }
  const serialized = JSON.stringify(body);
  const headers = {
    'cache-control': 'no-store',
    'content-length': Buffer.byteLength(serialized),
    'content-type': 'application/json; charset=utf-8',
    'cross-origin-resource-policy': 'same-origin',
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
  };
  if (cookies !== undefined) {
    headers['set-cookie'] = cookies;
  }
  response.writeHead(status, headers);
  response.end(serialized);
}
