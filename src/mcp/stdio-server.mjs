import { once } from 'node:events';
import { isAbsolute, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export const MCP_PROTOCOL_VERSION = '2025-03-26';
export const MAX_JSON_RPC_LINE_BYTES = 64 * 1024;
export const MAX_JSON_RPC_RESPONSE_BYTES = 64 * 1024;
export const MAX_MCP_LIST_ITEMS = 64;

const ACTION_NAME = 'cloudflare_pages_deploy';
const CREDENTIAL_LABEL = 'cloudflare-api-token';
const MAX_JSON_RPC_ID_BYTES = 128;
const MAX_JSON_RPC_RESULT_BYTES = 16 * 1024;
const PROVIDER = 'cloudflare';
const TOOL_NAMES = Object.freeze([
  'keyguard_status',
  'list_credentials',
  'list_actions',
  'create_deposit_link',
  'execute_action',
  'delete_credential',
]);

const EMPTY_INPUT_SCHEMA = freezeDeep({
  additionalProperties: false,
  properties: {},
  type: 'object',
});

export const MCP_TOOLS = freezeDeep([
  {
    description: 'Read the secret-free status of the local Keyguard daemon.',
    inputSchema: EMPTY_INPUT_SCHEMA,
    name: 'keyguard_status',
  },
  {
    description: 'List credential metadata without credential values.',
    inputSchema: EMPTY_INPUT_SCHEMA,
    name: 'list_credentials',
  },
  {
    description: 'List the fixed, allowlisted actions available in Keyguard.',
    inputSchema: EMPTY_INPUT_SCHEMA,
    name: 'list_actions',
  },
  {
    description: 'Direct the user to the local UI to create a deposit handoff.',
    inputSchema: {
      additionalProperties: false,
      properties: {
        label: { const: CREDENTIAL_LABEL, type: 'string' },
        provider: { const: PROVIDER, type: 'string' },
      },
      required: ['label', 'provider'],
      type: 'object',
    },
    name: 'create_deposit_link',
  },
  {
    description: 'Request policy evaluation for a fixed action; never launches a provider.',
    inputSchema: {
      additionalProperties: false,
      properties: {
        action: { const: ACTION_NAME, type: 'string' },
        agentId: { maxLength: 128, minLength: 1, type: 'string' },
        params: {
          additionalProperties: false,
          properties: {
            directory: { maxLength: 256, minLength: 1, type: 'string' },
            project: { maxLength: 63, minLength: 1, type: 'string' },
          },
          required: ['directory', 'project'],
          type: 'object',
        },
        projectRoot: { maxLength: 4 * 1024, minLength: 1, type: 'string' },
      },
      required: ['action', 'agentId', 'params', 'projectRoot'],
      type: 'object',
    },
    name: 'execute_action',
  },
  {
    description: 'Open a local-UI confirmation for a credential deletion; never deletes directly.',
    inputSchema: {
      additionalProperties: false,
      properties: {
        label: { const: CREDENTIAL_LABEL, type: 'string' },
      },
      required: ['label'],
      type: 'object',
    },
    name: 'delete_credential',
  },
]);

/**
 * A small, line-delimited JSON-RPC 2.0 transport. It never logs to stdout:
 * every stdout line is a protocol response, and all service errors are
 * reduced to fixed JSON-RPC errors.
 */
export function createMcpStdioServer(app, options = {}) {
  if (!isPlainObject(app) || typeof app.status !== 'function' || !isPlainObject(app.services)) {
    throw new TypeError('MCP stdio server requires a Keyguard application.');
  }
  if (!isPlainObject(options)) {
    throw new TypeError('MCP stdio server options must be an object.');
  }
  const input = options.input ?? process.stdin;
  const output = options.output ?? process.stdout;
  if (input === null || typeof input !== 'object' || typeof input.on !== 'function') {
    throw new TypeError('MCP input must be a readable stream.');
  }
  if (output === null || typeof output !== 'object' || typeof output.write !== 'function') {
    throw new TypeError('MCP output must be a writable stream.');
  }

  let running = false;
  let finished = false;
  let stopped = false;
  let inputEnded = false;
  let consuming = false;
  let finalizing = false;
  let transportOverrun = false;
  const lineBuffer = Buffer.alloc(MAX_JSON_RPC_LINE_BYTES);
  let lineBytes = 0;
  let discardingOversizedLine = false;
  let resolveClosed;
  const closed = new Promise((resolvePromise) => {
    resolveClosed = resolvePromise;
  });

  const controller = {
    get closed() {
      return closed;
    },
    get running() {
      return running;
    },
    start() {
      if (running || finished) {
        return controller;
      }
      running = true;
      input.on('data', onData);
      input.once('end', onEnd);
      input.once('error', onError);
      input.once('close', onClose);
      resumeInput();
      return controller;
    },
    async stop() {
      stopped = true;
      pauseInput();
      if (!consuming && !finalizing) {
        finish();
      }
      await closed;
    },
  };

  function finish() {
    if (finished) {
      return;
    }
    finished = true;
    running = false;
    resolveClosed();
  }

  function onData(chunk) {
    if (!running || finished || stopped) {
      return;
    }
    pauseInput();
    if (consuming) {
      // A compliant readable respects pause() synchronously. If a custom
      // source does not, drop its extra chunk rather than retaining an
      // unbounded application queue.
      transportOverrun = true;
      return;
    }
    const bytes = toBuffer(chunk);
    consuming = true;
    if (bytes === undefined) {
      void rejectInvalidChunk();
      return;
    }
    void consumeChunk(bytes);
  }

  async function consumeChunk(chunk) {
    try {
      let segmentStart = 0;
      for (let index = 0; index < chunk.length; index += 1) {
        if (chunk[index] !== 0x0A) {
          continue;
        }
        await appendLineSegment(chunk.subarray(segmentStart, index));
        if (discardingOversizedLine) {
          resetLine();
          discardingOversizedLine = false;
        } else {
          await processBufferedLine();
        }
        segmentStart = index + 1;
      }
      await appendLineSegment(chunk.subarray(segmentStart));
    } catch {
      resetLine();
      discardingOversizedLine = false;
      await respond(rpcError(null, -32603));
    } finally {
      await finishConsumption();
    }
  }

  async function rejectInvalidChunk() {
    try {
      await respond(rpcError(null, -32600));
    } finally {
      await finishConsumption();
    }
  }

  async function finishConsumption() {
    consuming = false;
    if (transportOverrun) {
      transportOverrun = false;
      resetLine();
      discardingOversizedLine = false;
      await respond(rpcError(null, -32600));
    }
    if (stopped) {
      finish();
    } else if (inputEnded) {
      void finalizeInput();
    } else {
      resumeInput();
    }
  }

  async function appendLineSegment(segment) {
    if (segment.length === 0 || discardingOversizedLine) {
      return;
    }
    const remaining = MAX_JSON_RPC_LINE_BYTES - lineBytes;
    if (segment.length <= remaining) {
      segment.copy(lineBuffer, lineBytes);
      lineBytes += segment.length;
      return;
    }
    if (remaining > 0) {
      segment.copy(lineBuffer, lineBytes, 0, remaining);
    }
    resetLine();
    discardingOversizedLine = true;
    await respond(rpcError(null, -32600));
  }

  async function processBufferedLine() {
    const lineEnd = lineBytes > 0 && lineBuffer[lineBytes - 1] === 0x0D
      ? lineBytes - 1
      : lineBytes;
    const line = lineBuffer.toString('utf8', 0, lineEnd);
    resetLine();
    try {
      const response = await handleLine(app, line);
      if (response !== undefined) {
        await respond(response);
      }
    } catch {
      await respond(rpcError(null, -32603));
    }
  }

  function onEnd() {
    inputEnded = true;
    if (!consuming) {
      void finalizeInput();
    }
  }

  function onError() {
    inputEnded = true;
    resetLine();
    discardingOversizedLine = false;
    if (!consuming) {
      void failAndFinish();
    }
  }

  function onClose() {
    if (inputEnded || stopped) {
      return;
    }
    inputEnded = true;
    if (!consuming) {
      void finalizeInput();
    }
  }

  async function finalizeInput() {
    if (finalizing || finished) {
      return;
    }
    finalizing = true;
    try {
      if (!stopped && !discardingOversizedLine && lineBytes > 0) {
        await processBufferedLine();
      }
    } catch {
      await respond(rpcError(null, -32603));
    } finally {
      resetLine();
      discardingOversizedLine = false;
      finish();
    }
  }

  async function failAndFinish() {
    if (finalizing || finished) {
      return;
    }
    finalizing = true;
    try {
      if (!stopped) {
        await respond(rpcError(null, -32603));
      }
    } finally {
      finish();
    }
  }

  async function respond(value) {
    try {
      await writeLine(output, value);
    } catch {
      // A broken transport has no safe recovery path; stdout remains protocol-only.
    }
  }

  function resetLine() {
    lineBuffer.fill(0, 0, lineBytes);
    lineBytes = 0;
  }

  function pauseInput() {
    if (typeof input.pause === 'function') {
      input.pause();
    }
  }

  function resumeInput() {
    if (!stopped && !finished && typeof input.resume === 'function') {
      input.resume();
    }
  }

  return Object.freeze(controller);
}

async function handleLine(app, line) {
  if (Buffer.byteLength(line, 'utf8') > MAX_JSON_RPC_LINE_BYTES) {
    return rpcError(null, -32600);
  }
  let value;
  try {
    value = JSON.parse(line);
  } catch {
    return rpcError(null, -32700);
  }

  let request;
  try {
    request = parseRequest(value);
  } catch {
    return rpcError(null, -32600);
  }

  let response;
  try {
    response = await dispatch(app, request);
  } catch (error) {
    response = error instanceof RpcFailure
      ? rpcError(request.id, error.code)
      : rpcError(request.id, -32603);
  }
  return request.notification ? undefined : response;
}

function parseRequest(value) {
  assertPlainObject(value, -32600);
  const keys = Object.keys(value).sort();
  const allowed = ['id', 'jsonrpc', 'method', 'params'];
  if (keys.some((key) => !allowed.includes(key)) || !Object.hasOwn(value, 'jsonrpc') || !Object.hasOwn(value, 'method')) {
    throw new RpcFailure(-32600);
  }
  const jsonrpc = dataValue(value, 'jsonrpc', -32600);
  const method = dataValue(value, 'method', -32600);
  const notification = !Object.hasOwn(value, 'id');
  const id = notification ? undefined : dataValue(value, 'id', -32600);
  const params = Object.hasOwn(value, 'params') ? dataValue(value, 'params', -32600) : {};
  if (
    jsonrpc !== '2.0'
    || typeof method !== 'string'
    || method.length === 0
    || method.length > 128
    || !/^[A-Za-z0-9_./-]+$/u.test(method)
    || (!notification && !validRequestId(id))
    || !isPlainObject(params)
  ) {
    throw new RpcFailure(-32600);
  }
  return { id, method, notification, params };
}

async function dispatch(app, request) {
  switch (request.method) {
    case 'initialize':
      validateInitialize(request.params);
      return rpcResult(request.id, {
        capabilities: { tools: {} },
        protocolVersion: MCP_PROTOCOL_VERSION,
        serverInfo: { name: 'atomical-keyguard', version: '0.0.0' },
      });
    case 'tools/list':
      assertExactKeys(request.params, [], -32602);
      return rpcResult(request.id, { tools: MCP_TOOLS });
    case 'tools/call': {
      const call = validateToolCall(request.params);
      const value = await callTool(app, call.name, call.arguments);
      return rpcResult(request.id, toolResult(value));
    }
    default:
      return rpcError(request.id, -32601);
  }
}

function validateInitialize(value) {
  assertExactKeys(value, ['capabilities', 'clientInfo', 'protocolVersion'], -32602);
  const protocolVersion = dataValue(value, 'protocolVersion', -32602);
  const capabilities = dataValue(value, 'capabilities', -32602);
  const clientInfo = dataValue(value, 'clientInfo', -32602);
  if (
    typeof protocolVersion !== 'string'
    || protocolVersion.length === 0
    || protocolVersion.length > 64
    || !isPlainObject(capabilities)
  ) {
    throw new RpcFailure(-32602);
  }
  assertExactKeys(clientInfo, ['name', 'version'], -32602);
  const name = dataValue(clientInfo, 'name', -32602);
  const version = dataValue(clientInfo, 'version', -32602);
  if (
    typeof name !== 'string'
    || name.length === 0
    || name.length > 128
    || typeof version !== 'string'
    || version.length === 0
    || version.length > 128
  ) {
    throw new RpcFailure(-32602);
  }
}

function validateToolCall(value) {
  assertExactKeys(value, ['arguments', 'name'], -32602);
  const name = dataValue(value, 'name', -32602);
  const argumentsValue = dataValue(value, 'arguments', -32602);
  if (typeof name !== 'string' || !TOOL_NAMES.includes(name) || !isPlainObject(argumentsValue)) {
    throw new RpcFailure(-32602);
  }
  return { arguments: argumentsValue, name };
}

async function callTool(app, name, argumentsValue) {
  switch (name) {
    case 'keyguard_status':
      assertExactKeys(argumentsValue, [], -32602);
      return projectStatus(await app.status());
    case 'list_credentials': {
      assertExactKeys(argumentsValue, [], -32602);
      const credentials = await invoke(app.services.vault, 'list');
      if (!Array.isArray(credentials) || credentials.length > MAX_MCP_LIST_ITEMS) {
        throw new Error('credential service unavailable');
      }
      return { credentials: credentials.map(projectCredential) };
    }
    case 'list_actions': {
      assertExactKeys(argumentsValue, [], -32602);
      const actions = await invoke(app.services.actionRegistry, 'list');
      if (!Array.isArray(actions) || actions.length > MAX_MCP_LIST_ITEMS) {
        throw new Error('action registry unavailable');
      }
      return { actions: actions.map(projectAction) };
    }
    case 'create_deposit_link': {
      const metadata = validateDepositArguments(argumentsValue);
      return {
        label: metadata.label,
        status: 'ui_required',
        ui: { path: '/?intent=create_deposit_link&label=cloudflare-api-token' },
      };
    }
    case 'execute_action': {
      const request = validateExecuteArguments(argumentsValue);
      const decision = await invoke(app.services.policyEngine, 'evaluate', request);
      return projectPolicyDecision(decision, request, app.services.actionRegistry);
    }
    case 'delete_credential': {
      const label = validateDeleteArguments(argumentsValue);
      return {
        label,
        status: 'confirmation_required',
        ui: { path: '/' },
      };
    }
    default:
      throw new RpcFailure(-32602);
  }
}

function validateDepositArguments(value) {
  assertExactKeys(value, ['label', 'provider'], -32602);
  const label = dataValue(value, 'label', -32602);
  const provider = dataValue(value, 'provider', -32602);
  if (label !== CREDENTIAL_LABEL || provider !== PROVIDER) {
    throw new RpcFailure(-32602);
  }
  return Object.freeze({ label, provider });
}

function validateExecuteArguments(value) {
  assertExactKeys(value, ['action', 'agentId', 'params', 'projectRoot'], -32602);
  const action = dataValue(value, 'action', -32602);
  const agentId = dataValue(value, 'agentId', -32602);
  const params = dataValue(value, 'params', -32602);
  const projectRoot = dataValue(value, 'projectRoot', -32602);
  if (
    action !== ACTION_NAME
    || typeof agentId !== 'string'
    || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(agentId)
    || typeof projectRoot !== 'string'
    || projectRoot.length === 0
    || projectRoot.length > 4 * 1024
    || !isAbsolute(projectRoot)
    || projectRoot.includes('\u0000')
  ) {
    throw new RpcFailure(-32602);
  }
  assertExactKeys(params, ['directory', 'project'], -32602);
  const directory = dataValue(params, 'directory', -32602);
  const project = dataValue(params, 'project', -32602);
  if (
    typeof directory !== 'string'
    || directory.length === 0
    || directory.length > 256
    || directory.includes('\\')
    || directory.includes('\u0000')
    || directory.startsWith('/')
    || directory.split('/').some((part) => part === '' || part === '.' || part === '..')
    || typeof project !== 'string'
    || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(project)
  ) {
    throw new RpcFailure(-32602);
  }
  return Object.freeze({
    action,
    agentId,
    params: Object.freeze({ directory, project }),
    projectRoot,
  });
}

function validateDeleteArguments(value) {
  assertExactKeys(value, ['label'], -32602);
  const label = dataValue(value, 'label', -32602);
  if (label !== CREDENTIAL_LABEL) {
    throw new RpcFailure(-32602);
  }
  return label;
}

function projectStatus(value) {
  assertPlainObject(value);
  const server = dataValue(value, 'server');
  const state = dataValue(value, 'state');
  assertPlainObject(server);
  const host = dataValue(server, 'host');
  const port = dataValue(server, 'port');
  const url = dataValue(server, 'url');
  if (
    host !== '127.0.0.1'
    || !Number.isInteger(port)
    || port < 0
    || port > 65_535
    || url !== `http://127.0.0.1:${port}`
    || !['running', 'stopped'].includes(state)
  ) {
    throw new Error('invalid status projection');
  }
  return {
    server: { host, port, url },
    state,
  };
}

function projectCredential(value) {
  assertPlainObject(value);
  const createdAt = dataValue(value, 'createdAt');
  const instanceId = dataValue(value, 'instanceId');
  const label = dataValue(value, 'label');
  const status = dataValue(value, 'status');
  const updatedAt = dataValue(value, 'updatedAt');
  if (
    !isIsoTimestamp(createdAt)
    || typeof instanceId !== 'string'
    || !/^[A-Za-z0-9_-]{32}$/u.test(instanceId)
    || !validLabel(label)
    || !['active', 'revoked'].includes(status)
    || !isIsoTimestamp(updatedAt)
  ) {
    throw new Error('invalid credential projection');
  }
  return { createdAt, instanceId, label, status, updatedAt };
}

function projectAction(value) {
  assertPlainObject(value);
  const approval = dataValue(value, 'approval');
  const name = dataValue(value, 'name');
  const params = dataValue(value, 'params');
  assertPlainObject(params);
  const directory = dataValue(params, 'directory');
  const project = dataValue(params, 'project');
  if (
    approval !== 'always'
    || name !== ACTION_NAME
    || directory !== 'relative_path'
    || project !== 'slug'
  ) {
    throw new Error('invalid action projection');
  }
  return { approval, name, params: { directory, project } };
}

function projectPolicyDecision(value, request, registry) {
  assertPlainObject(value);
  const status = dataValue(value, 'status');
  const action = fixedAction(registry, request.action);
  const credentialLabel = dataValue(action, 'credentialLabel');
  if (credentialLabel !== CREDENTIAL_LABEL) {
    throw new Error('invalid action mapping');
  }
  if (status === 'credential_needed') {
    return { action: request.action, credentialLabel, status };
  }
  if (status === 'approval_required') {
    const requestId = dataValue(value, 'requestId');
    const requiresDirtyTreeAcknowledgement = dataValue(value, 'requiresDirtyTreeAcknowledgement');
    if (
      typeof requestId !== 'string'
      || !/^approval_[A-Za-z0-9_-]{8,128}$/u.test(requestId)
      || typeof requiresDirtyTreeAcknowledgement !== 'boolean'
    ) {
      throw new Error('invalid approval projection');
    }
    return {
      action: request.action,
      credentialLabel,
      requestId,
      requiresDirtyTreeAcknowledgement,
      status,
    };
  }
  if (status === 'approved') {
    const requestId = dataValue(value, 'requestId');
    if (typeof requestId !== 'string' || !/^approval_[A-Za-z0-9_-]{8,128}$/u.test(requestId)) {
      throw new Error('invalid approval projection');
    }
    return {
      action: request.action,
      credentialLabel,
      requestId,
      requiresDirtyTreeAcknowledgement: false,
      status: 'approval_required',
    };
  }
  if (status === 'denied') {
    return { action: request.action, status: 'denied' };
  }
  throw new Error('invalid policy decision');
}

function fixedAction(registry, actionName) {
  if (registry === null || typeof registry !== 'object' || typeof registry.get !== 'function') {
    throw new Error('action registry unavailable');
  }
  const action = registry.get(actionName);
  if (!isPlainObject(action) || dataValue(action, 'name') !== ACTION_NAME) {
    throw new Error('action registry unavailable');
  }
  return action;
}

async function invoke(service, method, ...args) {
  if (service === null || typeof service !== 'object' || typeof service[method] !== 'function') {
    throw new Error('service unavailable');
  }
  return service[method](...args);
}

function toolResult(value) {
  const text = JSON.stringify(value);
  if (Buffer.byteLength(text, 'utf8') > MAX_JSON_RPC_RESULT_BYTES) {
    throw new RpcFailure(-32603);
  }
  return {
    content: [{ text, type: 'text' }],
    structuredContent: value,
  };
}

function rpcResult(id, result) {
  return { id, jsonrpc: '2.0', result };
}

function rpcError(id, code) {
  return {
    error: {
      code,
      message: SAFE_ERROR_MESSAGES[code] ?? SAFE_ERROR_MESSAGES[-32603],
    },
    id,
    jsonrpc: '2.0',
  };
}

const SAFE_ERROR_MESSAGES = Object.freeze({
  [-32700]: 'Parse error.',
  [-32603]: 'Internal error.',
  [-32602]: 'Invalid params.',
  [-32601]: 'Method not found.',
  [-32600]: 'Invalid request.',
});

async function writeLine(output, value) {
  const line = `${serializeResponse(value)}\n`;
  if (output.write(line) === false) {
    await once(output, 'drain');
  }
}

function serializeResponse(value) {
  let serialized;
  try {
    serialized = JSON.stringify(value);
  } catch {
    serialized = undefined;
  }
  if (typeof serialized === 'string' && Buffer.byteLength(serialized, 'utf8') <= MAX_JSON_RPC_RESPONSE_BYTES) {
    return serialized;
  }
  return JSON.stringify(rpcError(responseId(value), -32603));
}

function responseId(value) {
  if (!isPlainObject(value)) {
    return null;
  }
  const descriptor = Object.getOwnPropertyDescriptor(value, 'id');
  return descriptor !== undefined && Object.hasOwn(descriptor, 'value') && validRequestId(descriptor.value)
    ? descriptor.value
    : null;
}

function assertExactKeys(value, expected, code) {
  assertPlainObject(value, code);
  const actual = Object.keys(value).sort();
  const expectedKeys = [...expected].sort();
  if (
    actual.length !== expectedKeys.length
    || actual.some((key, index) => key !== expectedKeys[index])
  ) {
    throw new RpcFailure(code);
  }
  for (const key of expectedKeys) {
    dataValue(value, key, code);
  }
}

function dataValue(value, key, code = -32603) {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (descriptor === undefined || !Object.hasOwn(descriptor, 'value')) {
    throw new RpcFailure(code);
  }
  return descriptor.value;
}

function validRequestId(value) {
  return Number.isSafeInteger(value)
    || (typeof value === 'string' && Buffer.byteLength(value, 'utf8') <= MAX_JSON_RPC_ID_BYTES);
}

function toBuffer(value) {
  if (Buffer.isBuffer(value)) {
    return value;
  }
  if (typeof value === 'string') {
    return Buffer.from(value, 'utf8');
  }
  if (ArrayBuffer.isView(value) || value instanceof ArrayBuffer) {
    return Buffer.from(value);
  }
  return undefined;
}

function assertPlainObject(value, code = -32603) {
  if (!isPlainObject(value)) {
    throw new RpcFailure(code);
  }
}

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function validLabel(value) {
  return typeof value === 'string'
    && value.length > 0
    && value.length <= 128
    && value === value.trim()
    && !/[\u0000-\u001f]/u.test(value);
}

function isIsoTimestamp(value) {
  if (typeof value !== 'string') {
    return false;
  }
  const time = new Date(value);
  return !Number.isNaN(time.valueOf()) && time.toISOString() === value;
}

function freezeDeep(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const nested of Object.values(value)) {
      freezeDeep(nested);
    }
  }
  return value;
}

class RpcFailure extends Error {
  constructor(code) {
    super(String(code));
    this.code = code;
  }
}

function isDirectInvocation() {
  const entry = process.argv[1];
  return typeof entry === 'string' && import.meta.url === pathToFileURL(resolve(entry)).href;
}

async function runMain() {
  try {
    const { createKeyguardApp } = await import('../bootstrap.mjs');
    const app = await createKeyguardApp();
    const server = createMcpStdioServer(app);
    server.start();
    await server.closed;
  } catch {
    process.stderr.write('Atomical Keyguard MCP server could not start.\n');
    process.exitCode = 1;
  }
}

if (isDirectInvocation()) {
  void runMain();
}
