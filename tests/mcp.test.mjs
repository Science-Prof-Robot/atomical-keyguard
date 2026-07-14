import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { PassThrough, Readable } from 'node:stream';
import test from 'node:test';

import { createKeyguardApp } from '../src/bootstrap.mjs';
import {
  createMcpStdioServer,
  MAX_JSON_RPC_LINE_BYTES,
} from '../src/mcp/stdio-server.mjs';
import { withTemporaryDataDirectory } from './helpers.mjs';

const SECRET = 'mcp-secret-must-never-escape';
const FIXED_TIME = '2026-07-14T12:00:00.000Z';
const PROTOCOL_VERSION = '2025-03-26';

test('implements initialize and advertises exactly the six safe MCP tools', async () => {
  const { app } = createFakeApp();
  const responses = await runLines(app, [
    request(1, 'initialize', initializeParams()),
    request(2, 'tools/list', {}),
  ]);

  assert.equal(responses.length, 2);
  assert.equal(responses[0].jsonrpc, '2.0');
  assert.equal(responses[0].id, 1);
  assert.deepEqual(responses[0].result.capabilities, { tools: {} });
  assert.equal(responses[0].result.protocolVersion, PROTOCOL_VERSION);
  assert.equal(responses[0].result.serverInfo.name, 'atomical-keyguard');

  const tools = responses[1].result.tools;
  assert.deepEqual(tools.map((tool) => tool.name).sort(), [
    'create_deposit_link',
    'delete_credential',
    'execute_action',
    'keyguard_status',
    'list_actions',
    'list_credentials',
  ]);
  assert.equal(tools.some((tool) => /secret|reveal|export/iu.test(tool.name)), false);
  assert.equal(tools.every((tool) => tool.inputSchema?.additionalProperties === false), true);
  assertSafeOutput(responses);
});

test('returns only secret-free structured tool results and never executes or deletes on behalf of MCP', async () => {
  const { app, calls } = createFakeApp();
  const executeArguments = {
    action: 'cloudflare_pages_deploy',
    agentId: 'codex-test-agent',
    params: { directory: 'dist', project: 'keyguard-site' },
    projectRoot: '/approved/repository',
  };
  const responses = await runLines(app, [
    request(1, 'tools/call', { arguments: {}, name: 'keyguard_status' }),
    request(2, 'tools/call', { arguments: {}, name: 'list_credentials' }),
    request(3, 'tools/call', { arguments: {}, name: 'list_actions' }),
    request(4, 'tools/call', {
      arguments: { label: 'cloudflare-api-token', provider: 'cloudflare' },
      name: 'create_deposit_link',
    }),
    request(5, 'tools/call', { arguments: executeArguments, name: 'execute_action' }),
    request(6, 'tools/call', {
      arguments: { label: 'cloudflare-api-token' },
      name: 'delete_credential',
    }),
  ]);

  assert.deepEqual(structured(responses[0]), {
    server: { host: '127.0.0.1', port: 4545, url: 'http://127.0.0.1:4545' },
    state: 'stopped',
  });
  assert.deepEqual(structured(responses[1]), {
    credentials: [{
      createdAt: FIXED_TIME,
      instanceId: 'a'.repeat(32),
      label: 'cloudflare-api-token',
      status: 'active',
      updatedAt: FIXED_TIME,
    }],
  });
  assert.deepEqual(structured(responses[2]), {
    actions: [{
      approval: 'always',
      name: 'cloudflare_pages_deploy',
      params: { directory: 'relative_path', project: 'slug' },
    }],
  });
  assert.deepEqual(structured(responses[3]), {
    label: 'cloudflare-api-token',
    status: 'ui_required',
    ui: { path: '/?intent=create_deposit_link&label=cloudflare-api-token' },
  });
  assert.deepEqual(structured(responses[4]), {
    action: 'cloudflare_pages_deploy',
    credentialLabel: 'cloudflare-api-token',
    requestId: 'approval_12345678',
    requiresDirtyTreeAcknowledgement: true,
    status: 'approval_required',
  });
  assert.deepEqual(structured(responses[5]), {
    label: 'cloudflare-api-token',
    status: 'confirmation_required',
    ui: { path: '/' },
  });
  assert.deepEqual(calls.deposits, []);
  assert.deepEqual(calls.policyRequests, [executeArguments]);
  assert.equal(calls.executionAttempts, 0);
  assert.deepEqual(calls.deletedLabels, []);
  assertSafeOutput(responses);
  assert.equal(JSON.stringify(responses).includes('depositUrl'), false);
  assert.equal(JSON.stringify(responses).includes('envelope'), false);
  assert.equal(JSON.stringify(responses).includes('signature'), false);
  assert.equal(JSON.stringify(responses).includes('projectRoot'), false);
});

test('validates JSON-RPC and tool schemas, safely rejects reveal attempts, and continues after bad input', async () => {
  const { app, calls } = createFakeApp();
  const responses = await runLines(app, [
    '{not-json',
    request(2, 'unknown/method', {}),
    request(3, 'tools/call', {
      arguments: { label: 'cloudflare-api-token' },
      name: 'get_secret',
    }),
    request(4, 'tools/call', {
      arguments: {
        label: 'cloudflare-api-token',
        provider: 'cloudflare',
        secret: SECRET,
      },
      name: 'create_deposit_link',
    }),
    request(5, 'tools/call', {
      arguments: { confirmation: 'DELETE', label: 'cloudflare-api-token' },
      name: 'delete_credential',
    }),
    request(6, 'tools/call', {
      arguments: {
        action: 'cloudflare_pages_deploy',
        agentId: 'codex-test-agent',
        commit: 'f'.repeat(40),
        params: { directory: 'dist', project: 'keyguard-site' },
        projectRoot: '/approved/repository',
      },
      name: 'execute_action',
    }),
    request(7, 'tools/call', { arguments: {}, name: 'keyguard_status' }),
  ]);

  assert.deepEqual(responses.map((response) => response.id), [null, 2, 3, 4, 5, 6, 7]);
  assert.equal(responses[0].error.code, -32700);
  assert.equal(responses[1].error.code, -32601);
  for (const response of responses.slice(2, 6)) {
    assert.equal(response.error.code, -32602);
  }
  assert.deepEqual(structured(responses[6]), {
    server: { host: '127.0.0.1', port: 4545, url: 'http://127.0.0.1:4545' },
    state: 'stopped',
  });
  assert.deepEqual(calls.deposits, []);
  assert.deepEqual(calls.deletedLabels, []);
  assert.deepEqual(calls.policyRequests, []);
  assertSafeOutput(responses);
});

test('converts internal service failures to a uniform secret-free JSON-RPC error', async () => {
  const { app, controls } = createFakeApp();
  controls.failCredentialList = true;

  const responses = await runLines(app, [
    request(1, 'tools/call', { arguments: {}, name: 'list_credentials' }),
    request(2, 'tools/call', { arguments: {}, name: 'keyguard_status' }),
  ]);

  assert.equal(responses[0].error.code, -32603);
  assert.deepEqual(structured(responses[1]), {
    server: { host: '127.0.0.1', port: 4545, url: 'http://127.0.0.1:4545' },
    state: 'stopped',
  });
  assertSafeOutput(responses);
});

test('returns a local deposit UI intent without invoking the deposit service', async () => {
  const { app, calls, controls } = createFakeApp();
  controls.failDeposit = true;

  const responses = await runLines(app, [
    request(1, 'tools/call', {
      arguments: { label: 'cloudflare-api-token', provider: 'cloudflare' },
      name: 'create_deposit_link',
    }),
  ]);

  assert.deepEqual(structured(responses[0]), {
    label: 'cloudflare-api-token',
    status: 'ui_required',
    ui: { path: '/?intent=create_deposit_link&label=cloudflare-api-token' },
  });
  assert.deepEqual(calls.deposits, []);
  assertSafeOutput(responses);
});

test('never launches an already policy-approved action from MCP', async () => {
  const { app, calls, controls } = createFakeApp();
  controls.policyDecision = {
    requestId: 'approval_12345678',
    status: 'approved',
  };

  const responses = await runLines(app, [
    request(1, 'tools/call', {
      arguments: {
        action: 'cloudflare_pages_deploy',
        agentId: 'codex-test-agent',
        params: { directory: 'dist', project: 'keyguard-site' },
        projectRoot: '/approved/repository',
      },
      name: 'execute_action',
    }),
  ]);

  assert.deepEqual(structured(responses[0]), {
    action: 'cloudflare_pages_deploy',
    credentialLabel: 'cloudflare-api-token',
    requestId: 'approval_12345678',
    requiresDirtyTreeAcknowledgement: false,
    status: 'approval_required',
  });
  assert.equal(calls.executionAttempts, 0);
  assertSafeOutput(responses);
});

test('returns a secret-free credential-needed policy result without executing', async () => {
  const { app, calls, controls } = createFakeApp();
  controls.policyDecision = {
    action: SECRET,
    credentialLabel: SECRET,
    status: 'credential_needed',
  };

  const responses = await runLines(app, [
    request(1, 'tools/call', {
      arguments: {
        action: 'cloudflare_pages_deploy',
        agentId: 'codex-test-agent',
        params: { directory: 'dist', project: 'keyguard-site' },
        projectRoot: '/approved/repository',
      },
      name: 'execute_action',
    }),
  ]);

  assert.deepEqual(structured(responses[0]), {
    action: 'cloudflare_pages_deploy',
    credentialLabel: 'cloudflare-api-token',
    status: 'credential_needed',
  });
  assert.equal(calls.executionAttempts, 0);
  assertSafeOutput(responses);
});

test('rejects an oversized unterminated JSON-RPC frame before buffering the rest of the line', async () => {
  const { app } = createFakeApp();
  const session = startSession(app);

  try {
    session.input.write('x'.repeat(MAX_JSON_RPC_LINE_BYTES + 1));
    await waitForResponse(session);

    const oversizedResponses = responseLines(session.raw());
    assert.equal(oversizedResponses.length, 1);
    assert.equal(oversizedResponses[0].error.code, -32600);

    session.input.write(`discarded-tail\n${JSON.stringify(request(2, 'tools/call', {
      arguments: {},
      name: 'keyguard_status',
    }))}\n`);
    session.input.end();
    await session.server.closed;

    const responses = responseLines(session.raw());
    assert.deepEqual(responses.map((response) => response.id), [null, 2]);
    assert.equal(responses[1].result.structuredContent.state, 'stopped');
    assertSafeOutput(responses);
  } finally {
    await closeSession(session);
  }
});

test('keeps a byte-fragmented incomplete frame in one bounded accumulator', async () => {
  const source = await readFile(new URL('../src/mcp/stdio-server.mjs', import.meta.url), 'utf8');
  // This is intentionally structural rather than a brittle process-heap assertion:
  // one fixed buffer is the transport's bounded fragmentation invariant.
  assert.match(source, /const lineBuffer = Buffer\.alloc\(MAX_JSON_RPC_LINE_BYTES\);/u);
  assert.match(source, /segment\.copy\(lineBuffer, lineBytes/u);
  assert.doesNotMatch(source, /\blineParts\b/u);

  const fragmentedInput = new OneByteReadable(`${'x'.repeat(4 * 1024)}\r\n${JSON.stringify(request(1, 'tools/call', {
    arguments: {},
    name: 'keyguard_status',
  }))}\n`);
  const { app } = createFakeApp();
  const session = startSession(app, fragmentedInput);
  await withTimeout(session.server.closed, 'server did not settle byte-fragmented input');

  const responses = responseLines(session.raw());
  assert.equal(fragmentedInput.pushedChunks, fragmentedInput.bytes.length);
  assert.deepEqual(responses.map((response) => response.id), [null, 1]);
  assert.equal(responses[0].error.code, -32700);
  assert.equal(responses[1].result.structuredContent.state, 'stopped');
  assertSafeOutput(responses);
});

test('pauses input while policy evaluation is slow so a burst is not queued in promises', async () => {
  const { app, calls, controls } = createFakeApp();
  const firstEvaluation = deferred();
  const releaseEvaluation = deferred();
  controls.onPolicyEvaluate = async () => {
    if (calls.policyRequests.length === 1) {
      firstEvaluation.resolve();
    }
    await releaseEvaluation.promise;
  };
  const session = startSession(app);

  try {
    session.input.write(`${JSON.stringify(executeActionRequest(1, 'first-agent'))}\n`);
    await withTimeout(firstEvaluation.promise, 'first policy evaluation did not start');
    assert.equal(session.input.isPaused(), true);

    session.input.write([2, 3, 4, 5]
      .map((id) => `${JSON.stringify(executeActionRequest(id, `burst-agent-${id}`))}\n`)
      .join(''));
    await new Promise((resolvePromise) => setImmediate(resolvePromise));
    assert.equal(calls.policyRequests.length, 1);

    releaseEvaluation.resolve();
    session.input.end();
    await session.server.closed;

    const responses = responseLines(session.raw());
    assert.deepEqual(responses.map((response) => response.id), [1, 2, 3, 4, 5]);
    assert.equal(calls.policyRequests.length, 5);
    assertSafeOutput(responses);
  } finally {
    releaseEvaluation.resolve();
    await closeSession(session);
  }
});

test('returns a fixed safe error instead of emitting oversized credential projections', async () => {
  const { app, controls } = createFakeApp();
  controls.credentialList = Array.from({ length: 512 }, () => ({
    createdAt: FIXED_TIME,
    instanceId: 'a'.repeat(32),
    label: 'cloudflare-api-token',
    status: 'active',
    updatedAt: FIXED_TIME,
  }));
  const session = startSession(app);

  try {
    session.input.end(`${JSON.stringify(request(1, 'tools/call', {
      arguments: {},
      name: 'list_credentials',
    }))}\n`);
    await session.server.closed;

    const raw = session.raw();
    const responses = responseLines(raw);
    assert.equal(responses.length, 1);
    assert.equal(responses[0].error.code, -32603);
    for (const line of raw.trimEnd().split('\n')) {
      assert.ok(Buffer.byteLength(line, 'utf8') <= MAX_JSON_RPC_LINE_BYTES);
    }
    assertSafeOutput(responses);
  } finally {
    await closeSession(session);
  }
});

test('flushes a final bounded request at EOF and settles closed', async () => {
  const { app } = createFakeApp();
  const session = startSession(app);

  try {
    session.input.end(JSON.stringify(request(1, 'tools/call', {
      arguments: {},
      name: 'keyguard_status',
    })));
    await withTimeout(session.server.closed, 'server did not settle after EOF');

    const responses = responseLines(session.raw());
    assert.equal(responses.length, 1);
    assert.equal(responses[0].id, 1);
    assert.equal(responses[0].result.structuredContent.state, 'stopped');
  } finally {
    await closeSession(session);
  }
});

test('bootstrap exposes an injectable MCP server composition and package script', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    let captured;
    const app = await createKeyguardApp({
      dataDirectory,
      mcpServerFactory: (boundApp, options) => {
        captured = { boundApp, options };
        return Object.freeze({ start: () => undefined });
      },
    });
    const input = new PassThrough();
    const output = new PassThrough();
    const server = app.createMcpServer({ input, output });

    assert.equal(captured.boundApp, app);
    assert.equal(captured.options.input, input);
    assert.equal(captured.options.output, output);
    assert.equal(typeof server.start, 'function');

    const packageManifest = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
    assert.equal(packageManifest.scripts.mcp, 'node src/mcp/stdio-server.mjs');
  });
});

function request(id, method, params) {
  return { id, jsonrpc: '2.0', method, params };
}

function initializeParams() {
  return {
    capabilities: {},
    clientInfo: { name: 'keyguard-test-client', version: '1.0.0' },
    protocolVersion: PROTOCOL_VERSION,
  };
}

function structured(response) {
  assert.equal(response.jsonrpc, '2.0');
  assert.ok(response.result);
  assert.equal(Array.isArray(response.result.content), true);
  return response.result.structuredContent;
}

async function runLines(app, lines) {
  const session = startSession(app);

  for (const line of lines) {
    session.input.write(typeof line === 'string' ? `${line}\n` : `${JSON.stringify(line)}\n`);
  }
  session.input.end();
  await session.server.closed;

  const raw = session.raw();
  assert.equal(raw.endsWith('\n'), true);
  return responseLines(raw);
}

function startSession(app, input = new PassThrough()) {
  const output = new PassThrough();
  const chunks = [];
  output.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
  const server = createMcpStdioServer(app, { input, output });
  server.start();
  return {
    input,
    output,
    raw: () => Buffer.concat(chunks).toString('utf8'),
    server,
  };
}

class OneByteReadable extends Readable {
  constructor(value) {
    super({ highWaterMark: 1 });
    this.bytes = Buffer.from(value, 'utf8');
    this.index = 0;
    this.pushedChunks = 0;
  }

  _read() {
    if (this.index >= this.bytes.length) {
      this.push(null);
      return;
    }
    this.pushedChunks += 1;
    this.push(this.bytes.subarray(this.index, this.index + 1));
    this.index += 1;
  }
}

async function closeSession(session) {
  if (!session.input.writableEnded) {
    session.input.end();
  }
  await session.server.closed;
}

function responseLines(raw) {
  assert.equal(raw.endsWith('\n'), true);
  return raw.trimEnd().split('\n').map((line) => JSON.parse(line));
}

async function waitForResponse(session, timeoutMilliseconds = 250) {
  if (session.raw().length > 0) {
    return;
  }
  let timeout;
  try {
    await Promise.race([
      new Promise((resolvePromise) => session.output.once('data', resolvePromise)),
      new Promise((_, reject) => {
        timeout = setTimeout(() => reject(new Error('expected an early JSON-RPC response')), timeoutMilliseconds);
      }),
    ]);
  } finally {
    clearTimeout(timeout);
  }
}

function executeActionRequest(id, agentId) {
  return request(id, 'tools/call', {
    arguments: {
      action: 'cloudflare_pages_deploy',
      agentId,
      params: { directory: 'dist', project: 'keyguard-site' },
      projectRoot: '/approved/repository',
    },
    name: 'execute_action',
  });
}

function deferred() {
  let resolve;
  const promise = new Promise((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

async function withTimeout(promise, message, timeoutMilliseconds = 1_000) {
  let timeout;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timeout = setTimeout(() => reject(new Error(message)), timeoutMilliseconds);
      }),
    ]);
  } finally {
    clearTimeout(timeout);
  }
}

function createFakeApp() {
  const calls = {
    deletedLabels: [],
    deposits: [],
    executionAttempts: 0,
    policyRequests: [],
  };
  const controls = {
    credentialList: undefined,
    failCredentialList: false,
    failDeposit: false,
    onPolicyEvaluate: undefined,
    policyDecision: undefined,
  };
  const credential = {
    ciphertext: SECRET,
    createdAt: FIXED_TIME,
    instanceId: 'a'.repeat(32),
    label: 'cloudflare-api-token',
    secret: SECRET,
    status: 'active',
    updatedAt: FIXED_TIME,
  };
  const action = {
    approval: 'always',
    credentialLabel: 'cloudflare-api-token',
    execution: { environment: { CLOUDFLARE_API_TOKEN: SECRET } },
    name: 'cloudflare_pages_deploy',
    params: { directory: 'relative_path', project: 'slug' },
  };
  const services = {
    actionRegistry: {
      get: (name) => name === 'cloudflare_pages_deploy' ? action : undefined,
      list: () => [action],
    },
    depositService: {
      create: async (metadata) => {
        calls.deposits.push(metadata);
        if (controls.failDeposit) {
          throw new Error(`deposit failed: ${SECRET}`);
        }
        return {
          depositUrl: `https://deposit.example.invalid/${SECRET}`,
          expiresAt: '2026-07-14T12:10:00.000Z',
          label: metadata.label,
          status: 'pending',
        };
      },
    },
    execution: {
      executeApproved: async () => {
        calls.executionAttempts += 1;
        return { status: 'executed' };
      },
    },
    policyEngine: {
      evaluate: async (value) => {
        calls.policyRequests.push(value);
        await controls.onPolicyEvaluate?.(value);
        return controls.policyDecision ?? {
          envelope: {
            body: {
              action: 'cloudflare_pages_deploy',
              credentialLabel: 'cloudflare-api-token',
              project: { root: `/private/${SECRET}` },
              target: { directory: `/private/${SECRET}/dist` },
            },
            signature: { signature: SECRET },
          },
          requestId: 'approval_12345678',
          requiresDirtyTreeAcknowledgement: true,
          scope: { root: `/private/${SECRET}` },
          status: 'approval_required',
        };
      },
    },
    vault: {
      delete: async (label) => {
        calls.deletedLabels.push(label);
        return true;
      },
      list: async () => {
        if (controls.failCredentialList) {
          throw new Error(`credential list failed: ${SECRET}`);
        }
        return controls.credentialList ?? [credential];
      },
    },
  };
  const app = {
    services: Object.freeze(services),
    status() {
      return {
        internalDiagnostic: SECRET,
        server: { host: '127.0.0.1', port: 4545, url: 'http://127.0.0.1:4545' },
        state: 'stopped',
      };
    },
  };
  return { app, calls, controls };
}

function assertSafeOutput(value) {
  const serialized = JSON.stringify(value);
  assert.equal(serialized.includes(SECRET), false);
  assert.equal(serialized.includes('stack'), false);
  assert.equal(serialized.includes('ciphertext'), false);
}
