import assert from 'node:assert/strict';
import { request as httpRequest } from 'node:http';
import test from 'node:test';

import { createHttpServer } from '../src/http/server.mjs';

const SECRET_SENTINEL = 'ui-e2e-secret-must-not-reach-the-browser';
const FIXED_TIME = '2026-07-14T12:00:00.000Z';

test('serves fixed local UI assets with safe headers while retaining the JSON API', async () => {
  await withUiServer(async ({ listener }) => {
    const [home, script, styles, api, traversal, head] = await Promise.all([
      request(listener, '/'),
      request(listener, '/app.js'),
      request(listener, '/styles.css'),
      request(listener, '/api/status'),
      request(listener, '/%2e%2e/src/bootstrap.mjs'),
      request(listener, '/app.js', { method: 'HEAD' }),
    ]);

    assert.equal(home.statusCode, 200);
    assert.match(home.headers['content-type'], /^text\/html/u);
    assert.match(home.headers['content-security-policy'], /default-src 'self'/u);
    assert.equal(home.headers['cache-control'], 'no-store');
    assert.equal(home.headers['x-content-type-options'], 'nosniff');
    assert.match(home.raw, /<main\s+id="app"/u);
    assert.doesNotMatch(home.raw, /<main\s+id="app"\s+aria-live=/u);
    assert.match(home.raw, /id="announcements"\s+role="status"\s+aria-live="polite"/u);
    assert.doesNotMatch(home.raw, new RegExp(SECRET_SENTINEL));

    assert.equal(script.statusCode, 200);
    assert.match(script.headers['content-type'], /^text\/javascript/u);
    assert.match(script.raw, /guided setup/u);
    assert.equal(styles.statusCode, 200);
    assert.match(styles.headers['content-type'], /^text\/css/u);
    assert.match(styles.raw, /@media/u);
    assert.equal(head.statusCode, 200);
    assert.equal(head.raw, '');

    assert.equal(api.statusCode, 200);
    assert.equal(typeof api.body, 'object');
    assert.ok(api.headers['set-cookie']);
    assert.equal(traversal.statusCode, 404);
    assert.doesNotMatch(traversal.raw, /import\s+\{/u);
  });
});

test('supports browser-style same-origin UI mutations only with the issued CSRF state', async () => {
  await withUiServer(async ({ calls, listener }) => {
    const session = await createSession(listener);
    const denied = await request(listener, '/api/deposit-link', {
      body: { label: 'cloudflare-api-token', provider: 'cloudflare' },
      headers: { origin: listener.url },
      method: 'POST',
    });
    assert.equal(denied.statusCode, 403);

    const created = await request(listener, '/api/deposit-link', {
      body: { label: 'cloudflare-api-token', provider: 'cloudflare' },
      headers: session.headers,
      method: 'POST',
      origin: listener.url,
    });
    assert.equal(created.statusCode, 201);
    assert.deepEqual(created.body, {
      deposit: {
        depositUrl: 'https://deposit.example.invalid/one-time-link',
        expiresAt: '2026-07-14T12:10:00.000Z',
        label: 'cloudflare-api-token',
        status: 'pending',
      },
    });
    assert.deepEqual(calls.deposits, [{ label: 'cloudflare-api-token', provider: 'cloudflare' }]);
    assert.doesNotMatch(JSON.stringify(created.body), new RegExp(SECRET_SENTINEL));
  });
});

test('serves a local UI control-flow without unsafe installer or execution affordances', async () => {
  await withUiServer(async ({ listener }) => {
    const script = await request(listener, '/app.js');

    assert.equal(script.statusCode, 200);
    assert.match(script.raw, /\/api\/skill\/status/u);
    assert.match(script.raw, /\/api\/skill\/install-plan/u);
    assert.match(script.raw, /\/api\/skill\/install/u);
    assert.match(script.raw, /approve-scope/u);
    assert.match(script.raw, /revoke-credential/u);
    assert.match(script.raw, /\/api\/credentials\/\$\{encodeURIComponent\(label\)\}\/revoke/u);
    assert.match(script.raw, /confirmation:\s*'REVOKE'/u);
    assert.doesNotMatch(script.raw, /projectRoot/u);
    assert.doesNotMatch(script.raw, /homeDirectory/u);
    assert.doesNotMatch(script.raw, /provider logs/u);
    assert.doesNotMatch(script.raw, /revokeReason/u);
    assert.doesNotMatch(script.raw, new RegExp(SECRET_SENTINEL));
  });
});

async function withUiServer(run) {
  const fixture = createUiFixture();
  const controller = createHttpServer(fixture.app, { port: 0 });
  const listener = await controller.start();
  try {
    return await run({ ...fixture, listener });
  } finally {
    await controller.stop();
  }
}

async function createSession(listener) {
  const response = await request(listener, '/api/status');
  const cookies = normalizeSetCookie(response.headers['set-cookie']);
  const csrfCookie = cookies.find((cookie) => cookie.startsWith('keyguard_csrf='));
  assert.ok(csrfCookie);
  const csrf = cookieValue(csrfCookie);
  return {
    headers: {
      cookie: cookies.map((cookie) => cookie.split(';', 1)[0]).join('; '),
      'x-keyguard-csrf': csrf,
    },
  };
}

function request(listener, path, options = {}) {
  const rawBody = options.body === undefined ? undefined : JSON.stringify(options.body);
  const headers = { ...(options.headers ?? {}) };
  if (rawBody !== undefined) {
    headers['content-length'] = String(Buffer.byteLength(rawBody));
    headers['content-type'] = 'application/json';
  }
  if (options.origin !== undefined) {
    headers.origin = options.origin;
  }

  return new Promise((resolvePromise, rejectPromise) => {
    const requestHandle = httpRequest({
      headers,
      host: listener.host,
      method: options.method ?? 'GET',
      path,
      port: listener.port,
    }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        let body = raw;
        try {
          body = raw.length === 0 ? undefined : JSON.parse(raw);
        } catch {
          // Static content is intentionally returned as text.
        }
        resolvePromise({ body, headers: response.headers, raw, statusCode: response.statusCode });
      });
    });
    requestHandle.once('error', rejectPromise);
    if (rawBody !== undefined) {
      requestHandle.write(rawBody);
    }
    requestHandle.end();
  });
}

function createUiFixture() {
  const calls = { deposits: [] };
  const action = {
    approval: 'always',
    credential: { label: 'cloudflare-api-token', provider: 'cloudflare' },
    credentialLabel: 'cloudflare-api-token',
    name: 'cloudflare_pages_deploy',
    params: { directory: 'relative_path', project: 'slug' },
    version: 1,
  };
  const credential = {
    createdAt: FIXED_TIME,
    instanceId: 'a'.repeat(32),
    label: 'cloudflare-api-token',
    status: 'active',
    updatedAt: FIXED_TIME,
  };
  const app = {
    services: {
      actionRegistry: {
        get: (name) => name === action.name ? action : undefined,
        getCredentialBinding: ({ label, provider }) => (
          label === action.credential.label && provider === action.credential.provider
            ? action.credential
            : undefined
        ),
        list: async () => [{
          approval: action.approval,
          name: action.name,
          params: action.params,
          version: action.version,
        }],
      },
      activity: { list: async () => [] },
      approvals: { approveOnce: async () => ({}), deny: async () => ({}), list: async () => [] },
      depositService: {
        create: async (metadata) => {
          calls.deposits.push(metadata);
          return {
            depositUrl: 'https://deposit.example.invalid/one-time-link',
            expiresAt: '2026-07-14T12:10:00.000Z',
            label: metadata.label,
            secret: SECRET_SENTINEL,
            status: 'pending',
          };
        },
        receiveSigned: async () => credential,
      },
      memory: { dismiss: async () => ({}), list: async () => [], save: async () => ({}) },
      setup: { complete: async () => ({ complete: true, scope: 'project' }) },
      vault: { delete: async () => true, list: async () => [credential] },
    },
    status() {
      return {
        identity: { fingerprint: 'd'.repeat(64) },
        server: { host: '127.0.0.1', port: 4545, url: 'http://127.0.0.1:4545' },
        setup: { complete: false },
        state: 'running',
      };
    },
  };
  return { app, calls };
}

function normalizeSetCookie(value) {
  return Array.isArray(value) ? value : (typeof value === 'string' ? [value] : []);
}

function cookieValue(cookie) {
  const pair = cookie.split(';', 1)[0];
  return pair.slice(pair.indexOf('=') + 1);
}
