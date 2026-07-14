import assert from 'node:assert/strict';
import { request as httpRequest } from 'node:http';
import test from 'node:test';

import { createKeyguardApp } from '../src/bootstrap.mjs';
import { createHttpServer } from '../src/http/server.mjs';

const TEST_SECRET = 'http-api-secret-must-never-be-returned';
const FIXED_TIME = '2026-07-14T12:00:00.000Z';

test('rejects every non-loopback HTTP bind configuration', () => {
  const { app } = createFakeApp();

  for (const host of ['0.0.0.0', '::1', 'localhost', '192.168.1.10']) {
    assert.throws(
      () => createHttpServer(app, { host, port: 0 }),
      /127\.0\.0\.1/i,
    );
  }
});

test('issues a local session without CORS and rejects cross-origin or unprotected mutations', async () => {
  await withHttpServer(async ({ app, calls, listener }) => {
    const session = await createSession(listener);

    assert.equal(session.response.statusCode, 200);
    assert.equal(session.response.headers['access-control-allow-origin'], undefined);
    assert.equal(session.response.headers['access-control-allow-credentials'], undefined);
    assert.match(session.sessionCookie, /HttpOnly/u);
    assert.match(session.sessionCookie, /SameSite=Strict/u);
    assert.match(session.csrfCookie, /SameSite=Strict/u);

    const crossOrigin = await requestJson(listener, '/api/memory/memory_12345678/approve', {
      body: {},
      headers: session.headers,
      method: 'POST',
      origin: 'https://attacker.invalid',
    });
    assert.equal(crossOrigin.statusCode, 403);
    assertSafeError(crossOrigin, 'forbidden');

    const sessionless = await requestJson(listener, '/api/memory/memory_12345678/approve', {
      body: {},
      method: 'POST',
      origin: listener.url,
    });
    assert.equal(sessionless.statusCode, 403);
    assertSafeError(sessionless, 'forbidden');

    const withoutCsrf = await requestJson(listener, '/api/memory/memory_12345678/approve', {
      body: {},
      headers: { cookie: session.headers.cookie },
      method: 'POST',
      origin: listener.url,
    });
    assert.equal(withoutCsrf.statusCode, 403);
    assertSafeError(withoutCsrf, 'forbidden');

    const preflight = await requestJson(listener, '/api/status', {
      method: 'OPTIONS',
      origin: 'https://attacker.invalid',
    });
    assert.equal(preflight.statusCode, 405);
    assert.equal(preflight.headers['access-control-allow-origin'], undefined);
    assert.equal(calls.memorySave.length, 0);
    assert.equal(app.status().state, 'stopped');
  });
});

test('projects only a safe identity and persistent setup state, then completes setup behind local CSRF', async () => {
  await withHttpServer(async ({ calls, listener }) => {
    const initial = await requestJson(listener, '/api/status');
    assert.equal(initial.statusCode, 200);
    assert.deepEqual(initial.body, {
      identity: { fingerprint: 'd'.repeat(64) },
      server: { host: '127.0.0.1', port: 4545, url: 'http://127.0.0.1:4545' },
      setup: { complete: false },
      state: 'stopped',
    });
    assert.doesNotMatch(JSON.stringify(initial.body), new RegExp(TEST_SECRET));

    const session = await createSession(listener);
    const denied = await requestJson(listener, '/api/setup/complete', {
      body: { scope: 'project' },
      method: 'POST',
      origin: listener.url,
    });
    assert.equal(denied.statusCode, 403);
    assertSafeError(denied, 'forbidden');

    const malformed = await requestJson(listener, '/api/setup/complete', {
      body: { scope: 'everywhere' },
      headers: session.headers,
      method: 'POST',
      origin: listener.url,
    });
    assert.equal(malformed.statusCode, 400);
    assertSafeError(malformed, 'invalid_request');

    const completed = await requestJson(listener, '/api/setup/complete', {
      body: { scope: 'project' },
      headers: session.headers,
      method: 'POST',
      origin: listener.url,
    });
    assert.equal(completed.statusCode, 200);
    assert.deepEqual(completed.body, { setup: { complete: true, scope: 'project' } });
    assert.deepEqual(calls.setup, ['project']);

    const persisted = await requestJson(listener, '/api/status');
    assert.deepEqual(persisted.body.setup, { complete: true, scope: 'project' });
  });
});

test('returns credential projections only and requires an exact typed deletion confirmation', async () => {
  await withHttpServer(async ({ calls, listener }) => {
    const session = await createSession(listener);
    const listed = await requestJson(listener, '/api/credentials');

    assert.equal(listed.statusCode, 200);
    assert.deepEqual(listed.body, {
      items: [{
        createdAt: FIXED_TIME,
        instanceId: 'a'.repeat(32),
        label: 'cloudflare-api-token',
        status: 'active',
        updatedAt: FIXED_TIME,
      }],
    });
    assert.doesNotMatch(JSON.stringify(listed.body), new RegExp(TEST_SECRET));
    assert.equal(JSON.stringify(listed.body).includes('ciphertext'), false);

    const rejected = await requestJson(listener, '/api/credentials/cloudflare-api-token', {
      body: { confirmation: 'DELETE cloudflare-api-token' },
      headers: session.headers,
      method: 'DELETE',
      origin: listener.url,
    });
    assert.equal(rejected.statusCode, 400);
    assertSafeError(rejected, 'confirmation_required');
    assert.deepEqual(calls.deletedLabels, []);

    const deleted = await requestJson(listener, '/api/credentials/cloudflare-api-token', {
      body: { confirmation: 'DELETE' },
      headers: session.headers,
      method: 'DELETE',
      origin: listener.url,
    });
    assert.equal(deleted.statusCode, 200);
    assert.deepEqual(deleted.body, { deleted: true, label: 'cloudflare-api-token' });
    assert.deepEqual(calls.deletedLabels, ['cloudflare-api-token']);
  });
});

test('requires an exact revoke confirmation and returns only the revoked credential projection', async () => {
  await withHttpServer(async ({ calls, listener }) => {
    const session = await createSession(listener);

    const unsupportedMethod = await requestJson(listener, '/api/credentials/cloudflare-api-token/revoke');
    assert.equal(unsupportedMethod.statusCode, 405);
    assertSafeError(unsupportedMethod, 'method_not_allowed');

    const unprotected = await requestJson(listener, '/api/credentials/cloudflare-api-token/revoke', {
      body: { confirmation: 'REVOKE' },
      method: 'POST',
      origin: listener.url,
    });
    assert.equal(unprotected.statusCode, 403);
    assertSafeError(unprotected, 'forbidden');
    assert.deepEqual(calls.revokedLabels, []);

    const missingConfirmation = await requestJson(listener, '/api/credentials/cloudflare-api-token/revoke', {
      body: {},
      headers: session.headers,
      method: 'POST',
      origin: listener.url,
    });
    assert.equal(missingConfirmation.statusCode, 400);
    assertSafeError(missingConfirmation, 'invalid_request');
    assert.deepEqual(calls.revokedLabels, []);

    const rejected = await requestJson(listener, '/api/credentials/cloudflare-api-token/revoke', {
      body: { confirmation: 'REVOKE cloudflare-api-token' },
      headers: session.headers,
      method: 'POST',
      origin: listener.url,
    });
    assert.equal(rejected.statusCode, 400);
    assertSafeError(rejected, 'confirmation_required');
    assert.deepEqual(calls.revokedLabels, []);

    const revoked = await requestJson(listener, '/api/credentials/cloudflare-api-token/revoke', {
      body: { confirmation: 'REVOKE' },
      headers: session.headers,
      method: 'POST',
      origin: listener.url,
    });
    assert.equal(revoked.statusCode, 200);
    assert.deepEqual(revoked.body, {
      credential: {
        createdAt: FIXED_TIME,
        instanceId: 'a'.repeat(32),
        label: 'cloudflare-api-token',
        status: 'revoked',
        updatedAt: FIXED_TIME,
      },
    });
    assert.deepEqual(calls.revokedLabels, ['cloudflare-api-token']);
    assert.doesNotMatch(JSON.stringify(revoked.body), new RegExp(TEST_SECRET));
    assert.equal(JSON.stringify(revoked.body).includes('ciphertext'), false);
    assert.equal(JSON.stringify(revoked.body).includes('secret'), false);
  });
});

test('delegates a UI-only deposit link without exposing the deposited value', async () => {
  await withHttpServer(async ({ calls, listener }) => {
    const session = await createSession(listener);
    const response = await requestJson(listener, '/api/deposit-link', {
      body: { label: 'cloudflare-api-token', provider: 'cloudflare' },
      headers: session.headers,
      method: 'POST',
      origin: listener.url,
    });

    assert.equal(response.statusCode, 201);
    assert.deepEqual(response.body, {
      deposit: {
        depositUrl: 'https://deposit.example.invalid/one-time-link',
        expiresAt: '2026-07-14T12:10:00.000Z',
        label: 'cloudflare-api-token',
        status: 'pending',
      },
    });
    assert.deepEqual(calls.deposits, [{ label: 'cloudflare-api-token', provider: 'cloudflare' }]);
    assert.doesNotMatch(JSON.stringify(response.body), new RegExp(TEST_SECRET));
    assert.equal(JSON.stringify(response.body).includes('value'), false);
  });
});

test('projects generic installed actions and rejects uninstalled credential bindings before a handoff', async () => {
  const fixture = createGenericIntegrationApp();
  await withHttpServer(async ({ calls, listener }) => {
    const session = await createSession(listener);
    const actions = await requestJson(listener, '/api/actions');

    assert.equal(actions.statusCode, 200);
    assert.deepEqual(actions.body, {
      items: [{
        approval: 'always',
        credential: { label: 'example-api-token', provider: 'example' },
        name: 'example_publish',
        params: { site: 'slug' },
        version: 7,
      }],
    });

    const unavailable = await requestJson(listener, '/api/deposit-link', {
      body: { label: 'missing-api-token', provider: 'missing' },
      headers: session.headers,
      method: 'POST',
      origin: listener.url,
    });
    assert.equal(unavailable.statusCode, 409);
    assertSafeError(unavailable, 'not_installed');
    assert.deepEqual(calls.deposits, []);

    const available = await requestJson(listener, '/api/deposit-link', {
      body: { label: 'example-api-token', provider: 'example' },
      headers: session.headers,
      method: 'POST',
      origin: listener.url,
    });
    assert.equal(available.statusCode, 201);
    assert.deepEqual(calls.deposits, [{ label: 'example-api-token', provider: 'example' }]);
  }, fixture);
});

test('accepts a signed webhook without a UI session and returns only a credential projection', async () => {
  await withHttpServer(async ({ calls, listener }) => {
    const event = {
      handoffId: 'deposit_12345678',
      label: 'cloudflare-api-token',
      secret: TEST_SECRET,
      type: 'deposit.received',
    };
    const response = await requestJson(listener, '/atomic/events', {
      body: event,
      headers: {
        'x-agent-id': 'trusted-agent.example',
        'x-agent-sig': 'c2lnbmVkLXdlYmhvb2stcGF5bG9hZA',
        'x-agent-sig-time': FIXED_TIME,
        'x-webhook-token': 'webhook-token',
      },
      method: 'POST',
    });

    assert.equal(response.statusCode, 202);
    assert.deepEqual(response.body, {
      credential: {
        createdAt: FIXED_TIME,
        instanceId: 'a'.repeat(32),
        label: 'cloudflare-api-token',
        status: 'active',
        updatedAt: FIXED_TIME,
      },
    });
    assert.deepEqual(calls.receivedEvents, [{
      event,
      headers: {
        'X-Agent-Id': 'trusted-agent.example',
        'X-Agent-Sig': 'c2lnbmVkLXdlYmhvb2stcGF5bG9hZA',
        'X-Agent-Sig-Time': FIXED_TIME,
        'X-Webhook-Token': 'webhook-token',
      },
    }]);
    assert.doesNotMatch(JSON.stringify(response.body), new RegExp(TEST_SECRET));
  });
});

test('projects current list routes and invokes approval and memory mutations through typed contracts', async () => {
  await withHttpServer(async ({ calls, listener }) => {
    const session = await createSession(listener);
    const [approvals, activity, actions, memory] = await Promise.all([
      requestJson(listener, '/api/approvals'),
      requestJson(listener, '/api/activity'),
      requestJson(listener, '/api/actions'),
      requestJson(listener, '/api/memory'),
    ]);

    assert.deepEqual(approvals.body, {
      items: [{
        action: 'cloudflare_pages_deploy',
        credentialLabel: 'cloudflare-api-token',
        dirtyTreeAcknowledged: false,
        expiresAt: '2026-07-14T12:10:00.000Z',
        id: 'approval_12345678',
        project: {
          commit: 'c'.repeat(40),
          dirty: false,
          repositoryFingerprint: 'b'.repeat(64),
        },
        requiresDirtyTreeAcknowledgement: false,
        status: 'pending',
      }],
    });
    assert.deepEqual(activity.body, {
      items: [{
        action: 'cloudflare_pages_deploy',
        id: 'activity_12345678',
        receiptId: null,
        requestId: 'approval_12345678',
        stage: 'preparing',
        status: 'started',
        timestamp: FIXED_TIME,
      }],
    });
    assert.deepEqual(actions.body, {
      items: [{
        approval: 'always',
        credential: { label: 'cloudflare-api-token', provider: 'cloudflare' },
        name: 'cloudflare_pages_deploy',
        params: { directory: 'relative_path', project: 'slug' },
        version: 1,
      }],
    });
    assert.deepEqual(memory.body, {
      items: [{
        createdAt: FIXED_TIME,
        id: 'memory_12345678',
        scope: { kind: 'project', repositoryFingerprint: 'b'.repeat(64) },
        sourceReceiptId: 'receipt_12345678',
        status: 'candidate',
        text: 'Verified Cloudflare Pages deployment for keyguard-site at aaaaaaaaaaaa.',
        updatedAt: FIXED_TIME,
      }],
    });
    assert.doesNotMatch(JSON.stringify({ approvals, activity, actions, memory }), new RegExp(TEST_SECRET));

    const approved = await requestJson(listener, '/api/approvals/approval_12345678/approve', {
      body: { dirtyTreeAcknowledged: true },
      headers: session.headers,
      method: 'POST',
      origin: listener.url,
    });
    const denied = await requestJson(listener, '/api/approvals/approval_12345678/deny', {
      body: {},
      headers: session.headers,
      method: 'POST',
      origin: listener.url,
    });
    const saved = await requestJson(listener, '/api/memory/memory_12345678/approve', {
      body: {},
      headers: session.headers,
      method: 'POST',
      origin: listener.url,
    });
    const dismissed = await requestJson(listener, '/api/memory/memory_12345678/forget', {
      body: {},
      headers: session.headers,
      method: 'POST',
      origin: listener.url,
    });

    assert.equal(approved.statusCode, 200);
    assert.equal(denied.statusCode, 200);
    assert.equal(saved.statusCode, 200);
    assert.equal(dismissed.statusCode, 200);
    assert.deepEqual(calls.approved, [{ dirtyTreeAcknowledged: true, id: 'approval_12345678' }]);
    assert.deepEqual(calls.denied, ['approval_12345678']);
    assert.deepEqual(calls.memorySave, ['memory_12345678']);
    assert.deepEqual(calls.memoryDismiss, ['memory_12345678']);
  });
});

test('bridges valid once and exact-scope approvals into execution without returning raw execution data', async () => {
  await withHttpServer(async ({ calls, controls, listener }) => {
    const session = await createSession(listener);

    const approvedOnce = await requestJson(listener, '/api/approvals/approval_12345678/approve', {
      body: { dirtyTreeAcknowledged: true },
      headers: session.headers,
      method: 'POST',
      origin: listener.url,
    });
    assert.equal(approvedOnce.statusCode, 200);
    assert.equal(approvedOnce.body.approval.status, 'approved_once');
    assert.deepEqual(approvedOnce.body.execution, {
      receipt: {
        action: 'cloudflare_pages_deploy',
        id: 'receipt_12345678',
        providerStatus: 'succeeded',
        verificationStatus: 'verified',
      },
      status: 'verified',
    });
    assert.deepEqual(calls.executed, ['approval_12345678']);
    assert.equal(JSON.stringify(approvedOnce.body).includes('output'), false);
    assert.equal(JSON.stringify(approvedOnce.body).includes('root'), false);
    assert.equal(JSON.stringify(approvedOnce.body).includes('envelope'), false);
    assert.doesNotMatch(JSON.stringify(approvedOnce.body), new RegExp(TEST_SECRET));

    const approvedScope = await requestJson(listener, '/api/approvals/approval_12345678/approve-scope', {
      body: {},
      headers: session.headers,
      method: 'POST',
      origin: listener.url,
    });
    assert.equal(approvedScope.statusCode, 200);
    assert.equal(approvedScope.body.approval.status, 'approved_scope');
    assert.deepEqual(calls.approvedScopes, ['approval_12345678']);
    assert.deepEqual(calls.executed, ['approval_12345678', 'approval_12345678']);
    assert.equal(Object.hasOwn(approvedScope.body.approval, 'scope'), false);
    assert.equal(JSON.stringify(approvedScope.body).includes('/private/'), false);

    controls.approvalResult = {
      reason: 'dirty_tree_acknowledgement_required',
      requiresDirtyTreeAcknowledgement: true,
      status: 'pending',
    };
    const blocked = await requestJson(listener, '/api/approvals/approval_12345678/approve', {
      body: { dirtyTreeAcknowledged: false },
      headers: session.headers,
      method: 'POST',
      origin: listener.url,
    });
    assert.equal(blocked.statusCode, 200);
    assert.equal(blocked.body.approval.status, 'pending');
    assert.equal(Object.hasOwn(blocked.body, 'execution'), false);
    assert.deepEqual(calls.executed, ['approval_12345678', 'approval_12345678']);

    controls.approvalResult = {
      requiresDirtyTreeAcknowledgement: true,
      status: 'approved_once',
    };
    const malformedApproval = await requestJson(listener, '/api/approvals/approval_12345678/approve', {
      body: { dirtyTreeAcknowledged: false },
      headers: session.headers,
      method: 'POST',
      origin: listener.url,
    });
    assert.equal(malformedApproval.statusCode, 200);
    assert.equal(malformedApproval.body.approval.status, 'approved_once');
    assert.equal(Object.hasOwn(malformedApproval.body, 'execution'), false);
    assert.deepEqual(calls.executed, ['approval_12345678', 'approval_12345678']);

    controls.approvalResult = {
      dirtyTreeAcknowledged: true,
      requiresDirtyTreeAcknowledgement: true,
      status: 'approved_once',
    };
    const acknowledgedDirty = await requestJson(listener, '/api/approvals/approval_12345678/approve', {
      body: { dirtyTreeAcknowledged: true },
      headers: session.headers,
      method: 'POST',
      origin: listener.url,
    });
    assert.equal(acknowledgedDirty.statusCode, 200);
    assert.equal(acknowledgedDirty.body.execution.status, 'verified');
    assert.deepEqual(calls.executed, ['approval_12345678', 'approval_12345678', 'approval_12345678']);
  });
});

test('keeps installer discovery and opaque plans local while requiring typed apply confirmation', async () => {
  await withHttpServer(async ({ calls, listener }) => {
    const skillStatus = await requestJson(listener, '/api/skill/status');
    assert.equal(skillStatus.statusCode, 200);
    assert.deepEqual(skillStatus.body, {
      atomicCli: { detected: true },
      hosts: {
        claude: { detected: false, globalSkill: false, preselected: false, projectSkill: false },
        codex: { detected: true, globalSkill: false, preselected: true, projectSkill: true },
      },
      identity: { available: true },
      mcp: { registered: false },
      policy: { active: true, version: 1 },
      repository: { detected: true },
    });
    assert.doesNotMatch(JSON.stringify(skillStatus.body), new RegExp(TEST_SECRET));

    const unprotectedInstall = await requestJson(listener, '/api/skill/install', {
      body: { confirmation: 'INSTALL', planId: 'install_12345678' },
      method: 'POST',
      origin: listener.url,
    });
    assert.equal(unprotectedInstall.statusCode, 403);
    assertSafeError(unprotectedInstall, 'forbidden');
    assert.deepEqual(calls.installApplies, []);

    const session = await createSession(listener);
    const rootInjection = await requestJson(listener, '/api/skill/install-plan', {
      body: { hosts: ['codex'], projectRoot: `/private/${TEST_SECRET}` },
      headers: session.headers,
      method: 'POST',
      origin: listener.url,
    });
    assert.equal(rootInjection.statusCode, 400);
    assertSafeError(rootInjection, 'invalid_request');
    assert.deepEqual(calls.installPlans, []);

    const planned = await requestJson(listener, '/api/skill/install-plan', {
      body: { hosts: ['codex'], scope: 'project', sharing: 'private' },
      headers: session.headers,
      method: 'POST',
      origin: listener.url,
    });
    assert.equal(planned.statusCode, 201);
    assert.deepEqual(planned.body, {
      plan: {
        destinations: [
          { destination: '.atomical/keyguard/field-manual.md', scope: 'project' },
          { destination: '.agents/skills/atomical-keyguard/SKILL.md', scope: 'project' },
        ],
        expiresAt: '2026-07-14T12:02:00.000Z',
        hosts: ['codex'],
        planId: 'install_12345678',
        requiresConfirmation: true,
        requiresGlobalOptIn: false,
        scope: 'project',
        sharing: 'private',
        status: 'planned',
      },
    });
    assert.deepEqual(calls.installPlans, [{ hosts: ['codex'], scope: 'project', sharing: 'private' }]);
    assert.doesNotMatch(JSON.stringify(planned.body), new RegExp(TEST_SECRET));

    const missingConfirmation = await requestJson(listener, '/api/skill/install', {
      body: { confirmation: 'INSTALL ALL', planId: 'install_12345678' },
      headers: session.headers,
      method: 'POST',
      origin: listener.url,
    });
    assert.equal(missingConfirmation.statusCode, 400);
    assertSafeError(missingConfirmation, 'confirmation_required');
    assert.deepEqual(calls.installApplies, []);

    const installed = await requestJson(listener, '/api/skill/install', {
      body: { confirmation: 'INSTALL', planId: 'install_12345678' },
      headers: session.headers,
      method: 'POST',
      origin: listener.url,
    });
    assert.equal(installed.statusCode, 200);
    assert.deepEqual(installed.body, {
      install: {
        destinations: [
          { destination: '.atomical/keyguard/field-manual.md', scope: 'project', status: 'written' },
          { destination: '.agents/skills/atomical-keyguard/SKILL.md', scope: 'project', status: 'written' },
        ],
        hosts: ['codex'],
        scope: 'project',
        sharing: 'private',
        status: 'installed',
      },
    });
    assert.deepEqual(calls.installApplies, [{
      confirmation: { confirmed: true, globalOptIn: false },
      planId: 'install_12345678',
    }]);
    assert.doesNotMatch(JSON.stringify(installed.body), new RegExp(TEST_SECRET));
  });
});

test('rejects Windows-absolute installer destinations in plan and apply projections', async () => {
  const fixture = createFakeApp();
  let destination = 'C:\\outside';
  fixture.app.services.installerControl.plan = async () => unsafeInstallerPlanProjection(destination);
  fixture.app.services.installerControl.apply = async () => unsafeInstallerApplyProjection(destination);

  await withHttpServer(async ({ listener }) => {
    const session = await createSession(listener);
    for (const unsafeDestination of ['C:\\outside', 'C:/outside']) {
      destination = unsafeDestination;
      const planned = await requestJson(listener, '/api/skill/install-plan', {
        body: { hosts: ['codex'] },
        headers: session.headers,
        method: 'POST',
        origin: listener.url,
      });
      assert.equal(planned.statusCode, 503);
      assertSafeError(planned, 'service_unavailable');

      const applied = await requestJson(listener, '/api/skill/install', {
        body: { confirmation: 'INSTALL', planId: 'install_12345678' },
        headers: session.headers,
        method: 'POST',
        origin: listener.url,
      });
      assert.equal(applied.statusCode, 503);
      assertSafeError(applied, 'service_unavailable');
    }
  }, fixture);
});

test('bounds request bodies and turns untrusted service errors into uniform safe errors', async () => {
  await withHttpServer(async ({ controls, listener }) => {
    const session = await createSession(listener);
    const large = JSON.stringify({ label: 'cloudflare-api-token', provider: 'x'.repeat(17 * 1024) });
    const oversized = await requestJson(listener, '/api/deposit-link', {
      headers: session.headers,
      method: 'POST',
      origin: listener.url,
      rawBody: large,
    });
    assert.equal(oversized.statusCode, 413);
    assertSafeError(oversized, 'payload_too_large');

    const chunkedOversized = await requestJson(listener, '/api/deposit-link', {
      chunked: true,
      headers: session.headers,
      method: 'POST',
      origin: listener.url,
      rawBody: large,
    });
    assert.equal(chunkedOversized.statusCode, 413);
    assertSafeError(chunkedOversized, 'payload_too_large');

    const malformed = await requestJson(listener, '/api/deposit-link', {
      headers: session.headers,
      method: 'POST',
      origin: listener.url,
      rawBody: '{not-json',
    });
    assert.equal(malformed.statusCode, 400);
    assertSafeError(malformed, 'invalid_json');

    controls.failDeposits = true;
    const failed = await requestJson(listener, '/api/deposit-link', {
      body: { label: 'cloudflare-api-token', provider: 'cloudflare' },
      headers: session.headers,
      method: 'POST',
      origin: listener.url,
    });
    assert.equal(failed.statusCode, 500);
    assertSafeError(failed, 'request_failed');
  });
});

test('rejects malformed status projections and never echoes injected service strings', async () => {
  const fixture = createFakeApp();
  fixture.app.status = () => ({
    server: {
      host: '127.0.0.1',
      port: 4545,
      url: `http://127.0.0.1:4545/${TEST_SECRET}`,
    },
    state: 'stopped',
  });

  await withHttpServer(async ({ listener }) => {
    const response = await requestJson(listener, '/api/status');
    assert.equal(response.statusCode, 503);
    assertSafeError(response, 'service_unavailable');
  }, fixture);
});

test('bootstrap composes loopback server start and stop lifecycle methods', async () => {
  const fixture = createFakeApp();
  const app = await createKeyguardApp({
    actionRegistry: fixture.app.services.actionRegistry,
    activity: fixture.app.services.activity,
    approvals: fixture.app.services.approvals,
    depositService: fixture.app.services.depositService,
    execution: { executeApproved: async () => ({ status: 'approval_not_granted' }) },
    gitInspector: { inspect: async () => ({}) },
    identity: {
      fingerprint: 'c'.repeat(64),
      signCanonical: () => ({ algorithm: 'ed25519', fingerprint: 'c'.repeat(64), signature: 'a' }),
      verifyCanonical: () => true,
    },
    memory: fixture.app.services.memory,
    policyEngine: { evaluate: async () => ({ status: 'denied' }) },
    provider: { execute: async () => ({ status: 'failed' }) },
    vault: fixture.app.services.vault,
  });

  assert.equal(typeof app.createHttpServer, 'function');
  assert.equal(typeof app.start, 'function');
  assert.equal(typeof app.stop, 'function');

  const started = await app.start({ port: 0 });
  try {
    assert.equal(started.host, '127.0.0.1');
    assert.equal(app.status().state, 'running');
    assert.equal(app.status().server.port, started.port);
  } finally {
    await app.stop();
  }
  assert.equal(app.status().state, 'stopped');
});

async function withHttpServer(run, fixture = createFakeApp()) {
  const controller = createHttpServer(fixture.app, { port: 0 });
  const listener = await controller.start();
  try {
    await run({ ...fixture, listener });
  } finally {
    await controller.stop();
  }
}

async function createSession(listener) {
  const response = await requestJson(listener, '/api/status');
  const cookies = normalizeSetCookie(response.headers['set-cookie']);
  const sessionCookie = cookies.find((value) => value.startsWith('keyguard_session='));
  const csrfCookie = cookies.find((value) => value.startsWith('keyguard_csrf='));
  assert.ok(sessionCookie);
  assert.ok(csrfCookie);
  const csrf = cookieValue(csrfCookie);
  assert.ok(csrf);
  return {
    csrfCookie,
    headers: {
      cookie: cookies.map((value) => value.split(';', 1)[0]).join('; '),
      'x-keyguard-csrf': csrf,
    },
    response,
    sessionCookie,
  };
}

function requestJson(listener, path, options = {}) {
  const rawBody = options.rawBody ?? (options.body === undefined ? undefined : JSON.stringify(options.body));
  const headers = { ...(options.headers ?? {}) };
  if (rawBody !== undefined && options.chunked !== true) {
    headers['content-length'] = String(Buffer.byteLength(rawBody));
    headers['content-type'] = headers['content-type'] ?? 'application/json';
  }
  if (options.origin !== undefined) {
    headers.origin = options.origin;
  }

  return new Promise((resolvePromise, rejectPromise) => {
    const request = httpRequest({
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
        let body;
        try {
          body = raw.length === 0 ? undefined : JSON.parse(raw);
        } catch {
          body = raw;
        }
        resolvePromise({ body, headers: response.headers, raw, statusCode: response.statusCode });
      });
    });
    request.once('error', rejectPromise);
    if (rawBody !== undefined) {
      request.write(rawBody);
    }
    request.end();
  });
}

function unsafeInstallerPlanProjection(destination) {
  return {
    destinations: [{ destination, scope: 'project' }],
    expiresAt: '2026-07-14T12:02:00.000Z',
    hosts: ['codex'],
    planId: 'install_12345678',
    requiresConfirmation: true,
    requiresGlobalOptIn: false,
    scope: 'project',
    sharing: 'private',
    status: 'planned',
  };
}

function unsafeInstallerApplyProjection(destination) {
  return {
    destinations: [{ destination, scope: 'project', status: 'written' }],
    hosts: ['codex'],
    scope: 'project',
    sharing: 'private',
    status: 'installed',
  };
}

function createFakeApp() {
  const calls = {
    approved: [],
    approvedScopes: [],
    deletedLabels: [],
    denied: [],
    deposits: [],
    executed: [],
    installApplies: [],
    installPlans: [],
    memoryDismiss: [],
    memorySave: [],
    receivedEvents: [],
    revokedLabels: [],
    setup: [],
  };
  const controls = { approvalResult: undefined, failDeposits: false };
  const setupState = { complete: false, scope: undefined };
  const credential = {
    ciphertext: TEST_SECRET,
    createdAt: FIXED_TIME,
    instanceId: 'a'.repeat(32),
    label: 'cloudflare-api-token',
    secret: TEST_SECRET,
    status: 'active',
    updatedAt: FIXED_TIME,
  };
  const approval = {
    action: 'cloudflare_pages_deploy',
    credentialLabel: 'cloudflare-api-token',
    dirtyTreeAcknowledged: false,
    envelope: { secret: TEST_SECRET },
    expiresAt: '2026-07-14T12:10:00.000Z',
    id: 'approval_12345678',
    project: {
      commit: 'c'.repeat(40),
      dirty: false,
      repositoryFingerprint: 'b'.repeat(64),
      root: `/private/${TEST_SECRET}`,
    },
    reason: TEST_SECRET,
    requiresDirtyTreeAcknowledgement: false,
    status: 'pending',
  };
  const memory = {
    createdAt: FIXED_TIME,
    id: 'memory_12345678',
    rawRepositoryText: TEST_SECRET,
    scope: { kind: 'project', repositoryFingerprint: 'b'.repeat(64) },
    signature: { signature: TEST_SECRET },
    sourceReceiptId: 'receipt_12345678',
    status: 'candidate',
    text: 'Verified Cloudflare Pages deployment for keyguard-site at aaaaaaaaaaaa.',
    updatedAt: FIXED_TIME,
  };
  const action = {
    approval: 'always',
    credential: { label: 'cloudflare-api-token', provider: 'cloudflare' },
    credentialLabel: 'cloudflare-api-token',
    execution: { args: [TEST_SECRET] },
    name: 'cloudflare_pages_deploy',
    params: { directory: 'relative_path', project: 'slug' },
    version: 1,
  };
  const services = {
    actionRegistry: {
      get: (name) => name === action.name ? action : undefined,
      getCredentialBinding: ({ label, provider }) => (
        label === action.credential.label && provider === action.credential.provider
          ? action.credential
          : undefined
      ),
      list: () => [{
        approval: action.approval,
        name: action.name,
        params: action.params,
        version: action.version,
      }],
    },
    activity: {
      list: async () => [{
        action: 'cloudflare_pages_deploy',
        id: 'activity_12345678',
        message: TEST_SECRET,
        receiptId: null,
        requestId: 'approval_12345678',
        stage: 'preparing',
        status: 'started',
        timestamp: FIXED_TIME,
      }],
    },
    approvals: {
      approveOnce: async (id, options) => {
        calls.approved.push({ dirtyTreeAcknowledged: options?.dirtyTreeAcknowledged === true, id });
        return { ...approval, ...(controls.approvalResult ?? {}), status: controls.approvalResult?.status ?? 'approved_once' };
      },
      approveExactScope: async (id) => {
        calls.approvedScopes.push(id);
        return { ...approval, status: 'approved_scope' };
      },
      deny: async (id) => {
        calls.denied.push(id);
        return { ...approval, status: 'denied' };
      },
      list: async () => [approval],
    },
    depositService: {
      create: async (metadata) => {
        calls.deposits.push(metadata);
        if (controls.failDeposits) {
          throw new Error(`deposit adapter error: ${TEST_SECRET}`);
        }
        return {
          depositUrl: 'https://deposit.example.invalid/one-time-link',
          expiresAt: '2026-07-14T12:10:00.000Z',
          label: metadata.label,
          status: 'pending',
          value: TEST_SECRET,
        };
      },
      receiveSigned: async (event, headers) => {
        calls.receivedEvents.push({ event, headers });
        return credential;
      },
    },
    execution: {
      executeApproved: async (id) => {
        calls.executed.push(id);
        return {
          attention: 'none',
          output: { stderr: TEST_SECRET, stdout: TEST_SECRET },
          receipt: {
            action: 'cloudflare_pages_deploy',
            id: 'receipt_12345678',
            provider: { status: 'succeeded' },
            repository: { root: `/private/${TEST_SECRET}` },
            request: { envelope: TEST_SECRET },
            verification: { status: 'verified' },
          },
          status: 'verified',
        };
      },
    },
    installerControl: {
      apply: async (planId, confirmation) => {
        calls.installApplies.push({ confirmation, planId });
        return {
          destinations: [
            { destination: '.atomical/keyguard/field-manual.md', scope: 'project', status: 'written' },
            { destination: '.agents/skills/atomical-keyguard/SKILL.md', scope: 'project', status: 'written' },
          ],
          hosts: ['codex'],
          internalRoot: `/private/${TEST_SECRET}`,
          scope: 'project',
          sharing: 'private',
          status: 'installed',
        };
      },
      plan: async (selection) => {
        calls.installPlans.push(selection);
        return {
          destinations: [
            { destination: '.atomical/keyguard/field-manual.md', scope: 'project' },
            { destination: '.agents/skills/atomical-keyguard/SKILL.md', scope: 'project' },
          ],
          expiresAt: '2026-07-14T12:02:00.000Z',
          hosts: ['codex'],
          planId: 'install_12345678',
          rawPlan: TEST_SECRET,
          requiresConfirmation: true,
          requiresGlobalOptIn: false,
          scope: 'project',
          sharing: 'private',
          status: 'planned',
        };
      },
      status: async () => ({
        atomicCli: { detected: true, path: `/private/${TEST_SECRET}/atomic` },
        hosts: {
          claude: {
            detected: false,
            globalSkill: false,
            invocation: TEST_SECRET,
            preselected: false,
            projectSkill: false,
          },
          codex: {
            detected: true,
            globalSkill: false,
            invocation: TEST_SECRET,
            preselected: true,
            projectSkill: true,
          },
        },
        identity: { available: true, fingerprint: 'd'.repeat(64) },
        mcp: { registered: false },
        policy: { active: true, path: `/private/${TEST_SECRET}/policy.json`, version: 1 },
        projectRoot: `/private/${TEST_SECRET}`,
        repository: { detected: true, root: `/private/${TEST_SECRET}` },
      }),
    },
    memory: {
      dismiss: async (id) => {
        calls.memoryDismiss.push(id);
        return { ...memory, id, status: 'dismissed' };
      },
      list: async () => [memory],
      save: async (id) => {
        calls.memorySave.push(id);
        return { ...memory, id, status: 'saved' };
      },
    },
    setup: {
      complete: async (scope) => {
        calls.setup.push(scope);
        setupState.complete = true;
        setupState.scope = scope;
        return { complete: true, scope };
      },
    },
    vault: {
      delete: async (label) => {
        calls.deletedLabels.push(label);
        return true;
      },
      list: async () => [credential],
      revoke: async (label) => {
        calls.revokedLabels.push(label);
        return { ...credential, label, status: 'revoked' };
      },
    },
  };
  const app = {
    services: Object.freeze(services),
    status() {
      return {
        internalDiagnostic: TEST_SECRET,
        identity: { fingerprint: 'd'.repeat(64), privateKeyPath: `/private/${TEST_SECRET}` },
        server: { host: '127.0.0.1', port: 4545, url: 'http://127.0.0.1:4545' },
        setup: setupState.complete
          ? { complete: true, internalScopeRoot: `/private/${TEST_SECRET}`, scope: setupState.scope }
          : { complete: false, internalScopeRoot: `/private/${TEST_SECRET}` },
        state: 'stopped',
      };
    },
  };
  return { app, calls, controls };
}

function createGenericIntegrationApp() {
  const fixture = createFakeApp();
  const action = {
    approval: 'always',
    credential: { label: 'example-api-token', provider: 'example' },
    credentialLabel: 'example-api-token',
    name: 'example_publish',
    params: { site: 'slug' },
    version: 7,
  };
  fixture.app.services.actionRegistry.get = (name) => name === action.name ? action : undefined;
  fixture.app.services.actionRegistry.getCredentialBinding = ({ label, provider }) => (
    label === action.credential.label && provider === action.credential.provider
      ? action.credential
      : undefined
  );
  fixture.app.services.actionRegistry.list = () => [{
    approval: action.approval,
    name: action.name,
    params: action.params,
    version: action.version,
  }];
  return fixture;
}

function normalizeSetCookie(value) {
  if (Array.isArray(value)) {
    return value;
  }
  return typeof value === 'string' ? [value] : [];
}

function cookieValue(cookie) {
  const pair = cookie.split(';', 1)[0];
  return pair.slice(pair.indexOf('=') + 1);
}

function assertSafeError(response, expectedCode) {
  assert.deepEqual(Object.keys(response.body), ['error']);
  assert.equal(response.body.error.code, expectedCode);
  assert.equal(typeof response.body.error.message, 'string');
  assert.equal('stack' in response.body.error, false);
  assert.doesNotMatch(JSON.stringify(response.body), new RegExp(TEST_SECRET));
}
