import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { runInNewContext } from 'node:vm';
import test from 'node:test';

const PUBLIC_DIRECTORY = fileURLToPath(new URL('../public/', import.meta.url));

test('documents guided setup and the ordered accessible Home without secret affordances', async () => {
  const { app, html, styles } = await readUiAssets();

  assert.match(html, /<main\s+id="app">/u);
  assert.doesNotMatch(html, /<main\s+id="app"\s+aria-live=/u);
  assert.match(html, /id="announcements"\s+role="status"\s+aria-live="polite"/u);
  assert.match(html, /id="view"/u);
  assert.match(html, /<meta\s+name="color-scheme"\s+content="dark">/u);
  assert.match(html, /<script\s+type="module"\s+src="\/app\.js"><\/script>/u);
  assert.match(html, /<link\s+rel="stylesheet"\s+href="\/styles\.css">/u);
  assert.match(app, /guided setup/u);
  assert.match(app, /whoami/u);
  assert.match(app, /<details/u);
  assert.match(app, /aria-expanded/u);
  assert.match(app, /shortValue\(stringValue\(project\?\.commit, 'unavailable'\)\)/u);
  assert.match(app, /function runtimeSummary/u);
  assert.match(app, /status\?\.identity\?\.fingerprint/u);
  assert.match(app, /local runtime/u);
  assert.match(app, /captureRenderState/u);
  assert.match(app, /restoreRenderState/u);
  assert.match(app, /data-disclosure-key/u);
  assert.doesNotMatch(app, /app\.innerHTML/u);

  const names = ['attention', 'approvals', 'credentials', 'activity', 'memory'];
  const positions = names.map((name) => app.indexOf(`section: '${name}'`));
  assert.equal(positions.every((position) => position >= 0), true);
  assert.equal(positions.every((position, index) => index === 0 || position > positions[index - 1]), true);

  assert.match(styles, /position:\s*sticky/u);
  assert.match(styles, /@media\s*\(max-width:/u);
  assert.match(styles, /:focus-visible/u);

  const uiText = `${html}\n${app}\n${styles}`.toLowerCase();
  for (const forbidden of ['clipboard', 'copy', 'qrcode', 'reveal', 'masked value']) {
    assert.equal(uiText.includes(forbidden), false, `${forbidden} must not be an interface affordance`);
  }
  assert.doesNotMatch(uiText, /type\s*=\s*["']password["']/u);
});

test('renders installed integrations from the registry and has no default provider handoff', async () => {
  const { app } = await readUiAssets();

  assert.match(app, /actions:\s*\[\]/u);
  assert.match(app, /requestApi\('\/api\/actions'\)/u);
  assert.match(app, /No integrations enabled/u);
  assert.match(app, /function integrationCard/u);
  assert.match(app, /data-label="\$\{escapeAttribute\(credential\.label\)\}"/u);
  assert.match(app, /data-provider="\$\{escapeAttribute\(credential\.provider\)\}"/u);
  assert.doesNotMatch(app, /cloudflare-api-token/iu);
  assert.doesNotMatch(app, /provider:\s*'cloudflare'/iu);
  assert.doesNotMatch(app, /body:\s*\{\s*label:\s*'[^']+'/u);
});

test('keeps a deposit handoff in ephemeral state and protects every UI mutation with local CSRF state', async () => {
  const { app } = await readUiAssets();

  assert.match(app, /deposit:\s*null/u);
  assert.match(app, /clearDeposit/u);
  assert.match(app, /x-keyguard-csrf/u);
  assert.match(app, /credentials:\s*'same-origin'/u);
  assert.match(app, /\/api\/deposit-link/u);
  assert.match(app, /\/api\/approvals/u);
  assert.match(app, /\/api\/memory/u);
  assert.match(app, /confirmation:\s*'DELETE'/u);
  assert.match(app, /state\.credentials\.some\(\(credential\) => credential\.status === 'active'\)/u);
  assert.match(app, /new URL\(value\.depositUrl\)/u);
  assert.match(app, /parsed\.protocol === 'https:'/u);
  assert.match(app, /setTimeout/u);
  assert.match(app, /expiresAtMilliseconds > now/u);
  assert.match(app, /data-deposit-link/u);
  assert.match(app, /depositLink !== null && \(state\.deposit === null \|\| expireDepositIfNeeded\(\)\)/u);
  assert.match(app, /state\.depositPollTimer = window\.setInterval[\s\S]{0,300}scheduleDepositExpiry/u);
  assert.doesNotMatch(app, /localStorage[^\n]{0,100}deposit/iu);
  assert.doesNotMatch(app, /sessionStorage[^\n]{0,100}deposit/iu);
});

test('rejects expired and malformed deposit projections before the transient handoff can render', async () => {
  const { app } = await readUiAssets();
  const isPendingDeposit = extractFunction(app, 'isPendingDeposit', 'function arrayValue');
  const now = Date.parse('2026-07-14T12:00:00.000Z');
  const valid = {
    depositUrl: 'https://deposit.example.invalid/one-time-link',
    expiresAt: '2026-07-14T12:01:00.000Z',
    label: 'cloudflare-api-token',
    status: 'pending',
  };

  assert.equal(isPendingDeposit(valid, now), true);
  assert.equal(isPendingDeposit({ ...valid, expiresAt: 'not-a-timestamp' }, now), false);
  assert.equal(isPendingDeposit({ ...valid, expiresAt: '1970-01-01T00:00:00.000Z' }, now), false);
  assert.equal(isPendingDeposit({ ...valid, depositUrl: 'https://user:pass@deposit.example.invalid/link' }, now), false);
});

test('makes setup server-authoritative and keeps accessibility announcements narrow', async () => {
  const { app } = await readUiAssets();

  assert.match(app, /\/api\/setup\/complete/u);
  assert.match(app, /body:\s*\{\s*scope:\s*state\.setupScope\s*\}/u);
  assert.match(app, /setup\?\.complete/u);
  assert.doesNotMatch(app, /isSetupEndpointUnavailable/u);
  assert.doesNotMatch(app, /setupFallbackComplete/u);
  assert.doesNotMatch(app, /localStorage/u);
  assert.doesNotMatch(app, /SETUP_KEY/u);
  assert.doesNotMatch(app, /role="status"/u);
});

test('wires setup through safe discovery, an opaque install plan, and an explicit install', async () => {
  const { app } = await readUiAssets();

  assert.match(app, /\/api\/skill\/status/u);
  assert.match(app, /\/api\/skill\/install-plan/u);
  assert.match(app, /\/api\/skill\/install/u);
  assert.match(app, /hosts:\s*state\.setupHosts/u);
  assert.match(app, /scope:\s*state\.setupScope/u);
  assert.match(app, /sharing:\s*state\.setupSharing/u);
  assert.match(app, /confirmation:\s*'INSTALL'/u);
  assert.match(app, /planId:\s*state\.installPlan\.planId/u);
  assert.match(app, /globalOptIn:\s*state\.setupGlobalOptIn/u);
  assert.match(app, /await completeSetup\(\)/u);
  assert.match(app, /detectedHostChoices/u);
  assert.doesNotMatch(app, /setupFallbackComplete/u);
  assert.doesNotMatch(app, /isSetupEndpointUnavailable/u);
  assert.doesNotMatch(app, /localStorage/u);
  assert.doesNotMatch(app, /projectRoot/u);
  assert.doesNotMatch(app, /homeDirectory/u);
});

test('rejects unsafe installer plan projections before rendering them', async () => {
  const { app } = await readUiAssets();
  const isInstallPlanProjection = extractFunction(app, 'isInstallPlanProjection', 'function isInstallResultProjection');
  const plan = {
    destinations: [
      { destination: '.atomical/keyguard/field-manual.md', scope: 'project' },
      { destination: '.agents/skills/atomical-keyguard/SKILL.md', scope: 'project' },
    ],
    expiresAt: '2099-07-14T12:02:00.000Z',
    hosts: ['codex'],
    planId: 'install_12345678',
    requiresConfirmation: true,
    requiresGlobalOptIn: false,
    scope: 'project',
    sharing: 'private',
    status: 'planned',
  };

  assert.equal(isInstallPlanProjection(plan), true);
  assert.equal(isInstallPlanProjection({ ...plan, destinations: [{ destination: '../private/root', scope: 'project' }] }), false);
  assert.equal(isInstallPlanProjection({ ...plan, destinations: [{ destination: '/private/root', scope: 'project' }] }), false);
  assert.equal(isInstallPlanProjection({ ...plan, root: '/private/root' }), false);
  assert.equal(isInstallPlanProjection({ ...plan, expiresAt: 'not-a-timestamp' }), false);
  assert.equal(isInstallPlanProjection({ ...plan, requiresGlobalOptIn: true }), false);
});

test('keeps exact-scope approval server-bounded and surfaces compact execution outcomes', async () => {
  const { app } = await readUiAssets();
  const canApproveExactScope = extractFunction(app, 'canApproveExactScope', 'function isInstallPlanProjection');
  const isExecutionProjection = extractFunction(app, 'isExecutionProjection', 'function freezeExecution');

  assert.equal(canApproveExactScope({
    project: { dirty: false },
    requiresDirtyTreeAcknowledgement: false,
    status: 'pending',
  }), true);
  assert.equal(canApproveExactScope({
    project: { dirty: true },
    requiresDirtyTreeAcknowledgement: false,
    status: 'pending',
  }), false);
  assert.equal(canApproveExactScope({
    project: { dirty: false },
    requiresDirtyTreeAcknowledgement: true,
    status: 'pending',
  }), false);
  assert.equal(isExecutionProjection({ status: 'approval_not_granted' }), true);
  assert.equal(isExecutionProjection({ status: 'verified' }), false);

  assert.match(app, /function approveExactScope/u);
  assert.match(app, /approve-scope/u);
  assert.match(app, /execution\.receipt/u);
  assert.match(app, /preparing/u);
  assert.doesNotMatch(app, /execution\.envelope/u);
  assert.doesNotMatch(app, /provider logs/u);
});

test('keeps capability revocation typed, inline, and limited to a safe returned credential', async () => {
  const { app } = await readUiAssets();

  assert.match(app, /data-action="revoke-credential"/u);
  assert.match(app, /Type REVOKE/u);
  assert.match(app, /confirmation:\s*'REVOKE'/u);
  assert.match(app, /\/api\/credentials\/\$\{encodeURIComponent\(label\)\}\/revoke/u);
  assert.match(app, /method:\s*'POST'/u);
  assert.match(app, /const revokeConfirmation = status === 'active'/u);
  assert.match(app, /const revokeOpen = disclosureIsOpen\(revokeDisclosureKey, false\)/u);
  assert.match(app, /<details class="revoke-confirmation" data-disclosure-key=/u);
  assert.match(app, /<summary aria-expanded="\$\{revokeOpen\}">Revoke capability<\/summary>/u);
  assert.doesNotMatch(app, /<dialog/u);
  assert.doesNotMatch(app, /revokeReason/u);

  const isRevokedCredentialProjection = extractFunction(app, 'isRevokedCredentialProjection', 'function isPendingDeposit');
  const credential = {
    createdAt: '2026-07-14T12:00:00.000Z',
    instanceId: 'a'.repeat(32),
    label: 'cloudflare-api-token',
    status: 'revoked',
    updatedAt: '2026-07-14T12:01:00.000Z',
  };

  assert.equal(isRevokedCredentialProjection({ credential }, credential.label), true);
  assert.equal(isRevokedCredentialProjection({ credential, reason: 'untrusted' }, credential.label), false);
  assert.equal(isRevokedCredentialProjection({ credential: { ...credential, status: 'active' } }, credential.label), false);
  assert.equal(isRevokedCredentialProjection({ credential: { ...credential, label: 'different-label' } }, credential.label), false);
  assert.equal(isRevokedCredentialProjection({ credential: { ...credential, instanceId: 'short' } }, credential.label), false);
  assert.equal(isRevokedCredentialProjection({ credential: { ...credential, updatedAt: 'not-a-timestamp' } }, credential.label), false);
});

async function readUiAssets() {
  const [html, app, styles] = await Promise.all([
    readFile(new URL('index.html', `file://${PUBLIC_DIRECTORY}/`), 'utf8'),
    readFile(new URL('app.js', `file://${PUBLIC_DIRECTORY}/`), 'utf8'),
    readFile(new URL('styles.css', `file://${PUBLIC_DIRECTORY}/`), 'utf8'),
  ]);
  return { app, html, styles };
}

function extractFunction(source, name, nextDeclaration) {
  const start = source.indexOf(`function ${name}`);
  const end = source.indexOf(nextDeclaration, start);
  assert.notEqual(start, -1, `${name} must be defined`);
  assert.notEqual(end, -1, `${name} must end before ${nextDeclaration}`);
  return runInNewContext(`${source.slice(start, end)}; ${name};`, { Date, URL });
}
