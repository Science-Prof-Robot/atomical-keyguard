const POLL_INTERVAL_MILLISECONDS = 15_000;
const MAX_TIMER_DELAY_MILLISECONDS = 2_147_483_647;

const HOME_SECTIONS = Object.freeze([
  { section: 'attention', title: 'attention needed' },
  { section: 'approvals', title: 'approvals' },
  { section: 'credentials', title: 'credentials' },
  { section: 'actions', title: 'integrations' },
  { section: 'activity', title: 'recent activity' },
  { section: 'memory', title: 'memory · continuous' },
]);

const state = {
  activity: [],
  actions: [],
  approvals: [],
  credentials: [],
  deposit: null,
  depositExpiryTimer: null,
  depositPollTimer: null,
  depositIntentHandled: false,
  disclosures: new Map(),
  error: null,
  execution: new Map(),
  installPlan: null,
  installResult: null,
  loading: true,
  memory: [],
  message: null,
  setupGlobalOptIn: false,
  setupHosts: [],
  setupScope: 'project',
  setupSharing: 'private',
  setupStep: 0,
  skill: null,
  status: null,
};

const app = document.querySelector('#app');
const announcements = document.querySelector('#announcements');
const view = document.querySelector('#view');

if (app === null || announcements === null || view === null) {
  throw new Error('Keyguard app shell is unavailable.');
}

app.addEventListener('click', (event) => {
  const clicked = event.target instanceof Element ? event.target : null;
  const depositLink = clicked?.closest('[data-deposit-link]') ?? null;
  if (depositLink !== null && (state.deposit === null || expireDepositIfNeeded())) {
    event.preventDefault();
    render();
    return;
  }

  const target = clicked?.closest('[data-action]') ?? null;
  if (target === null) {
    return;
  }
  void handleAction(target);
});

app.addEventListener('submit', (event) => {
  const form = event.target instanceof HTMLFormElement ? event.target : null;
  if (form?.dataset.action === 'delete-credential') {
    event.preventDefault();
    void deleteCredential(form);
    return;
  }
  if (form?.dataset.action === 'revoke-credential') {
    event.preventDefault();
    void revokeCredential(form);
  }
});

app.addEventListener('toggle', (event) => {
  const details = event.target instanceof HTMLDetailsElement ? event.target : null;
  const summary = details?.querySelector('summary');
  const key = details?.dataset.disclosureKey;
  if (key !== undefined && key !== '') {
    state.disclosures.set(key, details.open);
  }
  if (summary !== null && summary !== undefined) {
    summary.setAttribute('aria-expanded', String(details.open));
  }
}, true);

void initialize();

async function initialize() {
  render();
  try {
    await refresh();
  } catch {
    state.error = 'Keyguard could not reach its local service. Check that the loopback daemon is running.';
  } finally {
    state.loading = false;
    render();
  }
}

async function handleAction(target) {
  const action = target.dataset.action;
  if (action === 'setup-next') {
    state.setupStep = Math.min(state.setupStep + 1, 2);
    render();
    return;
  }
  if (action === 'setup-back') {
    state.setupStep = Math.max(state.setupStep - 1, 0);
    render();
    return;
  }
  if (action === 'setup-scope') {
    const scope = target.dataset.scope === 'global' ? 'global' : 'project';
    if (state.setupScope !== scope) {
      state.setupScope = scope;
      clearInstallPlan();
    }
    render();
    return;
  }
  if (action === 'setup-host') {
    updateSetupHost(target.dataset.host, target instanceof HTMLInputElement && target.checked);
    render();
    return;
  }
  if (action === 'setup-global-opt-in') {
    state.setupGlobalOptIn = target instanceof HTMLInputElement && target.checked;
    render();
    return;
  }
  if (action === 'create-install-plan') {
    await perform('Preparing the local install plan…', createInstallPlan);
    return;
  }
  if (action === 'install-skill') {
    await perform('Installing the selected local skill…', installSkill);
    return;
  }
  if (action === 'refresh') {
    await perform('Refreshing local state…', refresh);
    return;
  }
  if (action === 'create-deposit') {
    await perform(
      'Creating a one-time handoff…',
      () => createDeposit(target.dataset.label, target.dataset.provider),
    );
    return;
  }
  if (action === 'clear-deposit') {
    clearDeposit();
    state.message = 'The one-time handoff was cleared from this page.';
    render();
    return;
  }
  if (action === 'approve') {
    await perform('Preparing approval execution…', () => approve(target.dataset.id));
    return;
  }
  if (action === 'approve-scope') {
    await perform('Preparing exact-scope execution…', () => approveExactScope(target.dataset.id));
    return;
  }
  if (action === 'deny') {
    await perform('Declining approval…', () => deny(target.dataset.id));
    return;
  }
  if (action === 'save-memory') {
    await perform('Saving memory…', () => saveMemory(target.dataset.id));
    return;
  }
  if (action === 'dismiss-memory') {
    await perform('Dismissing suggestion…', () => dismissMemory(target.dataset.id));
  }
}

async function perform(message, operation) {
  state.error = null;
  state.message = message;
  render();
  try {
    await operation();
  } catch {
    state.error = 'Keyguard could not complete that local request. Refresh and try again.';
  } finally {
    render();
  }
}

async function refresh() {
  expireDepositIfNeeded();
  const [status, credentials, actions, approvals, activity, memory, skill] = await Promise.all([
    requestApi('/api/status'),
    requestApi('/api/credentials'),
    requestApi('/api/actions'),
    requestApi('/api/approvals'),
    requestApi('/api/activity'),
    requestApi('/api/memory'),
    requestApi('/api/skill/status'),
  ]);
  if (!isSkillStatusProjection(skill)) {
    throw new Error('Local discovery was unavailable.');
  }
  state.status = status;
  state.credentials = arrayValue(credentials.items);
  state.actions = actionArray(actions.items);
  state.approvals = arrayValue(approvals.items);
  state.activity = arrayValue(activity.items);
  state.memory = arrayValue(memory.items);
  synchronizeSetupHosts(skill);
  state.skill = freezeSkillStatus(skill);
  applyDepositIntent();

  if (state.deposit !== null && state.credentials.some((credential) => (
    credential.label === state.deposit.label && credential.status === 'active'
  ))) {
    clearDeposit();
    state.message = 'Credential sealed. The one-time handoff has been cleared from this page.';
  }
}

function applyDepositIntent() {
  if (state.depositIntentHandled) {
    return;
  }
  state.depositIntentHandled = true;
  const query = new URL(window.location.href).searchParams;
  if (query.get('intent') !== 'create_deposit_link') {
    return;
  }
  const binding = installedCredentialBinding(query.get('label'), query.get('provider'));
  if (binding === null) {
    state.message = 'That credential binding is not installed in this Keyguard profile.';
    return;
  }
  state.message = hasActiveCredentialFor(binding.label)
    ? 'The requested credential is already sealed for this installed integration.'
    : 'The requested credential is installed. Create its one-time handoff from the integration card.';
}

async function completeSetup() {
  await requestApi('/api/setup/complete', {
    body: { scope: state.setupScope },
    method: 'POST',
  });
  await refresh();
  if (setupCompletionFromStatus(state.status) !== true) {
    throw new Error('Setup completion was not confirmed.');
  }
  state.message = 'Local skill installed. Home stays focused on the next local decision.';
}

async function createInstallPlan() {
  const hosts = selectedSetupHosts();
  if (hosts.length === 0) {
    throw new Error('Choose at least one detected local host.');
  }
  const response = await requestApi('/api/skill/install-plan', {
    body: { hosts: state.setupHosts, scope: state.setupScope, sharing: state.setupSharing },
    method: 'POST',
  });
  if (!isInstallPlanProjection(response.plan) || !matchesInstallSelection(response.plan)) {
    throw new Error('Install plan was unavailable.');
  }
  state.installPlan = freezeInstallPlan(response.plan);
  state.installResult = null;
  state.setupGlobalOptIn = false;
  state.message = 'Install plan ready. Review the relative destinations before writing.';
}

async function installSkill() {
  const plan = state.installPlan;
  if (plan === null || !isInstallPlanProjection(plan) || millisecondsUntil(plan.expiresAt) <= 0) {
    clearInstallPlan();
    throw new Error('Install plan expired.');
  }
  if (plan.requiresGlobalOptIn && state.setupGlobalOptIn !== true) {
    throw new Error('Global opt-in is required.');
  }
  const response = await requestApi('/api/skill/install', {
    body: {
      confirmation: 'INSTALL',
      globalOptIn: state.setupGlobalOptIn,
      planId: state.installPlan.planId,
    },
    method: 'POST',
  });
  if (!isInstallResultProjection(response.install) || !matchesInstallPlan(response.install, plan)) {
    throw new Error('Install result was unavailable.');
  }
  state.installResult = freezeInstallResult(response.install);
  await completeSetup();
}

async function createDeposit(label, provider) {
  const credential = installedCredentialBinding(label, provider);
  if (credential === null) {
    throw new Error('Credential binding is not installed.');
  }
  const response = await requestApi('/api/deposit-link', {
    body: { label: credential.label, provider: credential.provider },
    method: 'POST',
  });
  const deposit = response.deposit;
  if (!isPendingDeposit(deposit) || deposit.label !== credential.label) {
    throw new Error('Deposit response was unavailable.');
  }
  clearDeposit();
  state.deposit = Object.freeze({
    depositUrl: deposit.depositUrl,
    expiresAt: deposit.expiresAt,
    label: deposit.label,
  });
  state.message = 'One-time handoff ready. It is held only while this page remains open.';
  startDepositMonitor();
}

async function monitorDeposit() {
  if (state.deposit === null) {
    return;
  }
  if (expireDepositIfNeeded()) {
    render();
    return;
  }
  try {
    await refresh();
    render();
  } catch {
    // The current handoff remains local and expires on its original schedule.
  }
}

function startDepositMonitor() {
  if (state.deposit === null) {
    return;
  }

  state.depositPollTimer = window.setInterval(() => {
    void monitorDeposit();
  }, POLL_INTERVAL_MILLISECONDS);
  scheduleDepositExpiry();
}

function scheduleDepositExpiry() {
  if (state.deposit === null) {
    return;
  }
  const expectedDeposit = state.deposit;
  const remaining = millisecondsUntil(expectedDeposit.expiresAt);
  if (remaining <= 0) {
    if (expireDepositIfNeeded()) {
      render();
    }
    return;
  }
  const delay = Math.min(remaining + 1, MAX_TIMER_DELAY_MILLISECONDS);
  state.depositExpiryTimer = window.setTimeout(() => {
    state.depositExpiryTimer = null;
    if (state.deposit !== expectedDeposit) {
      return;
    }
    if (expireDepositIfNeeded()) {
      render();
      return;
    }
    scheduleDepositExpiry();
  }, delay);
}

function expireDepositIfNeeded() {
  if (state.deposit === null || millisecondsUntil(state.deposit.expiresAt) > 0) {
    return false;
  }
  clearDeposit();
  state.message = 'The one-time handoff expired and was cleared from this page.';
  return true;
}

function clearDeposit() {
  if (state.depositExpiryTimer !== null) {
    window.clearTimeout(state.depositExpiryTimer);
  }
  if (state.depositPollTimer !== null) {
    window.clearInterval(state.depositPollTimer);
  }
  state.deposit = null;
  state.depositExpiryTimer = null;
  state.depositPollTimer = null;
}

async function approve(id) {
  const approval = state.approvals.find((item) => item.id === id);
  const acknowledged = approval?.requiresDirtyTreeAcknowledgement === true
    && document.querySelector(`#dirty-${cssIdentifier(id)}`)?.checked === true;
  await approveAndExecute(id, 'approve', { dirtyTreeAcknowledged: acknowledged });
}

async function approveExactScope(id) {
  const approval = state.approvals.find((item) => item.id === id);
  if (!canApproveExactScope(approval)) {
    throw new Error('Exact-scope approval is unavailable.');
  }
  await approveAndExecute(id, 'approve-scope', {});
}

async function approveAndExecute(id, action, body) {
  state.execution.set(id, Object.freeze({ stage: 'preparing' }));
  render();
  try {
    const response = await requestApi(`/api/approvals/${encodeURIComponent(id)}/${action}`, {
      body,
      method: 'POST',
    });
    if (response.execution !== undefined) {
      if (!isExecutionProjection(response.execution)) {
        throw new Error('Execution result was unavailable.');
      }
      state.execution.set(id, freezeExecution(response.execution));
      state.message = executionMessage(response.execution);
    } else {
      state.execution.delete(id);
      state.message = 'Approval remains pending for a local decision.';
    }
    await refresh();
  } catch (error) {
    state.execution.delete(id);
    throw error;
  }
}

async function deny(id) {
  await requestApi(`/api/approvals/${encodeURIComponent(id)}/deny`, {
    body: {},
    method: 'POST',
  });
  state.message = 'Approval declined.';
  await refresh();
}

async function saveMemory(id) {
  await requestApi(`/api/memory/${encodeURIComponent(id)}/approve`, { body: {}, method: 'POST' });
  state.message = 'Memory saved to the project scope.';
  await refresh();
}

async function dismissMemory(id) {
  await requestApi(`/api/memory/${encodeURIComponent(id)}/forget`, { body: {}, method: 'POST' });
  state.message = 'Memory suggestion dismissed.';
  await refresh();
}

async function deleteCredential(form) {
  const label = form.dataset.label;
  const confirmation = new FormData(form).get('confirmation');
  if (confirmation !== 'DELETE') {
    state.error = 'Type DELETE before permanently removing this sealed credential.';
    render();
    return;
  }
  await perform('Removing sealed credential…', async () => {
    await requestApi(`/api/credentials/${encodeURIComponent(label)}`, {
      body: { confirmation: 'DELETE' },
      method: 'DELETE',
    });
    state.message = 'Sealed credential removed.';
    await refresh();
  });
}

async function revokeCredential(form) {
  const label = form.dataset.label;
  const confirmation = new FormData(form).get('confirmation');
  if (confirmation !== 'REVOKE') {
    state.error = 'Type REVOKE before disabling this sealed credential capability.';
    render();
    return;
  }
  await perform('Revoking credential capability…', async () => {
    const response = await requestApi(`/api/credentials/${encodeURIComponent(label)}/revoke`, {
      body: { confirmation: 'REVOKE' },
      method: 'POST',
    });
    if (!isRevokedCredentialProjection(response, label)) {
      throw new Error('Credential revocation response was unavailable.');
    }
    state.message = 'Credential capability revoked.';
    await refresh();
  });
}

async function requestApi(path, options = {}) {
  const method = options.method ?? 'GET';
  const headers = { accept: 'application/json' };
  if (options.body !== undefined) {
    headers['content-type'] = 'application/json';
  }
  if (method !== 'GET' && method !== 'HEAD') {
    const csrf = csrfToken();
    if (csrf.length === 0) {
      throw new Error('Local session is unavailable.');
    }
    headers['x-keyguard-csrf'] = csrf;
  }
  const response = await fetch(path, {
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
    credentials: 'same-origin',
    headers,
    method,
  });
  if (!response.ok) {
    throw new ApiRequestError(response.status);
  }
  if (response.status === 204) {
    return {};
  }
  try {
    return await response.json();
  } catch {
    throw new ApiRequestError(response.status);
  }
}

function render() {
  const snapshot = captureRenderState();
  expireDepositIfNeeded();
  view.innerHTML = state.loading
    ? loadingView()
    : (setupIsComplete() ? homeView() : setupView());
  restoreRenderState(snapshot);
  announcements.textContent = state.error ?? state.message ?? '';
}

function captureRenderState() {
  for (const details of view.querySelectorAll('details[data-disclosure-key]')) {
    const key = details.dataset.disclosureKey;
    if (key !== undefined && key !== '') {
      state.disclosures.set(key, details.open);
    }
  }
  const inputs = Array.from(view.querySelectorAll('input[id]'), (input) => ({
    checked: input.checked,
    id: input.id,
    value: input.value,
  }));
  const active = document.activeElement;
  if (!(active instanceof HTMLInputElement) || !view.contains(active) || active.id.length === 0) {
    return { active: null, inputs };
  }
  return {
    active: {
      id: active.id,
      selectionEnd: active.selectionEnd,
      selectionStart: active.selectionStart,
    },
    inputs,
  };
}

function restoreRenderState(snapshot) {
  for (const inputState of snapshot.inputs) {
    const input = document.getElementById(inputState.id);
    if (!(input instanceof HTMLInputElement) || !view.contains(input)) {
      continue;
    }
    if (input.type === 'checkbox' || input.type === 'radio') {
      input.checked = inputState.checked;
    } else {
      input.value = inputState.value;
    }
  }
  if (snapshot.active === null) {
    return;
  }
  const active = document.getElementById(snapshot.active.id);
  if (!(active instanceof HTMLInputElement) || !view.contains(active)) {
    return;
  }
  active.focus({ preventScroll: true });
  if (snapshot.active.selectionStart !== null && snapshot.active.selectionEnd !== null) {
    active.setSelectionRange(snapshot.active.selectionStart, snapshot.active.selectionEnd);
  }
}

function loadingView() {
  return `<div class="shell"><p class="eyebrow">atomical keyguard</p><p class="loading">Preparing local control…</p></div>`;
}

function setupView() {
  const steps = ['verify local runtime', 'choose scope and hosts', 'review and install'];
  const title = steps[state.setupStep];
  return `
    <div class="shell">
      ${identityStrip()}
      <section class="setup-card" aria-labelledby="setup-title">
        <p class="eyebrow">atomical keyguard</p>
        <h1 id="setup-title">guided setup</h1>
        <p class="lede">Establish the local control surface before asking it to protect a credential or approve an action.</p>
        <ol class="stepper" aria-label="Setup progress">
          ${steps.map((step, index) => `<li class="${index === state.setupStep ? 'current' : ''}">${escapeHtml(step)}</li>`).join('')}
        </ol>
        ${setupStepContent(title)}
        <div class="actions">
          ${state.setupStep > 0 ? '<button class="button secondary" type="button" data-action="setup-back">Back</button>' : ''}
          ${state.setupStep < steps.length - 1
            ? '<button class="button primary" type="button" data-action="setup-next">Continue</button>'
            : setupInstallAction()}
        </div>
      </section>
      ${feedback()}
    </div>`;
}

function setupStepContent(title) {
  if (state.setupStep === 0) {
    return `<div class="setup-step"><h2>${escapeHtml(title)}</h2><p>${runtimeSummary()}</p>${skillDiscoverySummary()}<p class="quiet">Discovery facts come only from this local service. No project paths or configuration contents are shown here.</p></div>`;
  }
  if (state.setupStep === 1) {
    const hosts = detectedHostChoices();
    return `<div class="setup-step"><h2>${escapeHtml(title)}</h2><p>Default to a private project installation. Global installation requires a separate opt-in immediately before writing.</p><div class="choice-list">
      ${scopeChoice('project', 'this project', 'repository-specific runbooks and memory')}
      ${scopeChoice('global', 'all projects', 'personal provider knowledge and safety defaults')}
    </div><div class="host-choices"><p class="status-line">detected local hosts</p>${hosts.length === 0
      ? '<p class="quiet">No supported local host was detected. Install planning is unavailable until one is detected.</p>'
      : hosts.map(hostChoice).join('')}</div><p class="quiet">sharing · private by default</p></div>`;
  }
  return setupInstallReview(title);
}

function scopeChoice(value, title, detail) {
  const selected = state.setupScope === value;
  return `<button class="scope-choice ${selected ? 'selected' : ''}" type="button" data-action="setup-scope" data-scope="${value}" aria-pressed="${selected}"><strong>${escapeHtml(title)} ▸</strong><span>${escapeHtml(detail)}</span></button>`;
}

function skillDiscoverySummary() {
  const skill = state.skill;
  if (skill === null) {
    return '<p class="quiet">Checking local installation discovery…</p>';
  }
  const detected = detectedHostChoices().map(hostLabel);
  const hosts = detected.length === 0 ? 'no supported host detected' : `${detected.join(' and ')} detected`;
  return `<ul class="review-list"><li>repository · ${skill.repository.detected ? 'detected' : 'not detected'}</li><li>hosts · ${escapeHtml(hosts)}</li><li>local identity · ${skill.identity.available ? 'available' : 'unavailable'}</li><li>policy · ${skill.policy.active ? 'active' : 'inactive'}</li></ul>`;
}

function detectedHostChoices() {
  return ['claude', 'codex'].filter((host) => state.skill?.hosts?.[host]?.detected === true);
}

function hostChoice(host) {
  const checked = selectedSetupHosts().includes(host);
  return `<label class="host-choice"><input type="checkbox" data-action="setup-host" data-host="${host}"${checked ? ' checked' : ''}><span><strong>${escapeHtml(hostLabel(host))}</strong><small>${escapeHtml(nativeInvocationHint(host))}</small></span></label>`;
}

function hostLabel(host) {
  return host === 'claude' ? 'Claude Code' : 'Codex';
}

function nativeInvocationHint(host) {
  return host === 'claude'
    ? 'Uses Claude Code’s native local skill invocation.'
    : 'Uses Codex’s native local skill invocation.';
}

function setupInstallReview(title) {
  const plan = state.installPlan;
  if (plan === null) {
    return `<div class="setup-step"><h2>${escapeHtml(title)}</h2><p>Request an opaque local plan before anything is written.</p><ul class="review-list"><li>scope · ${escapeHtml(state.setupScope)}</li><li>sharing · ${escapeHtml(state.setupSharing)}</li><li>hosts · ${escapeHtml(selectedSetupHosts().map(hostLabel).join(', ') || 'none selected')}</li><li>credential values rendered · 0</li></ul></div>`;
  }
  if (millisecondsUntil(plan.expiresAt) <= 0) {
    return `<div class="setup-step"><h2>${escapeHtml(title)}</h2><p class="quiet">The local install plan expired. Request a new plan before writing.</p></div>`;
  }
  const globalOptIn = plan.requiresGlobalOptIn
    ? `<label class="check"><input type="checkbox" data-action="setup-global-opt-in"${state.setupGlobalOptIn ? ' checked' : ''}> I explicitly opt in to writing this global local skill.</label>`
    : '';
  const installed = state.installResult === null
    ? ''
    : '<p class="quiet">Local files were installed. Confirming server-owned setup state…</p>';
  return `<div class="setup-step install-plan"><h2>${escapeHtml(title)}</h2><p>Only these relative destinations will be written:</p><ul class="install-destinations">${plan.destinations.map((destination) => `<li><span>${escapeHtml(destination.scope)}</span><code>${escapeHtml(destination.destination)}</code></li>`).join('')}</ul>${globalOptIn}${installed}</div>`;
}

function setupInstallAction() {
  const plan = state.installPlan;
  if (plan === null || millisecondsUntil(plan.expiresAt) <= 0) {
    return `<button class="button primary" type="button" data-action="create-install-plan"${selectedSetupHosts().length === 0 ? ' disabled' : ''}>Prepare install plan</button>`;
  }
  const disabled = plan.requiresGlobalOptIn && !state.setupGlobalOptIn;
  return `<button class="button primary" type="button" data-action="install-skill"${disabled ? ' disabled' : ''}>Install selected skill</button>`;
}

function homeView() {
  const attention = attentionItems();
  const sections = HOME_SECTIONS.slice(1).map((item) => sectionView(item)).join('');
  return `
    <div class="shell home-shell">
      ${identityStrip()}
      <header class="home-header">
        <div><p class="eyebrow">atomical keyguard</p><h1>local control</h1></div>
        <button class="button secondary" type="button" data-action="refresh">Refresh</button>
      </header>
      ${attention.length === 0 ? '<p class="all-clear">all clear · no local decision needs attention</p>' : sectionView(HOME_SECTIONS[0], attention)}
      ${sections}
      ${feedback()}
      <footer class="footer-note">loopback only · credential values rendered 0</footer>
    </div>`;
}

function identityStrip() {
  const server = state.status?.server;
  const host = stringValue(server?.host, 'local runtime');
  const port = Number.isInteger(server?.port) ? `:${server.port}` : '';
  const runtime = stringValue(state.status?.state, 'checking');
  const localRuntime = `${host}${port} local control`;
  const fingerprint = stringValue(state.status?.identity?.fingerprint, '');
  const identity = fingerprint.length > 0 ? fingerprint : localRuntime;
  return `<aside class="identity-strip" aria-label="Current local identity and service status"><span>whoami ▸ ${escapeHtml(identity)}</span><span>runtime ▸ ${escapeHtml(runtime)}</span><span>memory · continuous ▸ local review</span></aside>`;
}

function runtimeSummary() {
  const server = state.status?.server;
  const host = stringValue(server?.host, 'local runtime');
  const port = Number.isInteger(server?.port) ? `:${server.port}` : '';
  const runtime = stringValue(state.status?.state, 'checking');
  return escapeHtml(`Local runtime ${host}${port} is ${runtime}.`);
}

function attentionItems() {
  const items = [];
  if (state.deposit !== null) {
    items.push({ kind: 'deposit' });
  }
  for (const approval of state.approvals.filter((item) => item.status === 'pending')) {
    items.push({ approval, kind: 'approval' });
  }
  return items;
}

function sectionView(section, suppliedItems = undefined) {
  const content = suppliedItems ?? sectionContent(section.section);
  const disclosureKey = `section-${section.section}`;
  const open = disclosureIsOpen(disclosureKey, section.section === 'attention');
  return `<section class="home-section" data-section="${section.section}"><details data-disclosure-key="${disclosureKey}"${open ? ' open' : ''}><summary aria-expanded="${open}"><span>${escapeHtml(section.title)}</span><span class="count">${sectionCount(section.section, content)}</span></summary><div class="section-body">${Array.isArray(content) ? content.map(attentionItem).join('') : content}</div></details></section>`;
}

function sectionCount(name, content) {
  if (Array.isArray(content)) {
    return String(content.length);
  }
  if (name === 'approvals') return String(state.approvals.length);
  if (name === 'credentials') return String(state.credentials.length);
  if (name === 'actions') return String(state.actions.length);
  if (name === 'activity') return String(state.activity.length);
  if (name === 'memory') return String(state.memory.length);
  return '0';
}

function disclosureIsOpen(key, defaultOpen) {
  return state.disclosures.has(key) ? state.disclosures.get(key) : defaultOpen;
}

function attentionItem(item) {
  if (item.kind === 'deposit') {
    return depositCard();
  }
  return approvalCard(item.approval, true);
}

function sectionContent(name) {
  if (name === 'approvals') {
    return state.approvals.length === 0 ? emptyState('No approval is waiting.') : state.approvals.map((approval) => approvalCard(approval, false)).join('');
  }
  if (name === 'credentials') {
    return credentialsContent();
  }
  if (name === 'actions') {
    return integrationsContent();
  }
  if (name === 'activity') {
    return state.activity.length === 0 ? emptyState('Meaningful milestones will appear here.') : state.activity.map(activityRow).join('');
  }
  if (name === 'memory') {
    return state.memory.length === 0 ? emptyState('Verified memory suggestions will appear here.') : state.memory.map(memoryCard).join('');
  }
  return '';
}

function depositCard() {
  if (state.deposit === null || millisecondsUntil(state.deposit.expiresAt) <= 0) {
    return '';
  }
  const remaining = formatRemaining(millisecondsUntil(state.deposit.expiresAt));
  return `<article class="attention-card"><p class="status-line">deposit a credential</p><h2>${escapeHtml(state.deposit.label)}</h2><p>one-time · scoped · expires ${escapeHtml(remaining)}</p><p class="quiet">Waiting for deposit…</p><div class="actions"><a class="button primary" data-deposit-link href="${escapeAttribute(state.deposit.depositUrl)}" target="_blank" rel="noreferrer">Open secure handoff</a><button class="button secondary" type="button" data-action="clear-deposit">Clear from page</button></div></article>`;
}

function approvalCard(approval, attention) {
  const project = approval.project;
  const title = stringValue(approval.action, 'signed action').replaceAll('_', ' ');
  const id = stringValue(approval.id, 'approval');
  const dirtyId = `dirty-${cssIdentifier(id)}`;
  const disclosureKey = `approval-${id}-technical`;
  const technicalOpen = disclosureIsOpen(disclosureKey, false);
  const execution = state.execution.get(id);
  const isPending = approval.status === 'pending';
  const disabled = execution?.stage === 'preparing' ? ' disabled' : '';
  const scopeAction = canApproveExactScope(approval)
    ? `<button class="button secondary" type="button" data-action="approve-scope" data-id="${escapeAttribute(id)}"${disabled}>Approve this exact scope</button>`
    : '';
  const actions = isPending
    ? `<div class="actions"><button class="button primary" type="button" data-action="approve" data-id="${escapeAttribute(id)}"${disabled}>Approve once</button>${scopeAction}<button class="button secondary" type="button" data-action="deny" data-id="${escapeAttribute(id)}"${disabled}>Deny</button></div>`
    : '';
  const dirtyAcknowledgement = isPending && approval.requiresDirtyTreeAcknowledgement === true
    ? `<label class="check"><input id="${escapeAttribute(dirtyId)}" type="checkbox"> I understand this action uses a dirty tree once.</label>`
    : '';
  return `<article class="approval-card ${attention ? 'attention-card' : ''}"${execution?.stage === 'preparing' ? ' aria-busy="true"' : ''}><p class="status-line">${escapeHtml(stringValue(approval.status, 'pending'))}</p><h2>${escapeHtml(title)}</h2><dl class="facts"><div><dt>credential</dt><dd>${escapeHtml(stringValue(approval.credentialLabel, 'unavailable'))}</dd></div><div><dt>commit</dt><dd class="mono">${escapeHtml(shortValue(stringValue(project?.commit, 'unavailable')))}</dd></div><div><dt>expires</dt><dd>${escapeHtml(formatTime(approval.expiresAt))}</dd></div></dl>${executionStatusView(execution)}${dirtyAcknowledgement}<details class="technical" data-disclosure-key="${escapeAttribute(disclosureKey)}"${technicalOpen ? ' open' : ''}><summary aria-expanded="${technicalOpen}">technical envelope</summary><p class="mono">request ▸ ${escapeHtml(id)}</p></details>${actions}</article>`;
}

function executionStatusView(execution) {
  if (execution === undefined) {
    return '';
  }
  if (execution.stage === 'preparing') {
    return '<p class="execution-status" data-execution-status="preparing">preparing local execution…</p>';
  }
  if (!isExecutionProjection(execution)) {
    return '';
  }
  if (execution.receipt === undefined) {
    return `<p class="execution-status" data-execution-status="${escapeAttribute(execution.status)}">${escapeHtml(executionStatusLabel(execution.status))}</p>`;
  }
  return `<p class="execution-status" data-execution-status="${escapeAttribute(execution.status)}">receipt · ${escapeHtml(executionStatusLabel(execution.status))} · provider ${escapeHtml(execution.receipt.providerStatus)} · verification ${escapeHtml(execution.receipt.verificationStatus)}</p>`;
}

function executionMessage(execution) {
  return `Execution receipt ${executionStatusLabel(execution.status)}.`;
}

function executionStatusLabel(status) {
  const labels = {
    approval_not_granted: 'not granted',
    preparation_failed: 'needs attention before execution',
    provider_failed: 'provider did not complete',
    verification_failed: 'needs verification attention',
    verified: 'verified',
  };
  return labels[status] ?? 'requires local review';
}

function credentialsContent() {
  const rows = state.credentials.map(credentialCard).join('');
  const hasActiveCredential = state.credentials.some((credential) => credential.status === 'active');
  if (rows.length > 0) {
    return rows;
  }
  return hasActiveCredential
    ? emptyState('No active credential is available for an installed integration.')
    : emptyState('No sealed credentials yet.');
}

function integrationsContent() {
  if (state.actions.length === 0) {
    return emptyState('No integrations enabled. Keyguard will not create a credential handoff or run an external action until a reviewed integration is installed.');
  }
  return state.actions.map(integrationCard).join('');
}

function integrationCard(action) {
  const credential = action.credential;
  const active = hasActiveCredentialFor(credential.label);
  const parameterNames = Object.keys(action.params);
  const parameters = parameterNames.length === 0 ? 'no parameters' : parameterNames.join(', ');
  const handoff = active
    ? '<p class="quiet">sealed credential ready</p>'
    : `<button class="button primary" type="button" data-action="create-deposit" data-label="${escapeAttribute(credential.label)}" data-provider="${escapeAttribute(credential.provider)}">Create deposit link</button>`;
  return `<article class="integration-card"><p class="status-line">installed · approval required</p><h2>${escapeHtml(actionDisplayName(action.name))}</h2><dl class="facts"><div><dt>credential</dt><dd>${escapeHtml(credential.label)}</dd></div><div><dt>provider</dt><dd>${escapeHtml(credential.provider)}</dd></div><div><dt>parameters</dt><dd>${escapeHtml(parameters)}</dd></div><div><dt>version</dt><dd>${escapeHtml(String(action.version))}</dd></div></dl><div class="actions">${handoff}</div></article>`;
}

function hasActiveCredentialFor(label) {
  return state.credentials.some((credential) => (
    credential.label === label && credential.status === 'active'
  ));
}

function installedCredentialBinding(label, provider) {
  if (typeof label !== 'string' || typeof provider !== 'string') {
    return null;
  }
  return state.actions.find((action) => (
    action.credential.label === label && action.credential.provider === provider
  ))?.credential ?? null;
}

function installedCredentialBindingForLabel(label) {
  if (typeof label !== 'string') {
    return null;
  }
  return state.actions.find((action) => action.credential.label === label)?.credential ?? null;
}

function actionDisplayName(name) {
  return name.replaceAll('_', ' ');
}

function credentialCard(credential) {
  const label = stringValue(credential.label, 'credential');
  const status = stringValue(credential.status, 'unknown');
  const instance = stringValue(credential.instanceId, 'unavailable');
  const disclosureKey = `credential-${label}-technical`;
  const revokeDisclosureKey = `credential-${label}-revoke`;
  const technicalOpen = disclosureIsOpen(disclosureKey, false);
  const revokeOpen = disclosureIsOpen(revokeDisclosureKey, false);
  const binding = installedCredentialBindingForLabel(label);
  const revokeConfirmation = status === 'active'
    ? `<details class="revoke-confirmation" data-disclosure-key="${escapeAttribute(revokeDisclosureKey)}"${revokeOpen ? ' open' : ''}><summary aria-expanded="${revokeOpen}">Revoke capability</summary><form class="danger-zone" data-action="revoke-credential" data-label="${escapeAttribute(label)}"><label for="revoke-${escapeAttribute(cssIdentifier(label))}">Type REVOKE to stop this sealed credential from being used</label><div class="inline-form"><input id="revoke-${escapeAttribute(cssIdentifier(label))}" name="confirmation" autocomplete="off" inputmode="text"><button class="button danger" type="submit">Confirm revocation</button></div></form></details>`
    : '';
  const rotation = binding === null
    ? ''
    : `<div class="actions"><button class="button secondary" type="button" data-action="create-deposit" data-label="${escapeAttribute(binding.label)}" data-provider="${escapeAttribute(binding.provider)}">Rotate credential</button></div>`;
  return `<article class="credential-card"><div class="row-heading"><div><p class="status-line">sealed · ${escapeHtml(status)}</p><h2>${escapeHtml(label)}</h2></div><span class="status-badge">${escapeHtml(status)}</span></div>${revokeConfirmation}<details class="technical" data-disclosure-key="${escapeAttribute(disclosureKey)}"${technicalOpen ? ' open' : ''}><summary aria-expanded="${technicalOpen}">credential details</summary><dl class="facts"><div><dt>storage</dt><dd>sealed local vault</dd></div><div><dt>instance</dt><dd class="mono">${escapeHtml(shortValue(instance))}</dd></div><div><dt>last change</dt><dd>${escapeHtml(formatTime(credential.updatedAt))}</dd></div></dl><form class="danger-zone" data-action="delete-credential" data-label="${escapeAttribute(label)}"><label for="delete-${escapeAttribute(cssIdentifier(label))}">Type DELETE to permanently remove this credential</label><div class="inline-form"><input id="delete-${escapeAttribute(cssIdentifier(label))}" name="confirmation" autocomplete="off" inputmode="text"><button class="button danger" type="submit">Remove sealed credential</button></div></form></details>${rotation}</article>`;
}

function activityRow(activity) {
  const id = stringValue(activity.id, 'activity');
  const disclosureKey = `activity-${id}-technical`;
  const technicalOpen = disclosureIsOpen(disclosureKey, false);
  return `<article class="ledger-row"><time>${escapeHtml(formatTime(activity.timestamp))}</time><span>${escapeHtml(stringValue(activity.stage, 'recorded'))}</span><span>${escapeHtml(stringValue(activity.action, 'local action').replaceAll('_', ' '))}</span><details class="technical" data-disclosure-key="${escapeAttribute(disclosureKey)}"${technicalOpen ? ' open' : ''}><summary aria-expanded="${technicalOpen}">details</summary><p class="mono">receipt ▸ ${escapeHtml(stringValue(activity.receiptId, 'pending'))}</p></details></article>`;
}

function memoryCard(memory) {
  const status = stringValue(memory.status, 'proposed');
  const id = stringValue(memory.id, 'memory');
  const disclosureKey = `memory-${id}-technical`;
  const technicalOpen = disclosureIsOpen(disclosureKey, false);
  const actions = status === 'candidate'
    ? `<div class="actions"><button class="button primary" type="button" data-action="save-memory" data-id="${escapeAttribute(id)}">Save</button><button class="button secondary" type="button" data-action="dismiss-memory" data-id="${escapeAttribute(id)}">Dismiss</button></div>`
    : '';
  return `<article class="memory-card"><p class="status-line">${escapeHtml(status)}</p><p>${escapeHtml(stringValue(memory.text, 'Local memory record.'))}</p><details class="technical" data-disclosure-key="${escapeAttribute(disclosureKey)}"${technicalOpen ? ' open' : ''}><summary aria-expanded="${technicalOpen}">provenance</summary><p class="mono">source ▸ ${escapeHtml(stringValue(memory.sourceReceiptId, 'local review'))}</p><p>scope ▸ project</p></details>${actions}</article>`;
}

function feedback() {
  const message = state.error ?? state.message;
  if (message === null) {
    return '';
  }
  return `<p class="feedback ${state.error === null ? 'success' : 'error'}">${escapeHtml(message)}</p>`;
}

function emptyState(message) {
  return `<p class="empty-state">${escapeHtml(message)}</p>`;
}

function csrfToken() {
  const entry = document.cookie.split(';').map((value) => value.trim()).find((value) => value.startsWith('keyguard_csrf='));
  return entry === undefined ? '' : entry.slice('keyguard_csrf='.length);
}

function setupIsComplete() {
  return setupCompletionFromStatus(state.status) === true;
}

function setupCompletionFromStatus(status) {
  const complete = status?.setup?.complete;
  return typeof complete === 'boolean' ? complete : undefined;
}

function selectedSetupHosts() {
  return Array.isArray(state.setupHosts) ? [...state.setupHosts] : [];
}

function synchronizeSetupHosts(skill) {
  const detected = ['claude', 'codex'].filter((host) => skill.hosts[host].detected);
  const previous = selectedSetupHosts();
  const next = state.skill === null
    ? detected.filter((host) => skill.hosts[host].preselected)
    : previous.filter((host) => detected.includes(host));
  if (!sameStringArray(previous, next)) {
    state.setupHosts = next;
    clearInstallPlan();
  }
}

function updateSetupHost(host, checked) {
  if (!detectedHostChoices().includes(host)) {
    return;
  }
  const previous = selectedSetupHosts();
  const next = checked
    ? [...new Set([...previous, host])].sort()
    : previous.filter((value) => value !== host);
  if (!sameStringArray(previous, next)) {
    state.setupHosts = next;
    clearInstallPlan();
  }
}

function clearInstallPlan() {
  state.installPlan = null;
  state.installResult = null;
  state.setupGlobalOptIn = false;
}

function matchesInstallSelection(plan) {
  return plan.scope === state.setupScope
    && plan.sharing === state.setupSharing
    && sameStringArray(plan.hosts, selectedSetupHosts());
}

function matchesInstallPlan(result, plan) {
  return result.scope === plan.scope
    && result.sharing === plan.sharing
    && sameStringArray(result.hosts, plan.hosts)
    && result.destinations.length === plan.destinations.length
    && result.destinations.every((destination, index) => (
      destination.scope === plan.destinations[index].scope
      && destination.destination === plan.destinations[index].destination
    ));
}

function sameStringArray(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function isSkillStatusProjection(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const keys = ['atomicCli', 'hosts', 'identity', 'mcp', 'policy', 'repository'];
  if (Object.keys(value).length !== keys.length || keys.some((key) => !Object.hasOwn(value, key))) {
    return false;
  }
  if (
    value.atomicCli === null || typeof value.atomicCli !== 'object' || value.atomicCli.detected === undefined
    || value.identity === null || typeof value.identity !== 'object' || value.identity.available === undefined
    || value.mcp === null || typeof value.mcp !== 'object' || value.mcp.registered === undefined
    || value.policy === null || typeof value.policy !== 'object'
    || value.repository === null || typeof value.repository !== 'object' || value.repository.detected === undefined
    || value.hosts === null || typeof value.hosts !== 'object'
  ) {
    return false;
  }
  if (
    typeof value.atomicCli.detected !== 'boolean'
    || typeof value.identity.available !== 'boolean'
    || typeof value.mcp.registered !== 'boolean'
    || typeof value.policy.active !== 'boolean'
    || (value.policy.version !== null && (!Number.isInteger(value.policy.version) || value.policy.version < 0))
    || typeof value.repository.detected !== 'boolean'
  ) {
    return false;
  }
  return ['claude', 'codex'].every((host) => {
    const details = value.hosts[host];
    return details !== null
      && typeof details === 'object'
      && Object.keys(details).length === 4
      && ['detected', 'globalSkill', 'preselected', 'projectSkill'].every((key) => typeof details[key] === 'boolean');
  });
}

function freezeSkillStatus(value) {
  return Object.freeze({
    atomicCli: Object.freeze({ detected: value.atomicCli.detected }),
    hosts: Object.freeze({
      claude: Object.freeze({ ...value.hosts.claude }),
      codex: Object.freeze({ ...value.hosts.codex }),
    }),
    identity: Object.freeze({ available: value.identity.available }),
    mcp: Object.freeze({ registered: value.mcp.registered }),
    policy: Object.freeze({ active: value.policy.active, version: value.policy.version }),
    repository: Object.freeze({ detected: value.repository.detected }),
  });
}

function canApproveExactScope(approval) {
  return approval !== null
    && typeof approval === 'object'
    && approval.status === 'pending'
    && approval.requiresDirtyTreeAcknowledgement !== true
    && approval.project !== null
    && typeof approval.project === 'object'
    && approval.project.dirty === false;
}

function isInstallPlanProjection(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const keys = [
    'destinations',
    'expiresAt',
    'hosts',
    'planId',
    'requiresConfirmation',
    'requiresGlobalOptIn',
    'scope',
    'sharing',
    'status',
  ];
  if (Object.keys(value).length !== keys.length || keys.some((key) => !Object.hasOwn(value, key))) {
    return false;
  }
  if (
    value.status !== 'planned'
    || !['project', 'global', 'both'].includes(value.scope)
    || !['private', 'shared'].includes(value.sharing)
    || value.requiresConfirmation !== true
    || typeof value.requiresGlobalOptIn !== 'boolean'
    || value.requiresGlobalOptIn !== (value.scope === 'global' || value.scope === 'both')
    || typeof value.planId !== 'string'
    || !/^install_[A-Za-z0-9_-]{8,128}$/u.test(value.planId)
    || typeof value.expiresAt !== 'string'
    || !Array.isArray(value.hosts)
    || value.hosts.length === 0
    || value.hosts.some((host) => !['claude', 'codex'].includes(host))
    || new Set(value.hosts).size !== value.hosts.length
    || !Array.isArray(value.destinations)
    || value.destinations.length === 0
  ) {
    return false;
  }
  const expiresAt = new Date(value.expiresAt);
  if (
    !Number.isFinite(expiresAt.valueOf())
    || expiresAt.valueOf() <= Date.now()
    || expiresAt.toISOString() !== value.expiresAt
  ) {
    return false;
  }
  return value.destinations.every((destination) => {
    if (destination === null || typeof destination !== 'object' || Array.isArray(destination)) {
      return false;
    }
    if (
      Object.keys(destination).length !== 2
      || !Object.hasOwn(destination, 'destination')
      || !Object.hasOwn(destination, 'scope')
      || !['project', 'global'].includes(destination.scope)
      || typeof destination.destination !== 'string'
      || destination.destination.length === 0
      || destination.destination.startsWith('/')
      || destination.destination.includes('\\')
      || /[\u0000-\u001f]/u.test(destination.destination)
    ) {
      return false;
    }
    return destination.destination.split('/').every((segment) => segment !== '' && segment !== '.' && segment !== '..');
  });
}

function isInstallResultProjection(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const keys = ['destinations', 'hosts', 'scope', 'sharing', 'status'];
  if (Object.keys(value).length !== keys.length || keys.some((key) => !Object.hasOwn(value, key))) {
    return false;
  }
  if (
    value.status !== 'installed'
    || !['project', 'global', 'both'].includes(value.scope)
    || !['private', 'shared'].includes(value.sharing)
    || !Array.isArray(value.hosts)
    || value.hosts.length === 0
    || value.hosts.some((host) => !['claude', 'codex'].includes(host))
    || new Set(value.hosts).size !== value.hosts.length
    || !Array.isArray(value.destinations)
    || value.destinations.length === 0
  ) {
    return false;
  }
  return value.destinations.every((destination) => (
    destination !== null
    && typeof destination === 'object'
    && !Array.isArray(destination)
    && Object.keys(destination).length === 3
    && Object.hasOwn(destination, 'destination')
    && Object.hasOwn(destination, 'scope')
    && Object.hasOwn(destination, 'status')
    && ['project', 'global'].includes(destination.scope)
    && ['written', 'updated', 'unchanged', 'mode_repaired'].includes(destination.status)
    && typeof destination.destination === 'string'
    && destination.destination.length > 0
    && !destination.destination.startsWith('/')
    && !destination.destination.includes('\\')
    && !/[\u0000-\u001f]/u.test(destination.destination)
    && destination.destination.split('/').every((segment) => segment !== '' && segment !== '.' && segment !== '..')
  ));
}

function freezeInstallPlan(value) {
  return Object.freeze({
    destinations: Object.freeze(value.destinations.map((destination) => Object.freeze({ ...destination }))),
    expiresAt: value.expiresAt,
    hosts: Object.freeze([...value.hosts]),
    planId: value.planId,
    requiresConfirmation: true,
    requiresGlobalOptIn: value.requiresGlobalOptIn,
    scope: value.scope,
    sharing: value.sharing,
    status: 'planned',
  });
}

function freezeInstallResult(value) {
  return Object.freeze({
    destinations: Object.freeze(value.destinations.map((destination) => Object.freeze({ ...destination }))),
    hosts: Object.freeze([...value.hosts]),
    scope: value.scope,
    sharing: value.sharing,
    status: 'installed',
  });
}

function isExecutionProjection(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  if (!Object.hasOwn(value, 'status')) {
    return false;
  }
  if (!['approval_not_granted', 'preparation_failed', 'provider_failed', 'verification_failed', 'verified'].includes(value.status)) {
    return false;
  }
  if (value.status === 'approval_not_granted') {
    return Object.keys(value).length === 1;
  }
  if (Object.keys(value).length !== 2 || !Object.hasOwn(value, 'receipt')) {
    return false;
  }
  const receipt = value.receipt;
  return receipt !== null
    && typeof receipt === 'object'
    && !Array.isArray(receipt)
    && Object.keys(receipt).length === 4
    && typeof receipt.id === 'string'
    && receipt.id.length > 0
    && typeof receipt.action === 'string'
    && receipt.action.length > 0
    && ['succeeded', 'failed', 'not_started'].includes(receipt.providerStatus)
    && ['verified', 'failed', 'not_run'].includes(receipt.verificationStatus);
}

function freezeExecution(value) {
  if (value.receipt === undefined) {
    return Object.freeze({ status: value.status });
  }
  return Object.freeze({
    receipt: Object.freeze({
      action: value.receipt.action,
      id: value.receipt.id,
      providerStatus: value.receipt.providerStatus,
      verificationStatus: value.receipt.verificationStatus,
    }),
    status: value.status,
  });
}

function isRevokedCredentialProjection(value, expectedLabel) {
  if (
    value === null
    || typeof value !== 'object'
    || Array.isArray(value)
    || Object.keys(value).length !== 1
    || !Object.hasOwn(value, 'credential')
    || typeof expectedLabel !== 'string'
    || expectedLabel.length === 0
    || expectedLabel.length > 128
    || expectedLabel !== expectedLabel.trim()
    || /[\u0000-\u001f]/u.test(expectedLabel)
  ) {
    return false;
  }
  const credential = value.credential;
  if (
    credential === null
    || typeof credential !== 'object'
    || Array.isArray(credential)
    || Object.keys(credential).length !== 5
    || !['createdAt', 'instanceId', 'label', 'status', 'updatedAt'].every((key) => Object.hasOwn(credential, key))
    || credential.label !== expectedLabel
    || credential.status !== 'revoked'
    || typeof credential.instanceId !== 'string'
    || !/^[A-Za-z0-9_-]{32}$/u.test(credential.instanceId)
    || typeof credential.createdAt !== 'string'
    || typeof credential.updatedAt !== 'string'
  ) {
    return false;
  }
  const createdAt = new Date(credential.createdAt);
  const updatedAt = new Date(credential.updatedAt);
  return Number.isFinite(createdAt.valueOf())
    && createdAt.toISOString() === credential.createdAt
    && Number.isFinite(updatedAt.valueOf())
    && updatedAt.toISOString() === credential.updatedAt;
}

function isPendingDeposit(value, now = Date.now()) {
  if (
    value === null
    || typeof value !== 'object'
    || typeof value.depositUrl !== 'string'
    || typeof value.expiresAt !== 'string'
    || typeof value.label !== 'string'
    || value.status !== 'pending'
  ) {
    return false;
  }

  const expiresAt = new Date(value.expiresAt);
  const expiresAtMilliseconds = expiresAt.valueOf();
  if (
    !Number.isFinite(expiresAtMilliseconds)
    || !(expiresAtMilliseconds > now)
    || expiresAt.toISOString() !== value.expiresAt
  ) {
    return false;
  }

  try {
    const parsed = new URL(value.depositUrl);
    return parsed.protocol === 'https:'
      && parsed.username.length === 0
      && parsed.password.length === 0;
  } catch {
    return false;
  }
}

class ApiRequestError extends Error {
  constructor(status) {
    super('Local request failed.');
    this.status = status;
  }
}

function arrayValue(value) {
  return Array.isArray(value) ? value : [];
}

function actionArray(value) {
  if (!Array.isArray(value) || value.length > 64 || !value.every(isActionProjection)) {
    throw new Error('Installed action list was unavailable.');
  }
  return Object.freeze(value.map(freezeAction));
}

function isActionProjection(value) {
  if (!isPlainObject(value)) {
    return false;
  }
  const keys = ['approval', 'credential', 'name', 'params', 'version'];
  if (Object.keys(value).length !== keys.length || !keys.every((key) => Object.hasOwn(value, key))) {
    return false;
  }
  const approval = ownDataValue(value, 'approval');
  const credential = ownDataValue(value, 'credential');
  const name = ownDataValue(value, 'name');
  const params = ownDataValue(value, 'params');
  const version = ownDataValue(value, 'version');
  return approval === 'always'
    && typeof name === 'string'
    && /^[a-z][a-z0-9_]{2,127}$/u.test(name)
    && Number.isInteger(version)
    && version >= 1
    && version <= 1_000_000
    && isCredentialBindingProjection(credential)
    && isBoundedJsonObject(params);
}

function isCredentialBindingProjection(value) {
  if (!isPlainObject(value) || Object.keys(value).length !== 2) {
    return false;
  }
  const label = ownDataValue(value, 'label');
  const provider = ownDataValue(value, 'provider');
  return typeof label === 'string'
    && label.length > 0
    && label.length <= 128
    && label === label.trim()
    && !/[\u0000-\u001f]/u.test(label)
    && typeof provider === 'string'
    && /^[a-z0-9][a-z0-9-]{0,63}$/u.test(provider);
}

function isBoundedJsonObject(value) {
  return isPlainObject(value) && isBoundedJson(value, { keys: 0 }, 0);
}

function isBoundedJson(value, state, depth) {
  if (depth > 8) {
    return false;
  }
  if (value === null || typeof value === 'boolean') {
    return true;
  }
  if (typeof value === 'number') {
    return Number.isFinite(value);
  }
  if (typeof value === 'string') {
    return value.length <= 1024;
  }
  if (Array.isArray(value)) {
    return value.length <= 64
      && Object.getOwnPropertySymbols(value).length === 0
      && value.every((item, index) => Object.hasOwn(value, index) && isBoundedJson(item, state, depth + 1));
  }
  if (!isPlainObject(value) || Object.getOwnPropertySymbols(value).length > 0) {
    return false;
  }
  const keys = Object.keys(value);
  if (keys.length > 64 || state.keys + keys.length > 64) {
    return false;
  }
  state.keys += keys.length;
  return keys.every((key) => {
    const item = ownDataValue(value, key);
    return key.length > 0
      && key.length <= 128
      && !/[\u0000-\u001f]/u.test(key)
      && item !== undefined
      && isBoundedJson(item, state, depth + 1);
  });
}

function freezeAction(value) {
  return Object.freeze({
    approval: value.approval,
    credential: Object.freeze({
      label: value.credential.label,
      provider: value.credential.provider,
    }),
    name: value.name,
    params: freezeJson(value.params),
    version: value.version,
  });
}

function freezeJson(value) {
  if (value === null || typeof value !== 'object') {
    return value;
  }
  if (Array.isArray(value)) {
    return Object.freeze(value.map(freezeJson));
  }
  const result = Object.create(null);
  for (const key of Object.keys(value)) {
    Object.defineProperty(result, key, {
      configurable: false,
      enumerable: true,
      value: freezeJson(value[key]),
      writable: false,
    });
  }
  return Object.freeze(result);
}

function ownDataValue(value, key) {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  return descriptor !== undefined && Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined;
}

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function stringValue(value, fallback) {
  return typeof value === 'string' && value.length > 0 ? value : fallback;
}

function millisecondsUntil(timestamp) {
  const value = Date.parse(timestamp);
  return Number.isFinite(value) ? Math.max(0, value - Date.now()) : 0;
}

function formatRemaining(milliseconds) {
  const minutes = Math.floor(milliseconds / 60_000);
  const seconds = Math.floor((milliseconds % 60_000) / 1_000);
  return `${minutes}m ${String(seconds).padStart(2, '0')}s`;
}

function formatTime(timestamp) {
  const value = Date.parse(timestamp);
  if (!Number.isFinite(value)) {
    return 'local time unavailable';
  }
  return new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit' }).format(value);
}

function shortValue(value) {
  return value.length > 18 ? `${value.slice(0, 10)}…${value.slice(-6)}` : value;
}

function cssIdentifier(value) {
  return String(value).replaceAll(/[^A-Za-z0-9_-]/gu, '-');
}

function escapeHtml(value) {
  return String(value).replaceAll(/[&<>'"]/gu, (character) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    "'": '&#39;',
    '"': '&quot;',
  })[character]);
}

function escapeAttribute(value) {
  return escapeHtml(value);
}
