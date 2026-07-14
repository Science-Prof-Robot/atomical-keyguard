import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import {
  mkdir,
  mkdtemp,
  realpath,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { sha256 } from '../src/core/canonical.mjs';
import { LocalIdentity } from '../src/identity/local-identity.mjs';
import { createKeyguardApp } from '../src/bootstrap.mjs';
import { createActionRegistry } from '../src/policy/action-registry.mjs';
import { PolicyEngine } from '../src/policy/policy-engine.mjs';
import { CLOUDFLARE_PAGES_ACTION as ACTION_NAME, createCloudflarePagesIntegration } from '../src/providers/cloudflare-pages.mjs';
import { GitInspector } from '../src/project/git-inspector.mjs';
import { ApprovalService } from '../src/services/approvals.mjs';
import { SealedVault } from '../src/storage/sealed-vault.mjs';
import { withTemporaryDataDirectory } from './helpers.mjs';

const execFileAsync = promisify(execFile);
const INITIAL_TIME = '2026-07-14T12:00:00.000Z';

test('registry is empty by default and installs an explicit reviewed Pages integration', async () => {
  await withTemporaryRepository(async (repositoryRoot) => {
    const emptyRegistry = createActionRegistry({ approvedProjectRoots: [repositoryRoot] });
    const registry = createActionRegistry({
      approvedProjectRoots: [repositoryRoot],
      integrations: [createCloudflarePagesIntegration()],
    });
    const action = registry.get(ACTION_NAME);

    assert.deepEqual(emptyRegistry.list(), []);
    assert.equal(emptyRegistry.get(ACTION_NAME), undefined);
    assert.deepEqual(registry.list(), [{
      approval: 'always',
      name: ACTION_NAME,
      params: {
        directory: 'relative_path',
        project: 'slug',
      },
      version: 1,
    }]);
    assert.equal(action.name, 'cloudflare_pages_deploy');
    assert.equal(action.version, 1);
    assert.equal(action.credentialLabel, 'cloudflare-api-token');
    assert.deepEqual(action.credential, {
      label: 'cloudflare-api-token',
      provider: 'cloudflare',
    });
    assert.equal(action.approval, 'always');
    assert.deepEqual(action.params, {
      directory: 'relative_path',
      project: 'slug',
    });
    assert.deepEqual(action.approvedProjectRoots, [await realpath(repositoryRoot)]);
    assert.equal(action.approvedProjectRoots.includes('*'), false);
    assert.deepEqual(registry.getCredentialBinding({
      label: 'cloudflare-api-token',
      provider: 'cloudflare',
    }), {
      label: 'cloudflare-api-token',
      provider: 'cloudflare',
    });
    assert.equal(registry.getCredentialBinding({
      label: 'cloudflare-api-token',
      provider: 'attacker',
    }), undefined);
    const sharedCredentialRegistry = createActionRegistry({
      approvedProjectRoots: [repositoryRoot],
      integrations: ['example_publish', 'example_preview'].map((name) => ({
        action: {
          approval: 'always',
          credential: { label: 'example-api-token', provider: 'example' },
          name,
          params: {},
          version: 1,
        },
        async execute() {
          return { status: 'succeeded', stderr: '', stdout: '' };
        },
        async prepare() {
          return { params: {}, target: {} };
        },
      })),
    });
    assert.deepEqual(sharedCredentialRegistry.list().map((item) => item.name), [
      'example_preview',
      'example_publish',
    ]);
    assert.deepEqual(sharedCredentialRegistry.getCredentialBinding({
      label: 'example-api-token',
      provider: 'example',
    }), {
      label: 'example-api-token',
      provider: 'example',
    });
    assert.throws(
      () => createActionRegistry({
        approvedProjectRoots: [repositoryRoot],
        integrations: [
          reviewedIntegration('example_publish', { label: 'shared-token', provider: 'example' }),
          reviewedIntegration('other_publish', { label: 'shared-token', provider: 'other' }),
        ],
      }),
      /credential label.*multiple providers/i,
    );
    assert.doesNotMatch(JSON.stringify(registry.list()), /executable|wrangler|argv/u);
    assert.throws(
      () => createActionRegistry({
        approvedProjectRoots: [repositoryRoot],
        integrations: [createCloudflarePagesIntegration(), createCloudflarePagesIntegration()],
      }),
      /duplicate.*action|duplicate.*credential/i,
    );
    assert.throws(
      () => createActionRegistry({ approvedProjectRoots: ['*'] }),
      /approved project root/i,
    );
    assert.throws(() => {
      action.credentialLabel = 'attacker-token';
    }, /read only|Cannot assign/i);
  });
});

function reviewedIntegration(name, credential) {
  return {
    action: {
      approval: 'always',
      credential,
      name,
      params: {},
      version: 1,
    },
    async execute() {
      return { status: 'succeeded', stderr: '', stdout: '' };
    },
    async prepare() {
      return { params: {}, target: {} };
    },
  };
}

test('the explicit Pages integration validates only existing contained deployment directories and a strict project slug', async () => {
  await withTemporaryRepository(async (repositoryRoot) => {
    const outsideDirectory = await mkdtemp(join(tmpdir(), 'atomical-keyguard-outside-'));
    const escapePath = join(repositoryRoot, 'escape');
    const registry = createActionRegistry({
      approvedProjectRoots: [repositoryRoot],
      integrations: [createCloudflarePagesIntegration()],
    });
    const snapshot = { root: await realpath(repositoryRoot) };

    try {
      await symlink(outsideDirectory, escapePath);
      const validated = await registry.prepare(
        ACTION_NAME,
        { directory: 'dist', project: 'keyguard-site' },
        snapshot,
      );

      assert.deepEqual(validated, {
        params: {
          directory: 'dist',
          project: 'keyguard-site',
        },
        target: {
          directory: await realpath(join(repositoryRoot, 'dist')),
          project: 'keyguard-site',
        },
      });
      await assert.rejects(
        registry.prepare(ACTION_NAME, { directory: '../../secret', project: 'keyguard-site' }, snapshot),
        /relative path/i,
      );
      await assert.rejects(
        registry.prepare(ACTION_NAME, { directory: '/tmp', project: 'keyguard-site' }, snapshot),
        /relative path/i,
      );
      await assert.rejects(
        registry.prepare(ACTION_NAME, { directory: 'escape', project: 'keyguard-site' }, snapshot),
        /inside the project root/i,
      );
      await assert.rejects(
        registry.prepare(ACTION_NAME, { directory: 'missing', project: 'keyguard-site' }, snapshot),
        /does not exist/i,
      );
      await assert.rejects(
        registry.prepare(ACTION_NAME, { directory: 'dist', project: 'Bad Project' }, snapshot),
        /slug/i,
      );
    } finally {
      await rm(outsideDirectory, { force: true, recursive: true });
    }
  });
});

test('denies unknown actions before Git or vault work', async () => {
  await withPolicySystem(async ({ approvals, clock, identity, repositoryRoot }) => {
    let gitInspections = 0;
    let vaultReads = 0;
    const engine = new PolicyEngine({
      approvalService: approvals,
      clock,
      gitInspector: {
        async inspect() {
          gitInspections += 1;
          throw new Error('must not inspect an unknown action');
        },
      },
      identity,
      registry: createActionRegistry({ approvedProjectRoots: [repositoryRoot] }),
      vault: {
        async list() {
          vaultReads += 1;
          throw new Error('must not read the vault for an unknown action');
        },
      },
    });
    const decision = await engine.evaluate(requestFor(repositoryRoot, {
      action: 'run_arbitrary_shell',
      executable: 'sh',
      params: { directory: 'dist', project: 'keyguard-site' },
    }));

    assert.equal(decision.status, 'denied');
    assert.equal(decision.code, 'unknown_action');
    assert.equal(gitInspections, 0);
    assert.equal(vaultReads, 0);
  });
});

test('accepts a trusted non-Cloudflare integration supplied at startup and delegates preparation', async () => {
  await withPolicySystem(async ({ approvals, clock, identity, repositoryRoot, vault }) => {
    const preparationCalls = [];
    const executionCalls = [];
    const integration = {
      action: {
        approval: 'always',
        credential: { label: 'example-api-token', provider: 'example' },
        name: 'example_publish',
        params: { site: 'slug' },
        version: 7,
      },
      async execute({ envelope, secret }) {
        executionCalls.push({ envelope, secret });
        return { exitCode: 0, status: 'succeeded', stderr: '', stdout: '' };
      },
      async prepare({ params, projectRoot, snapshot }) {
        preparationCalls.push({ params, projectRoot, snapshot });
        if (params?.site !== 'keyguard-site') {
          throw new Error('site must be a slug');
        }
        return {
          params: { site: params.site },
          target: { projectRoot, site: params.site },
        };
      },
    };
    const registry = createActionRegistry({
      approvedProjectRoots: [repositoryRoot],
      integrations: [integration],
    });
    const engine = new PolicyEngine({
      approvalService: approvals,
      clock,
      gitInspector: new GitInspector(),
      identity,
      registry,
      vault,
    });

    const decision = await engine.evaluate({
      action: 'example_publish',
      agentId: 'codex-test-agent',
      params: { site: 'keyguard-site' },
      projectRoot: repositoryRoot,
    });

    assert.deepEqual(registry.list(), [{
      approval: 'always',
      name: 'example_publish',
      params: { site: 'slug' },
      version: 7,
    }]);
    assert.equal(decision.status, 'credential_needed');
    assert.equal(decision.credentialLabel, 'example-api-token');
    assert.equal(preparationCalls.length, 1);
    assert.equal(preparationCalls[0].projectRoot, await realpath(repositoryRoot));
    await registry.execute({ action: 'example_publish' }, 'test-only-secret');
    assert.equal(executionCalls.length, 1);
    assert.equal(executionCalls[0].secret, 'test-only-secret');
  });
});

test('returns credential_needed for missing and revoked fixed credentials', async () => {
  await withPolicySystem(async ({ engine, repositoryRoot, vault }) => {
    const missing = await engine.evaluate(requestFor(repositoryRoot));

    assert.equal(missing.status, 'credential_needed');
    assert.equal(missing.credentialLabel, 'cloudflare-api-token');

    await vault.put({ label: 'cloudflare-api-token', provider: 'cloudflare' }, 'test-only-deploy-secret');
    const active = await engine.evaluate(requestFor(repositoryRoot));
    assert.equal(active.status, 'approval_required');

    await vault.revoke('cloudflare-api-token');
    const revoked = await engine.evaluate(requestFor(repositoryRoot));
    assert.equal(revoked.status, 'credential_needed');
    assert.equal(revoked.credentialLabel, 'cloudflare-api-token');
  });
});

test('requires an exact credential provider binding before creating an approval', async () => {
  await withPolicySystem(async ({ engine, repositoryRoot, vault }) => {
    await vault.put(
      { label: 'cloudflare-api-token', provider: 'different-provider' },
      'wrong-provider-test-secret',
    );

    const mismatched = await engine.evaluate(requestFor(repositoryRoot));

    assert.equal(mismatched.status, 'credential_needed');
    assert.equal(mismatched.credentialLabel, 'cloudflare-api-token');

    await vault.delete('cloudflare-api-token');
    await vault.put(
      { label: 'cloudflare-api-token', provider: 'cloudflare' },
      'matching-provider-test-secret',
    );

    const matched = await engine.evaluate(requestFor(repositoryRoot));
    assert.equal(matched.status, 'approval_required');
  });
});

test('builds a signed canonical envelope from daemon-derived state and ignores caller execution fields', async () => {
  await withPolicySystem(async ({ clock, engine, identity, repositoryRoot, vault }) => {
    await vault.put(
      { label: 'cloudflare-api-token', provider: 'cloudflare' },
      'test-only-deploy-secret',
    );
    const actualCommit = await git(repositoryRoot, ['rev-parse', 'HEAD']);
    const maliciousCommit = '0000000000000000000000000000000000000000';
    const request = requestFor(repositoryRoot, {
      allowedProjectRoots: ['*'],
      args: ['-c', 'echo attacker'],
      commit: maliciousCommit,
      credentialLabel: 'attacker-token',
      environment: { CLOUDFLARE_API_TOKEN: 'attacker-controlled' },
      executable: 'sh',
      gitCommit: maliciousCommit,
    });

    const first = await engine.evaluate(request);
    const second = await engine.evaluate(request);

    assert.equal(first.status, 'approval_required');
    assert.equal(second.status, 'approval_required');
    assert.equal(first.envelope.body.project.commit, actualCommit);
    assert.equal(first.envelope.body.params.directory, 'dist');
    assert.equal(first.envelope.body.target.directory, await realpath(join(repositoryRoot, 'dist')));
    assert.equal(first.envelope.body.target.project, 'keyguard-site');
    assert.equal(first.envelope.body.credentialLabel, 'cloudflare-api-token');
    assert.equal(first.envelope.body.credentialProvider, 'cloudflare');
    assert.equal(first.envelope.bodyHash, sha256(first.envelope.body));
    assert.notEqual(first.envelope.body.nonce, second.envelope.body.nonce);
    assert.equal(identity.verifyCanonical(first.envelope.body, first.envelope.signature), true);
    assert.equal(
      Date.parse(first.envelope.body.expiresAt) - Date.parse(first.envelope.body.requestedAt),
      10 * 60 * 1000,
    );
    for (const field of ['allowedProjectRoots', 'args', 'environment', 'executable']) {
      assert.equal(field in first.envelope.body, false, `${field} must not enter the policy envelope`);
    }
    assert.doesNotMatch(JSON.stringify(first.envelope), /test-only-deploy-secret|attacker-controlled/);
    assert.equal(first.envelope.body.requestedAt, clock.now().toISOString());
  });
});

test('bootstrap composes the daemon-owned policy and approval services', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    const app = await createKeyguardApp({
      approvedProjectRoots: [process.cwd()],
      dataDirectory,
      integrations: [createCloudflarePagesIntegration()],
    });

    assert.equal(typeof app.services.actionRegistry.get, 'function');
    assert.equal(typeof app.services.gitInspector.inspect, 'function');
    assert.equal(typeof app.services.approvals.request, 'function');
    assert.equal(typeof app.services.policyEngine.evaluate, 'function');
  });
});

async function withPolicySystem(run) {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    await withTemporaryRepository(async (repositoryRoot) => {
      const clock = controllableClock(INITIAL_TIME);
      const [identity, vault] = await Promise.all([
        LocalIdentity.open({ dataDirectory }),
        SealedVault.open({ clock, dataDirectory }),
      ]);
      const approvals = await ApprovalService.open({
        clock,
        dataDirectory,
        identity,
        vault,
      });
      const registry = createActionRegistry({
        approvedProjectRoots: [repositoryRoot],
        integrations: [createCloudflarePagesIntegration()],
      });
      const engine = new PolicyEngine({
        approvalService: approvals,
        clock,
        gitInspector: new GitInspector(),
        identity,
        registry,
        vault,
      });

      await run({ approvals, clock, engine, identity, repositoryRoot, vault });
    });
  });
}

function controllableClock(initialTime) {
  let current = new Date(initialTime);
  return {
    advance(milliseconds) {
      current = new Date(current.valueOf() + milliseconds);
    },
    now() {
      return new Date(current);
    },
  };
}

function requestFor(repositoryRoot, overrides = {}) {
  return {
    action: ACTION_NAME,
    agentId: 'codex-test-agent',
    params: { directory: 'dist', project: 'keyguard-site' },
    projectRoot: repositoryRoot,
    ...overrides,
  };
}

async function withTemporaryRepository(run) {
  const repositoryRoot = await mkdtemp(join(tmpdir(), 'atomical-keyguard-policy-'));

  try {
    await git(repositoryRoot, ['init']);
    await git(repositoryRoot, ['config', 'user.email', 'tests@example.invalid']);
    await git(repositoryRoot, ['config', 'user.name', 'Atomical Keyguard Tests']);
    await mkdir(join(repositoryRoot, 'dist'), { recursive: true });
    await Promise.all([
      writeFile(join(repositoryRoot, 'README.md'), '# Policy test repository\n'),
      writeFile(join(repositoryRoot, 'dist', 'index.html'), '<h1>Initial</h1>\n'),
    ]);
    await git(repositoryRoot, ['add', '.']);
    await git(repositoryRoot, ['commit', '-m', 'initial']);
    return await run(repositoryRoot);
  } finally {
    await rm(repositoryRoot, { force: true, recursive: true });
  }
}

async function git(cwd, args) {
  const { stdout } = await execFileAsync('git', args, {
    cwd,
    env: {
      ...process.env,
      GIT_CONFIG_NOSYSTEM: '1',
      GIT_TERMINAL_PROMPT: '0',
    },
  });
  return stdout.trim();
}
