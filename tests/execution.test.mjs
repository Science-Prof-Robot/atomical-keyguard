import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { appendFile, mkdir, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import test from 'node:test';

import { createKeyguardApp } from '../src/bootstrap.mjs';
import { LocalIdentity } from '../src/identity/local-identity.mjs';
import { createActionRegistry } from '../src/policy/action-registry.mjs';
import { PolicyEngine } from '../src/policy/policy-engine.mjs';
import { CLOUDFLARE_PAGES_ACTION as ACTION_NAME, CloudflarePagesAdapter, createCloudflarePagesIntegration } from '../src/providers/cloudflare-pages.mjs';
import { GitInspector } from '../src/project/git-inspector.mjs';
import { ActivityService } from '../src/services/activity.mjs';
import { ApprovalService } from '../src/services/approvals.mjs';
import { ExecutionService } from '../src/services/execution.mjs';
import { MemoryService } from '../src/services/memory.mjs';
import { SealedVault } from '../src/storage/sealed-vault.mjs';
import { withTemporaryDataDirectory } from './helpers.mjs';

const execFileAsync = promisify(execFile);
const INITIAL_TIME = '2026-07-14T12:00:00.000Z';

test('Cloudflare Pages adapter uses fixed npx argv, a child-only token, and redacted output', async () => {
  await withTemporaryProviderTarget(async ({ directory, projectRoot }) => {
    const secret = 'task-4-test-token-!/~';
    const calls = [];
    const adapter = new CloudflarePagesAdapter({
      runner: async (file, args, options) => {
        calls.push({ args, file, options });
        return {
          stderr: `encoded=${encodeURIComponent(options.env.CLOUDFLARE_API_TOKEN)}`,
          stdout: `deployed token=${options.env.CLOUDFLARE_API_TOKEN}`,
        };
      },
      timeoutMilliseconds: 4_000,
    });

    const result = await adapter.execute({
      directory,
      project: 'keyguard-site',
      projectRoot,
      secret,
    });

    assert.equal(calls.length, 1);
    assert.equal(calls[0].file, 'npx');
    assert.deepEqual(calls[0].args, [
      'wrangler',
      'pages',
      'deploy',
      directory,
      '--project-name',
      'keyguard-site',
    ]);
    assert.equal(Array.isArray(calls[0].args), true);
    assert.equal(calls[0].options.cwd, projectRoot);
    assert.equal(calls[0].options.shell, false);
    assert.equal(calls[0].options.timeout, 4_000);
    assert.equal(calls[0].options.env.CLOUDFLARE_API_TOKEN, secret);
    assert.notEqual(process.env.CLOUDFLARE_API_TOKEN, secret);
    assert.equal(result.status, 'succeeded');
    assert.match(result.stdout, /\[REDACTED\]/);
    assert.match(result.stderr, /\[REDACTED\]/);
    assert.doesNotMatch(JSON.stringify(result), new RegExp(escapeRegExp(secret)));
    assert.equal('secret' in result, false);

    await assert.rejects(
      adapter.execute({
        directory,
        project: 'keyguard-site; echo unsafe',
        projectRoot,
        secret,
      }),
      /project/i,
    );
  });
});

test('Cloudflare Pages adapter revalidates a real target directory before runner launch', async () => {
  const temporaryProjectRoot = await mkdtemp(join(tmpdir(), 'atomical-keyguard-provider-'));
  const projectRoot = await realpath(temporaryProjectRoot);
  const directory = join(projectRoot, 'dist');
  let runnerCalls = 0;

  try {
    await mkdir(directory);
    const adapter = new CloudflarePagesAdapter({
      runner: async () => {
        runnerCalls += 1;
        return { stderr: '', stdout: '' };
      },
    });
    await rm(directory, { force: true, recursive: true });

    await assert.rejects(
      adapter.execute({
        directory,
        project: 'keyguard-site',
        projectRoot,
        secret: 'adapter-revalidation-test-token',
      }),
      /target/i,
    );

    assert.equal(runnerCalls, 0);
  } finally {
    await rm(temporaryProjectRoot, { force: true, recursive: true });
  }
});

test('executes an explicitly installed non-Cloudflare integration through the same sealed approval path', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    await withTemporaryRepository(async (repositoryRoot) => {
      const clock = controllableClock(INITIAL_TIME);
      const [identity, vault] = await Promise.all([
        LocalIdentity.open({ dataDirectory }),
        SealedVault.open({ clock, dataDirectory }),
      ]);
      const calls = [];
      const integration = {
        action: {
          approval: 'always',
          credential: { label: 'example-api-token', provider: 'example' },
          name: 'example_publish',
          params: { site: 'slug' },
          version: 7,
        },
        async execute({ envelope, secret }) {
          calls.push({ envelope, secret });
          return { status: 'succeeded', stderr: '', stdout: 'published' };
        },
        async prepare({ params, projectRoot }) {
          if (params?.site !== 'docs') {
            throw new Error('site is invalid');
          }
          return {
            params: { site: 'docs' },
            target: { projectRoot, site: 'docs' },
          };
        },
      };
      const actionRegistry = createActionRegistry({
        approvedProjectRoots: [repositoryRoot],
        integrations: [integration],
      });
      const gitInspector = new GitInspector();
      const approvals = await ApprovalService.open({
        actionRegistry,
        clock,
        dataDirectory,
        gitInspector,
        identity,
        vault,
      });
      const [activity, memory] = await Promise.all([
        ActivityService.open({ clock, dataDirectory }),
        MemoryService.open({ clock, dataDirectory, identity }),
      ]);
      const engine = new PolicyEngine({
        approvalService: approvals,
        clock,
        gitInspector,
        identity,
        registry: actionRegistry,
        vault,
      });
      const execution = await ExecutionService.open({
        actionRegistry,
        activity,
        approvals,
        clock,
        dataDirectory,
        gitInspector,
        identity,
        memory,
        verifier: async () => true,
        vault,
      });
      await vault.put({ label: 'example-api-token', provider: 'example' }, 'example-test-secret');

      const decision = await engine.evaluate({
        action: 'example_publish',
        agentId: 'codex-test-agent',
        params: { site: 'docs' },
        projectRoot: repositoryRoot,
      });
      assert.equal(decision.status, 'approval_required');
      assert.equal(decision.envelope.body.actionVersion, 7);
      assert.deepEqual(decision.envelope.body.target, {
        projectRoot: decision.envelope.body.project.root,
        site: 'docs',
      });
      await approvals.approveOnce(decision.requestId);

      const result = await execution.executeApproved(decision.requestId);

      assert.equal(result.status, 'verified');
      assert.equal(result.receipt.action, 'example_publish');
      assert.equal(result.receipt.actionVersion, 7);
      assert.deepEqual(result.receipt.target, {
        projectRoot: decision.envelope.body.project.root,
        site: 'docs',
      });
      assert.equal(calls.length, 1);
      assert.equal(calls[0].secret, 'example-test-secret');
      assert.equal(calls[0].envelope.body.action, 'example_publish');
      assert.equal(JSON.stringify(result).includes('example-test-secret'), false);
    });
  });
});

test('redacts token variants that cross the output cap before returning runner diagnostics', async () => {
  await withTemporaryProviderTarget(async ({ directory, projectRoot }) => {
    const secret = 'cross-boundary-task-4-token';
    const literalPrefix = 'x'.repeat((64 * 1024) - 5);
    const encodedSecret = Buffer.from(secret, 'utf8').toString('base64url');
    const encodedPrefix = 'y'.repeat((64 * 1024) - 5);
    const adapter = new CloudflarePagesAdapter({
      runner: async () => ({
        stderr: `${encodedPrefix}${encodedSecret}`,
        stdout: `${literalPrefix}${secret}`,
      }),
    });
    const errorAdapter = new CloudflarePagesAdapter({
      runner: async () => {
        throw new Error(`${literalPrefix}${secret}`);
      },
    });

    const result = await adapter.execute({
      directory,
      project: 'keyguard-site',
      projectRoot,
      secret,
    });
    const errorResult = await errorAdapter.execute({
      directory,
      project: 'keyguard-site',
      projectRoot,
      secret,
    });

    for (const diagnostic of [result.stdout, result.stderr, errorResult.stderr]) {
      assert.equal(diagnostic.includes(secret), false);
      assert.equal(diagnostic.includes(secret.slice(0, 5)), false);
    }
    assert.equal(result.stderr.includes(encodedSecret.slice(0, 5)), false);
  });
});

test('executes one consumed approval with a safe signed receipt, redacted activity, and a memory candidate', async () => {
  await withExecutionSystem(async (system) => {
    const secret = 'execution-test-only-token';
    await activateCredential(system.vault, secret);
    const decision = await approveRequest(system);
    const runnerCalls = [];
    const execution = await createExecution(system, {
      runner: async (file, args, options) => {
        runnerCalls.push({ args, file, options });
        return {
          stderr: `encoded=${Buffer.from(options.env.CLOUDFLARE_API_TOKEN).toString('base64url')}`,
          stdout: `deploying ${options.env.CLOUDFLARE_API_TOKEN}`,
        };
      },
      verifier: async () => true,
    });

    const result = await execution.executeApproved(decision.requestId);

    assert.equal(result.status, 'verified');
    assert.equal(runnerCalls.length, 1);
    assert.equal(runnerCalls[0].file, 'npx');
    assert.equal(runnerCalls[0].options.env.CLOUDFLARE_API_TOKEN, secret);
    assert.match(result.output.stdout, /\[REDACTED\]/);
    assert.match(result.output.stderr, /\[REDACTED\]/);
    assert.doesNotMatch(JSON.stringify(result), new RegExp(escapeRegExp(secret)));
    assert.equal(result.receipt.action, ACTION_NAME);
    assert.equal(result.receipt.approval.id, decision.requestId);
    assert.equal(result.receipt.request.id, decision.requestId);
    assert.equal(result.receipt.dirtyTreeAllowed, false);
    assert.equal(result.receipt.secretExposedToModel, false);
    assert.equal(result.receipt.provider.status, 'succeeded');
    assert.equal(result.receipt.verification.status, 'verified');
    assert.equal('stdout' in result.receipt, false);
    assert.equal('stderr' in result.receipt, false);
    assert.equal(Object.isFrozen(result.receipt), true);
    assert.equal(Object.isFrozen(result.receipt.target), true);
    assert.equal(
      system.identity.verifyCanonical(receiptBody(result.receipt), result.receipt.signature),
      true,
    );

    const [activities, memories, receipts] = await Promise.all([
      system.activity.list(),
      system.memory.list(),
      execution.listReceipts(),
    ]);
    assert.deepEqual(activities.map((activity) => activity.stage), [
      'preparing',
      'executing',
      'verifying',
    ]);
    assert.equal(receipts.length, 2);
    const providerAttempt = receipts.find((receipt) => receipt.id === result.receipt.verificationOf);
    assert.notEqual(providerAttempt, undefined);
    assert.equal(providerAttempt.provider.status, 'succeeded');
    assert.equal(providerAttempt.verification.status, 'not_run');
    assert.notEqual(providerAttempt.id, result.receipt.id);
    assert.equal(memories.length, 1);
    assert.equal(memories[0].status, 'candidate');
    assert.equal(memories[0].scope.kind, 'project');
    assert.doesNotMatch(JSON.stringify({ activities, memories, receipts }), new RegExp(escapeRegExp(secret)));
  });
});

test('records dirty-tree allowance in the receipt only after the one-time acknowledgement', async () => {
  await withExecutionSystem(async (system) => {
    await activateCredential(system.vault, 'dirty-tree-test-token');
    await appendFile(join(system.repositoryRoot, 'dist', 'index.html'), '\ndirty deployment');
    const decision = await system.engine.evaluate(requestFor(system.repositoryRoot));
    assert.equal(decision.requiresDirtyTreeAcknowledgement, true);
    await system.approvals.approveOnce(decision.requestId, { dirtyTreeAcknowledged: true });
    const execution = await createExecution(system, {
      runner: async () => ({ stderr: '', stdout: 'deployed' }),
      verifier: async () => true,
    });

    const result = await execution.executeApproved(decision.requestId);

    assert.equal(result.status, 'verified');
    assert.equal(result.receipt.dirtyTreeAllowed, true);
  });
});

test('retains a signed verification failure and permits only a provenance-bound verification retry', async () => {
  await withExecutionSystem(async (system) => {
    await activateCredential(system.vault, 'verification-test-token');
    const decision = await approveRequest(system);
    let runnerCalls = 0;
    let verificationAttempts = 0;
    const execution = await createExecution(system, {
      runner: async () => {
        runnerCalls += 1;
        return { stderr: '', stdout: 'provider completed' };
      },
      verifier: async () => {
        verificationAttempts += 1;
        return verificationAttempts > 1;
      },
    });

    const failed = await execution.executeApproved(decision.requestId);

    assert.equal(failed.status, 'verification_failed');
    assert.equal(failed.attention, 'needs_attention');
    assert.equal(failed.receipt.provider.status, 'succeeded');
    assert.equal(failed.receipt.verification.status, 'failed');
    assert.equal(runnerCalls, 1);
    assert.equal((await system.memory.list()).length, 0);
    const initialReceipts = await execution.listReceipts();
    assert.equal(initialReceipts.length, 2);
    assert.equal(
      initialReceipts.some((receipt) => receipt.id === failed.receipt.verificationOf),
      true,
    );

    const retried = await execution.retryVerification(failed.receipt.id);

    assert.equal(retried.status, 'verified');
    assert.equal(retried.receipt.retryOf, failed.receipt.id);
    assert.equal(retried.receipt.verificationOf, failed.receipt.verificationOf);
    assert.equal(retried.receipt.verification.status, 'verified');
    assert.equal(runnerCalls, 1);
    assert.equal((await execution.listReceipts()).length, 3);
    assert.equal((await system.memory.list()).length, 1);
  });
});

test('persists a signed provider-attempt receipt before verification settles', async () => {
  await withExecutionSystem(async (system) => {
    await activateCredential(system.vault, 'pending-verification-test-token');
    const decision = await approveRequest(system);
    let beginVerification;
    let releaseVerification;
    const verificationStarted = new Promise((resolve) => {
      beginVerification = resolve;
    });
    const verificationRelease = new Promise((resolve) => {
      releaseVerification = resolve;
    });
    const execution = await createExecution(system, {
      runner: async () => ({ stderr: '', stdout: 'provider completed' }),
      verifier: async () => {
        beginVerification();
        return verificationRelease;
      },
    });

    const pending = execution.executeApproved(decision.requestId);
    await verificationStarted;

    const receiptsWhilePending = await execution.listReceipts();

    assert.equal(receiptsWhilePending.length, 1);
    assert.equal(receiptsWhilePending[0].provider.status, 'succeeded');
    assert.equal(receiptsWhilePending[0].verification.status, 'not_run');

    releaseVerification(true);
    const result = await pending;

    assert.equal(result.status, 'verified');
    assert.equal(result.receipt.verificationOf, receiptsWhilePending[0].id);
    assert.notEqual(result.receipt.id, receiptsWhilePending[0].id);
    assert.equal((await execution.listReceipts()).length, 2);
  });
});

test('fails closed when no verifier is injected', async () => {
  await withExecutionSystem(async (system) => {
    await activateCredential(system.vault, 'no-verifier-test-token');
    const decision = await approveRequest(system);
    const execution = await createExecution(system, {
      runner: async () => ({ stderr: '', stdout: 'provider completed' }),
    });

    const result = await execution.executeApproved(decision.requestId);

    assert.equal(result.status, 'verification_failed');
    assert.equal(result.attention, 'needs_attention');
    assert.equal(result.receipt.provider.status, 'succeeded');
    assert.equal(result.receipt.verification.status, 'failed');
    assert.equal((await execution.listReceipts()).length, 2);
    assert.equal((await system.memory.list()).length, 0);
  });
});

test('persists the provider-attempt receipt when activity recording fails after deployment', async () => {
  await withExecutionSystem(async (system) => {
    const secret = 'activity-error-test-token';
    await activateCredential(system.vault, secret);
    const decision = await approveRequest(system);
    let runnerCalls = 0;
    const activity = {
      append: async (milestone) => {
        if (milestone.stage === 'verifying') {
          throw new Error(`activity failure ${secret}`);
        }
        return system.activity.append(milestone);
      },
    };
    const execution = await createExecution(system, {
      activity,
      runner: async () => {
        runnerCalls += 1;
        return { stderr: '', stdout: 'provider completed' };
      },
      verifier: async () => true,
    });

    const result = await execution.executeApproved(decision.requestId);

    assert.equal(result.status, 'verified');
    assert.equal(runnerCalls, 1);
    assert.equal(result.receipt.provider.status, 'succeeded');
    assert.equal(result.receipt.verification.status, 'verified');
    assert.equal((await execution.listReceipts()).length, 2);
    assert.doesNotMatch(JSON.stringify(result), new RegExp(escapeRegExp(secret)));
  });
});

test('performs a final post-consume Git check before reading a secret or launching the provider', async () => {
  await withExecutionSystem(async (system) => {
    await activateCredential(system.vault, 'final-check-test-token');
    const decision = await approveRequest(system);
    let runnerCalls = 0;
    let secretReads = 0;
    const originalRead = system.vault.readForExecution.bind(system.vault);
    system.vault.readForExecution = async (...args) => {
      secretReads += 1;
      return originalRead(...args);
    };
    const execution = await createExecution(system, {
      gitInspector: {
        inspect: async () => ({
          ...decision.envelope.body.project,
          commit: 'f'.repeat(40),
        }),
      },
      runner: async () => {
        runnerCalls += 1;
        return { stderr: '', stdout: 'must not run' };
      },
      verifier: async () => true,
    });

    const result = await execution.executeApproved(decision.requestId);

    assert.equal(result.status, 'preparation_failed');
    assert.equal(result.receipt.provider.status, 'not_started');
    assert.equal(runnerCalls, 0);
    assert.equal(secretReads, 0);
  });
});

test('re-prepares an installed action before reading its secret and fails closed when the target is unavailable', async () => {
  await withExecutionSystem(async (system) => {
    await activateCredential(system.vault, 'final-target-check-token');
    const decision = await approveRequest(system);
    let runnerCalls = 0;
    let secretReads = 0;
    const originalRead = system.vault.readForExecution.bind(system.vault);
    system.vault.readForExecution = async (...args) => {
      secretReads += 1;
      return originalRead(...args);
    };
    const actionRegistry = {
      execute: async () => {
        runnerCalls += 1;
        return { status: 'succeeded', stderr: '', stdout: 'must not run' };
      },
      get: system.registry.get.bind(system.registry),
      prepare: async () => {
        throw new Error('target became unavailable');
      },
    };
    const execution = await createExecution(system, {
      actionRegistry,
      runner: async () => ({ stderr: '', stdout: 'must not run' }),
      verifier: async () => true,
    });

    const result = await execution.executeApproved(decision.requestId);

    assert.equal(result.status, 'preparation_failed');
    assert.equal(result.receipt.provider.status, 'not_started');
    assert.equal(runnerCalls, 0);
    assert.equal(secretReads, 0);
  });
});

test('re-prepares an installed action after secret access before launch', async () => {
  await withExecutionSystem(async (system) => {
    await activateCredential(system.vault, 'post-read-target-check-token');
    const decision = await approveRequest(system);
    let prepareCalls = 0;
    let runnerCalls = 0;
    const actionRegistry = {
      execute: async () => {
        runnerCalls += 1;
        return { status: 'succeeded', stderr: '', stdout: 'must not run' };
      },
      get: system.registry.get.bind(system.registry),
      prepare: async () => {
        prepareCalls += 1;
        if (prepareCalls === 2) {
          throw new Error('target changed before launch');
        }
        return {
          params: decision.envelope.body.params,
          target: decision.envelope.body.target,
        };
      },
    };
    const execution = await createExecution(system, {
      actionRegistry,
      runner: async () => ({ stderr: '', stdout: 'must not run' }),
      verifier: async () => true,
    });

    const result = await execution.executeApproved(decision.requestId);

    assert.equal(result.status, 'preparation_failed');
    assert.equal(result.receipt.provider.status, 'not_started');
    assert.equal(prepareCalls, 2);
    assert.equal(runnerCalls, 0);
  });
});

test('bootstrap composes neutral execution services without constructing a provider runner', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    let runnerReads = 0;
    const options = {
      approvedProjectRoots: [process.cwd()],
      dataDirectory,
      verifier: async () => true,
    };
    Object.defineProperty(options, 'providerRunner', {
      enumerable: true,
      get() {
        runnerReads += 1;
        return async () => ({ stderr: '', stdout: '' });
      },
    });
    const app = await createKeyguardApp(options);

    assert.deepEqual(app.services.actionRegistry.list(), []);
    assert.equal(runnerReads, 0);
    assert.equal(Object.hasOwn(app.services, 'provider'), false);
    assert.equal(typeof app.services.execution.executeApproved, 'function');
    assert.equal(typeof app.services.execution.retryVerification, 'function');
    assert.equal(typeof app.services.activity.list, 'function');
    assert.equal(typeof app.services.memory.createVerifiedCandidate, 'function');
  });
});

async function withExecutionSystem(run) {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    await withTemporaryRepository(async (repositoryRoot) => {
      const clock = controllableClock(INITIAL_TIME);
      const [identity, vault] = await Promise.all([
        LocalIdentity.open({ dataDirectory }),
        SealedVault.open({ clock, dataDirectory }),
      ]);
      const approvalGitInspector = new GitInspector();
      const registry = createActionRegistry({
        approvedProjectRoots: [repositoryRoot],
        integrations: [createCloudflarePagesIntegration()],
      });
      const approvals = await ApprovalService.open({
        actionRegistry: registry,
        clock,
        dataDirectory,
        gitInspector: approvalGitInspector,
        identity,
        vault,
      });
      const engine = new PolicyEngine({
        approvalService: approvals,
        clock,
        gitInspector: approvalGitInspector,
        identity,
        registry,
        vault,
      });
      const [activity, memory] = await Promise.all([
        ActivityService.open({ clock, dataDirectory }),
        MemoryService.open({ clock, dataDirectory, identity }),
      ]);

      await run({
        activity,
        approvals,
        clock,
        dataDirectory,
        engine,
        identity,
        memory,
        repositoryRoot,
        registry,
        vault,
      });
    });
  });
}

async function createExecution(system, options) {
  const actionRegistry = options.actionRegistry ?? createActionRegistry({
    approvedProjectRoots: [system.repositoryRoot],
    integrations: [createCloudflarePagesIntegration({ runner: options.runner })],
  });
  return ExecutionService.open({
    actionRegistry,
    activity: options.activity ?? system.activity,
    approvals: system.approvals,
    clock: system.clock,
    dataDirectory: system.dataDirectory,
    gitInspector: options.gitInspector ?? new GitInspector(),
    identity: system.identity,
    memory: system.memory,
    verifier: options.verifier,
    vault: system.vault,
  });
}

async function activateCredential(vault, secret) {
  await vault.put({ label: 'cloudflare-api-token', provider: 'cloudflare' }, secret);
}

async function approveRequest(system) {
  const decision = await system.engine.evaluate(requestFor(system.repositoryRoot));
  assert.equal(decision.status, 'approval_required');
  const approval = await system.approvals.approveOnce(decision.requestId);
  assert.equal(approval.status, 'approved_once');
  return decision;
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

function receiptBody(receipt) {
  const { signature, ...body } = receipt;
  return body;
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
  const repositoryRoot = await mkdtemp(join(tmpdir(), 'atomical-keyguard-execution-'));

  try {
    await git(repositoryRoot, ['init']);
    await git(repositoryRoot, ['config', 'user.email', 'tests@example.invalid']);
    await git(repositoryRoot, ['config', 'user.name', 'Atomical Keyguard Tests']);
    await mkdir(join(repositoryRoot, 'dist'), { recursive: true });
    await Promise.all([
      writeFile(join(repositoryRoot, 'README.md'), '# Execution test repository\n'),
      writeFile(join(repositoryRoot, 'dist', 'index.html'), '<h1>Initial</h1>\n'),
    ]);
    await git(repositoryRoot, ['add', '.']);
    await git(repositoryRoot, ['commit', '-m', 'initial']);
    return await run(repositoryRoot);
  } finally {
    await rm(repositoryRoot, { force: true, recursive: true });
  }
}

async function withTemporaryProviderTarget(run) {
  const temporaryProjectRoot = await mkdtemp(join(tmpdir(), 'atomical-keyguard-provider-'));
  const projectRoot = await realpath(temporaryProjectRoot);
  const directory = join(projectRoot, 'dist');

  try {
    await mkdir(directory);
    return await run({ directory, projectRoot });
  } finally {
    await rm(temporaryProjectRoot, { force: true, recursive: true });
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

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
