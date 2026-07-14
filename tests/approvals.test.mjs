import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { appendFile, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { LocalIdentity } from '../src/identity/local-identity.mjs';
import { createActionRegistry } from '../src/policy/action-registry.mjs';
import { PolicyEngine } from '../src/policy/policy-engine.mjs';
import { CLOUDFLARE_PAGES_ACTION as ACTION_NAME, createCloudflarePagesIntegration } from '../src/providers/cloudflare-pages.mjs';
import { GitInspector } from '../src/project/git-inspector.mjs';
import { ApprovalService } from '../src/services/approvals.mjs';
import { SealedVault } from '../src/storage/sealed-vault.mjs';
import { withTemporaryDataDirectory } from './helpers.mjs';

const execFileAsync = promisify(execFile);
const INITIAL_TIME = '2026-07-14T12:00:00.000Z';

test('expires an approved request and rejects a tampered canonical envelope hash', async () => {
  await withApprovalSystem(async ({ approvals, clock, engine, repositoryRoot, vault }) => {
    await activateCredential(vault);
    const decision = await engine.evaluate(requestFor(repositoryRoot));

    await assert.rejects(
      approvals.request({ ...decision.envelope, bodyHash: '0'.repeat(64) }),
      /envelope/i,
    );
    const approved = await approvals.approveOnce(decision.requestId);
    assert.equal(approved.status, 'approved_once');

    clock.advance((10 * 60 * 1000) + 1);
    const expired = await approvals.consume(
      decision.requestId,
      decision.envelope.body.project.commit,
    );

    assert.equal(expired.status, 'expired');
    assert.equal(expired.reason, 'approval_expired');
  });
});

test('lists only a compact secret-free approval summary for the local control UI', async () => {
  await withApprovalSystem(async ({ approvals, engine, repositoryRoot, vault }) => {
    await activateCredential(vault);
    const decision = await engine.evaluate(requestFor(repositoryRoot));

    const listed = await approvals.list();

    assert.deepEqual(listed, [{
      action: ACTION_NAME,
      credentialLabel: 'cloudflare-api-token',
      dirtyTreeAcknowledged: false,
      expiresAt: decision.envelope.body.expiresAt,
      id: decision.requestId,
      project: {
        commit: decision.envelope.body.project.commit,
        dirty: false,
        repositoryFingerprint: decision.envelope.body.project.repositoryFingerprint,
      },
      requiresDirtyTreeAcknowledgement: false,
      status: 'pending',
    }]);
    assert.equal(Object.isFrozen(listed), true);
    assert.equal(Object.isFrozen(listed[0]), true);
    assert.equal(Object.isFrozen(listed[0].project), true);

    const serialized = JSON.stringify(listed);
    assert.equal(serialized.includes(repositoryRoot), false);
    assert.equal(serialized.includes(decision.envelope.body.target.directory), false);
    assert.equal(serialized.includes('envelope'), false);
    assert.equal(serialized.includes('signature'), false);
    assert.equal(serialized.includes('scope'), false);
    assert.equal(serialized.includes('credentialRevision'), false);
  });
});

test('atomically permits exactly one concurrent consume for an approve-once request', async () => {
  await withApprovalSystem(async ({ approvals, engine, repositoryRoot, vault }) => {
    await activateCredential(vault);
    const decision = await engine.evaluate(requestFor(repositoryRoot));
    await approvals.approveOnce(decision.requestId);

    const attempts = await Promise.all([
      approvals.consume(decision.requestId, decision.envelope.body.project.commit),
      approvals.consume(decision.requestId, decision.envelope.body.project.commit),
    ]);
    const authorized = attempts.filter((attempt) => attempt.status === 'approved');
    const replay = attempts.find((attempt) => attempt.status !== 'approved');

    assert.equal(authorized.length, 1);
    assert.equal(replay.status, 'denied');
    assert.equal(replay.reason, 'already_consumed');

    const secondReplay = await approvals.consume(
      decision.requestId,
      decision.envelope.body.project.commit,
    );
    assert.equal(secondReplay.status, 'denied');
    assert.equal(secondReplay.reason, 'already_consumed');
  });
});

test('invalidates approvals when the canonical repository commit changes or the credential is revoked', async () => {
  await withApprovalSystem(async ({ approvals, engine, repositoryRoot, vault }) => {
    await activateCredential(vault);
    const beforeCommit = await engine.evaluate(requestFor(repositoryRoot));
    await approvals.approveOnce(beforeCommit.requestId);

    await writeFile(join(repositoryRoot, 'next.txt'), 'next commit\n');
    await git(repositoryRoot, ['add', 'next.txt']);
    await git(repositoryRoot, ['commit', '-m', 'next']);
    const changedCommit = await git(repositoryRoot, ['rev-parse', 'HEAD']);
    const changed = await approvals.consume(beforeCommit.requestId, changedCommit);

    assert.equal(changed.status, 'invalidated');
    assert.equal(changed.reason, 'commit_changed');

    const beforeRevocation = await engine.evaluate(requestFor(repositoryRoot));
    await approvals.approveOnce(beforeRevocation.requestId);
    await vault.revoke('cloudflare-api-token');
    const revoked = await approvals.consume(
      beforeRevocation.requestId,
      beforeRevocation.envelope.body.project.commit,
    );

    assert.equal(revoked.status, 'invalidated');
    assert.equal(revoked.reason, 'credential_unavailable');
  });
});

test('does not revive an approved request when a revoked credential label is recreated at the same timestamp', async () => {
  await withApprovalSystem(async ({ approvals, engine, repositoryRoot, vault }) => {
    await activateCredential(vault);
    const decision = await engine.evaluate(requestFor(repositoryRoot));
    await approvals.approveOnce(decision.requestId);

    await vault.revoke('cloudflare-api-token');
    await vault.delete('cloudflare-api-token');
    await activateCredential(vault);

    const consumed = await approvals.consume(
      decision.requestId,
      decision.envelope.body.project.commit,
    );
    assert.equal(consumed.status, 'invalidated');
    assert.equal(consumed.reason, 'credential_changed');
  });
});

test('invalidates an approved request when a reviewed action changes its credential provider', async () => {
  await withApprovalSystem(async ({
    approvals,
    clock,
    dataDirectory,
    engine,
    identity,
    repositoryRoot,
    vault,
  }) => {
    await activateCredential(vault);
    const decision = await engine.evaluate(requestFor(repositoryRoot));
    await approvals.approveOnce(decision.requestId);

    const referenceIntegration = createCloudflarePagesIntegration();
    const changedRegistry = createActionRegistry({
      approvedProjectRoots: [repositoryRoot],
      integrations: [{
        ...referenceIntegration,
        action: {
          ...referenceIntegration.action,
          credential: {
            label: 'cloudflare-api-token',
            provider: 'different-provider',
          },
        },
      }],
    });
    const reopened = await ApprovalService.open({
      actionRegistry: changedRegistry,
      clock,
      dataDirectory,
      identity,
      vault,
    });

    const consumed = await reopened.consume(
      decision.requestId,
      decision.envelope.body.project.commit,
    );

    assert.equal(consumed.status, 'invalidated');
    assert.equal(consumed.reason, 'action_unavailable');
  });
});

test('requires a one-time dirty-tree acknowledgement bound to the requested envelope', async () => {
  await withApprovalSystem(async ({ approvals, engine, repositoryRoot, vault }) => {
    await activateCredential(vault);
    await appendFile(join(repositoryRoot, 'dist', 'index.html'), '\ndirty deployment');
    const decision = await engine.evaluate(requestFor(repositoryRoot));

    assert.equal(decision.status, 'approval_required');
    assert.equal(decision.requiresDirtyTreeAcknowledgement, true);
    assert.equal(decision.envelope.body.project.dirty, true);

    const missingAcknowledgement = await approvals.approveOnce(decision.requestId);
    assert.equal(missingAcknowledgement.status, 'pending');
    assert.equal(missingAcknowledgement.reason, 'dirty_tree_acknowledgement_required');

    const approved = await approvals.approveOnce(decision.requestId, {
      dirtyTreeAcknowledged: true,
    });
    assert.equal(approved.status, 'approved_once');
    assert.equal(approved.dirtyTreeAcknowledged, true);

    const consumed = await approvals.consume(
      decision.requestId,
      decision.envelope.body.project.commit,
    );
    assert.equal(consumed.status, 'approved');
    assert.equal(consumed.envelope.bodyHash, decision.envelope.bodyHash);
  });
});

test('approves only the server-stored exact scope without returning filesystem scope paths', async () => {
  await withApprovalSystem(async ({ approvals, engine, repositoryRoot, vault }) => {
    await activateCredential(vault);
    const decision = await engine.evaluate(requestFor(repositoryRoot));

    const approved = await approvals.approveExactScope(decision.requestId, {
      ...decision.scope,
      target: { ...decision.scope.target, project: 'model-supplied-broadened-target' },
    });

    assert.equal(approved.status, 'approved_scope');
    assert.equal(Object.hasOwn(approved, 'scope'), false);
    assert.equal(JSON.stringify(approved).includes(repositoryRoot), false);
    assert.equal(JSON.stringify(approved).includes(decision.envelope.body.target.directory), false);

    const consumed = await approvals.consume(
      decision.requestId,
      decision.envelope.body.project.commit,
    );
    assert.equal(consumed.status, 'approved');
  });
});

test('permits only the proposed exact reusable scope for action, credential, repository, target, and commit', async () => {
  await withApprovalSystem(async ({ approvals, engine, repositoryRoot, vault }) => {
    await activateCredential(vault);
    const first = await engine.evaluate(requestFor(repositoryRoot));

    const broadened = await approvals.approveScope(first.requestId, {
      ...first.scope,
      target: { ...first.scope.target, project: 'other-site' },
    });
    assert.equal(broadened.status, 'pending');
    assert.equal(broadened.reason, 'scope_mismatch');

    const scoped = await approvals.approveScope(first.requestId, first.scope);
    assert.equal(scoped.status, 'approved_scope');
    assert.equal(scoped.scope.commit, first.envelope.body.project.commit);
    const current = await approvals.consume(first.requestId, first.envelope.body.project.commit);
    assert.equal(current.status, 'approved');

    const exactMatch = await engine.evaluate(requestFor(repositoryRoot));
    assert.equal(exactMatch.status, 'approved');
    assert.equal(exactMatch.envelope.body.target.project, 'keyguard-site');

    const changedTarget = await engine.evaluate(requestFor(repositoryRoot, {
      params: { directory: 'dist', project: 'other-site' },
    }));
    assert.equal(changedTarget.status, 'approval_required');
  });
});

test('does not allow a denied approval to be consumed', async () => {
  await withApprovalSystem(async ({ approvals, engine, repositoryRoot, vault }) => {
    await activateCredential(vault);
    const decision = await engine.evaluate(requestFor(repositoryRoot));
    const denied = await approvals.deny(decision.requestId);
    assert.equal(denied.status, 'denied');

    const consumed = await approvals.consume(
      decision.requestId,
      decision.envelope.body.project.commit,
    );
    assert.equal(consumed.status, 'denied');
    assert.equal(consumed.reason, 'approval_denied');
  });
});

test('revokes an approved reusable scope when its originating approval is denied', async () => {
  await withApprovalSystem(async ({ approvals, engine, repositoryRoot, vault }) => {
    await activateCredential(vault);
    const first = await engine.evaluate(requestFor(repositoryRoot));
    const scoped = await approvals.approveScope(first.requestId, first.scope);
    assert.equal(scoped.status, 'approved_scope');

    const denied = await approvals.deny(first.requestId);
    assert.equal(denied.status, 'denied');
    const persisted = JSON.parse(await readFile(approvals.storagePath, 'utf8'));
    assert.deepEqual(persisted.scopes, []);
    assert.equal(persisted.approvals[0].scopeId, null);

    const followUp = await engine.evaluate(requestFor(repositoryRoot));
    assert.equal(followUp.status, 'approval_required');

    const consumed = await approvals.consume(
      followUp.requestId,
      followUp.envelope.body.project.commit,
    );
    assert.equal(consumed.status, 'denied');
    assert.equal(consumed.reason, 'approval_not_approved');
  });
});

test('invalidates an already auto-approved scope child when its origin is denied', async () => {
  await withApprovalSystem(async ({ approvals, engine, repositoryRoot, vault }) => {
    await activateCredential(vault);
    const origin = await engine.evaluate(requestFor(repositoryRoot));
    await approvals.approveScope(origin.requestId, origin.scope);
    const child = await engine.evaluate(requestFor(repositoryRoot));
    assert.equal(child.status, 'approved');

    const beforeDenial = JSON.parse(await readFile(approvals.storagePath, 'utf8'));
    const childBeforeDenial = beforeDenial.approvals.find((record) => record.id === child.requestId);
    assert.equal(childBeforeDenial.status, 'approved_scope');
    assert.equal(childBeforeDenial.scopeId, beforeDenial.approvals[0].scopeId);

    await approvals.deny(origin.requestId);

    const persisted = JSON.parse(await readFile(approvals.storagePath, 'utf8'));
    const childAfterDenial = persisted.approvals.find((record) => record.id === child.requestId);
    assert.deepEqual(persisted.scopes, []);
    assert.equal(childAfterDenial.status, 'invalidated');
    assert.equal(childAfterDenial.invalidatedReason, 'scope_revoked');
    assert.equal(childAfterDenial.scopeId, null);

    const consumedChild = await approvals.consume(
      child.requestId,
      child.envelope.body.project.commit,
    );
    assert.equal(consumedChild.status, 'invalidated');
    assert.equal(consumedChild.reason, 'scope_revoked');

    const retry = await engine.evaluate(requestFor(repositoryRoot));
    assert.equal(retry.status, 'approval_required');
  });
});

test('clears a consumed scope child link when its origin is denied', async () => {
  await withApprovalSystem(async ({ approvals, engine, repositoryRoot, vault }) => {
    await activateCredential(vault);
    const origin = await engine.evaluate(requestFor(repositoryRoot));
    await approvals.approveScope(origin.requestId, origin.scope);
    const child = await engine.evaluate(requestFor(repositoryRoot));
    const consumedChild = await approvals.consume(
      child.requestId,
      child.envelope.body.project.commit,
    );
    assert.equal(consumedChild.status, 'approved');

    await approvals.deny(origin.requestId);

    const persisted = JSON.parse(await readFile(approvals.storagePath, 'utf8'));
    const childAfterDenial = persisted.approvals.find((record) => record.id === child.requestId);
    assert.deepEqual(persisted.scopes, []);
    assert.equal(childAfterDenial.status, 'consumed');
    assert.equal(childAfterDenial.scopeId, null);

    const retry = await engine.evaluate(requestFor(repositoryRoot));
    assert.equal(retry.status, 'approval_required');
  });
});

test('invalidates an already auto-approved scope child when its origin invalidates', async () => {
  await withApprovalSystem(async ({ approvals, engine, repositoryRoot, vault }) => {
    await activateCredential(vault);
    const origin = await engine.evaluate(requestFor(repositoryRoot));
    await approvals.approveScope(origin.requestId, origin.scope);
    const child = await engine.evaluate(requestFor(repositoryRoot));
    assert.equal(child.status, 'approved');

    await writeFile(join(repositoryRoot, 'next.txt'), 'next commit\n');
    await git(repositoryRoot, ['add', 'next.txt']);
    await git(repositoryRoot, ['commit', '-m', 'invalidate scoped origin']);
    const invalidatedOrigin = await approvals.consume(
      origin.requestId,
      origin.envelope.body.project.commit,
    );
    assert.equal(invalidatedOrigin.status, 'invalidated');
    assert.equal(invalidatedOrigin.reason, 'commit_changed');

    const persisted = JSON.parse(await readFile(approvals.storagePath, 'utf8'));
    const childAfterInvalidation = persisted.approvals.find((record) => record.id === child.requestId);
    assert.deepEqual(persisted.scopes, []);
    assert.equal(childAfterInvalidation.status, 'invalidated');
    assert.equal(childAfterInvalidation.invalidatedReason, 'scope_revoked');
    assert.equal(childAfterInvalidation.scopeId, null);

    const consumedChild = await approvals.consume(
      child.requestId,
      child.envelope.body.project.commit,
    );
    assert.equal(consumedChild.status, 'invalidated');
    assert.equal(consumedChild.reason, 'scope_revoked');

    const retry = await engine.evaluate(requestFor(repositoryRoot));
    assert.equal(retry.status, 'approval_required');
  });
});

test('invalidates an approval when its signed target becomes an external symlink', async () => {
  await withApprovalSystem(async ({ approvals, engine, repositoryRoot, vault }) => {
    await activateCredential(vault);
    const ignoredDirectory = join(repositoryRoot, 'ignored-deploy');
    await mkdir(ignoredDirectory);
    await writeFile(join(ignoredDirectory, 'index.html'), '<h1>Ignored</h1>\n');
    await writeFile(join(repositoryRoot, '.gitignore'), 'ignored-deploy\n');
    await git(repositoryRoot, ['add', '.gitignore']);
    await git(repositoryRoot, ['commit', '-m', 'ignore deploy directory']);

    const decision = await engine.evaluate(requestFor(repositoryRoot, {
      params: { directory: 'ignored-deploy', project: 'keyguard-site' },
    }));
    assert.equal(decision.status, 'approval_required');
    await approvals.approveOnce(decision.requestId);

    const externalDirectory = await mkdtemp(join(tmpdir(), 'atomical-keyguard-external-target-'));
    try {
      await rm(ignoredDirectory, { force: true, recursive: true });
      await symlink(externalDirectory, ignoredDirectory);

      const consumed = await approvals.consume(
        decision.requestId,
        decision.envelope.body.project.commit,
      );
      assert.equal(consumed.status, 'invalidated');
      assert.equal(consumed.reason, 'target_changed');
    } finally {
      await rm(externalDirectory, { force: true, recursive: true });
    }
  });
});

test('returns a deeply frozen approval envelope for provider execution', async () => {
  await withApprovalSystem(async ({ approvals, engine, repositoryRoot, vault }) => {
    await activateCredential(vault);
    const decision = await engine.evaluate(requestFor(repositoryRoot));
    await approvals.approveOnce(decision.requestId);

    const consumed = await approvals.consume(
      decision.requestId,
      decision.envelope.body.project.commit,
    );

    assert.equal(consumed.status, 'approved');
    assert.equal(Object.isFrozen(consumed), true);
    assert.equal(Object.isFrozen(consumed.envelope), true);
    assert.equal(Object.isFrozen(consumed.envelope.body), true);
    assert.equal(Object.isFrozen(consumed.envelope.body.target), true);
    assert.throws(() => {
      consumed.envelope.body.target.project = 'other-site';
    }, TypeError);
    assert.equal(consumed.envelope.body.target.project, 'keyguard-site');
  });
});

test('fails closed if a persisted reusable scope no longer matches its signed envelope', async () => {
  await withApprovalSystem(async ({
    approvals,
    clock,
    dataDirectory,
    engine,
    identity,
    repositoryRoot,
    vault,
  }) => {
    await activateCredential(vault);
    await engine.evaluate(requestFor(repositoryRoot));
    const persisted = JSON.parse(await readFile(approvals.storagePath, 'utf8'));
    persisted.approvals[0].scopeProposal.target.project = 'other-site';
    await writeFile(approvals.storagePath, JSON.stringify(persisted), { mode: 0o600 });

    await assert.rejects(
      ApprovalService.open({ clock, dataDirectory, identity, vault }),
      /Approval is unavailable\./,
    );
  });
});

test('fails closed when persisted scope state has a denied originating approval', async () => {
  await withApprovalSystem(async ({
    approvals,
    clock,
    dataDirectory,
    engine,
    identity,
    repositoryRoot,
    vault,
  }) => {
    await activateCredential(vault);
    const decision = await engine.evaluate(requestFor(repositoryRoot));
    await approvals.approveScope(decision.requestId, decision.scope);
    const persisted = JSON.parse(await readFile(approvals.storagePath, 'utf8'));
    persisted.approvals[0].status = 'denied';
    await writeFile(approvals.storagePath, JSON.stringify(persisted), { mode: 0o600 });

    await assert.rejects(
      ApprovalService.open({ clock, dataDirectory, identity, vault }),
      /Approval is unavailable\./,
    );
  });
});

async function withApprovalSystem(run) {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    await withTemporaryRepository(async (repositoryRoot) => {
      const clock = controllableClock(INITIAL_TIME);
      const [identity, vault] = await Promise.all([
        LocalIdentity.open({ dataDirectory }),
        SealedVault.open({ clock, dataDirectory }),
      ]);
      const registry = createActionRegistry({
        approvedProjectRoots: [repositoryRoot],
        integrations: [createCloudflarePagesIntegration()],
      });
      const approvals = await ApprovalService.open({
        actionRegistry: registry,
        clock,
        dataDirectory,
        identity,
        vault,
      });
      const engine = new PolicyEngine({
        approvalService: approvals,
        clock,
        gitInspector: new GitInspector(),
        identity,
        registry,
        vault,
      });

      await run({ approvals, clock, dataDirectory, engine, identity, repositoryRoot, vault });
    });
  });
}

async function activateCredential(vault) {
  await vault.put({ label: 'cloudflare-api-token', provider: 'cloudflare' }, 'test-only-deploy-secret');
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
  const repositoryRoot = await mkdtemp(join(tmpdir(), 'atomical-keyguard-approvals-'));

  try {
    await git(repositoryRoot, ['init']);
    await git(repositoryRoot, ['config', 'user.email', 'tests@example.invalid']);
    await git(repositoryRoot, ['config', 'user.name', 'Atomical Keyguard Tests']);
    await mkdir(join(repositoryRoot, 'dist'), { recursive: true });
    await Promise.all([
      writeFile(join(repositoryRoot, 'README.md'), '# Approval test repository\n'),
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
