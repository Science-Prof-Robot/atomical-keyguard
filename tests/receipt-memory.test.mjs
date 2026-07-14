import assert from 'node:assert/strict';
import test from 'node:test';

import { LocalIdentity } from '../src/identity/local-identity.mjs';
import { ACTION_NAME } from '../src/policy/action-registry.mjs';
import { ActivityService } from '../src/services/activity.mjs';
import { MemoryService } from '../src/services/memory.mjs';
import { withTemporaryDataDirectory } from './helpers.mjs';

const FIXED_TIME = '2026-07-14T12:00:00.000Z';

test('memory accepts only a signed verified receipt and requires explicit Save or Dismiss', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    const clock = { now: () => new Date(FIXED_TIME) };
    const identity = await LocalIdentity.open({ dataDirectory });
    const memory = await MemoryService.open({ clock, dataDirectory, identity });
    const receipt = signedReceipt(identity);

    const candidate = await memory.createVerifiedCandidate(receipt);

    assert.equal(candidate.status, 'candidate');
    assert.equal(candidate.scope.kind, 'project');
    assert.deepEqual(candidate.scope, {
      kind: 'project',
      repositoryFingerprint: 'b'.repeat(64),
    });
    assert.equal(JSON.stringify(candidate).includes('/approved/project'), false);
    assert.equal(candidate.sourceReceiptId, receipt.id);
    assert.match(candidate.sourceReceiptHash, /^[a-f0-9]{64}$/);
    assert.equal(candidate.sourceSignerFingerprint, identity.fingerprint);
    assert.equal(
      candidate.text,
      'Verified Cloudflare Pages deployment for keyguard-site at aaaaaaaaaaaa.',
    );
    assert.equal(identity.verifyCanonical(memoryBody(candidate), candidate.signature), true);

    const saved = await memory.save(candidate.id);
    assert.equal(saved.status, 'saved');
    assert.equal(identity.verifyCanonical(memoryBody(saved), saved.signature), true);

    const dismissedCandidate = await memory.createVerifiedCandidate({
      ...receipt,
      id: 'receipt_87654321',
      signature: identity.signCanonical({ ...receiptBody(receipt), id: 'receipt_87654321' }),
    });
    const dismissed = await memory.dismiss(dismissedCandidate.id);
    assert.equal(dismissed.status, 'dismissed');

    const unsignedFailure = {
      ...receipt,
      verification: { status: 'failed' },
    };
    assert.equal(await memory.createVerifiedCandidate(unsignedFailure), undefined);
    assert.deepEqual((await memory.list()).map((entry) => entry.status), ['saved', 'dismissed']);
  });
});

test('memory rejects a locally signed receipt with mismatched claimed agent identity', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    const identity = await LocalIdentity.open({ dataDirectory });
    const memory = await MemoryService.open({
      clock: { now: () => new Date(FIXED_TIME) },
      dataDirectory,
      identity,
    });
    const receipt = signedReceipt(identity);
    const body = {
      ...receiptBody(receipt),
      agent: {
        ...receipt.agent,
        identity: 'f'.repeat(64),
      },
    };
    const mismatchedReceipt = {
      ...body,
      signature: identity.signCanonical(body),
    };

    assert.equal(await memory.createVerifiedCandidate(mismatchedReceipt), undefined);
  });
});

test('activity is append-only and accepts only typed secret-free milestones', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    const activity = await ActivityService.open({
      clock: { now: () => new Date(FIXED_TIME) },
      dataDirectory,
    });
    const milestone = await activity.append({
      action: ACTION_NAME,
      receiptId: null,
      requestId: 'approval_12345678',
      stage: 'preparing',
      status: 'started',
    });

    assert.equal(Object.isFrozen(milestone), true);
    assert.deepEqual(await activity.list(), [milestone]);
    await assert.rejects(
      activity.append({
        action: ACTION_NAME,
        message: 'provider output must never persist',
        receiptId: null,
        requestId: 'approval_12345678',
        stage: 'preparing',
        status: 'started',
      }),
      /activity/i,
    );
    assert.equal(JSON.stringify(await activity.list()).includes('provider output'), false);
  });
});

function signedReceipt(identity) {
  const body = {
    action: ACTION_NAME,
    agent: {
      id: 'codex-test-agent',
      identity: identity.fingerprint,
    },
    approval: {
      id: 'approval_12345678',
      status: 'consumed',
    },
    commit: 'a'.repeat(40),
    credentialLabel: 'cloudflare-api-token',
    dirtyTreeAllowed: false,
    id: 'receipt_12345678',
    provider: {
      status: 'succeeded',
    },
    repository: {
      fingerprint: 'b'.repeat(64),
      root: '/approved/project',
    },
    request: {
      envelopeHash: 'c'.repeat(64),
      id: 'approval_12345678',
      signature: identity.signCanonical({ kind: 'test-request-signature' }),
    },
    retryOf: null,
    secretExposedToModel: false,
    target: {
      directory: '/approved/project/dist',
      project: 'keyguard-site',
    },
    timestamps: {
      executedAt: FIXED_TIME,
      requestedAt: FIXED_TIME,
    },
    verification: {
      status: 'verified',
    },
    verificationOf: null,
  };
  return Object.freeze({ ...body, signature: identity.signCanonical(body) });
}

function receiptBody(receipt) {
  const { signature, ...body } = receipt;
  return body;
}

function memoryBody(memory) {
  const { signature, ...body } = memory;
  return body;
}
