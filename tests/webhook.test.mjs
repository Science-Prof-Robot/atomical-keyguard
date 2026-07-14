import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import test from 'node:test';

import { canonicalJson } from '../src/core/canonical.mjs';
import { DepositService } from '../src/services/deposits.mjs';
import { JsonStore } from '../src/storage/json-store.mjs';
import { SealedVault } from '../src/storage/sealed-vault.mjs';
import { assertNoSecretBearingFields, withTemporaryDataDirectory } from './helpers.mjs';

const INITIAL_TIME = '2026-07-14T12:00:00.000Z';
const LABEL = 'cloudflare-api-token';
const PROVIDER = 'cloudflare';

test('creates a test-demo transient link and seals a verified webhook without retaining its URL or value', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    const system = await createDepositSystem({ dataDirectory });
    const secret = 'webhook-value-must-not-escape';
    const created = await system.service.create({ label: LABEL, provider: PROVIDER });

    assert.deepEqual(Object.keys(created).sort(), ['depositUrl', 'expiresAt', 'label', 'status']);
    assert.equal(created.label, LABEL);
    assert.equal(created.status, 'pending');
    assert.match(created.depositUrl, /^https:\/\/demo\.example\/deposit\//u);
    assert.equal('handoffId' in created, false);
    assert.equal(system.gatewayCalls.length, 1);
    assert.deepEqual(await system.service.list(), [{
      expiresAt: created.expiresAt,
      label: LABEL,
      status: 'pending',
    }]);
    const pendingPersisted = await readFile(system.service.storagePath, 'utf8');
    assert.equal(pendingPersisted.includes(created.depositUrl), false);
    assert.equal(pendingPersisted.includes('depositUrl'), false);

    const event = depositEvent(system.gatewayCalls[0].handoffId, secret);
    const headers = signedHeaders(system.clock, event);
    const projection = await system.service.receiveSigned(event, headers);

    assert.equal(system.verifierCalls.length, 1);
    assert.equal(system.verifierCalls[0].signedPayload, canonicalJson({
      agentId: 'trusted-agent.example',
      event,
      signatureTime: headers['x-agent-sig-time'],
    }));
    assert.deepEqual(Object.keys(projection).sort(), [
      'createdAt',
      'instanceId',
      'label',
      'status',
      'updatedAt',
    ]);
    assert.equal(projection.label, LABEL);
    assert.equal(projection.status, 'active');
    assertNoSecretBearingFields(projection);
    assert.equal(JSON.stringify(projection).includes(secret), false);
    assert.deepEqual(await system.service.list(), []);
    assert.equal(await system.vault.readForExecution(LABEL), secret);

    const persisted = await readFile(system.service.storagePath, 'utf8');
    assert.equal(persisted.includes(secret), false);
    assert.equal(persisted.includes(created.depositUrl), false);
    assert.equal(persisted.includes('depositUrl'), false);
  });
});

test('fails closed without an explicitly configured test-demo gateway and rejects non-allowlisted deposit metadata', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    const clock = controllableClock(INITIAL_TIME);
    const vault = await SealedVault.open({ clock, dataDirectory });
    const unavailable = await DepositService.open({
      clock,
      dataDirectory,
      trustedPublicKeyVerifier: async () => true,
      vault,
    });

    await assert.rejects(
      unavailable.create({ label: LABEL }),
      safeUnavailable(),
    );
    assert.deepEqual(await unavailable.list(), []);

    const system = await createDepositSystem({ dataDirectory, vault });
    await assert.rejects(
      system.service.create({ label: 'github-token', provider: 'github' }),
      safeUnavailable(),
    );
    await assert.rejects(
      system.service.create({ label: LABEL, provider: PROVIDER, description: 'untrusted metadata' }),
      safeUnavailable(),
    );
    assert.equal(system.gatewayCalls.length, 0);
  });
});

test('rejects a plaintext remote URL from an explicit sealed-local test-demo gateway', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    const system = await createDepositSystem({
      atomicalGateway: Object.freeze({
        configured: true,
        createDepositLink: async () => ({ url: 'http://example.test/deposit/one-time' }),
        isPublicDepositBox: false,
        kind: 'sealed-local-test-demo',
      }),
      dataDirectory,
    });

    await assert.rejects(
      system.service.create({ label: LABEL, provider: PROVIDER }),
      safeUnavailable(),
    );
    assert.deepEqual(await system.service.list(), []);
    assert.equal((await readFile(system.service.storagePath, 'utf8')).includes('example.test'), false);
  });
});

test('rejects missing, malformed, stale, future, unsigned, and wrong-token webhooks without consuming the handoff', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    let verifierAccepts = false;
    const system = await createDepositSystem({
      dataDirectory,
      maxWebhookAgeMilliseconds: 1_000,
      trustedPublicKeyVerifier: async (request) => {
        system.verifierCalls.push(request);
        return verifierAccepts;
      },
      webhookToken: 'fixed-webhook-token',
    });
    const created = await system.service.create({ label: LABEL, provider: PROVIDER });
    const event = depositEvent(system.gatewayCalls[0].handoffId, 'secret-for-invalid-webhook-tests');
    const validHeaders = {
      ...signedHeaders(system.clock, event),
      'x-webhook-token': 'fixed-webhook-token',
    };

    await assert.rejects(system.service.receiveSigned(event, {}), safeUnavailable());
    await assert.rejects(
      system.service.receiveSigned(event, { ...validHeaders, 'x-agent-sig': 'not a signature!' }),
      safeUnavailable(),
    );
    await assert.rejects(
      system.service.receiveSigned(event, {
        ...validHeaders,
        'x-agent-sig-time': new Date(system.clock.now().valueOf() - 1_001).toISOString(),
      }),
      safeUnavailable(),
    );
    await assert.rejects(
      system.service.receiveSigned(event, {
        ...validHeaders,
        'x-agent-sig-time': new Date(system.clock.now().valueOf() + 1_001).toISOString(),
      }),
      safeUnavailable(),
    );
    await assert.rejects(
      system.service.receiveSigned(event, { ...validHeaders, 'x-webhook-token': 'wrong-token' }),
      safeUnavailable(),
    );
    await assert.rejects(system.service.receiveSigned(event, validHeaders), safeUnavailable());
    assert.deepEqual(await system.service.list(), [{
      expiresAt: created.expiresAt,
      label: LABEL,
      status: 'pending',
    }]);

    verifierAccepts = true;
    const projection = await system.service.receiveSigned(event, validHeaders);
    assert.equal(projection.label, LABEL);
    assert.deepEqual(await system.service.list(), []);
  });
});

test('removes expired handoffs and permits exactly one concurrent, non-replayable receipt', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    const system = await createDepositSystem({ dataDirectory, depositTtlMilliseconds: 1_000 });
    await system.service.create({ label: LABEL, provider: PROVIDER });
    const expiredEvent = depositEvent(system.gatewayCalls[0].handoffId, 'expired-handoff-secret');
    system.clock.advance(1_001);

    await assert.rejects(
      system.service.receiveSigned(expiredEvent, signedHeaders(system.clock, expiredEvent)),
      safeUnavailable(),
    );
    assert.deepEqual(await system.service.list(), []);

    const created = await system.service.create({ label: LABEL, provider: PROVIDER });
    const event = depositEvent(system.gatewayCalls[1].handoffId, 'one-time-deposit-secret');
    const headers = signedHeaders(system.clock, event);
    const outcomes = await Promise.allSettled([
      system.service.receiveSigned(event, headers),
      system.service.receiveSigned(event, headers),
    ]);

    assert.equal(outcomes.filter((outcome) => outcome.status === 'fulfilled').length, 1);
    assert.equal(outcomes.filter((outcome) => outcome.status === 'rejected').length, 1);
    await assert.rejects(system.service.receiveSigned(event, headers), safeUnavailable());
    assert.equal(await system.vault.readForExecution(LABEL), 'one-time-deposit-secret');
    assert.deepEqual(await system.service.list(), []);
    assert.equal(created.depositUrl.includes('one-time-deposit-secret'), false);
  });
});

test('claims a valid receipt before any vault read and makes it non-replayable', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    const backingVault = await SealedVault.open({
      clock: controllableClock(INITIAL_TIME),
      dataDirectory,
    });
    const guardedVault = rejectArmedVaultLists(backingVault);
    const system = await createDepositSystem({ dataDirectory, vault: guardedVault });
    const secret = 'claim-before-vault-read-secret';
    await system.service.create({ label: LABEL, provider: PROVIDER });
    const event = depositEvent(system.gatewayCalls[0].handoffId, secret);
    const headers = signedHeaders(system.clock, event);

    guardedVault.armListFailure();
    const projection = await system.service.receiveSigned(event, headers);

    assert.equal(projection.status, 'active');
    assert.equal(guardedVault.armedListCalls, 0);
    assert.equal(await backingVault.readForExecution(LABEL), secret);
    await assert.rejects(system.service.receiveSigned(event, headers), safeUnavailable());
  });
});

test('keeps an active claim isolated from an invalid concurrent receipt and never replays it', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    const backingVault = await SealedVault.open({
      clock: controllableClock(INITIAL_TIME),
      dataDirectory,
    });
    const pausingVault = pauseFirstConditionalVaultWrite(backingVault);
    const system = await createDepositSystem({ dataDirectory, vault: pausingVault });
    const created = await system.service.create({ label: LABEL, provider: PROVIDER });
    const event = depositEvent(system.gatewayCalls[0].handoffId, 'race-replay-secret');
    const headers = signedHeaders(system.clock, event);
    const receipt = system.service.receiveSigned(event, headers);

    await pausingVault.waitForFirstWrite();
    await assert.rejects(system.service.receiveSigned({}, {}), safeUnavailable());
    pausingVault.releaseFirstWrite();

    const projection = await receipt;
    assert.equal(projection.status, 'active');
    assert.deepEqual(await system.service.list(), []);
    const persisted = await readFile(system.service.storagePath, 'utf8');
    assert.deepEqual(JSON.parse(persisted).handoffs, []);
    assert.equal(persisted.includes('race-replay-secret'), false);
    assert.equal(persisted.includes(created.depositUrl), false);

    await backingVault.delete(LABEL);
    await assert.rejects(system.service.receiveSigned(event, headers), safeUnavailable());
    await assert.rejects(backingVault.readForExecution(LABEL));
  });
});

test('retains a failed post-seal cleanup claim until expiry without exposing or replaying the deposit', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    const store = failOnceWhenSealedHandoffIsRemoved(dataDirectory);
    const system = await createDepositSystem({
      dataDirectory,
      depositTtlMilliseconds: 1_000,
      store,
    });
    const secret = 'sealed-before-simulated-discard-failure';
    const created = await system.service.create({ label: LABEL, provider: PROVIDER });
    const event = depositEvent(system.gatewayCalls[0].handoffId, secret);

    const projection = await system.service.receiveSigned(event, signedHeaders(system.clock, event));

    assert.equal(store.failureCount, 1);
    assert.equal(projection.status, 'active');
    assert.equal(await system.vault.readForExecution(LABEL), secret);
    assert.deepEqual(await system.service.list(), []);
    const persisted = await readFile(system.service.storagePath, 'utf8');
    assert.deepEqual(JSON.parse(persisted).handoffs.map((handoff) => handoff.status), ['claimed']);
    assert.equal(persisted.includes(secret), false);
    assert.equal(persisted.includes(created.depositUrl), false);
    await assert.rejects(
      system.service.receiveSigned(event, signedHeaders(system.clock, event)),
      safeUnavailable(),
    );

    await system.vault.delete(LABEL);
    await assert.rejects(
      system.service.create({ label: LABEL, provider: PROVIDER }),
      safeUnavailable(),
    );
    system.clock.advance(1_001);
    const replacement = await system.service.create({ label: LABEL, provider: PROVIDER });
    assert.match(replacement.depositUrl, /^https:\/\/demo\.example\/deposit\//u);
  });
});

test('quarantines a sealed handoff across repeated cleanup failures, credential deletion, restart, and replay', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    const store = failEveryHandoffRemoval(dataDirectory);
    const system = await createDepositSystem({ dataDirectory, store });
    const secret = 'sealed-before-persistent-cleanup-failure';
    const created = await system.service.create({ label: LABEL, provider: PROVIDER });
    const event = depositEvent(system.gatewayCalls[0].handoffId, secret);
    const headers = signedHeaders(system.clock, event);

    const projection = await system.service.receiveSigned(event, headers);

    assert.equal(projection.status, 'active');
    assert.equal(await system.vault.readForExecution(LABEL), secret);
    const persisted = await readFile(system.service.storagePath, 'utf8');
    assert.deepEqual(JSON.parse(persisted).handoffs.map((handoff) => handoff.status), ['claimed']);
    assert.equal(persisted.includes(secret), false);
    assert.equal(persisted.includes(created.depositUrl), false);

    await system.vault.delete(LABEL);
    const reopened = await createDepositSystem({
      clock: system.clock,
      dataDirectory,
    });

    await assert.rejects(reopened.service.receiveSigned(event, headers), safeUnavailable());
    await assert.rejects(reopened.vault.readForExecution(LABEL));
  });
});

test('quarantines a failed pre-seal handoff until expiry instead of retrying it', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    const vault = await SealedVault.open({
      clock: controllableClock(INITIAL_TIME),
      dataDirectory,
    });
    const retryingVault = failOnceBeforeConditionalVaultWrite(vault);
    const system = await createDepositSystem({
      dataDirectory,
      depositTtlMilliseconds: 1_000,
      vault: retryingVault,
    });
    const secret = 'retry-after-pre-seal-storage-failure';
    const created = await system.service.create({ label: LABEL, provider: PROVIDER });
    const event = depositEvent(system.gatewayCalls[0].handoffId, secret);
    const headers = signedHeaders(system.clock, event);

    await assert.rejects(system.service.receiveSigned(event, headers), safeUnavailable());
    assert.equal(retryingVault.failureCount, 1);
    assert.deepEqual(await system.service.list(), []);
    await assert.rejects(vault.readForExecution(LABEL));
    const persisted = await readFile(system.service.storagePath, 'utf8');
    assert.deepEqual(JSON.parse(persisted).handoffs.map((handoff) => handoff.status), ['claimed']);
    assert.equal(persisted.includes(secret), false);
    assert.equal(persisted.includes(created.depositUrl), false);

    await assert.rejects(system.service.receiveSigned(event, headers), safeUnavailable());
    assert.equal(retryingVault.failureCount, 1);
    system.clock.advance(1_001);
    const replacement = await system.service.create({ label: LABEL, provider: PROVIDER });
    assert.match(replacement.depositUrl, /^https:\/\/demo\.example\/deposit\//u);
  });
});

test('replaces an active credential atomically through an instance-bound deposit handoff', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    const system = await createDepositSystem({ dataDirectory });
    const original = await system.vault.put({ label: LABEL, provider: PROVIDER }, 'old-active-value');
    const replacementValue = 'replacement-value-never-projected';
    const created = await system.service.create({ label: LABEL, provider: PROVIDER });
    const event = depositEvent(system.gatewayCalls[0].handoffId, replacementValue);

    assert.equal(await system.vault.readForExecution(LABEL), 'old-active-value');
    const projection = await system.service.receiveSigned(event, signedHeaders(system.clock, event));

    assert.equal(projection.status, 'active');
    assert.notEqual(projection.instanceId, original.instanceId);
    assertNoSecretBearingFields(projection);
    assert.equal(await system.vault.readForExecution(LABEL), replacementValue);
    const persisted = await readFile(system.service.storagePath, 'utf8');
    assert.equal(persisted.includes('old-active-value'), false);
    assert.equal(persisted.includes(replacementValue), false);
    assert.equal(persisted.includes(created.depositUrl), false);
  });
});

test('fails closed when a captured credential instance changes before webhook receipt', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    const system = await createDepositSystem({ dataDirectory });
    const initial = await system.vault.put({ label: LABEL, provider: PROVIDER }, 'initial-rotation-value');
    await system.service.create({ label: LABEL, provider: PROVIDER });
    const event = depositEvent(system.gatewayCalls[0].handoffId, 'stale-webhook-rotation-value');
    const concurrent = await system.vault.putIfCurrentInstance(
      { label: LABEL, provider: PROVIDER },
      'concurrent-rotation-value',
      initial.instanceId,
    );

    await assert.rejects(
      system.service.receiveSigned(event, signedHeaders(system.clock, event)),
      safeUnavailable(),
    );
    assert.equal(concurrent.status, 'active');
    assert.equal(await system.vault.readForExecution(LABEL), 'concurrent-rotation-value');
    assert.deepEqual(await system.service.list(), []);
    const persisted = await readFile(system.service.storagePath, 'utf8');
    assert.equal(persisted.includes('stale-webhook-rotation-value'), false);
    assert.equal(persisted.includes('concurrent-rotation-value'), false);
  });
});

test('fails closed when no trusted public-key verifier is injected', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    const system = await createDepositSystem({
      dataDirectory,
      trustedPublicKeyVerifier: undefined,
    });
    await system.service.create({ label: LABEL, provider: PROVIDER });
    const event = depositEvent(system.gatewayCalls[0].handoffId, 'unverified-secret');

    await assert.rejects(
      system.service.receiveSigned(event, signedHeaders(system.clock, event)),
      safeUnavailable(),
    );
    assert.equal((await system.service.list()).length, 1);
  });
});

async function createDepositSystem(options = {}) {
  const clock = options.clock ?? controllableClock(INITIAL_TIME);
  const vault = options.vault ?? await SealedVault.open({
    clock,
    dataDirectory: options.dataDirectory,
  });
  const gatewayCalls = [];
  const verifierCalls = [];
  const atomicalGateway = options.atomicalGateway ?? testDemoGateway(gatewayCalls);
  const trustedPublicKeyVerifier = Object.hasOwn(options, 'trustedPublicKeyVerifier')
    ? options.trustedPublicKeyVerifier
    : async (request) => {
      verifierCalls.push(request);
      return request.agentId === 'trusted-agent.example'
        && request.signature === 'c2lnbmVkLXdlYmhvb2stcGF5bG9hZA'
        && request.signedPayload === canonicalJson({
          agentId: request.agentId,
          event: request.event,
          signatureTime: request.signatureTime,
        });
    };
  const service = await DepositService.open({
    atomicalGateway,
    clock,
    dataDirectory: options.dataDirectory,
    depositTtlMilliseconds: options.depositTtlMilliseconds,
    maxWebhookAgeMilliseconds: options.maxWebhookAgeMilliseconds,
    trustedPublicKeyVerifier,
    vault,
    webhookToken: options.webhookToken,
    store: options.store,
  });

  return {
    clock,
    gatewayCalls,
    service,
    vault,
    verifierCalls,
  };
}

function testDemoGateway(calls) {
  return Object.freeze({
    configured: true,
    createDepositLink: async (request) => {
      calls.push({ ...request });
      return { url: `https://demo.example/deposit/${request.handoffId}` };
    },
    isPublicDepositBox: false,
    kind: 'sealed-local-test-demo',
  });
}

function failOnceWhenSealedHandoffIsRemoved(dataDirectory) {
  const backingStore = new JsonStore(join(dataDirectory, 'deposits.json'));
  let failureCount = 0;
  return {
    get failureCount() {
      return failureCount;
    },
    initialize: (...args) => backingStore.initialize(...args),
    update: async (updater) => backingStore.update(async (state) => {
      const before = JSON.parse(JSON.stringify(state));
      const next = await updater(state);
      const removedHandoff = before.handoffs.some((handoff) => handoff.status === 'claimed')
        && next.handoffs.length < before.handoffs.length;
      if (failureCount === 0 && removedHandoff) {
        failureCount += 1;
        throw new Error('simulated post-seal discard failure');
      }
      return next;
    }),
  };
}

function failEveryHandoffRemoval(dataDirectory) {
  const backingStore = new JsonStore(join(dataDirectory, 'deposits.json'));
  return {
    initialize: (...args) => backingStore.initialize(...args),
    update: async (updater) => backingStore.update(async (state) => {
      const before = JSON.parse(JSON.stringify(state));
      const next = await updater(state);
      if (next.handoffs.length < before.handoffs.length) {
        throw new Error('simulated persistent handoff cleanup failure');
      }
      return next;
    }),
  };
}

function failOnceBeforeConditionalVaultWrite(vault) {
  let failureCount = 0;
  return {
    get failureCount() {
      return failureCount;
    },
    list: (...args) => vault.list(...args),
    putIfCurrentInstance: async (...args) => {
      if (failureCount === 0) {
        failureCount += 1;
        throw new Error('simulated pre-seal vault failure');
      }
      return vault.putIfCurrentInstance(...args);
    },
  };
}

function rejectArmedVaultLists(vault) {
  let armed = false;
  let armedListCalls = 0;
  return {
    get armedListCalls() {
      return armedListCalls;
    },
    armListFailure() {
      armed = true;
    },
    list: async (...args) => {
      if (armed) {
        armedListCalls += 1;
        throw new Error('vault.list must not run after receipt validation');
      }
      return vault.list(...args);
    },
    putIfCurrentInstance: (...args) => vault.putIfCurrentInstance(...args),
  };
}

function pauseFirstConditionalVaultWrite(vault) {
  let firstWriteEntered;
  const firstWriteEnteredPromise = new Promise((resolvePromise) => {
    firstWriteEntered = resolvePromise;
  });
  let releaseFirstWrite;
  const firstWriteGate = new Promise((resolvePromise) => {
    releaseFirstWrite = resolvePromise;
  });
  let writeCount = 0;

  return {
    list: (...args) => vault.list(...args),
    putIfCurrentInstance: async (...args) => {
      writeCount += 1;
      if (writeCount === 1) {
        firstWriteEntered();
        await firstWriteGate;
      }
      return vault.putIfCurrentInstance(...args);
    },
    releaseFirstWrite,
    waitForFirstWrite: () => firstWriteEnteredPromise,
  };
}

function depositEvent(handoffId, secret) {
  return {
    handoffId,
    label: LABEL,
    secret,
    type: 'deposit.received',
  };
}

function signedHeaders(clock) {
  return {
    'x-agent-id': 'trusted-agent.example',
    'x-agent-sig': 'c2lnbmVkLXdlYmhvb2stcGF5bG9hZA',
    'x-agent-sig-time': clock.now().toISOString(),
  };
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

function safeUnavailable() {
  return (error) => {
    assert.equal(error?.code, 'deposit_unavailable');
    assert.equal(error?.message, 'Deposit is unavailable.');
    return true;
  };
}
