import assert from 'node:assert/strict';
import test from 'node:test';

import { createKeyguardApp } from '../src/bootstrap.mjs';
import { canonicalJson, sha256 } from '../src/core/canonical.mjs';
import { KeyguardError } from '../src/core/errors.mjs';
import { assertNoSecretBearingFields, withTemporaryDataDirectory } from './helpers.mjs';

test('status reports only loopback configuration, a public fingerprint, and persistent setup without secret-bearing fields', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    const secretSentinel = 'must-not-appear-in-public-status';
    const app = await createKeyguardApp({
      clock: { now: () => new Date('2026-07-14T00:00:00.000Z') },
      dataDirectory,
      environmentDiscovery: async () => ({ secretSentinel }),
      providerRunner: async () => {
        throw new Error(secretSentinel);
      },
    });

    const status = app.status();

    assert.deepEqual(status.server, {
      host: '127.0.0.1',
      port: 4545,
      url: 'http://127.0.0.1:4545',
    });
    assert.equal(status.state, 'stopped');
    assert.match(status.identity.fingerprint, /^[a-f0-9]{64}$/u);
    assert.deepEqual(status.setup, { complete: false });
    assertNoSecretBearingFields(status);
    assert.doesNotMatch(JSON.stringify(status), new RegExp(secretSentinel));

    await app.services.setup.complete('project');
    assert.deepEqual(app.status().setup, { complete: true, scope: 'project' });

    const reopened = await createKeyguardApp({
      clock: { now: () => new Date('2026-07-14T00:00:00.000Z') },
      dataDirectory,
      environmentDiscovery: async () => ({ secretSentinel }),
      providerRunner: async () => {
        throw new Error(secretSentinel);
      },
    });
    assert.deepEqual(reopened.status().setup, { complete: true, scope: 'project' });
  });
});

test('canonical JSON sorts record keys before SHA-256 hashing', () => {
  assert.equal(
    canonicalJson({ nested: { z: true, a: null }, b: 2, a: 1 }),
    '{"a":1,"b":2,"nested":{"a":null,"z":true}}',
  );
  assert.equal(
    sha256({ b: 2, a: 1 }),
    '43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777',
  );
});

test('canonical JSON rejects sparse arrays', () => {
  assert.throws(
    () => canonicalJson([1, , 2]),
    /Canonical JSON does not support sparse arrays/,
  );
});

test('canonical JSON rejects accessor properties without invoking getters', () => {
  let getterCalls = 0;
  const record = {
    get value() {
      getterCalls += 1;
      return getterCalls;
    },
  };

  assert.throws(
    () => canonicalJson(record),
    /Canonical JSON does not support accessor properties/,
  );
  assert.equal(getterCalls, 0);
});

test('KeyguardError serializes only its typed safe fields', () => {
  const error = new KeyguardError({
    code: 'invalid_configuration',
    requestId: 'req_123',
    retryable: false,
    safeMessage: 'Keyguard configuration is invalid.',
  });

  assert.equal(error.name, 'KeyguardError');
  assert.deepEqual(error.toSafeResponse(), {
    code: 'invalid_configuration',
    requestId: 'req_123',
    retryable: false,
    safeMessage: 'Keyguard configuration is invalid.',
  });
  assert.equal('cause' in error.toSafeResponse(), false);
  assert.equal('stack' in error.toSafeResponse(), false);
});

test('KeyguardError rejects values outside its public response shape', () => {
  assert.throws(
    () => new KeyguardError({ code: 1, safeMessage: 'Configuration is invalid.' }),
    /code must be a string/,
  );
  assert.throws(
    () => new KeyguardError({ code: 'invalid_configuration', safeMessage: { token: 'sentinel' } }),
    /safeMessage must be a string/,
  );
  assert.throws(
    () => new KeyguardError({
      code: 'invalid_configuration',
      requestId: { id: 'req_123' },
      safeMessage: 'Configuration is invalid.',
    }),
    /requestId must be a string when provided/,
  );
  assert.throws(
    () => new KeyguardError({
      code: 'invalid_configuration',
      retryable: 'false',
      safeMessage: 'Configuration is invalid.',
    }),
    /retryable must be a boolean/,
  );
});
