import assert from 'node:assert/strict';
import test from 'node:test';

import { KeyguardError } from '../src/core/errors.mjs';

test('constructs an error with the required fields and defaults', () => {
  const error = new KeyguardError({ code: 'E_CODE', safeMessage: 'A safe message.' });

  assert.ok(error instanceof KeyguardError);
  assert.ok(error instanceof Error);
  assert.equal(error.name, 'KeyguardError');
  assert.equal(error.code, 'E_CODE');
  assert.equal(error.safeMessage, 'A safe message.');
  assert.equal(error.message, 'A safe message.');
  assert.equal(error.retryable, false);
  assert.equal(error.requestId, undefined);
});

test('retains an explicit requestId and retryable flag', () => {
  const error = new KeyguardError({
    code: 'E_RETRY',
    safeMessage: 'Try later.',
    requestId: 'req-123',
    retryable: true,
  });

  assert.equal(error.requestId, 'req-123');
  assert.equal(error.retryable, true);
});

test('toSafeResponse omits requestId when it was not provided', () => {
  const error = new KeyguardError({ code: 'E_CODE', safeMessage: 'msg' });

  assert.deepEqual(error.toSafeResponse(), {
    code: 'E_CODE',
    retryable: false,
    safeMessage: 'msg',
  });
});

test('toSafeResponse includes requestId when provided', () => {
  const error = new KeyguardError({
    code: 'E_CODE',
    safeMessage: 'msg',
    requestId: 'req-9',
    retryable: true,
  });

  assert.deepEqual(error.toSafeResponse(), {
    code: 'E_CODE',
    retryable: true,
    safeMessage: 'msg',
    requestId: 'req-9',
  });
});

test('toSafeResponse exposes only allow-listed keys', () => {
  const error = new KeyguardError({ code: 'E_CODE', safeMessage: 'msg', requestId: 'r' });
  assert.deepEqual(Object.keys(error.toSafeResponse()).sort(), [
    'code',
    'requestId',
    'retryable',
    'safeMessage',
  ]);
});

test('rejects a non-string code', () => {
  assert.throws(
    () => new KeyguardError({ code: 42, safeMessage: 'msg' }),
    /code must be a string\./,
  );
});

test('rejects a non-string safeMessage', () => {
  assert.throws(
    () => new KeyguardError({ code: 'E_CODE', safeMessage: null }),
    /safeMessage must be a string\./,
  );
});

test('rejects a non-string requestId when provided', () => {
  assert.throws(
    () => new KeyguardError({ code: 'E_CODE', safeMessage: 'msg', requestId: 5 }),
    /requestId must be a string when provided\./,
  );
});

test('rejects a non-boolean retryable', () => {
  assert.throws(
    () => new KeyguardError({ code: 'E_CODE', safeMessage: 'msg', retryable: 'yes' }),
    /retryable must be a boolean\./,
  );
});

test('is throwable and catchable as an Error', () => {
  assert.throws(
    () => {
      throw new KeyguardError({ code: 'E_THROW', safeMessage: 'boom' });
    },
    (error) => error instanceof KeyguardError && error.code === 'E_THROW',
  );
});
