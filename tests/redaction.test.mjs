import assert from 'node:assert/strict';
import test from 'node:test';

import {
  MAX_REDACTION_INPUT_LENGTH,
  redactSensitiveOutput,
} from '../src/core/redaction.mjs';

test('redacts literal, base64, base64url, URL-encoded, and JSON-escaped secret variants', () => {
  const secret = '~~~%\"\\n';
  const variants = [
    secret,
    Buffer.from(secret, 'utf8').toString('base64'),
    Buffer.from(secret, 'utf8').toString('base64url'),
    encodeURIComponent(secret),
    encodeURIComponent(secret).replace(/%[0-9A-F]{2}/g, (encoded) => encoded.toLowerCase()),
    JSON.stringify(secret).slice(1, -1),
  ];
  const text = variants.map((variant, index) => `variant-${index}=${variant}`).join(' | ');

  const redacted = redactSensitiveOutput(text, secret);

  for (const variant of variants) {
    assert.doesNotMatch(redacted, new RegExp(escapeRegExp(variant)));
  }
  assert.equal((redacted.match(/\[REDACTED\]/g) ?? []).length, variants.length);
});

test('treats secrets as literal text rather than regular expressions', () => {
  const secret = 'a.b*+?^$()[]{}|';
  const text = `before ${secret} middle ${secret} after`;

  assert.equal(
    redactSensitiveOutput(text, secret),
    'before [REDACTED] middle [REDACTED] after',
  );
});

test('rejects an empty secret instead of redacting every string boundary', () => {
  assert.throws(
    () => redactSensitiveOutput('safe diagnostic output', ''),
    /secret must be a non-empty string/i,
  );
});

test('bounds redaction work without returning an unredacted tail', () => {
  const secret = 'test-only-secret-after-boundary';
  const input = `${'x'.repeat(MAX_REDACTION_INPUT_LENGTH)}${secret}`;

  const redacted = redactSensitiveOutput(input, secret);

  assert.doesNotMatch(redacted, new RegExp(escapeRegExp(secret)));
  assert.equal(redacted.endsWith('[TRUNCATED]'), true);
  assert.ok(redacted.length <= MAX_REDACTION_INPUT_LENGTH + '[TRUNCATED]'.length);
});

test('redacts a secret that crosses the truncation boundary', () => {
  const secret = 'test-only-cross-boundary-secret';
  const visiblePrefix = secret.slice(0, 5);
  const input = `${'x'.repeat(MAX_REDACTION_INPUT_LENGTH - visiblePrefix.length)}${secret}`;

  const redacted = redactSensitiveOutput(input, secret);

  assert.equal(redacted.includes(visiblePrefix), false);
  assert.equal(redacted.includes('[REDACTED]'), true);
  assert.equal(redacted.endsWith('[TRUNCATED]'), true);
  assert.ok(redacted.length <= MAX_REDACTION_INPUT_LENGTH + '[TRUNCATED]'.length);
});

test('redacts form-style percent encodings with mixed-case escape digits', () => {
  const secret = '~~~%"\\n';
  const encoded = '%7E%7e%7E%25%22%5Cn';

  assert.equal(
    redactSensitiveOutput(`encoded=${encoded}`, secret),
    'encoded=[REDACTED]',
  );
});

test('redacts JSON Unicode-escaped secret characters', () => {
  assert.equal(
    redactSensitiveOutput('payload=\\u0073ecret', 'secret'),
    'payload=[REDACTED]',
  );
});

test('redacts an encodeURI form that preserves a solidus', () => {
  assert.equal(
    redactSensitiveOutput(encodeURI('a/b c'), 'a/b c'),
    '[REDACTED]',
  );
});

test('redacts URLSearchParams-style form encoding safe characters', () => {
  assert.equal(
    redactSensitiveOutput('*%7E', '*~'),
    '[REDACTED]',
  );
});

test('redacts JSON optional solidus escapes', () => {
  assert.equal(
    redactSensitiveOutput('{"value":"a\\/b"}', 'a/b'),
    '{"value":"[REDACTED]"}',
  );
});

test('redacts the full fixed JSON escape vocabulary', () => {
  const secret = '"\\/\b\f\n\r\t';
  const escaped = JSON.stringify(secret).slice(1, -1).replace('/', '\\/');

  assert.equal(
    redactSensitiveOutput(`value=${escaped}`, secret),
    'value=[REDACTED]',
  );
});

test('caps output when replacement markers would expand a full-size input', () => {
  const input = 'a'.repeat(MAX_REDACTION_INPUT_LENGTH);
  const redacted = redactSensitiveOutput(input, 'a');

  assert.equal(redacted.includes('a'), false);
  assert.ok(redacted.length <= MAX_REDACTION_INPUT_LENGTH);
});

test('keeps a reserved later marker within the output cap', () => {
  const input = `${'ax'.repeat(5_955)}ya${'z'.repeat(11)}a`;
  const redacted = redactSensitiveOutput(input, 'a');

  assert.equal(redacted.includes('a'), false);
  assert.ok(redacted.length <= MAX_REDACTION_INPUT_LENGTH);
  assert.equal(redacted.endsWith('[TRUNCATED]'), true);
});

test('redacts a maximum-length multibyte percent encoding that crosses the cutoff', () => {
  const secret = '€'.repeat(16 * 1024);
  const encoded = encodeURIComponent(secret);
  const input = `${'x'.repeat(MAX_REDACTION_INPUT_LENGTH - 20)}${encoded}`;

  const redacted = redactSensitiveOutput(input, secret);

  assert.equal(redacted.includes('%'), false);
  assert.equal(redacted.includes('[REDACTED]'), true);
  assert.equal(redacted.endsWith('[TRUNCATED]'), true);
  assert.ok(redacted.length <= MAX_REDACTION_INPUT_LENGTH);
});

test('redacts a secret containing an unpaired surrogate without throwing', () => {
  const secret = 'token-\ud800';

  assert.equal(
    redactSensitiveOutput(`value=${secret}`, secret),
    'value=[REDACTED]',
  );
});

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
