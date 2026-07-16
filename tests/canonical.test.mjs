import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import { canonicalJson, sha256 } from '../src/core/canonical.mjs';

test('serializes primitive values', () => {
  assert.equal(canonicalJson(null), 'null');
  assert.equal(canonicalJson(true), 'true');
  assert.equal(canonicalJson(false), 'false');
  assert.equal(canonicalJson(0), '0');
  assert.equal(canonicalJson(-12.5), '-12.5');
  assert.equal(canonicalJson('hello'), '"hello"');
  assert.equal(canonicalJson('a"b\n'), '"a\\"b\\n"');
});

test('sorts object keys deterministically regardless of insertion order', () => {
  const first = canonicalJson({ b: 1, a: 2, c: 3 });
  const second = canonicalJson({ c: 3, a: 2, b: 1 });

  assert.equal(first, '{"a":2,"b":1,"c":3}');
  assert.equal(first, second);
});

test('serializes nested objects and arrays', () => {
  assert.equal(
    canonicalJson({ z: [3, 2, 1], a: { y: true, x: null } }),
    '{"a":{"x":null,"y":true},"z":[3,2,1]}',
  );
});

test('preserves array order rather than sorting elements', () => {
  assert.equal(canonicalJson(['c', 'a', 'b']), '["c","a","b"]');
});

test('serializes an empty object and an empty array', () => {
  assert.equal(canonicalJson({}), '{}');
  assert.equal(canonicalJson([]), '[]');
});

test('rejects non-finite numbers', () => {
  assert.throws(() => canonicalJson(Number.NaN), /non-finite numbers/);
  assert.throws(() => canonicalJson(Number.POSITIVE_INFINITY), /non-finite numbers/);
  assert.throws(() => canonicalJson(Number.NEGATIVE_INFINITY), /non-finite numbers/);
});

test('rejects unsupported value types', () => {
  assert.throws(() => canonicalJson(undefined), /does not support undefined values/);
  assert.throws(() => canonicalJson(() => {}), /does not support function values/);
  assert.throws(() => canonicalJson(10n), /does not support bigint values/);
  assert.throws(() => canonicalJson(Symbol('x')), /does not support symbol values/);
});

test('rejects circular references', () => {
  const value = {};
  value.self = value;
  assert.throws(() => canonicalJson(value), /circular values/);
});

test('allows the same object reused across sibling positions', () => {
  const shared = { a: 1 };
  assert.equal(
    canonicalJson({ first: shared, second: shared }),
    '{"first":{"a":1},"second":{"a":1}}',
  );
});

test('rejects sparse arrays', () => {
  const sparse = [1];
  sparse[3] = 4;
  assert.throws(() => canonicalJson(sparse), /sparse arrays/);
});

test('rejects non-plain objects', () => {
  class Custom {
    constructor() {
      this.value = 1;
    }
  }
  assert.throws(() => canonicalJson(new Custom()), /only plain objects and arrays/);
  assert.throws(() => canonicalJson(new Date()), /only plain objects and arrays/);
});

test('accepts objects with a null prototype', () => {
  const value = Object.create(null);
  value.a = 1;
  assert.equal(canonicalJson(value), '{"a":1}');
});

test('rejects accessor properties on objects', () => {
  const value = {};
  Object.defineProperty(value, 'a', { enumerable: true, get: () => 1 });
  assert.throws(() => canonicalJson(value), /accessor properties/);
});

test('rejects accessor properties on arrays', () => {
  const value = [];
  Object.defineProperty(value, '0', { enumerable: true, get: () => 1 });
  assert.throws(() => canonicalJson(value), /accessor properties/);
});

test('sha256 hashes the canonical form and matches an independent digest', () => {
  const value = { b: 1, a: 2 };
  const expected = createHash('sha256')
    .update('{"a":2,"b":1}', 'utf8')
    .digest('hex');

  assert.equal(sha256(value), expected);
});

test('sha256 is insensitive to object key ordering', () => {
  assert.equal(sha256({ a: 1, b: 2 }), sha256({ b: 2, a: 1 }));
});

test('sha256 distinguishes different values', () => {
  assert.notEqual(sha256({ a: 1 }), sha256({ a: 2 }));
});

test('sha256 propagates canonicalization errors', () => {
  assert.throws(() => sha256(undefined), /does not support undefined values/);
});
