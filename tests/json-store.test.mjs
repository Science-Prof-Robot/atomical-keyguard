import assert from 'node:assert/strict';
import { chmod, readFile, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import test from 'node:test';

import { JsonStore } from '../src/storage/json-store.mjs';
import { withTemporaryDataDirectory } from './helpers.mjs';

test('rejects an invalid filePath in the constructor', () => {
  assert.throws(() => new JsonStore(''), /filePath must be a non-empty string\./);
  assert.throws(() => new JsonStore(42), /filePath must be a non-empty string\./);
});

test('exposes an absolute resolved path', () => {
  const store = new JsonStore('relative/store.json');
  assert.equal(store.path, join(process.cwd(), 'relative/store.json'));
});

test('initialize writes the initial value when the file is absent', async () => {
  await withTemporaryDataDirectory(async (directory) => {
    const store = new JsonStore(join(directory, 'nested', 'store.json'));

    const value = await store.initialize({ count: 0 });

    assert.deepEqual(value, { count: 0 });
    assert.deepEqual(JSON.parse(await readFile(store.path, 'utf8')), { count: 0 });
  });
});

test('initialize returns the existing value without overwriting it', async () => {
  await withTemporaryDataDirectory(async (directory) => {
    const store = new JsonStore(join(directory, 'store.json'));
    await store.initialize({ count: 1 });

    const value = await store.initialize({ count: 999 });

    assert.deepEqual(value, { count: 1 });
    assert.deepEqual(await store.read(), { count: 1 });
  });
});

test('initialize returns a defensive copy of the initial value', async () => {
  await withTemporaryDataDirectory(async (directory) => {
    const store = new JsonStore(join(directory, 'store.json'));
    const initial = { nested: { count: 0 } };

    const value = await store.initialize(initial);
    value.nested.count = 5;

    assert.deepEqual(await store.read(), { nested: { count: 0 } });
  });
});

test('read throws when the document is unavailable', async () => {
  await withTemporaryDataDirectory(async (directory) => {
    const store = new JsonStore(join(directory, 'missing.json'));
    await assert.rejects(() => store.read(), /Stored data is unavailable\./);
  });
});

test('read returns a defensive copy that does not mutate stored state', async () => {
  await withTemporaryDataDirectory(async (directory) => {
    const store = new JsonStore(join(directory, 'store.json'));
    await store.initialize({ items: [1, 2] });

    const first = await store.read();
    first.items.push(3);

    assert.deepEqual(await store.read(), { items: [1, 2] });
  });
});

test('update applies a mutation and returns the next value', async () => {
  await withTemporaryDataDirectory(async (directory) => {
    const store = new JsonStore(join(directory, 'store.json'));
    await store.initialize({ count: 0 });

    const next = await store.update((current) => ({ count: current.count + 1 }));

    assert.deepEqual(next, { count: 1 });
    assert.deepEqual(await store.read(), { count: 1 });
  });
});

test('update supports async updater functions', async () => {
  await withTemporaryDataDirectory(async (directory) => {
    const store = new JsonStore(join(directory, 'store.json'));
    await store.initialize({ count: 10 });

    const next = await store.update(async (current) => {
      await Promise.resolve();
      return { count: current.count * 2 };
    });

    assert.deepEqual(next, { count: 20 });
  });
});

test('update rejects a non-function updater', async () => {
  await withTemporaryDataDirectory(async (directory) => {
    const store = new JsonStore(join(directory, 'store.json'));
    await store.initialize({});
    await assert.rejects(() => store.update(null), /update must be a function\./);
  });
});

test('update throws when the document does not yet exist', async () => {
  await withTemporaryDataDirectory(async (directory) => {
    const store = new JsonStore(join(directory, 'missing.json'));
    await assert.rejects(
      () => store.update((current) => current),
      /Stored data is unavailable\./,
    );
  });
});

test('update rejects a non-serializable next value and leaves prior state intact', async () => {
  await withTemporaryDataDirectory(async (directory) => {
    const store = new JsonStore(join(directory, 'store.json'));
    await store.initialize({ count: 1 });

    await assert.rejects(
      () => store.update(() => ({ bad: 1n })),
      /Stored data is unavailable\./,
    );

    assert.deepEqual(await store.read(), { count: 1 });
  });
});

test('serializes concurrent updates so no increment is lost', async () => {
  await withTemporaryDataDirectory(async (directory) => {
    const store = new JsonStore(join(directory, 'store.json'));
    await store.initialize({ count: 0 });

    await Promise.all(
      Array.from({ length: 20 }, () =>
        store.update((current) => ({ count: current.count + 1 }))),
    );

    assert.deepEqual(await store.read(), { count: 20 });
  });
});

test('writes the document and any temporary artifacts with private file permissions', async () => {
  await withTemporaryDataDirectory(async (directory) => {
    const store = new JsonStore(join(directory, 'store.json'));
    await store.initialize({ count: 0 });

    const details = await stat(store.path);
    assert.equal(details.mode & 0o777, 0o600);
  });
});

test('reports unavailable when the stored file contains invalid JSON', async () => {
  await withTemporaryDataDirectory(async (directory) => {
    const filePath = join(directory, 'store.json');
    await writeFile(filePath, 'not-json', { mode: 0o600 });
    const store = new JsonStore(filePath);

    await assert.rejects(() => store.read(), /Stored data is unavailable\./);
  });
});

test('reports unavailable when the target path is a directory', async () => {
  await withTemporaryDataDirectory(async (directory) => {
    const store = new JsonStore(directory);
    await assert.rejects(() => store.read(), /Stored data is unavailable\./);
  });
});

test('reports unavailable when the containing directory is world-writable', async () => {
  await withTemporaryDataDirectory(async (directory) => {
    await chmod(directory, 0o777);
    const store = new JsonStore(join(directory, 'store.json'));

    await assert.rejects(() => store.read(), /Stored data is unavailable\./);
  });
});
