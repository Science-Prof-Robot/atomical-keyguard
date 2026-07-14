import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import {
  access,
  chmod,
  mkdir,
  open,
  readFile,
  stat,
  symlink,
  unlink,
  writeFile,
} from 'node:fs/promises';
import { join, relative, resolve, sep } from 'node:path';
import test from 'node:test';

import { createKeyguardApp } from '../src/bootstrap.mjs';
import { JsonStore } from '../src/storage/json-store.mjs';
import { defaultDataDirectory, SealedVault } from '../src/storage/sealed-vault.mjs';
import { assertNoSecretBearingFields, withTemporaryDataDirectory } from './helpers.mjs';

const FIXED_TIME = '2026-07-14T12:00:00.000Z';

test('seals credentials at rest and exposes only a safe projection', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    const vault = await SealedVault.open({
      clock: { now: () => new Date(FIXED_TIME) },
      dataDirectory,
    });
    const secret = 'test-only-token-~~~%\"\\n';

    const projection = await vault.put(
      { label: 'cloudflare-pages', provider: 'cloudflare' },
      secret,
    );

    assert.equal(projection.createdAt, FIXED_TIME);
    assert.equal(projection.label, 'cloudflare-pages');
    assert.match(projection.instanceId, /^[A-Za-z0-9_-]{32}$/u);
    assert.equal(projection.status, 'active');
    assert.equal(projection.updatedAt, FIXED_TIME);
    assertSafeProjection(projection);
    assert.deepEqual(await vault.list(), [projection]);
    assert.equal(await vault.readForExecution('cloudflare-pages'), secret);

    const persistedText = await readFile(vault.storagePath, 'utf8');
    const persisted = JSON.parse(persistedText);
    const record = persisted.credentials[0];

    assert.doesNotMatch(persistedText, new RegExp(escapeRegExp(secret)));
    assert.equal(record.label, 'cloudflare-pages');
    assert.equal(typeof record.sealed.ciphertext, 'string');
    assert.equal(typeof record.sealed.iv, 'string');
    assert.equal(typeof record.sealed.authTag, 'string');
    assert.notEqual(record.sealed.ciphertext, secret);
  });
});

test('creates a new opaque credential instance for a recreated label at the same timestamp', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    const vault = await SealedVault.open({
      clock: { now: () => new Date(FIXED_TIME) },
      dataDirectory,
    });
    const first = await vault.put({ label: 'deploy-token' }, 'first-test-only-secret');

    await vault.revoke('deploy-token');
    await vault.delete('deploy-token');
    const replacement = await vault.put({ label: 'deploy-token' }, 'second-test-only-secret');

    assert.equal(first.createdAt, replacement.createdAt);
    assert.equal(first.updatedAt, replacement.updatedAt);
    assert.match(first.instanceId, /^[A-Za-z0-9_-]{32}$/u);
    assert.match(replacement.instanceId, /^[A-Za-z0-9_-]{32}$/u);
    assert.notEqual(first.instanceId, replacement.instanceId);
    assertSafeProjection(first);
    assertSafeProjection(replacement);
  });
});

test('atomically replaces only the expected active or revoked credential instance', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    const vault = await SealedVault.open({
      clock: { now: () => new Date(FIXED_TIME) },
      dataDirectory,
    });
    const original = await vault.put({ label: 'deploy-token' }, 'old-revoked-secret');

    const replacement = await vault.putIfCurrentInstance(
      { label: 'deploy-token' },
      'replacement-secret',
      original.instanceId,
    );

    assert.equal(replacement.status, 'active');
    assert.notEqual(replacement.instanceId, original.instanceId);
    assertSafeProjection(replacement);
    assert.equal(await vault.readForExecution('deploy-token'), 'replacement-secret');
    const revoked = await vault.revoke('deploy-token');
    const restored = await vault.putIfCurrentInstance(
      { label: 'deploy-token' },
      'restored-secret',
      revoked.instanceId,
    );
    assert.equal(restored.status, 'active');
    assert.notEqual(restored.instanceId, replacement.instanceId);
    await assert.rejects(
      vault.putIfCurrentInstance(
        { label: 'deploy-token' },
        'stale-replacement-secret',
        original.instanceId,
      ),
      /Credential is not available for execution\./,
    );
    assert.deepEqual(await vault.list(), [restored]);
  });
});

test('conditionally creates only when an expected credential instance is absent', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    const vault = await SealedVault.open({ dataDirectory });
    const created = await vault.putIfCurrentInstance(
      { label: 'conditional-token' },
      'conditional-secret',
      null,
    );

    assert.equal(created.status, 'active');
    await assert.rejects(
      vault.putIfCurrentInstance(
        { label: 'conditional-token' },
        'second-conditional-secret',
        null,
      ),
      /Credential is not available for execution\./,
    );
    assert.equal(await vault.readForExecution('conditional-token'), 'conditional-secret');
  });
});

test('creates an exact 32-byte master key with private file permissions', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    const vault = await SealedVault.open({ dataDirectory });

    const [masterKey, masterKeyStats, storeStats] = await Promise.all([
      readFile(vault.masterKeyPath),
      stat(vault.masterKeyPath),
      stat(vault.storagePath),
    ]);

    assert.equal(masterKey.length, 32);
    assert.equal(masterKeyStats.mode & 0o777, 0o600);
    assert.equal(storeStats.mode & 0o777, 0o600);
  });
});

test('uses a default data directory outside the project tree', () => {
  const projectDirectory = resolve(process.cwd());
  const configuredDirectory = resolve(defaultDataDirectory());
  const fromProject = relative(projectDirectory, configuredDirectory);

  assert.notEqual(configuredDirectory, projectDirectory);
  assert.ok(
    fromProject === '..' || fromProject.startsWith(`..${sep}`),
    `default state directory must be outside the project: ${configuredDirectory}`,
  );
});

test('does not change permissions on an existing caller-owned data directory', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    await chmod(dataDirectory, 0o755);

    await SealedVault.open({ dataDirectory });

    assert.equal((await stat(dataDirectory)).mode & 0o777, 0o755);
  });
});

test('rejects group- and world-writable caller-owned data directories without changing them', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    for (const mode of [0o770, 0o707]) {
      const unsafeDirectory = join(dataDirectory, `unsafe-${mode.toString(8)}`);
      await mkdir(unsafeDirectory, { mode: 0o700 });
      await chmod(unsafeDirectory, mode);

      await assert.rejects(
        SealedVault.open({ dataDirectory: unsafeDirectory }),
        /Credential is not available for execution\./,
      );
      assert.equal((await stat(unsafeDirectory)).mode & 0o777, mode);
    }
  });
});

test('rejects symlinked master-key and state files without changing linked targets', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    for (const [kind, fileName, contents] of [
      ['master-key', 'master.key', randomBytes(32)],
      ['state', 'credentials.json', JSON.stringify({ credentials: [], version: 1 })],
    ]) {
      const isolatedDirectory = join(dataDirectory, kind);
      const targetPath = join(isolatedDirectory, 'target');
      const linkPath = join(isolatedDirectory, fileName);
      await mkdir(isolatedDirectory, { mode: 0o700 });
      await writeFile(targetPath, contents, { mode: 0o600 });
      await chmod(targetPath, 0o644);
      await symlink(targetPath, linkPath);

      await assert.rejects(
        SealedVault.open({ dataDirectory: isolatedDirectory }),
        /(?:Stored data is unavailable|Credential is not available for execution)\./,
      );
      assert.equal((await stat(targetPath)).mode & 0o777, 0o644);
    }
  });
});

test('bootstrap composes sealed internals and an explicitly non-public Atomical seam', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    const app = await createKeyguardApp({ dataDirectory });

    assert.equal(typeof app.services.vault.put, 'function');
    assert.equal(typeof app.services.vault.readForExecution, 'function');
    assert.equal(typeof app.services.identity.signCanonical, 'function');
    assert.deepEqual(app.services.atomicalGateway, {
      configured: false,
      isPublicDepositBox: false,
      kind: 'sealed-local-test-demo',
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
  });
});

test('serializes concurrent updates from separate JSON store instances', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    const filePath = join(dataDirectory, 'concurrent.json');
    const initializer = new JsonStore(filePath);
    await initializer.initialize({ count: 0 });
    const updateCount = 12;
    const stores = Array.from({ length: updateCount }, () => new JsonStore(filePath));

    await Promise.all(stores.map((store) => store.update(async (state) => {
      const count = state.count;
      await new Promise((resolveImmediate) => setImmediate(resolveImmediate));
      return { count: count + 1 };
    })));

    assert.equal((await initializer.read()).count, updateCount);
  });
});

test('serializes a read-modify-write across independent Node processes', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    const filePath = join(dataDirectory, 'cross-process.json');
    const initializer = new JsonStore(filePath);
    await initializer.initialize({ count: 0 });

    const firstReadyPath = join(dataDirectory, 'first-ready');
    const firstReleasePath = join(dataDirectory, 'first-release');
    const secondReadyPath = join(dataDirectory, 'second-ready');
    const secondReleasePath = join(dataDirectory, 'second-release');
    const first = startStoreUpdateWorker(filePath, firstReadyPath, firstReleasePath);
    let second;

    try {
      assert.equal(await waitForFile(firstReadyPath, 2_000), true);
      second = startStoreUpdateWorker(filePath, secondReadyPath, secondReleasePath);
      const secondEnteredBeforeFirstRelease = await waitForFile(secondReadyPath, 1_000);

      await writeFile(firstReleasePath, 'release', { flag: 'wx', mode: 0o600 });
      if (!secondEnteredBeforeFirstRelease) {
        assert.equal(await waitForFile(secondReadyPath, 2_000), true);
      }
      await writeFile(secondReleasePath, 'release', { flag: 'wx', mode: 0o600 });

      await Promise.all([first.completed, second.completed]);
      assert.equal((await initializer.read()).count, 2);
    } finally {
      first.child.kill();
      second?.child.kill();
    }
  });
});

test('fails closed within a bounded wait when a cross-process store lock remains occupied', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    const filePath = join(dataDirectory, 'blocked.json');
    const store = new JsonStore(filePath);
    await store.initialize({ count: 0 });
    const lockPath = join(dataDirectory, '.blocked.json.lock');
    const lockHandle = await open(lockPath, 'wx', 0o600);
    const startedAt = performance.now();

    try {
      await assert.rejects(
        store.update((state) => ({ ...state, count: state.count + 1 })),
        /Stored data is unavailable\./,
      );
      assert.ok(performance.now() - startedAt < 6_500);
    } finally {
      await lockHandle.close();
      await unlink(lockPath);
    }

    assert.deepEqual(await store.read(), { count: 0 });
  });
});

test('revocation and deletion make credentials unavailable for execution', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    const vault = await SealedVault.open({ dataDirectory });
    await vault.put({ label: 'deploy-token' }, 'test-only-deploy-token');

    const revoked = await vault.revoke('deploy-token');

    assert.deepEqual(revoked.status, 'revoked');
    assertSafeProjection(revoked);
    await assert.rejects(
      vault.readForExecution('deploy-token'),
      /Credential is not available for execution\./,
    );

    await vault.delete('deploy-token');
    assert.deepEqual(await vault.list(), []);
    await assert.rejects(
      vault.readForExecution('deploy-token'),
      /Credential is not available for execution\./,
    );
  });
});

test('fails closed when sealed ciphertext or authenticated metadata is corrupted', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    const vault = await SealedVault.open({ dataDirectory });
    await vault.put({ label: 'integrity-token' }, 'test-only-integrity-token');

    const persisted = JSON.parse(await readFile(vault.storagePath, 'utf8'));
    const record = persisted.credentials[0];
    record.label = 'tampered-label';
    record.sealed.ciphertext = `${record.sealed.ciphertext === 'A' ? 'B' : 'A'}${record.sealed.ciphertext.slice(1)}`;
    await writeFile(vault.storagePath, JSON.stringify(persisted), { mode: 0o600 });

    await assert.rejects(
      SealedVault.open({ dataDirectory }),
      /Credential is not available for execution\./,
    );
  });
});

test('fails closed when each sealed envelope or AAD field is independently tampered', async (t) => {
  const mutations = [
    ['ciphertext', (record) => {
      record.sealed.ciphertext = alterBase64url(record.sealed.ciphertext);
    }],
    ['iv', (record) => {
      record.sealed.iv = alterBase64url(record.sealed.iv);
    }],
    ['auth tag', (record) => {
      record.sealed.authTag = alterBase64url(record.sealed.authTag);
    }],
    ['label AAD', (record) => {
      record.label = 'independently-tampered-label';
    }],
    ['status AAD', (record) => {
      record.status = 'revoked';
    }],
    ['createdAt AAD', (record) => {
      record.createdAt = '2026-07-14T12:00:01.000Z';
    }],
    ['updatedAt AAD', (record) => {
      record.updatedAt = '2026-07-14T12:00:02.000Z';
    }],
    ['credential instance ID AAD', (record) => {
      record.instanceId = 'A'.repeat(32);
    }],
    ['version AAD', (record) => {
      record.version = 2;
    }],
  ];

  for (const [field, mutate] of mutations) {
    await t.test(field, async () => {
      await withTemporaryDataDirectory(async (dataDirectory) => {
        const vault = await SealedVault.open({ dataDirectory });
        await vault.put({ label: 'integrity-token' }, 'test-only-integrity-token');
        const persisted = JSON.parse(await readFile(vault.storagePath, 'utf8'));

        mutate(persisted.credentials[0]);
        await writeFile(vault.storagePath, JSON.stringify(persisted), { mode: 0o600 });

        await assert.rejects(
          SealedVault.open({ dataDirectory }),
          /Credential is not available for execution\./,
        );
      });
    });
  }
});

test('fails closed when the persisted master key is replaced', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    const vault = await SealedVault.open({ dataDirectory });
    await vault.put({ label: 'master-key-integrity' }, 'test-only-master-key-integrity');
    await writeFile(vault.masterKeyPath, randomBytes(32), { mode: 0o600 });

    await assert.rejects(
      SealedVault.open({ dataDirectory }),
      /Credential is not available for execution\./,
    );
  });
});

function assertSafeProjection(projection) {
  assert.deepEqual(Object.keys(projection).sort(), [
    'createdAt',
    'instanceId',
    'label',
    'status',
    'updatedAt',
  ]);
  assert.match(projection.instanceId, /^[A-Za-z0-9_-]{32}$/u);
  assertNoSecretBearingFields(projection);

  for (const forbiddenField of ['authTag', 'ciphertext', 'iv', 'masterKey', 'secret', 'tag', 'value']) {
    assert.equal(forbiddenField in projection, false, `${forbiddenField} must not be projected`);
  }
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function alterBase64url(value) {
  return `${value[0] === 'A' ? 'B' : 'A'}${value.slice(1)}`;
}

function startStoreUpdateWorker(filePath, readyPath, releasePath) {
  const workerModuleUrl = new URL('../src/storage/json-store.mjs', import.meta.url).href;
  const workerSource = `
    import { JsonStore } from ${JSON.stringify(workerModuleUrl)};
    import { access, writeFile } from 'node:fs/promises';

    const [storePath, ready, release] = process.argv.slice(1);
    const delay = (milliseconds) => new Promise((resolveDelay) => setTimeout(resolveDelay, milliseconds));
    async function waitForRelease() {
      for (;;) {
        try {
          await access(release);
          return;
        } catch {
          await delay(5);
        }
      }
    }

    const store = new JsonStore(storePath);
    await store.update(async (state) => {
      await writeFile(ready, 'ready', { flag: 'wx', mode: 0o600 });
      await waitForRelease();
      return { ...state, count: state.count + 1 };
    });
  `;
  const child = spawn(
    process.execPath,
    ['--input-type=module', '--eval', workerSource, filePath, readyPath, releasePath],
    { stdio: ['ignore', 'ignore', 'ignore'] },
  );
  const completed = new Promise((resolveCompleted, rejectCompleted) => {
    child.once('error', rejectCompleted);
    child.once('exit', (code, signal) => {
      if (code === 0) {
        resolveCompleted();
      } else {
        rejectCompleted(new Error(`Store worker exited with code ${code ?? signal}.`));
      }
    });
  });

  return { child, completed };
}

async function waitForFile(filePath, timeoutMilliseconds) {
  const deadline = Date.now() + timeoutMilliseconds;
  while (Date.now() < deadline) {
    try {
      await access(filePath);
      return true;
    } catch {
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 10));
    }
  }
  return false;
}
