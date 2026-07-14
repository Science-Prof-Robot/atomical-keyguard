import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { chmod, mkdir, readFile, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import test from 'node:test';

import { LocalIdentity } from '../src/identity/local-identity.mjs';
import { withTemporaryDataDirectory } from './helpers.mjs';

test('persists a private Ed25519 identity and signs canonical values', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    const identity = await LocalIdentity.open({ dataDirectory });
    const signed = identity.signCanonical({ z: true, a: { second: 2, first: 1 } });

    assert.deepEqual(Object.keys(signed).sort(), ['algorithm', 'fingerprint', 'signature']);
    assert.equal(signed.algorithm, 'ed25519');
    assert.match(signed.fingerprint, /^[a-f0-9]{64}$/);
    assert.match(signed.signature, /^[A-Za-z0-9_-]+$/);
    assert.equal(identity.verifyCanonical({ a: { first: 1, second: 2 }, z: true }, signed), true);
    assert.equal(identity.verifyCanonical({ a: { first: 1, second: 3 }, z: true }, signed), false);

    const [privateKey, privateKeyStats] = await Promise.all([
      readFile(identity.privateKeyPath, 'utf8'),
      stat(identity.privateKeyPath),
    ]);
    assert.match(privateKey, /BEGIN PRIVATE KEY/);
    assert.equal(privateKeyStats.mode & 0o777, 0o600);
    assert.doesNotMatch(JSON.stringify(signed), /BEGIN PRIVATE KEY/);

    const reloadedIdentity = await LocalIdentity.open({ dataDirectory });
    assert.equal(reloadedIdentity.fingerprint, identity.fingerprint);
    assert.equal(reloadedIdentity.verifyCanonical({ z: true, a: { second: 2, first: 1 } }, signed), true);
  });
});

test('signReceipt returns only public signature information', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    const identity = await LocalIdentity.open({ dataDirectory });
    const receipt = Object.freeze({
      action: 'cloudflare_pages_deploy',
      id: 'receipt_123',
      status: 'verified',
    });

    const signedReceipt = identity.signReceipt(receipt);

    assert.deepEqual(Object.keys(signedReceipt).sort(), ['signature']);
    assert.equal('receipt' in signedReceipt, false);
    assert.equal('receiptHash' in signedReceipt, false);
    assert.deepEqual(Object.keys(signedReceipt.signature).sort(), ['algorithm', 'fingerprint', 'signature']);
    assert.equal(identity.verifyCanonical(receipt, signedReceipt.signature), true);
    assert.doesNotMatch(JSON.stringify(signedReceipt), /PRIVATE KEY|BEGIN/);
  });
});

test('rejects persisted key material that is not Ed25519', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    const identityDirectory = join(dataDirectory, 'identity');
    const keyPair = generateKeyPairSync('rsa', { modulusLength: 2048 });
    await mkdir(identityDirectory, { mode: 0o700, recursive: true });
    await Promise.all([
      writeFile(
        join(identityDirectory, 'identity-private.pem'),
        keyPair.privateKey.export({ format: 'pem', type: 'pkcs8' }),
        { mode: 0o600 },
      ),
      writeFile(
        join(identityDirectory, 'identity-public.pem'),
        keyPair.publicKey.export({ format: 'pem', type: 'spki' }),
        { mode: 0o600 },
      ),
    ]);

    await assert.rejects(
      LocalIdentity.open({ dataDirectory }),
      /Local identity is unavailable\./,
    );
  });
});

test('signReceipt never returns arbitrary caller-supplied receipt data', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    const identity = await LocalIdentity.open({ dataDirectory });
    const receipt = { details: 'test-only-receipt-secret', id: 'receipt_123' };
    const signedReceipt = identity.signReceipt(receipt);

    assert.doesNotMatch(JSON.stringify(signedReceipt), /test-only-receipt-secret/);
    assert.equal(identity.verifyCanonical(receipt, signedReceipt.signature), true);
  });
});

test('does not change permissions on an existing caller-owned identity directory', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    await chmod(dataDirectory, 0o755);

    await LocalIdentity.open({ dataDirectory, identityDirectory: dataDirectory });

    assert.equal((await stat(dataDirectory)).mode & 0o777, 0o755);
  });
});

test('rejects group- and world-writable caller-owned identity directories without changing them', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    for (const mode of [0o770, 0o707]) {
      const identityDirectory = join(dataDirectory, `unsafe-${mode.toString(8)}`);
      await mkdir(identityDirectory, { mode: 0o700 });
      await chmod(identityDirectory, mode);

      await assert.rejects(
        LocalIdentity.open({ dataDirectory, identityDirectory }),
        /Local identity is unavailable\./,
      );
      assert.equal((await stat(identityDirectory)).mode & 0o777, mode);
    }
  });
});

test('rejects custom identity key paths under group- or world-writable directories', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    for (const mode of [0o770, 0o707]) {
      const unsafeDirectory = join(dataDirectory, `unsafe-key-path-${mode.toString(8)}`);
      await mkdir(unsafeDirectory, { mode: 0o700 });
      await chmod(unsafeDirectory, mode);

      await assert.rejects(
        LocalIdentity.open({
          dataDirectory,
          privateKeyPath: join(unsafeDirectory, 'identity-private.pem'),
        }),
        /Local identity is unavailable\./,
      );
      assert.equal((await stat(unsafeDirectory)).mode & 0o777, mode);
    }
  });
});

test('rejects a symlinked persisted identity key without changing its target', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    const identity = await LocalIdentity.open({ dataDirectory });
    const targetPath = join(dataDirectory, 'identity-target.pem');
    await writeFile(targetPath, 'untrusted key target', { mode: 0o600 });
    await chmod(targetPath, 0o644);
    await rm(identity.publicKeyPath);
    await symlink(targetPath, identity.publicKeyPath);

    await assert.rejects(
      LocalIdentity.open({ dataDirectory }),
      /Local identity is unavailable\./,
    );
    assert.equal((await stat(targetPath)).mode & 0o777, 0o644);
  });
});
