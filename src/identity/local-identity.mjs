import { Buffer } from 'node:buffer';
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
} from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';

import { canonicalJson } from '../core/canonical.mjs';
import { defaultDataDirectory } from '../storage/sealed-vault.mjs';

const PRIVATE_FILE_MODE = 0o600;
const PRIVATE_DIRECTORY_MODE = 0o700;

/**
 * A persisted local Ed25519 signer. Signing output carries only public
 * verification information; private material never leaves this module.
 */
export class LocalIdentity {
  #fingerprint;
  #identityDirectory;
  #privateKey;
  #privateKeyPath;
  #publicKey;
  #publicKeyPath;
  #ready;

  constructor(options = {}) {
    const normalizedOptions = typeof options === 'string' ? { dataDirectory: options } : options;
    if (normalizedOptions === null || typeof normalizedOptions !== 'object') {
      throw new TypeError('LocalIdentity options must be an object.');
    }

    const dataDirectory = normalizedOptions.dataDirectory ?? defaultDataDirectory();
    if (typeof dataDirectory !== 'string' || dataDirectory.length === 0) {
      throw new TypeError('dataDirectory must be a non-empty string.');
    }

    this.#identityDirectory = resolve(
      normalizedOptions.identityDirectory ?? join(dataDirectory, 'identity'),
    );
    this.#privateKeyPath = resolve(
      normalizedOptions.privateKeyPath ?? join(this.#identityDirectory, 'identity-private.pem'),
    );
    this.#publicKeyPath = resolve(
      normalizedOptions.publicKeyPath ?? join(this.#identityDirectory, 'identity-public.pem'),
    );
    if (this.#privateKeyPath === this.#publicKeyPath) {
      throw new TypeError('privateKeyPath and publicKeyPath must be different.');
    }

    this.#ready = this.#initialize();
  }

  static async open(options = {}) {
    const identity = new LocalIdentity(options);
    await identity.#ready;
    return identity;
  }

  get fingerprint() {
    return this.#fingerprint;
  }

  get privateKeyPath() {
    return this.#privateKeyPath;
  }

  get publicKeyPath() {
    return this.#publicKeyPath;
  }

  signCanonical(value) {
    const body = canonicalBody(value);
    const signature = sign(null, body, this.#privateKey).toString('base64url');
    return Object.freeze({
      algorithm: 'ed25519',
      fingerprint: this.#fingerprint,
      signature,
    });
  }

  verifyCanonical(value, signedValue) {
    try {
      const signature = signatureBytes(signedValue, this.#fingerprint);
      return verify(null, canonicalBody(value), this.#publicKey, signature);
    } catch {
      return false;
    }
  }

  signReceipt(receipt) {
    return Object.freeze({
      signature: this.signCanonical(receipt),
    });
  }

  async #initialize() {
    await ensurePrivateDirectory(this.#identityDirectory);
    await ensurePrivateDirectory(dirname(this.#privateKeyPath));
    await ensurePrivateDirectory(dirname(this.#publicKeyPath));
    const keyPair = await loadOrCreateKeyPair(this.#privateKeyPath, this.#publicKeyPath);
    this.#privateKey = keyPair.privateKey;
    this.#publicKey = keyPair.publicKey;
    this.#fingerprint = fingerprint(keyPair.publicKey);
  }
}

function canonicalBody(value) {
  return Buffer.from(canonicalJson(value), 'utf8');
}

function signatureBytes(signedValue, expectedFingerprint) {
  if (typeof signedValue === 'string') {
    return decodeBase64url(signedValue);
  }
  if (signedValue === null || typeof signedValue !== 'object') {
    throw new TypeError('Signed value is invalid.');
  }
  if (
    signedValue.algorithm !== 'ed25519'
    || signedValue.fingerprint !== expectedFingerprint
    || typeof signedValue.signature !== 'string'
  ) {
    throw new TypeError('Signed value is invalid.');
  }
  return decodeBase64url(signedValue.signature);
}

function decodeBase64url(value) {
  if (typeof value !== 'string' || value.length === 0 || !/^[A-Za-z0-9_-]+$/u.test(value)) {
    throw new TypeError('Signature is invalid.');
  }
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length === 0 || bytes.toString('base64url') !== value) {
    throw new TypeError('Signature is invalid.');
  }
  return bytes;
}

function fingerprint(publicKey) {
  const der = publicKey.export({ format: 'der', type: 'spki' });
  return createHash('sha256').update(der).digest('hex');
}

async function loadOrCreateKeyPair(privateKeyPath, publicKeyPath) {
  const privatePem = await readOptionalPrivateKey(privateKeyPath);
  if (privatePem !== undefined) {
    return loadExistingKeyPair(privatePem, publicKeyPath);
  }

  if (await exists(publicKeyPath)) {
    throw identityUnavailable();
  }

  const keyPair = generateKeyPairSync('ed25519');
  const privateKeyPem = keyPair.privateKey.export({ format: 'pem', type: 'pkcs8' });
  const publicKeyPem = keyPair.publicKey.export({ format: 'pem', type: 'spki' });

  try {
    await writeExclusivePrivateFile(privateKeyPath, privateKeyPem);
  } catch (error) {
    if (error?.code === 'EEXIST') {
      return loadOrCreateKeyPair(privateKeyPath, publicKeyPath);
    }
    throw identityUnavailable();
  }

  try {
    await writeExclusivePrivateFile(publicKeyPath, publicKeyPem);
  } catch (error) {
    if (error?.code === 'EEXIST') {
      return loadExistingKeyPair(privateKeyPem, publicKeyPath);
    }
    throw identityUnavailable();
  }

  return keyPair;
}

async function loadExistingKeyPair(privatePem, publicKeyPath) {
  let privateKey;
  let derivedPublicKey;
  try {
    privateKey = createPrivateKey(privatePem);
    derivedPublicKey = createPublicKey(privateKey);
    if (
      privateKey.asymmetricKeyType !== 'ed25519'
      || derivedPublicKey.asymmetricKeyType !== 'ed25519'
    ) {
      throw identityUnavailable();
    }
  } catch {
    throw identityUnavailable();
  }

  const expectedPublicPem = derivedPublicKey.export({ format: 'pem', type: 'spki' });
  const storedPublicPem = await readOptionalPublicKey(publicKeyPath);
  if (storedPublicPem === undefined) {
    try {
      await writeExclusivePrivateFile(publicKeyPath, expectedPublicPem);
    } catch (error) {
      if (error?.code === 'EEXIST') {
        return loadExistingKeyPair(privatePem, publicKeyPath);
      }
      throw identityUnavailable();
    }
  } else {
    try {
      const storedPublicKey = createPublicKey(storedPublicPem);
      if (storedPublicKey.asymmetricKeyType !== 'ed25519') {
        throw identityUnavailable();
      }
      const expectedDer = derivedPublicKey.export({ format: 'der', type: 'spki' });
      const storedDer = storedPublicKey.export({ format: 'der', type: 'spki' });
      if (!Buffer.from(expectedDer).equals(Buffer.from(storedDer))) {
        throw identityUnavailable();
      }
    } catch (error) {
      if (error?.message === 'Local identity is unavailable.') {
        throw error;
      }
      throw identityUnavailable();
    }
  }

  return { privateKey, publicKey: derivedPublicKey };
}

async function readOptionalPrivateKey(filePath) {
  return readOptionalKeyFile(filePath);
}

async function readOptionalPublicKey(filePath) {
  return readOptionalKeyFile(filePath);
}

async function readOptionalKeyFile(filePath) {
  let handle;
  try {
    handle = await open(
      filePath,
      constants.O_RDONLY | constants.O_NOFOLLOW,
    );
    const details = await handle.stat();
    if (!details.isFile()) {
      throw identityUnavailable();
    }
    await handle.chmod(PRIVATE_FILE_MODE);
    return await handle.readFile('utf8');
  } catch (error) {
    if (error?.code === 'ENOENT') {
      return undefined;
    }
    if (error?.message === 'Local identity is unavailable.') {
      throw error;
    }
    throw identityUnavailable();
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

async function writeExclusivePrivateFile(filePath, contents) {
  let handle;
  try {
    handle = await open(
      filePath,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      PRIVATE_FILE_MODE,
    );
    await handle.chmod(PRIVATE_FILE_MODE);
    await handle.writeFile(contents, 'utf8');
    await handle.sync();
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

async function ensurePrivateDirectory(directoryPath) {
  try {
    await mkdir(directoryPath, { mode: PRIVATE_DIRECTORY_MODE, recursive: true });
    const details = await lstat(directoryPath);
    if (
      !details.isDirectory()
      || details.isSymbolicLink()
      || (details.mode & 0o022) !== 0
    ) {
      throw identityUnavailable();
    }
  } catch {
    throw identityUnavailable();
  }
}

async function exists(filePath) {
  try {
    await lstat(filePath);
    return true;
  } catch (error) {
    if (error?.code === 'ENOENT') {
      return false;
    }
    throw identityUnavailable();
  }
}

function identityUnavailable() {
  return new Error('Local identity is unavailable.');
}
