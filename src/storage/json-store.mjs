import { randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, rename, unlink } from 'node:fs/promises';
import { basename, dirname, join, resolve } from 'node:path';

const PRIVATE_FILE_MODE = 0o600;
const PRIVATE_DIRECTORY_MODE = 0o700;
const LOCK_RETRY_MILLISECONDS = 10;
const LOCK_TIMEOUT_MILLISECONDS = 5_000;
const queuesByPath = new Map();

/**
 * A small, private JSON document store. Mutations are serialized in-process and
 * committed with a same-directory atomic rename, so a failed write cannot leave
 * a partially-written document at the live path.
 */
export class JsonStore {
  #filePath;
  #directoryPath;
  #lockPath;

  constructor(filePath) {
    if (typeof filePath !== 'string' || filePath.length === 0) {
      throw new TypeError('filePath must be a non-empty string.');
    }

    this.#filePath = resolve(filePath);
    this.#directoryPath = dirname(this.#filePath);
    this.#lockPath = join(this.#directoryPath, `.${basename(this.#filePath)}.lock`);
  }

  get path() {
    return this.#filePath;
  }

  async initialize(initialValue) {
    return this.#enqueue(() => this.#withWriteLock(async () => {
      const existing = await this.#readRaw();
      if (existing !== undefined) {
        return cloneJson(existing);
      }

      await this.#writeRaw(initialValue);
      return cloneJson(initialValue);
    }));
  }

  async read() {
    return this.#enqueue(async () => {
      const value = await this.#readRaw();
      if (value === undefined) {
        throw unavailable();
      }
      return cloneJson(value);
    });
  }

  async update(update) {
    if (typeof update !== 'function') {
      throw new TypeError('update must be a function.');
    }

    return this.#enqueue(() => this.#withWriteLock(async () => {
      const existing = await this.#readRaw();
      if (existing === undefined) {
        throw unavailable();
      }

      const next = await update(cloneJson(existing));
      ensureJsonValue(next);
      await this.#writeRaw(next);
      return cloneJson(next);
    }));
  }

  #enqueue(operation) {
    return enqueueForPath(this.#filePath, operation);
  }

  async #withWriteLock(operation) {
    await this.#ensureDirectory();
    const release = await acquireExclusiveLock(this.#lockPath);
    try {
      return await operation();
    } finally {
      await release();
    }
  }

  async #readRaw() {
    await this.#ensureDirectory();

    let handle;
    try {
      handle = await open(
        this.#filePath,
        constants.O_RDONLY | constants.O_NOFOLLOW,
      );
      const details = await handle.stat();
      if (!details.isFile()) {
        throw unavailable();
      }
      await handle.chmod(PRIVATE_FILE_MODE);
      return JSON.parse(await handle.readFile('utf8'));
    } catch (error) {
      if (error?.code === 'ENOENT') {
        return undefined;
      }
      throw unavailable();
    } finally {
      await handle?.close().catch(() => undefined);
    }
  }

  async #writeRaw(value) {
    await this.#ensureDirectory();
    const serialized = serializeJson(value);
    const temporaryPath = join(
      this.#directoryPath,
      `.${basename(this.#filePath)}.${randomUUID()}.tmp`,
    );
    let handle;
    let temporaryFileExists = false;

    try {
      handle = await open(
        temporaryPath,
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
        PRIVATE_FILE_MODE,
      );
      temporaryFileExists = true;
      await handle.chmod(PRIVATE_FILE_MODE);
      await handle.writeFile(serialized, 'utf8');
      await handle.sync();
      await handle.close();
      handle = undefined;

      await rename(temporaryPath, this.#filePath);
      temporaryFileExists = false;
      await syncDirectory(this.#directoryPath);
    } catch {
      throw unavailable();
    } finally {
      if (handle !== undefined) {
        await handle.close().catch(() => undefined);
      }
      if (temporaryFileExists) {
        await unlink(temporaryPath).catch(() => undefined);
      }
    }
  }

  async #ensureDirectory() {
    try {
      await mkdir(this.#directoryPath, { mode: PRIVATE_DIRECTORY_MODE, recursive: true });
      const details = await lstat(this.#directoryPath);
      if (
        !details.isDirectory()
        || details.isSymbolicLink()
        || (details.mode & 0o022) !== 0
      ) {
        throw unavailable();
      }
    } catch (error) {
      if (error?.message === 'Stored data is unavailable.') {
        throw error;
      }
      throw unavailable();
    }
  }
}

function enqueueForPath(filePath, operation) {
  const previous = queuesByPath.get(filePath) ?? Promise.resolve();
  const result = previous.then(operation, operation);
  const continuation = result.catch(() => undefined);
  queuesByPath.set(filePath, continuation);
  continuation.finally(() => {
    if (queuesByPath.get(filePath) === continuation) {
      queuesByPath.delete(filePath);
    }
  }).catch(() => undefined);
  return result;
}

async function acquireExclusiveLock(lockPath) {
  const deadline = Date.now() + LOCK_TIMEOUT_MILLISECONDS;

  for (;;) {
    let handle;
    try {
      handle = await open(
        lockPath,
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
        PRIVATE_FILE_MODE,
      );
      return async () => {
        try {
          await handle.close();
        } finally {
          await unlink(lockPath);
        }
      };
    } catch (error) {
      await handle?.close().catch(() => undefined);
      if (error?.code !== 'EEXIST' || Date.now() >= deadline) {
        throw unavailable();
      }
      await delay(LOCK_RETRY_MILLISECONDS);
    }
  }
}

function delay(milliseconds) {
  return new Promise((resolveDelay) => setTimeout(resolveDelay, milliseconds));
}

async function syncDirectory(directoryPath) {
  let handle;
  try {
    handle = await open(directoryPath, 'r');
    await handle.sync();
  } catch (error) {
    if (!['EINVAL', 'ENOTSUP', 'EPERM'].includes(error?.code)) {
      throw error;
    }
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

function serializeJson(value) {
  ensureJsonValue(value);
  try {
    return JSON.stringify(value);
  } catch {
    throw unavailable();
  }
}

function ensureJsonValue(value) {
  try {
    if (JSON.stringify(value) === undefined) {
      throw unavailable();
    }
  } catch (error) {
    if (error?.message === 'Stored data is unavailable.') {
      throw error;
    }
    throw unavailable();
  }
}

function cloneJson(value) {
  try {
    return JSON.parse(JSON.stringify(value));
  } catch {
    throw unavailable();
  }
}

function unavailable() {
  return new Error('Stored data is unavailable.');
}
