import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import { createKeyguardApp } from './bootstrap.mjs';

const LOOPBACK_HOST = '127.0.0.1';

/**
 * Returns true only when this module is the process entry point. Keeping this
 * check exported makes the direct-invocation boundary testable without a child
 * process.
 */
export function isDirectInvocation(argv = process.argv, moduleUrl = import.meta.url) {
  const entry = Array.isArray(argv) ? argv[1] : undefined;
  if (typeof entry !== 'string' || entry.length === 0 || typeof moduleUrl !== 'string') {
    return false;
  }
  try {
    return moduleUrl === pathToFileURL(resolve(entry)).href;
  } catch {
    return false;
  }
}

/**
 * Starts the default application with no caller-provided server settings. The
 * application owns the fixed 127.0.0.1 listener; this entry point deliberately
 * does not accept a host or port override.
 */
export async function startDaemon(options = {}) {
  if (options === null || typeof options !== 'object' || Array.isArray(options)) {
    throw new TypeError('Daemon options must be an object.');
  }
  const createApp = options.createApp ?? createKeyguardApp;
  const stderr = options.stderr ?? process.stderr;
  const signals = options.signals ?? process;
  if (typeof createApp !== 'function') {
    throw new TypeError('createApp must be a function.');
  }
  if (stderr === null || typeof stderr !== 'object' || typeof stderr.write !== 'function') {
    throw new TypeError('stderr must provide a write function.');
  }
  if (
    signals === null
    || typeof signals !== 'object'
    || typeof signals.once !== 'function'
    || typeof signals.removeListener !== 'function'
  ) {
    throw new TypeError('signals must provide once and removeListener functions.');
  }

  const app = await createApp();
  if (
    app === null
    || typeof app !== 'object'
    || typeof app.start !== 'function'
    || typeof app.stop !== 'function'
  ) {
    throw new TypeError('createApp must return an application with start and stop methods.');
  }

  const listener = await app.start();
  let url;
  try {
    url = safeLoopbackUrl(listener);
  } catch (error) {
    await stopQuietly(app);
    throw error;
  }

  let resolveClosed;
  const closed = new Promise((resolvePromise) => {
    resolveClosed = resolvePromise;
  });
  let stopping;
  const removeSignalHandlers = () => {
    signals.removeListener('SIGINT', onSignal);
    signals.removeListener('SIGTERM', onSignal);
  };
  const stop = () => {
    if (stopping !== undefined) {
      return stopping;
    }
    stopping = (async () => {
      try {
        await app.stop();
      } finally {
        removeSignalHandlers();
        resolveClosed();
      }
    })();
    return stopping;
  };
  const onSignal = () => {
    void stop().catch(() => {
      process.exitCode = 1;
    });
  };

  signals.once('SIGINT', onSignal);
  signals.once('SIGTERM', onSignal);
  try {
    stderr.write(`Atomical Keyguard listening on ${url}\n`);
  } catch (error) {
    await stopQuietly({ stop });
    throw error;
  }

  return Object.freeze({ closed, stop, url });
}

function safeLoopbackUrl(listener) {
  if (
    listener === null
    || typeof listener !== 'object'
    || listener.host !== LOOPBACK_HOST
    || !Number.isInteger(listener.port)
    || listener.port < 0
    || listener.port > 65_535
  ) {
    throw new TypeError('Daemon did not start on the loopback listener.');
  }
  return `http://${LOOPBACK_HOST}:${listener.port}`;
}

async function stopQuietly(app) {
  try {
    await app.stop();
  } catch {
    // Errors are intentionally not exposed by this process entry point.
  }
}

async function runMain() {
  try {
    const daemon = await startDaemon();
    await daemon.closed;
  } catch {
    try {
      process.stderr.write('Atomical Keyguard could not start.\n');
    } catch {
      // There is no safe output fallback when stderr is unavailable.
    }
    process.exitCode = 1;
  }
}

if (isDirectInvocation()) {
  void runMain();
}
