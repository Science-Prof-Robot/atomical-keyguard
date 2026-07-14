import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { isDirectInvocation, startDaemon } from '../src/daemon.mjs';

test('recognizes only a direct daemon entry point', () => {
  const daemonUrl = new URL('../src/daemon.mjs', import.meta.url).href;

  assert.equal(isDirectInvocation(['node', '/tmp/not-the-daemon.mjs'], daemonUrl), false);
  assert.equal(isDirectInvocation(['node', fileURLToPath(daemonUrl)], daemonUrl), true);
});

test('starts the fixed loopback app, emits only a safe URL, and shuts down on a signal', async () => {
  for (const signal of ['SIGINT', 'SIGTERM']) {
    const signals = new EventEmitter();
    const writes = [];
    const calls = { startArguments: [], stops: 0 };
    const app = {
      async start(...args) {
        calls.startArguments.push(args);
        return {
          host: '127.0.0.1',
          port: 4545,
          url: 'http://127.0.0.1:4545/private/daemon-secret',
        };
      },
      async stop() {
        calls.stops += 1;
      },
    };

    const daemon = await startDaemon({
      createApp: async () => app,
      signals,
      stderr: { write: (value) => writes.push(value) },
    });

    assert.deepEqual(calls.startArguments, [[]]);
    assert.deepEqual(writes, ['Atomical Keyguard listening on http://127.0.0.1:4545\n']);
    assert.equal(daemon.url, 'http://127.0.0.1:4545');

    signals.emit(signal);
    await daemon.closed;
    signals.emit(signal === 'SIGINT' ? 'SIGTERM' : 'SIGINT');

    assert.equal(calls.stops, 1);
    assert.deepEqual(writes, ['Atomical Keyguard listening on http://127.0.0.1:4545\n']);
  }
});
