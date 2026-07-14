import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';

import { createApiRouter } from './router.mjs';

export const LOOPBACK_HOST = '127.0.0.1';
export const DEFAULT_PORT = 4545;

const STATIC_ASSETS = new Map([
  ['/', Object.freeze({
    contentType: 'text/html; charset=utf-8',
    file: new URL('../../public/index.html', import.meta.url),
  })],
  ['/app.js', Object.freeze({
    contentType: 'text/javascript; charset=utf-8',
    file: new URL('../../public/app.js', import.meta.url),
  })],
  ['/styles.css', Object.freeze({
    contentType: 'text/css; charset=utf-8',
    file: new URL('../../public/styles.css', import.meta.url),
  })],
]);

const STATIC_HEADERS = Object.freeze({
  'cache-control': 'no-store',
  'content-security-policy': "default-src 'self'; base-uri 'none'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; script-src 'self'; style-src 'self'",
  'cross-origin-opener-policy': 'same-origin',
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
});

/**
 * Creates a lifecycle-managed HTTP server that can bind only the IPv4
 * loopback interface. It deliberately exposes no listen host override.
 */
export function createHttpServer(app, options = {}) {
  if (app === null || typeof app !== 'object') {
    throw new TypeError('HTTP server requires an application.');
  }
  if (options === null || typeof options !== 'object' || Array.isArray(options)) {
    throw new TypeError('HTTP server options must be an object.');
  }
  const host = options.host ?? LOOPBACK_HOST;
  if (host !== LOOPBACK_HOST) {
    throw new TypeError('HTTP server host must be 127.0.0.1.');
  }
  const configuredPort = options.port ?? DEFAULT_PORT;
  if (!Number.isInteger(configuredPort) || configuredPort < 0 || configuredPort > 65_535) {
    throw new TypeError('HTTP server port must be an integer from 0 through 65535.');
  }

  let listening = false;
  let boundPort = configuredPort;
  let server;
  const router = options.router ?? createApiRouter({
    app,
    originProvider: () => descriptor().url,
    services: options.services ?? app.services,
    sessionTokenGenerator: options.sessionTokenGenerator,
  });
  if (typeof router !== 'function') {
    throw new TypeError('router must be a function.');
  }

  server = createServer((request, response) => {
    Promise.resolve(serveStaticAsset(request, response)).then((served) => (
      served ? undefined : router(request, response)
    )).catch(() => {
      if (!response.headersSent && !response.writableEnded) {
        const body = JSON.stringify({ error: { code: 'request_failed', message: 'Request could not be completed.' } });
        response.writeHead(500, {
          'cache-control': 'no-store',
          'content-length': Buffer.byteLength(body),
          'content-type': 'application/json; charset=utf-8',
          'x-content-type-options': 'nosniff',
        });
        response.end(body);
      } else {
        response.destroy();
      }
    });
  });
  server.on('clientError', (_error, socket) => {
    socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
  });

  function descriptor() {
    return Object.freeze({
      host,
      port: boundPort,
      url: `http://${host}:${boundPort}`,
    });
  }

  return Object.freeze({
    get running() {
      return listening;
    },
    get server() {
      return server;
    },
    async start() {
      if (listening) {
        return descriptor();
      }
      await listen(server, configuredPort, host);
      const address = server.address();
      if (address === null || typeof address === 'string' || address.address !== host) {
        await close(server).catch(() => undefined);
        throw new Error('HTTP server did not bind the loopback interface.');
      }
      boundPort = address.port;
      listening = true;
      return descriptor();
    },
    status() {
      return Object.freeze({ ...descriptor(), state: listening ? 'running' : 'stopped' });
    },
    async stop() {
      if (listening) {
        await close(server);
        listening = false;
      }
      return descriptor();
    },
  });
}

async function serveStaticAsset(request, response) {
  const method = request.method ?? '';
  if (method !== 'GET' && method !== 'HEAD') {
    return false;
  }

  let pathname;
  try {
    pathname = new URL(request.url ?? '/', 'http://127.0.0.1').pathname;
  } catch {
    return false;
  }
  const asset = STATIC_ASSETS.get(pathname);
  if (asset === undefined) {
    return false;
  }

  const body = await readFile(asset.file);
  response.writeHead(200, {
    ...STATIC_HEADERS,
    'content-length': body.length,
    'content-type': asset.contentType,
  });
  response.end(method === 'HEAD' ? undefined : body);
  return true;
}

function listen(server, port, host) {
  return new Promise((resolvePromise, rejectPromise) => {
    const reject = (error) => {
      server.off('listening', resolve);
      rejectPromise(error);
    };
    const resolve = () => {
      server.off('error', reject);
      resolvePromise();
    };
    server.once('error', reject);
    server.once('listening', resolve);
    server.listen({ exclusive: true, host, port });
  });
}

function close(server) {
  return new Promise((resolvePromise, rejectPromise) => {
    server.close((error) => {
      if (error === undefined) {
        resolvePromise();
      } else {
        rejectPromise(error);
      }
    });
  });
}
