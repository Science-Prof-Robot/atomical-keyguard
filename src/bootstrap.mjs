import { LocalIdentity } from './identity/local-identity.mjs';
import { createHttpServer as createLoopbackHttpServer } from './http/server.mjs';
import { createMcpStdioServer } from './mcp/stdio-server.mjs';
import { createActionRegistry } from './policy/action-registry.mjs';
import { PolicyEngine } from './policy/policy-engine.mjs';
import { GitInspector } from './project/git-inspector.mjs';
import { ActivityService } from './services/activity.mjs';
import { ApprovalService } from './services/approvals.mjs';
import { DepositService } from './services/deposits.mjs';
import { ExecutionService } from './services/execution.mjs';
import { InstallerControlService } from './services/installer-control.mjs';
import { MemoryService } from './services/memory.mjs';
import { SetupService } from './services/setup.mjs';
import { SealedVault } from './storage/sealed-vault.mjs';

const LOOPBACK_SERVER = Object.freeze({
  host: '127.0.0.1',
  port: 4545,
  url: 'http://127.0.0.1:4545',
});

export async function createKeyguardApp(options = {}) {
  const vault = options.vault ?? await SealedVault.open({
    clock: options.clock,
    dataDirectory: options.dataDirectory,
  });
  const identity = options.identity ?? await LocalIdentity.open({
    dataDirectory: options.dataDirectory,
  });
  const identityFingerprint = publicFingerprint(identity);
  const setup = options.setup ?? options.setupService ?? await SetupService.open({
    dataDirectory: options.dataDirectory,
    storagePath: options.setupStoragePath,
    store: options.setupStore,
  });
  if (
    setup === null
    || typeof setup !== 'object'
    || typeof setup.complete !== 'function'
    || typeof setup.status !== 'function'
  ) {
    throw new TypeError('setup service must provide complete and status methods.');
  }
  const actionRegistry = options.actionRegistry ?? createActionRegistry(actionRegistryOptions(options));
  const gitInspector = options.gitInspector ?? new GitInspector();
  const approvals = options.approvals ?? await ApprovalService.open({
    actionRegistry,
    clock: options.clock,
    dataDirectory: options.dataDirectory,
    gitInspector,
    identity,
    vault,
  });
  const policyEngine = options.policyEngine ?? new PolicyEngine({
    approvalService: approvals,
    clock: options.clock,
    gitInspector,
    identity,
    registry: actionRegistry,
    vault,
  });
  const activity = options.activity ?? await ActivityService.open({
    clock: options.clock,
    dataDirectory: options.dataDirectory,
  });
  const memory = options.memory ?? await MemoryService.open({
    clock: options.clock,
    dataDirectory: options.dataDirectory,
    identity,
  });
  const execution = options.execution ?? await ExecutionService.open({
    actionRegistry,
    activity,
    approvals,
    clock: options.clock,
    dataDirectory: options.dataDirectory,
    gitInspector,
    identity,
    memory,
    vault,
    verifier: options.verifier,
  });
  const atomicalGateway = options.atomicalGateway ?? Object.freeze({
    configured: false,
    isPublicDepositBox: false,
    kind: 'sealed-local-test-demo',
  });
  const depositService = options.depositService ?? options.deposits ?? await DepositService.open({
    actionRegistry,
    atomicalGateway,
    clock: options.clock,
    dataDirectory: options.dataDirectory,
    depositTtlMilliseconds: options.depositTtlMilliseconds,
    maxWebhookAgeMilliseconds: options.maxWebhookAgeMilliseconds,
    trustedPublicKeyVerifier: options.trustedPublicKeyVerifier,
    vault,
    webhookToken: options.webhookToken,
  });
  const installerControl = options.installerControl ?? await InstallerControlService.open({
    actionRegistry,
    applyInstall: options.installerApplyInstall,
    clock: options.clock,
    discoverEnvironment: options.installerDiscoverEnvironment,
    environment: options.installerEnvironment,
    homeDirectory: options.installerHomeDirectory,
    identity,
    planIdGenerator: options.installerPlanIdGenerator,
    planInstall: options.installerPlanInstall,
    planTtlMilliseconds: options.installerPlanTtlMilliseconds,
    policy: options.installerPolicy,
    policyVersion: options.installerPolicyVersion,
    projectRoot: options.installerProjectRoot ?? options.projectRoot,
  });
  if (
    installerControl === null
    || typeof installerControl !== 'object'
    || typeof installerControl.apply !== 'function'
    || typeof installerControl.plan !== 'function'
    || typeof installerControl.status !== 'function'
  ) {
    throw new TypeError('installer control must provide status, plan, and apply methods.');
  }
  const httpServerFactory = options.httpServerFactory ?? createLoopbackHttpServer;
  if (typeof httpServerFactory !== 'function') {
    throw new TypeError('httpServerFactory must be a function.');
  }
  const mcpServerFactory = options.mcpServerFactory ?? createMcpStdioServer;
  if (typeof mcpServerFactory !== 'function') {
    throw new TypeError('mcpServerFactory must be a function.');
  }

  const services = Object.freeze({
    actionRegistry,
    activity,
    approvals,
    atomicalGateway,
    clock: options.clock,
    dataDirectory: options.dataDirectory,
    depositService,
    environmentDiscovery: options.environmentDiscovery,
    execution,
    gitInspector,
    identity,
    installerControl,
    memory,
    policyEngine,
    setup,
    vault,
  });

  let httpServer;
  let configuredServerOptions;
  let mcpServer;
  let configuredMcpServerOptions;
  let app;
  const createServer = (serverOptions = {}) => {
    if (serverOptions === null || typeof serverOptions !== 'object' || Array.isArray(serverOptions)) {
      throw new TypeError('HTTP server options must be an object.');
    }
    if (httpServer === undefined) {
      configuredServerOptions = { ...serverOptions };
      httpServer = httpServerFactory(app, configuredServerOptions);
      return httpServer;
    }
    if (
      (Object.hasOwn(serverOptions, 'host') && serverOptions.host !== configuredServerOptions.host)
      || (Object.hasOwn(serverOptions, 'port') && serverOptions.port !== configuredServerOptions.port)
    ) {
      throw new TypeError('HTTP server is already configured.');
    }
    return httpServer;
  };
  const createMcpServer = (serverOptions = {}) => {
    if (serverOptions === null || typeof serverOptions !== 'object' || Array.isArray(serverOptions)) {
      throw new TypeError('MCP server options must be an object.');
    }
    if (mcpServer === undefined) {
      configuredMcpServerOptions = { ...serverOptions };
      mcpServer = mcpServerFactory(app, configuredMcpServerOptions);
      if (mcpServer === null || typeof mcpServer !== 'object') {
        throw new TypeError('mcpServerFactory must return an MCP server.');
      }
      return mcpServer;
    }
    for (const [key, value] of Object.entries(serverOptions)) {
      if (configuredMcpServerOptions[key] !== value) {
        throw new TypeError('MCP server is already configured.');
      }
    }
    return mcpServer;
  };

  app = Object.freeze({
    createHttpServer(serverOptions = {}) {
      return createServer(serverOptions);
    },
    createMcpServer(serverOptions = {}) {
      return createMcpServer(serverOptions);
    },
    async start(serverOptions = {}) {
      return createServer(serverOptions).start();
    },
    async stop() {
      if (httpServer === undefined) {
        return { ...LOOPBACK_SERVER };
      }
      return httpServer.stop();
    },
    services,
    status() {
      const setupStatus = publicSetupStatus(setup.status());
      if (httpServer !== undefined && typeof httpServer.status === 'function') {
        const status = httpServer.status();
        return {
          identity: { fingerprint: identityFingerprint },
          server: {
            host: status.host,
            port: status.port,
            url: status.url,
          },
          setup: setupStatus,
          state: status.state,
        };
      }
      return {
        identity: { fingerprint: identityFingerprint },
        server: { ...LOOPBACK_SERVER },
        setup: setupStatus,
        state: 'stopped',
      };
    },
  });
  return app;
}

function actionRegistryOptions(options) {
  const registryOptions = {};
  if (options.approvedProjectRoots !== undefined) {
    registryOptions.approvedProjectRoots = options.approvedProjectRoots;
  }
  if (options.integrations !== undefined) {
    registryOptions.integrations = options.integrations;
  }
  return registryOptions;
}

function publicFingerprint(identity) {
  const fingerprint = identity?.fingerprint;
  if (typeof fingerprint !== 'string' || !/^[a-f0-9]{64}$/u.test(fingerprint)) {
    throw new TypeError('identity must provide a public fingerprint.');
  }
  return fingerprint;
}

function publicSetupStatus(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('setup status is unavailable.');
  }
  const complete = Object.getOwnPropertyDescriptor(value, 'complete');
  if (complete === undefined || !Object.hasOwn(complete, 'value') || typeof complete.value !== 'boolean') {
    throw new TypeError('setup status is unavailable.');
  }
  if (!complete.value) {
    return { complete: false };
  }
  const scope = Object.getOwnPropertyDescriptor(value, 'scope');
  if (
    scope === undefined
    || !Object.hasOwn(scope, 'value')
    || !['project', 'global', 'both'].includes(scope.value)
  ) {
    throw new TypeError('setup status is unavailable.');
  }
  return { complete: true, scope: scope.value };
}
