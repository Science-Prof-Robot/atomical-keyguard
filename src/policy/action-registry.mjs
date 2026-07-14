import { realpathSync, statSync } from 'node:fs';
import { isAbsolute, parse } from 'node:path';

export const ACTION_NAME = 'cloudflare_pages_deploy';
export const POLICY_VERSION = 1;

/**
 * Builds the daemon-owned action registry. The only configurable value is the
 * explicitly trusted project-root list; action, credential, and execution
 * mappings are intentionally not request-configurable.
 */
export function createActionRegistry(options = {}) {
  if (options === null || typeof options !== 'object' || Array.isArray(options)) {
    throw new TypeError('Action registry options must be an object.');
  }
  for (const key of Object.keys(options)) {
    if (key !== 'approvedProjectRoots') {
      throw new TypeError('Action registry options contain an unsupported field.');
    }
  }

  const approvedProjectRoots = normalizeApprovedRoots(
    options.approvedProjectRoots ?? [process.cwd()],
  );
  const action = deepFreeze({
    approval: 'always',
    approvedProjectRoots,
    credentialLabel: 'cloudflare-api-token',
    execution: {
      args: [
        'wrangler',
        'pages',
        'deploy',
        '{{directory}}',
        '--project-name',
        '{{project}}',
      ],
      environment: {
        CLOUDFLARE_API_TOKEN: '$credential',
      },
      executable: 'npx',
    },
    name: ACTION_NAME,
    params: {
      directory: 'relative_path',
      project: 'slug',
    },
  });
  const listedAction = deepFreeze({
    approval: action.approval,
    name: action.name,
    params: action.params,
  });
  const listedActions = Object.freeze([listedAction]);

  return Object.freeze({
    get(actionName) {
      return actionName === ACTION_NAME ? action : undefined;
    },
    list() {
      return listedActions;
    },
    policyVersion: POLICY_VERSION,
  });
}

function normalizeApprovedRoots(roots) {
  if (!Array.isArray(roots) || roots.length === 0) {
    throw new TypeError('At least one approved project root is required.');
  }

  const canonicalRoots = new Set();
  for (const root of roots) {
    if (
      typeof root !== 'string'
      || root.length === 0
      || root.includes('*')
      || !isAbsolute(root)
    ) {
      throw new TypeError('Each approved project root must be an explicit absolute directory.');
    }

    let canonicalRoot;
    try {
      canonicalRoot = realpathSync(root);
      if (!statSync(canonicalRoot).isDirectory()) {
        throw new Error('not a directory');
      }
    } catch {
      throw new TypeError('Each approved project root must be an existing directory.');
    }
    if (canonicalRoot === parse(canonicalRoot).root) {
      throw new TypeError('An approved project root must not be a filesystem root.');
    }
    canonicalRoots.add(canonicalRoot);
  }

  return Object.freeze([...canonicalRoots].sort());
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const item of Object.values(value)) {
      deepFreeze(item);
    }
  }
  return value;
}
