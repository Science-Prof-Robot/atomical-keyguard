import assert from 'node:assert/strict';
import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import test from 'node:test';

import { InstallerControlService } from '../src/services/installer-control.mjs';
import { withTemporaryDataDirectory } from './helpers.mjs';

const TEST_SECRET = 'installer-control-secret-must-never-be-returned';
const INITIAL_TIME = '2026-07-14T12:00:00.000Z';

test('keeps fixed installer roots and plans server-side while projecting only opaque safe destinations', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    const projectRoot = join(dataDirectory, 'project');
    const homeDirectory = join(dataDirectory, 'home');
    await Promise.all([mkdir(projectRoot), mkdir(homeDirectory)]);

    const clock = controllableClock(INITIAL_TIME);
    const calls = { apply: [], plan: [] };
    const rawPlan = installPlan({ homeDirectory, projectRoot });
    const installer = await InstallerControlService.open({
      applyInstall: async (plan, confirmation) => {
        calls.apply.push({ confirmation, plan });
        return {
          files: rawPlan.files.map((file) => ({ path: file.path, status: 'written' })),
          hosts: rawPlan.hosts,
          scope: rawPlan.scope,
          sharing: rawPlan.sharing,
          status: 'installed',
        };
      },
      clock,
      discoverEnvironment: async (root, options) => discovery({ homeDirectory, projectRoot, root, options }),
      homeDirectory,
      planIdGenerator: () => 'a'.repeat(16),
      planInstall: async (selection) => {
        calls.plan.push(selection);
        return rawPlan;
      },
      projectRoot,
    });

    const status = await installer.status();
    assert.deepEqual(status, {
      atomicCli: { detected: true },
      hosts: {
        claude: {
          detected: true,
          globalSkill: false,
          preselected: true,
          projectSkill: false,
        },
        codex: {
          detected: true,
          globalSkill: false,
          preselected: true,
          projectSkill: false,
        },
      },
      identity: { available: true },
      mcp: { registered: true },
      policy: { active: true, version: 7 },
      repository: { detected: true },
    });
    assert.doesNotMatch(JSON.stringify(status), new RegExp(TEST_SECRET));
    assert.equal(JSON.stringify(status).includes(projectRoot), false);
    assert.equal(JSON.stringify(status).includes(homeDirectory), false);

    await assert.rejects(
      installer.plan({ hosts: ['codex'], projectRoot: '/model-supplied-root' }),
      /selection|unsupported|request/i,
    );

    const plan = await installer.plan({ hosts: ['codex'] });
    assert.deepEqual(calls.plan, [{
      homeDirectory,
      hosts: ['codex'],
      projectRoot,
      scope: 'project',
      sharing: 'private',
    }]);
    assert.deepEqual(plan, {
      destinations: [
        { destination: '.atomical/keyguard/field-manual.md', scope: 'project' },
        { destination: '.agents/skills/atomical-keyguard/SKILL.md', scope: 'project' },
        { destination: '.gitignore', scope: 'project' },
      ],
      expiresAt: '2026-07-14T12:02:00.000Z',
      hosts: ['codex'],
      planId: `install_${'a'.repeat(16)}`,
      requiresConfirmation: true,
      requiresGlobalOptIn: false,
      scope: 'project',
      sharing: 'private',
      status: 'planned',
    });
    assert.doesNotMatch(JSON.stringify(plan), new RegExp(TEST_SECRET));
    assert.equal(JSON.stringify(plan).includes(projectRoot), false);
    assert.equal(JSON.stringify(plan).includes(homeDirectory), false);

    const installed = await installer.apply(plan.planId, { confirmed: true, globalOptIn: false });
    assert.deepEqual(calls.apply, [{
      confirmation: { confirmed: true, globalOptIn: false },
      plan: rawPlan,
    }]);
    assert.deepEqual(installed, {
      destinations: [
        { destination: '.atomical/keyguard/field-manual.md', scope: 'project', status: 'written' },
        { destination: '.agents/skills/atomical-keyguard/SKILL.md', scope: 'project', status: 'written' },
        { destination: '.gitignore', scope: 'project', status: 'written' },
      ],
      hosts: ['codex'],
      scope: 'project',
      sharing: 'private',
      status: 'installed',
    });
    await assert.rejects(
      installer.apply(plan.planId, { confirmed: true, globalOptIn: false }),
      /plan/i,
    );

    const expiring = await installer.plan({ hosts: ['codex'] });
    clock.advance((2 * 60 * 1000) + 1);
    await assert.rejects(
      installer.apply(expiring.planId, { confirmed: true, globalOptIn: false }),
      /plan/i,
    );
  });
});

test('requires explicit global opt-in before a cached global plan can apply', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    const projectRoot = join(dataDirectory, 'project');
    const homeDirectory = join(dataDirectory, 'home');
    await Promise.all([mkdir(projectRoot), mkdir(homeDirectory)]);

    const rawPlan = globalInstallPlan({ homeDirectory, projectRoot });
    const calls = [];
    const installer = await InstallerControlService.open({
      applyInstall: async (_plan, confirmation) => {
        calls.push(confirmation);
        return {
          files: rawPlan.files.map((file) => ({ path: file.path, status: 'written' })),
          hosts: rawPlan.hosts,
          scope: rawPlan.scope,
          sharing: rawPlan.sharing,
          status: 'installed',
        };
      },
      discoverEnvironment: async (root, options) => discovery({ homeDirectory, projectRoot, root, options }),
      homeDirectory,
      planIdGenerator: () => 'b'.repeat(16),
      planInstall: async () => rawPlan,
      projectRoot,
    });

    const plan = await installer.plan({ hosts: ['codex'], scope: 'global' });
    assert.equal(plan.requiresGlobalOptIn, true);
    await assert.rejects(
      installer.apply(plan.planId, { confirmed: true, globalOptIn: false }),
      /global opt-in/i,
    );
    assert.deepEqual(calls, []);

    const installed = await installer.apply(plan.planId, { confirmed: true, globalOptIn: true });
    assert.equal(installed.status, 'installed');
    assert.deepEqual(calls, [{ confirmed: true, globalOptIn: true }]);
  });
});

test('rejects injected artifacts whose scopes conflict with the requested top-level scope', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    const projectRoot = join(dataDirectory, 'project');
    const homeDirectory = join(dataDirectory, 'home');
    await Promise.all([mkdir(projectRoot), mkdir(homeDirectory)]);

    const projectPlanWithGlobalFile = installPlan({ homeDirectory, projectRoot });
    projectPlanWithGlobalFile.files[0] = globalInstallPlan({ homeDirectory, projectRoot }).files[0];

    const globalPlanWithProjectFile = globalInstallPlan({ homeDirectory, projectRoot });
    globalPlanWithProjectFile.files[0] = installPlan({ homeDirectory, projectRoot }).files[0];

    const bothPlanWithoutGlobalFiles = bothInstallPlan({ homeDirectory, projectRoot });
    bothPlanWithoutGlobalFiles.files = bothPlanWithoutGlobalFiles.files.filter((file) => file.scope === 'project');

    for (const { rawPlan, scope } of [
      { rawPlan: projectPlanWithGlobalFile, scope: 'project' },
      { rawPlan: globalPlanWithProjectFile, scope: 'global' },
      { rawPlan: bothPlanWithoutGlobalFiles, scope: 'both' },
    ]) {
      const calls = [];
      const installer = await InstallerControlService.open({
        applyInstall: async (plan) => {
          calls.push(plan);
          throw new Error('applyInstall must not receive a malformed plan.');
        },
        discoverEnvironment: async (root, options) => discovery({ homeDirectory, projectRoot, root, options }),
        homeDirectory,
        planIdGenerator: () => 'c'.repeat(16),
        planInstall: async () => rawPlan,
        projectRoot,
      });

      await assert.rejects(
        installer.plan({ hosts: ['codex'], scope }),
        /unavailable/i,
      );
      assert.deepEqual(calls, []);
    }
  });
});

test('does not pass a post-preview global artifact to an injected apply seam', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    const projectRoot = join(dataDirectory, 'project');
    const homeDirectory = join(dataDirectory, 'home');
    await Promise.all([mkdir(projectRoot), mkdir(homeDirectory)]);

    const rawPlan = installPlan({ homeDirectory, projectRoot });
    const calls = [];
    const installer = await InstallerControlService.open({
      applyInstall: async (plan, confirmation) => {
        calls.push({ confirmation, plan });
        return appliedPlan(plan);
      },
      discoverEnvironment: async (root, options) => discovery({ homeDirectory, projectRoot, root, options }),
      homeDirectory,
      planIdGenerator: () => 'd'.repeat(16),
      planInstall: async () => rawPlan,
      projectRoot,
    });

    const preview = await installer.plan({ hosts: ['codex'], scope: 'project' });
    rawPlan.files[0] = globalInstallPlan({ homeDirectory, projectRoot }).files[0];

    const installed = await installer.apply(preview.planId, { confirmed: true, globalOptIn: false });
    assert.equal(installed.status, 'installed');
    assert.equal(calls.length, 1);
    assert.equal(calls[0].plan.files.every((file) => file.scope === 'project'), true);
    assert.equal(calls[0].confirmation.globalOptIn, false);
  });
});

test('rejects Windows-absolute artifact destinations from injected plans on every host platform', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    const projectRoot = join(dataDirectory, 'project');
    const homeDirectory = join(dataDirectory, 'home');
    await Promise.all([mkdir(projectRoot), mkdir(homeDirectory)]);

    for (const unsafeDestination of [
      'C:\\escape',
      'C:/escape',
      '\\\\server\\share',
      '\\\\?\\C:\\escape',
      '\\??\\C:\\escape',
    ]) {
      const rawPlan = installPlan({ homeDirectory, projectRoot });
      rawPlan.files[0] = {
        ...rawPlan.files[0],
        path: `${projectRoot}/${unsafeDestination}`,
      };
      const installer = await InstallerControlService.open({
        discoverEnvironment: async (root, options) => discovery({ homeDirectory, projectRoot, root, options }),
        homeDirectory,
        planIdGenerator: () => 'e'.repeat(16),
        planInstall: async () => rawPlan,
        projectRoot,
      });

      await assert.rejects(installer.plan({ hosts: ['codex'] }), /unavailable/i);
    }
  });
});

test('purges expired previews and refuses an unbounded number of live installer plans', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    const projectRoot = join(dataDirectory, 'project');
    const homeDirectory = join(dataDirectory, 'home');
    await Promise.all([mkdir(projectRoot), mkdir(homeDirectory)]);

    const clock = controllableClock(INITIAL_TIME);
    const rawPlan = installPlan({ homeDirectory, projectRoot });
    let nextId = 0;
    const installer = await InstallerControlService.open({
      clock,
      discoverEnvironment: async (root, options) => discovery({ homeDirectory, projectRoot, root, options }),
      homeDirectory,
      planIdGenerator: () => String(++nextId).padStart(8, '0'),
      planInstall: async () => rawPlan,
      projectRoot,
    });

    for (let index = 0; index < 64; index += 1) {
      await installer.plan({ hosts: ['codex'] });
    }
    await assert.rejects(installer.plan({ hosts: ['codex'] }), /unavailable/i);

    clock.advance((2 * 60 * 1000) + 1);
    const replacement = await installer.plan({ hosts: ['codex'] });
    assert.match(replacement.planId, /^install_/u);
  });
});

function discovery({ homeDirectory, projectRoot, root }) {
  assert.equal(root, projectRoot);
  return {
    atomicCli: { detected: true, path: join(homeDirectory, TEST_SECRET, 'atomic') },
    homeDirectory,
    hosts: {
      claude: {
        detected: true,
        globalSkill: false,
        invocation: `/${TEST_SECRET}/claude`,
        preselected: true,
        projectSkill: false,
      },
      codex: {
        detected: true,
        globalSkill: false,
        invocation: `/${TEST_SECRET}/codex`,
        preselected: true,
        projectSkill: false,
      },
    },
    identity: { available: true, fingerprint: 'a'.repeat(64) },
    mcp: { registered: true },
    policy: { active: true, path: join(projectRoot, TEST_SECRET, 'policy.json'), version: 7 },
    projectRoot,
    repository: { detected: true, root: projectRoot },
  };
}

function installPlan({ homeDirectory, projectRoot }) {
  const files = [
    {
      content: TEST_SECRET,
      kind: 'write',
      path: join(projectRoot, '.atomical', 'keyguard', 'field-manual.md'),
      root: projectRoot,
      scope: 'project',
    },
    {
      content: TEST_SECRET,
      kind: 'write',
      path: join(projectRoot, '.agents', 'skills', 'atomical-keyguard', 'SKILL.md'),
      root: projectRoot,
      scope: 'project',
    },
    {
      entries: [`/${TEST_SECRET}`],
      kind: 'gitignore',
      path: join(projectRoot, '.gitignore'),
      root: projectRoot,
      scope: 'project',
    },
  ];
  return {
    files,
    homeDirectory,
    hosts: ['codex'],
    projectRoot,
    requiresConfirmation: true,
    requiresGlobalOptIn: false,
    scope: 'project',
    sharing: 'private',
    version: 1,
  };
}

function globalInstallPlan({ homeDirectory, projectRoot }) {
  return {
    files: [{
      content: TEST_SECRET,
      kind: 'write',
      path: join(homeDirectory, '.agents', 'skills', 'atomical-keyguard', 'SKILL.md'),
      root: homeDirectory,
      scope: 'global',
    }],
    homeDirectory,
    hosts: ['codex'],
    projectRoot,
    requiresConfirmation: true,
    requiresGlobalOptIn: true,
    scope: 'global',
    sharing: 'private',
    version: 1,
  };
}

function bothInstallPlan({ homeDirectory, projectRoot }) {
  const project = installPlan({ homeDirectory, projectRoot });
  const global = globalInstallPlan({ homeDirectory, projectRoot });
  return {
    ...project,
    files: [...project.files, ...global.files],
    requiresGlobalOptIn: true,
    scope: 'both',
  };
}

function appliedPlan(plan) {
  return {
    files: plan.files.map((file) => ({ path: file.path, status: 'written' })),
    hosts: plan.hosts,
    scope: plan.scope,
    sharing: plan.sharing,
    status: 'installed',
  };
}

function controllableClock(initialTime) {
  let current = new Date(initialTime);
  return {
    advance(milliseconds) {
      current = new Date(current.valueOf() + milliseconds);
    },
    now() {
      return new Date(current);
    },
  };
}
