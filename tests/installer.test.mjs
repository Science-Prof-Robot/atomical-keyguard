import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { constants } from 'node:fs';
import { chmod, lstat, mkdir, mkdtemp, open, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { discoverEnvironment } from '../src/installer/discovery.mjs';
import { applyInstall, planInstall } from '../src/installer/skill-installer.mjs';
import { renderGuidanceShim } from '../src/installer/templates.mjs';

test('discovers the project environment without modifying it', async () => {
  await withInstallerEnvironment(async ({ homeDirectory, projectRoot }) => {
    await mkdir(join(projectRoot, '.atomical', 'keyguard'), { recursive: true });
    await Promise.all([
      mkdir(join(projectRoot, '.git')),
      mkdir(join(homeDirectory, '.agents'), { recursive: true }),
      mkdir(join(homeDirectory, '.claude'), { recursive: true }),
      mkdir(join(homeDirectory, '.codex'), { recursive: true }),
      writeFile(join(homeDirectory, '.claude.json'), JSON.stringify({
        mcpServers: { 'atomical-keyguard': { command: 'keyguard' } },
      })),
      writeFile(join(projectRoot, '.atomical', 'keyguard', 'policy.json'), JSON.stringify({
        version: 7,
      })),
    ]);
    const before = await listTree(projectRoot);

    const detection = await discoverEnvironment(projectRoot, {
      environment: { PATH: '' },
      homeDirectory,
      identity: { fingerprint: 'a'.repeat(64) },
    });

    assert.equal(detection.repository.detected, true);
    assert.equal(detection.repository.root, detection.projectRoot);
    assert.equal(detection.atomicCli.detected, false);
    assert.deepEqual(detection.identity, {
      available: true,
      fingerprint: 'a'.repeat(64),
    });
    assert.equal(detection.hosts.claude.detected, true);
    assert.equal(detection.hosts.claude.preselected, true);
    assert.equal(detection.hosts.codex.detected, true);
    assert.equal(detection.hosts.codex.preselected, true);
    assert.equal(detection.mcp.registered, true);
    assert.equal(detection.policy.active, true);
    assert.equal(detection.policy.version, 7);
    assert.deepEqual(await listTree(projectRoot), before);
  });
});

test('plans a private project install for detected hosts without writing files', async () => {
  await withInstallerEnvironment(async ({ homeDirectory, projectRoot }) => {
    await Promise.all([
      mkdir(join(homeDirectory, '.claude'), { recursive: true }),
      mkdir(join(homeDirectory, '.codex'), { recursive: true }),
    ]);
    const detection = await discoverEnvironment(projectRoot, {
      environment: { PATH: '' },
      homeDirectory,
    });

    const plan = await planInstall({ discovery: detection });

    assert.equal(plan.scope, 'project');
    assert.equal(plan.sharing, 'private');
    assert.equal(Object.hasOwn(plan, 'confirmed'), false);
    assert.equal(Object.hasOwn(plan, 'globalOptIn'), false);
    assert.deepEqual(plan.hosts, ['claude', 'codex']);
    assert.equal(plan.files.some((file) => file.kind === 'gitignore'), true);
    assert.equal(
      plan.files.find((file) => file.kind === 'gitignore').entries.every((entry) => entry.startsWith('/')),
      true,
    );
    assert.equal(
      plan.files.some((file) => file.path.endsWith('/.claude/skills/atomical-keyguard/SKILL.md')),
      true,
    );
    assert.equal(
      plan.files.some((file) => file.path.endsWith('/.agents/skills/atomical-keyguard/SKILL.md')),
      true,
    );
    assert.equal(await exists(join(projectRoot, '.claude', 'skills', 'atomical-keyguard')), false);
    assert.equal(await exists(join(projectRoot, '.gitignore')), false);

    const sharedPlan = await planInstall({ discovery: detection, sharing: 'shared' });
    assert.equal(sharedPlan.files.some((file) => file.kind === 'gitignore'), false);
  });
});

test('requires a separate explicit opt-in before applying global writes', async () => {
  await withInstallerEnvironment(async ({ homeDirectory, projectRoot }) => {
    const plan = await planInstall({
      homeDirectory,
      hosts: ['claude'],
      projectRoot,
      scope: 'global',
    });

    assert.equal(plan.requiresGlobalOptIn, true);
    await assert.rejects(applyInstall(plan), /confirmation/i);
    await assert.rejects(
      applyInstall(plan, { confirmed: true }),
      /global opt-in/i,
    );

    const result = await applyInstall(plan, { confirmed: true, globalOptIn: true });

    assert.equal(result.status, 'installed');
    assert.equal(
      await exists(join(homeDirectory, '.claude', 'skills', 'atomical-keyguard', 'SKILL.md')),
      true,
    );
    assert.equal(
      await exists(join(projectRoot, '.claude', 'skills', 'atomical-keyguard', 'SKILL.md')),
      false,
    );
  });
});

test('does not accept confirmation or global opt-in baked into a plan', async () => {
  await withInstallerEnvironment(async ({ homeDirectory, projectRoot }) => {
    const plan = await planInstall({
      confirmed: true,
      globalOptIn: true,
      homeDirectory,
      hosts: ['claude'],
      projectRoot,
      scope: 'global',
    });

    await assert.rejects(applyInstall(plan), /confirmation/i);
    await assert.rejects(
      applyInstall(plan, { confirmed: true }),
      /global opt-in/i,
    );
    assert.equal(Object.hasOwn(plan, 'confirmed'), false);
    assert.equal(Object.hasOwn(plan, 'globalOptIn'), false);
  });
});

test('applies only confirmed private artifacts, merges .gitignore, and never runs Git', async () => {
  await withInstallerEnvironment(async ({ homeDirectory, projectRoot, sandbox }) => {
    const binDirectory = join(sandbox, 'bin');
    const gitSentinel = join(sandbox, 'git-was-run');
    await mkdir(binDirectory);
    await Promise.all([
      writeFile(join(projectRoot, '.gitignore'), 'node_modules/\n'),
      writeFile(join(binDirectory, 'git'), `#!/bin/sh\ntouch ${gitSentinel}\n`),
    ]);
    await chmod(join(binDirectory, 'git'), 0o755);
    const plan = await planInstall({
      homeDirectory,
      hosts: ['claude', 'codex'],
      projectRoot,
    });
    const originalPath = process.env.PATH;
    process.env.PATH = binDirectory;
    let result;
    try {
      result = await applyInstall(plan, { confirmed: true });
    } finally {
      process.env.PATH = originalPath;
    }

    assert.equal(result.status, 'installed');
    assert.deepEqual(
      [...result.files.map((file) => file.path)].sort(),
      [...plan.files.map((file) => file.path)].sort(),
    );
    assert.equal(await exists(gitSentinel), false);
    const gitignore = await readFile(join(projectRoot, '.gitignore'), 'utf8');
    assert.match(gitignore, /^node_modules\/$/m);
    assert.match(gitignore, /^\/\.atomical\/keyguard\/$/m);
    assert.match(gitignore, /^\/\.claude\/skills\/atomical-keyguard\/$/m);
    assert.match(gitignore, /^\/\.agents\/skills\/atomical-keyguard\/$/m);
    assert.match(gitignore, /^\/CLAUDE\.local\.md$/m);
    assert.match(gitignore, /^\/AGENTS\.md$/m);
    assert.match(
      await readFile(join(projectRoot, '.claude', 'skills', 'atomical-keyguard', 'SKILL.md'), 'utf8'),
      /\/atomical-keyguard/,
    );
    assert.match(
      await readFile(join(projectRoot, '.agents', 'skills', 'atomical-keyguard', 'SKILL.md'), 'utf8'),
      /\$atomical-keyguard/,
    );
    assert.match(
      await readFile(join(projectRoot, '.atomical', 'keyguard', 'field-manual.md'), 'utf8'),
      /Never reveal, request, store, or log credential values\./,
    );
    assert.match(
      await readFile(join(projectRoot, 'CLAUDE.local.md'), 'utf8'),
      /Atomical Keyguard/,
    );
    assert.match(
      await readFile(join(projectRoot, 'AGENTS.md'), 'utf8'),
      /Atomical Keyguard/,
    );
  });
});

test('rejects a tampered plan before it can write outside the selected roots', async () => {
  await withInstallerEnvironment(async ({ homeDirectory, projectRoot, sandbox }) => {
    const plan = await planInstall({
      homeDirectory,
      hosts: ['codex'],
      projectRoot,
    });
    const outsidePath = join(sandbox, 'outside.md');
    const tampered = {
      ...plan,
      files: [
        ...plan.files,
        {
          content: 'outside selected roots',
          kind: 'write',
          path: outsidePath,
          scope: 'project',
        },
      ],
    };

    await assert.rejects(
      applyInstall(tampered, { confirmed: true }),
      /install plan/i,
    );
    assert.equal(await exists(outsidePath), false);
  });
});

test('rejects a symlinked host path before writing any planned artifact', async () => {
  await withInstallerEnvironment(async ({ homeDirectory, projectRoot, sandbox }) => {
    const outsideDirectory = join(sandbox, 'outside');
    await mkdir(outsideDirectory);
    await symlink(outsideDirectory, join(projectRoot, '.agents'));
    const plan = await planInstall({
      homeDirectory,
      hosts: ['codex'],
      projectRoot,
    });

    await assert.rejects(
      applyInstall(plan, { confirmed: true }),
      /symbolic link/i,
    );
    assert.equal(
      await exists(join(projectRoot, '.atomical', 'keyguard', 'field-manual.md')),
      false,
    );
    assert.equal(
      await exists(join(outsideDirectory, 'skills', 'atomical-keyguard', 'SKILL.md')),
      false,
    );
  });
});

test('rejects equal project and home roots for a combined install', async () => {
  await withInstallerEnvironment(async ({ projectRoot }) => {
    await assert.rejects(
      planInstall({
        homeDirectory: projectRoot,
        hosts: ['codex'],
        projectRoot,
        scope: 'both',
      }),
      /must differ/i,
    );
  });
});

test('rejects a group/world-writable selected root before planning writes', { skip: process.platform === 'win32' }, async () => {
  await withInstallerEnvironment(async ({ homeDirectory, projectRoot }) => {
    await chmod(projectRoot, 0o777);

    await assert.rejects(
      planInstall({ homeDirectory, hosts: ['codex'], projectRoot }),
      /group.*world|writable/i,
    );
  });
});

test('rejects a group/world-writable planned parent before writing any artifact', { skip: process.platform === 'win32' }, async () => {
  await withInstallerEnvironment(async ({ homeDirectory, projectRoot }) => {
    const unsafeParent = join(projectRoot, '.agents');
    await mkdir(unsafeParent);
    await chmod(unsafeParent, 0o777);
    const plan = await planInstall({ homeDirectory, hosts: ['codex'], projectRoot });

    await assert.rejects(
      applyInstall(plan, { confirmed: true }),
      /group.*world|writable/i,
    );
    assert.equal(
      await exists(join(projectRoot, '.atomical', 'keyguard', 'field-manual.md')),
      false,
    );
  });
});

test('rejects oversized existing installer targets before reading or writing artifacts', async () => {
  await withInstallerEnvironment(async ({ homeDirectory, projectRoot }) => {
    await writeFile(join(projectRoot, '.gitignore'), 'x'.repeat((256 * 1024) + 1));
    const plan = await planInstall({ homeDirectory, hosts: ['codex'], projectRoot });

    await assert.rejects(
      applyInstall(plan, { confirmed: true }),
      /too large/i,
    );
    assert.equal(
      await exists(join(projectRoot, '.atomical', 'keyguard', 'field-manual.md')),
      false,
    );
  });
});

test('rejects FIFO installer targets without blocking', { skip: process.platform === 'win32' }, async () => {
  await withInstallerEnvironment(async ({ homeDirectory, projectRoot }) => {
    const fifoPath = join(projectRoot, 'AGENTS.md');
    execFileSync('mkfifo', [fifoPath]);
    const plan = await planInstall({ homeDirectory, hosts: ['codex'], projectRoot });
    const pending = applyInstall(plan, { confirmed: true });
    let outcome;
    try {
      outcome = await Promise.race([
        pending.then(
          () => ({ kind: 'resolved' }),
          (error) => ({ error, kind: 'rejected' }),
        ),
        delay(200).then(() => ({ kind: 'timeout' })),
      ]);
    } finally {
      if (outcome?.kind === 'timeout') {
        const writer = await open(fifoPath, constants.O_WRONLY | constants.O_NONBLOCK).catch(() => undefined);
        await writer?.close();
      }
      await pending.catch(() => undefined);
    }

    assert.equal(outcome.kind, 'rejected');
    assert.match(outcome.error.message, /regular file/i);
  });
});

test('repairs matching private artifact modes without overwriting their contents', { skip: process.platform === 'win32' }, async () => {
  await withInstallerEnvironment(async ({ homeDirectory, projectRoot }) => {
    const guidancePath = join(projectRoot, 'AGENTS.md');
    await writeFile(guidancePath, renderGuidanceShim('codex'));
    await chmod(guidancePath, 0o644);
    const plan = await planInstall({ homeDirectory, hosts: ['codex'], projectRoot });

    await applyInstall(plan, { confirmed: true });

    assert.equal((await lstat(guidancePath)).mode & 0o777, 0o600);
    assert.equal(await readFile(guidancePath, 'utf8'), renderGuidanceShim('codex'));
  });
});

async function withInstallerEnvironment(run) {
  const sandbox = await mkdtemp(join(tmpdir(), 'atomical-keyguard-installer-'));
  const homeDirectory = join(sandbox, 'home');
  const projectRoot = join(sandbox, 'project');

  try {
    await Promise.all([
      mkdir(homeDirectory, { recursive: true }),
      mkdir(projectRoot, { recursive: true }),
    ]);
    return await run({ homeDirectory, projectRoot, sandbox });
  } finally {
    await rm(sandbox, { force: true, recursive: true });
  }
}

async function exists(path) {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if (error?.code === 'ENOENT') {
      return false;
    }
    throw error;
  }
}

async function listTree(root, relativePath = '') {
  const directory = relativePath.length === 0 ? root : join(root, relativePath);
  const entries = await readdir(directory, { withFileTypes: true });
  const paths = [];
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
    const child = relativePath.length === 0 ? entry.name : join(relativePath, entry.name);
    paths.push(child);
    if (entry.isDirectory()) {
      paths.push(...await listTree(root, child));
    }
  }
  return paths;
}

function delay(milliseconds) {
  return new Promise((resolvePromise) => {
    setTimeout(resolvePromise, milliseconds);
  });
}
