import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { appendFile, mkdir, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { GitInspector } from '../src/project/git-inspector.mjs';

const execFileAsync = promisify(execFile);

test('inspects the canonical Git worktree from a nested caller path without exposing remote data', async () => {
  await withTemporaryRepository(async (repositoryRoot) => {
    const nestedDirectory = join(repositoryRoot, 'nested', 'child');
    const inspector = new GitInspector();
    const expectedCommit = await git(repositoryRoot, ['rev-parse', 'HEAD']);

    const snapshot = await inspector.inspect(nestedDirectory);

    assert.deepEqual(Object.keys(snapshot).sort(), [
      'commit',
      'dirty',
      'dirtyFingerprint',
      'repositoryFingerprint',
      'root',
    ]);
    assert.equal(snapshot.root, await realpath(repositoryRoot));
    assert.equal(snapshot.commit, expectedCommit);
    assert.equal(snapshot.dirty, false);
    assert.match(snapshot.repositoryFingerprint, /^[a-f0-9]{64}$/);
    assert.match(snapshot.dirtyFingerprint, /^[a-f0-9]{64}$/);
    assert.doesNotMatch(JSON.stringify(snapshot), /not-for-output/);
  });
});

test('derives a changed dirty-worktree fingerprint from the current worktree', async () => {
  await withTemporaryRepository(async (repositoryRoot) => {
    const inspector = new GitInspector();
    const cleanSnapshot = await inspector.inspect(repositoryRoot);

    await appendFile(join(repositoryRoot, 'dist', 'index.html'), '\nchanged once');
    const firstDirtySnapshot = await inspector.inspect(repositoryRoot);
    await appendFile(join(repositoryRoot, 'dist', 'index.html'), '\nchanged twice');
    const secondDirtySnapshot = await inspector.inspect(repositoryRoot);

    assert.equal(firstDirtySnapshot.dirty, true);
    assert.equal(secondDirtySnapshot.dirty, true);
    assert.notEqual(firstDirtySnapshot.dirtyFingerprint, cleanSnapshot.dirtyFingerprint);
    assert.notEqual(secondDirtySnapshot.dirtyFingerprint, firstDirtySnapshot.dirtyFingerprint);
    assert.equal(firstDirtySnapshot.commit, cleanSnapshot.commit);
  });
});

test('uses Git-derived commits instead of a caller-supplied commit value', async () => {
  await withTemporaryRepository(async (repositoryRoot) => {
    const inspector = new GitInspector();
    const initialSnapshot = await inspector.inspect(repositoryRoot, {
      commit: '0000000000000000000000000000000000000000',
    });

    await writeFile(join(repositoryRoot, 'next.txt'), 'next commit\n');
    await git(repositoryRoot, ['add', 'next.txt']);
    await git(repositoryRoot, ['commit', '-m', 'next']);

    const expectedCommit = await git(repositoryRoot, ['rev-parse', 'HEAD']);
    const changedSnapshot = await inspector.inspect(repositoryRoot, {
      commit: initialSnapshot.commit,
    });

    assert.notEqual(changedSnapshot.commit, initialSnapshot.commit);
    assert.equal(changedSnapshot.commit, expectedCommit);
  });
});

test('fails closed for non-Git directories and invalid roots', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'atomical-keyguard-non-git-'));
  const inspector = new GitInspector();

  try {
    await assert.rejects(
      inspector.inspect(directory),
      /Git project inspection is unavailable\./,
    );
    await assert.rejects(
      inspector.inspect(join(directory, 'does-not-exist')),
      /Git project inspection is unavailable\./,
    );
    await assert.rejects(
      inspector.inspect(null),
      /Git project inspection is unavailable\./,
    );
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
});

async function withTemporaryRepository(run) {
  const repositoryRoot = await mkdtemp(join(tmpdir(), 'atomical-keyguard-git-'));

  try {
    await git(repositoryRoot, ['init']);
    await git(repositoryRoot, ['config', 'user.email', 'tests@example.invalid']);
    await git(repositoryRoot, ['config', 'user.name', 'Atomical Keyguard Tests']);
    await git(repositoryRoot, [
      'remote',
      'add',
      'origin',
      'https://not-for-output:private-token@example.invalid/atomical-keyguard.git',
    ]);
    await mkdir(join(repositoryRoot, 'dist'), { recursive: true });
    await mkdir(join(repositoryRoot, 'nested', 'child'), { recursive: true });
    await Promise.all([
      writeFile(join(repositoryRoot, 'README.md'), '# Test repository\n'),
      writeFile(join(repositoryRoot, 'dist', 'index.html'), '<h1>Initial</h1>\n'),
      writeFile(join(repositoryRoot, 'nested', 'child', '.keep'), ''),
    ]);
    await git(repositoryRoot, ['add', '.']);
    await git(repositoryRoot, ['commit', '-m', 'initial']);
    return await run(repositoryRoot);
  } finally {
    await rm(repositoryRoot, { force: true, recursive: true });
  }
}

async function git(cwd, args) {
  const { stdout } = await execFileAsync('git', args, {
    cwd,
    env: {
      ...process.env,
      GIT_CONFIG_NOSYSTEM: '1',
      GIT_TERMINAL_PROMPT: '0',
    },
  });
  return stdout.trim();
}
