import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import test from 'node:test';

import { SetupService } from '../src/services/setup.mjs';
import { withTemporaryDataDirectory } from './helpers.mjs';

test('persists only a typed, nonsecret setup-completion projection', async () => {
  await withTemporaryDataDirectory(async (dataDirectory) => {
    const setup = await SetupService.open({ dataDirectory });

    assert.deepEqual(setup.status(), { complete: false });
    await assert.rejects(setup.complete('everywhere'), /scope/i);

    const completed = await setup.complete('project');
    assert.deepEqual(completed, { complete: true, scope: 'project' });
    assert.deepEqual(setup.status(), { complete: true, scope: 'project' });

    const persisted = JSON.parse(await readFile(join(dataDirectory, 'setup.json'), 'utf8'));
    assert.deepEqual(persisted, { complete: true, scope: 'project', version: 1 });

    const reopened = await SetupService.open({ dataDirectory });
    assert.deepEqual(reopened.status(), { complete: true, scope: 'project' });
    assert.equal(JSON.stringify(reopened.status()).includes(dataDirectory), false);
  });
});
