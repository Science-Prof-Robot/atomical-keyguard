import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const SECRET_BEARING_FIELD_NAME = /(?:secret|token|credential|password|private|authorization|vault)/i;

export async function withTemporaryDataDirectory(run) {
  const dataDirectory = await mkdtemp(join(tmpdir(), 'atomical-keyguard-'));

  try {
    return await run(dataDirectory);
  } finally {
    await rm(dataDirectory, { force: true, recursive: true });
  }
}

export function assertNoSecretBearingFields(value, path = '$') {
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoSecretBearingFields(item, `${path}[${index}]`));
    return;
  }

  if (value !== null && typeof value === 'object') {
    for (const [key, item] of Object.entries(value)) {
      assert.doesNotMatch(
        key,
        SECRET_BEARING_FIELD_NAME,
        `${path}.${key} must not be a secret-bearing field`,
      );
      assertNoSecretBearingFields(item, `${path}.${key}`);
    }
  }
}
