import { createHash } from 'node:crypto';

export function canonicalJson(value) {
  return serialize(value, new Set());
}

export function sha256(value) {
  return createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex');
}

function serialize(value, ancestors) {
  if (value === null) {
    return 'null';
  }

  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) {
        throw new TypeError('Canonical JSON does not support non-finite numbers.');
      }
      return JSON.stringify(value);
    case 'string':
      return JSON.stringify(value);
    case 'object':
      return serializeObject(value, ancestors);
    default:
      throw new TypeError(`Canonical JSON does not support ${typeof value} values.`);
  }
}

function serializeObject(value, ancestors) {
  if (ancestors.has(value)) {
    throw new TypeError('Canonical JSON does not support circular values.');
  }

  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      for (const key of Object.keys(value)) {
        getOwnDataProperty(value, key);
      }

      const items = [];
      for (let index = 0; index < value.length; index += 1) {
        if (!Object.hasOwn(value, index)) {
          throw new TypeError('Canonical JSON does not support sparse arrays.');
        }
        items.push(serialize(getOwnDataProperty(value, index), ancestors));
      }
      return `[${items.join(',')}]`;
    }

    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError('Canonical JSON accepts only plain objects and arrays.');
    }

    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${serialize(getOwnDataProperty(value, key), ancestors)}`)
      .join(',')}}`;
  } finally {
    ancestors.delete(value);
  }
}

function getOwnDataProperty(value, key) {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (descriptor === undefined || !Object.hasOwn(descriptor, 'value')) {
    throw new TypeError('Canonical JSON does not support accessor properties.');
  }
  return descriptor.value;
}
