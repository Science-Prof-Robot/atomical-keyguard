import { Buffer } from 'node:buffer';

export const MAX_REDACTION_INPUT_LENGTH = 64 * 1024;
const MAX_SECRET_LENGTH = 16 * 1024;
// UTF-8 can use three bytes per JavaScript code unit, and percent encoding
// uses three source characters per byte.
const MAX_VARIANT_LENGTH = MAX_SECRET_LENGTH * 9;
const REDACTED = '[REDACTED]';
const TRUNCATED = '[TRUNCATED]';

/**
 * Redacts bounded, commonly serialized forms of one secret from diagnostic text.
 * Matching uses literal strings and fixed-format parsers only; no regular
 * expression is constructed from secret material.
 */
export function redactSensitiveOutput(text, secret) {
  if (typeof text !== 'string') {
    throw new TypeError('text must be a string.');
  }
  if (typeof secret !== 'string' || secret.length === 0) {
    throw new TypeError('secret must be a non-empty string.');
  }
  if (secret.length > MAX_SECRET_LENGTH) {
    throw new RangeError('secret exceeds the redaction limit.');
  }

  const variants = secretVariants(secret);
  const ranges = findSensitiveRanges(text, secret, variants);
  return renderRedacted(text, ranges);
}

function secretVariants(secret) {
  const bytes = Buffer.from(secret, 'utf8');
  const base64 = bytes.toString('base64');
  const componentEncoded = encodeUriComponent(bytes);
  const uriEncoded = encodeUri(bytes);
  const formEncoded = encodeForm(bytes);
  const strictPercentEncoded = encodeNonAlphanumeric(bytes);
  const percentEncoded = encodeAllBytes(bytes);
  const jsonEscaped = JSON.stringify(secret).slice(1, -1);
  const raw = new Set([
    secret,
    base64,
    base64.replace(/=+$/u, ''),
    bytes.toString('base64url'),
    componentEncoded,
    componentEncoded.replace(/%20/gu, '+'),
    uriEncoded,
    uriEncoded.replace(/%20/gu, '+'),
    formEncoded,
    strictPercentEncoded,
    strictPercentEncoded.replace(/%20/gu, '+'),
    percentEncoded,
    jsonEscaped,
  ]);
  const percentEncodedVariants = new Set([
    componentEncoded,
    componentEncoded.replace(/%20/gu, '+'),
    uriEncoded,
    uriEncoded.replace(/%20/gu, '+'),
    formEncoded,
    strictPercentEncoded,
    strictPercentEncoded.replace(/%20/gu, '+'),
    percentEncoded,
  ].map(normalizePercentEscapes));

  return {
    percentEncoded: [...percentEncodedVariants].filter((variant) => variant.length > 0),
    raw: [...raw].filter((variant) => variant.length > 0),
  };
}

function encodeNonAlphanumeric(bytes) {
  let encoded = '';
  for (const byte of bytes) {
    encoded += isAsciiAlphanumeric(byte) ? String.fromCharCode(byte) : percentByte(byte);
  }
  return encoded;
}

function encodeUriComponent(bytes) {
  let encoded = '';
  for (const byte of bytes) {
    encoded += isUriComponentUnescaped(byte)
      ? String.fromCharCode(byte)
      : percentByte(byte);
  }
  return encoded;
}

function encodeUri(bytes) {
  let encoded = '';
  for (const byte of bytes) {
    encoded += isUriUnescaped(byte)
      ? String.fromCharCode(byte)
      : percentByte(byte);
  }
  return encoded;
}

function encodeForm(bytes) {
  let encoded = '';
  for (const byte of bytes) {
    if (byte === 0x20) {
      encoded += '+';
    } else {
      encoded += isFormUnescaped(byte)
        ? String.fromCharCode(byte)
        : percentByte(byte);
    }
  }
  return encoded;
}

function encodeAllBytes(bytes) {
  let encoded = '';
  for (const byte of bytes) {
    encoded += percentByte(byte);
  }
  return encoded;
}

function percentByte(byte) {
  return `%${byte.toString(16).padStart(2, '0').toUpperCase()}`;
}

function isAsciiAlphanumeric(byte) {
  return (byte >= 0x30 && byte <= 0x39)
    || (byte >= 0x41 && byte <= 0x5a)
    || (byte >= 0x61 && byte <= 0x7a);
}

function isUriComponentUnescaped(byte) {
  return isAsciiAlphanumeric(byte)
    || byte === 0x21 // !
    || byte === 0x27 // '
    || byte === 0x28 // (
    || byte === 0x29 // )
    || byte === 0x2a // *
    || byte === 0x2d // -
    || byte === 0x2e // .
    || byte === 0x5f // _
    || byte === 0x7e; // ~
}

function isUriUnescaped(byte) {
  return isUriComponentUnescaped(byte)
    || byte === 0x23 // #
    || byte === 0x24 // $
    || byte === 0x26 // &
    || byte === 0x2b // +
    || byte === 0x2c // ,
    || byte === 0x2f // /
    || byte === 0x3a // :
    || byte === 0x3b // ;
    || byte === 0x3d // =
    || byte === 0x3f // ?
    || byte === 0x40; // @
}

function isFormUnescaped(byte) {
  return isAsciiAlphanumeric(byte)
    || byte === 0x2a // *
    || byte === 0x2d // -
    || byte === 0x2e // .
    || byte === 0x5f; // _
}

function normalizePercentEscapes(value) {
  return value.replace(/%[0-9a-f]{2}/giu, (escape) => escape.toUpperCase());
}

function findSensitiveRanges(text, secret, variants) {
  const scanText = text.slice(
    0,
    Math.min(text.length, MAX_REDACTION_INPUT_LENGTH + MAX_VARIANT_LENGTH),
  );
  const ranges = [];

  for (const variant of variants.raw) {
    ranges.push(...findLiteralRanges(scanText, variant));
  }

  const normalizedPercentText = normalizePercentEscapes(scanText);
  for (const variant of variants.percentEncoded) {
    ranges.push(...findLiteralRanges(normalizedPercentText, variant));
  }

  ranges.push(...findJsonEscapeRanges(scanText, secret));
  return mergeRanges(ranges);
}

function findLiteralRanges(text, variant) {
  const ranges = [];
  let start = text.indexOf(variant);

  while (start !== -1 && start < MAX_REDACTION_INPUT_LENGTH) {
    ranges.push({ end: start + variant.length, start });
    start = text.indexOf(variant, start + 1);
  }

  return ranges;
}

function findJsonEscapeRanges(text, secret) {
  const decoded = [];
  const starts = [];
  const ends = [];
  const escapedPrefix = [0];

  for (let index = 0; index < text.length;) {
    const escape = jsonEscapeAt(text, index);
    if (escape !== undefined) {
      decoded.push(escape.value);
      starts.push(index);
      ends.push(escape.end);
      escapedPrefix.push(escapedPrefix.at(-1) + 1);
      index = escape.end;
      continue;
    }

    decoded.push(text[index]);
    starts.push(index);
    ends.push(index + 1);
    escapedPrefix.push(escapedPrefix.at(-1));
    index += 1;
  }

  const decodedText = decoded.join('');
  const ranges = [];
  let decodedStart = decodedText.indexOf(secret);
  while (decodedStart !== -1) {
    const decodedEnd = decodedStart + secret.length;
    if (
      starts[decodedStart] < MAX_REDACTION_INPUT_LENGTH
      && escapedPrefix[decodedEnd] !== escapedPrefix[decodedStart]
    ) {
      ranges.push({
        end: ends[decodedEnd - 1],
        start: starts[decodedStart],
      });
    }
    decodedStart = decodedText.indexOf(secret, decodedStart + 1);
  }

  return ranges;
}

function jsonEscapeAt(text, index) {
  if (text[index] !== '\\' || index + 2 > text.length) {
    return undefined;
  }

  switch (text[index + 1]) {
    case '"':
      return { end: index + 2, value: '"' };
    case '\\':
      return { end: index + 2, value: '\\' };
    case '/':
      return { end: index + 2, value: '/' };
    case 'b':
      return { end: index + 2, value: String.fromCharCode(0x08) };
    case 'f':
      return { end: index + 2, value: String.fromCharCode(0x0c) };
    case 'n':
      return { end: index + 2, value: String.fromCharCode(0x0a) };
    case 'r':
      return { end: index + 2, value: String.fromCharCode(0x0d) };
    case 't':
      return { end: index + 2, value: String.fromCharCode(0x09) };
    case 'u':
      return unicodeEscapeAt(text, index);
    default:
      return undefined;
  }
}

function unicodeEscapeAt(text, index) {
  if (index + 6 > text.length) {
    return undefined;
  }

  let value = 0;
  for (let offset = 2; offset < 6; offset += 1) {
    const digit = hexDigit(text.charCodeAt(index + offset));
    if (digit === -1) {
      return undefined;
    }
    value = (value * 16) + digit;
  }
  return {
    end: index + 6,
    value: String.fromCharCode(value),
  };
}

function hexDigit(code) {
  if (code >= 0x30 && code <= 0x39) {
    return code - 0x30;
  }
  if (code >= 0x41 && code <= 0x46) {
    return code - 0x41 + 10;
  }
  if (code >= 0x61 && code <= 0x66) {
    return code - 0x61 + 10;
  }
  return -1;
}

function mergeRanges(ranges) {
  const sorted = ranges
    .filter((range) => range.end > range.start)
    .sort((left, right) => left.start - right.start || right.end - left.end);
  const merged = [];

  for (const range of sorted) {
    const previous = merged.at(-1);
    if (previous !== undefined && range.start <= previous.end) {
      previous.end = Math.max(previous.end, range.end);
    } else {
      merged.push({ ...range });
    }
  }

  return merged;
}

function renderRedacted(text, ranges) {
  const sourceLimit = Math.min(text.length, MAX_REDACTION_INPUT_LENGTH);
  const chunks = [];
  let cursor = 0;

  for (const range of ranges) {
    if (range.start >= sourceLimit) {
      break;
    }
    if (range.start > cursor) {
      chunks.push({ text: text.slice(cursor, range.start), type: 'safe' });
    }
    chunks.push({ text: REDACTED, type: 'marker' });
    cursor = Math.max(cursor, range.end);
    if (cursor >= sourceLimit) {
      break;
    }
  }

  if (cursor < sourceLimit) {
    chunks.push({ text: text.slice(cursor, sourceLimit), type: 'safe' });
  }

  const projectedLength = chunks.reduce((length, chunk) => length + chunk.text.length, 0);
  const requiresTruncation = text.length > sourceLimit || projectedLength > MAX_REDACTION_INPUT_LENGTH;
  const payloadLimit = MAX_REDACTION_INPUT_LENGTH
    - (requiresTruncation ? TRUNCATED.length : 0);
  const markerLater = [];
  let hasMarkerLater = false;

  for (let index = chunks.length - 1; index >= 0; index -= 1) {
    markerLater[index] = hasMarkerLater;
    if (chunks[index].type === 'marker') {
      hasMarkerLater = true;
    }
  }

  const outputParts = [];
  let outputLength = 0;

  for (let index = 0; index < chunks.length; index += 1) {
    const chunk = chunks[index];
    if (chunk.type === 'marker') {
      if (outputLength + REDACTED.length > payloadLimit) {
        outputLength -= removeSafeOutputForMarker(
          outputParts,
          outputLength + REDACTED.length - payloadLimit,
        );
      }
      if (outputLength + REDACTED.length <= payloadLimit) {
        outputParts.push({ text: REDACTED, type: 'marker' });
        outputLength += REDACTED.length;
      }
      continue;
    }

    const reservedMarkerLength = markerLater[index] ? REDACTED.length : 0;
    const availableLength = payloadLimit - outputLength - reservedMarkerLength;
    if (availableLength <= 0) {
      continue;
    }

    const safeText = chunk.text.slice(0, availableLength);
    if (safeText.length > 0) {
      outputParts.push({ text: safeText, type: 'safe' });
      outputLength += safeText.length;
    }
  }

  const output = outputParts.map((part) => part.text).join('');
  return requiresTruncation ? `${output}${TRUNCATED}` : output;
}

function removeSafeOutputForMarker(outputParts, requiredLength) {
  let removedLength = 0;

  for (let index = outputParts.length - 1; index >= 0 && removedLength < requiredLength; index -= 1) {
    const part = outputParts[index];
    if (part.type !== 'safe') {
      continue;
    }

    const removeFromPart = Math.min(part.text.length, requiredLength - removedLength);
    part.text = part.text.slice(0, part.text.length - removeFromPart);
    removedLength += removeFromPart;
    if (part.text.length === 0) {
      outputParts.splice(index, 1);
    } else {
      outputParts[index] = part;
    }
  }

  return removedLength;
}
