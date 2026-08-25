#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const MAX_SAFE_INTEGER = 9_007_199_254_740_991;

function validate(value) {
  if (typeof value === 'number' && (!Number.isInteger(value) || !Number.isSafeInteger(value))) {
    throw new TypeError('numbers must be safe integers');
  }
  if (typeof value === 'string') {
    for (let index = 0; index < value.length; index += 1) {
      const unit = value.charCodeAt(index);
      if (unit >= 0xD800 && unit <= 0xDBFF) {
        const next = value.charCodeAt(index + 1);
        if (!(next >= 0xDC00 && next <= 0xDFFF)) throw new TypeError('lone Unicode surrogate');
        index += 1;
      } else if (unit >= 0xDC00 && unit <= 0xDFFF) {
        throw new TypeError('lone Unicode surrogate');
      }
    }
  }
  if (Array.isArray(value)) value.forEach(validate);
  else if (value && typeof value === 'object') {
    for (const [key, child] of Object.entries(value)) {
      validate(key);
      validate(child);
    }
  } else if (!['string', 'number', 'boolean', 'object'].includes(typeof value)) {
    throw new TypeError(`unsupported JSON value: ${typeof value}`);
  }
}

function text(value) {
  if (value === null) return 'null';
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number' || typeof value === 'boolean') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(text).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${text(value[key])}`).join(',')}}`;
}

export function canonicalize(value) {
  validate(value);
  return Buffer.from(text(value), 'utf8');
}

export function digest(value) {
  return createHash('sha256').update(canonicalize(value)).digest('hex');
}

export { MAX_SAFE_INTEGER };

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const vectors = JSON.parse(readFileSync(process.argv[2], 'utf8'));
  const results = vectors.map((vector) => {
    try {
      return { description: vector.description, canonical: canonicalize(vector.value).toString('utf8'), sha256: digest(vector.value) };
    } catch (error) {
      return { description: vector.description, error: error.message };
    }
  });
  process.stdout.write(`${JSON.stringify(results)}\n`);
}
