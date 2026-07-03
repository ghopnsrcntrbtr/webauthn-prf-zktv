import { fromBase64Url, toBase64Url } from '../utils/base64';
import { RecordFormatError } from '../errors';
import {
  GCM_TAG_LENGTH,
  MIN_SALT_LENGTH,
  NONCE_LENGTH,
  type ScryptParams,
  type WrappedSecretRecord,
} from './types';

interface SerializedRecordV1 {
  v: 1;
  scheme: string;
  ciphertext: string;
  nonce: string;
  salt: string;
  kdfParams?: ScryptParams;
}

export function serializeRecord(record: WrappedSecretRecord): string {
  const out: SerializedRecordV1 = {
    v: 1,
    scheme: record.scheme,
    ciphertext: toBase64Url(record.ciphertext),
    nonce: toBase64Url(record.nonce),
    salt: toBase64Url(record.salt),
    ...(record.kdfParams ? { kdfParams: record.kdfParams } : {}),
  };
  return JSON.stringify(out);
}

export function parseRecord(json: string): WrappedSecretRecord {
  let raw: unknown;
  try {
    raw = JSON.parse(json);
  } catch {
    throw new RecordFormatError('Record is not valid JSON');
  }
  if (typeof raw !== 'object' || raw === null) {
    throw new RecordFormatError('Record is not a JSON object');
  }
  const obj = raw as Record<string, unknown>;
  if (obj.v !== 1) throw new RecordFormatError('Unsupported record version');
  if (obj.scheme !== 'prf-v1' && obj.scheme !== 'pw-v1') {
    throw new RecordFormatError('Unknown wrap scheme');
  }
  const ciphertext = decodeField(obj, 'ciphertext');
  const nonce = decodeField(obj, 'nonce');
  const salt = decodeField(obj, 'salt');
  if (nonce.length !== NONCE_LENGTH) throw new RecordFormatError('Invalid nonce length');
  if (salt.length < MIN_SALT_LENGTH) throw new RecordFormatError('Salt too short');
  if (ciphertext.length <= GCM_TAG_LENGTH) throw new RecordFormatError('Ciphertext too short');

  if (obj.scheme === 'pw-v1') {
    const kdfParams = parseKdfParams(obj.kdfParams);
    return { scheme: 'pw-v1', ciphertext, nonce, salt, kdfParams };
  }
  if (obj.kdfParams !== undefined) {
    throw new RecordFormatError('prf-v1 records must not carry kdfParams');
  }
  return { scheme: 'prf-v1', ciphertext, nonce, salt };
}

function decodeField(obj: Record<string, unknown>, field: string): Uint8Array {
  const value = obj[field];
  if (typeof value !== 'string') {
    throw new RecordFormatError(`Missing or non-string field: ${field}`);
  }
  try {
    return fromBase64Url(value);
  } catch {
    throw new RecordFormatError(`Field is not valid base64url: ${field}`);
  }
}

function parseKdfParams(value: unknown): ScryptParams {
  if (typeof value !== 'object' || value === null) {
    throw new RecordFormatError('pw-v1 records require kdfParams');
  }
  const { N, r, p } = value as Record<string, unknown>;
  for (const [name, candidate] of Object.entries({ N, r, p })) {
    if (typeof candidate !== 'number' || !Number.isInteger(candidate) || candidate <= 0) {
      throw new RecordFormatError(`kdfParams.${name} must be a positive integer`);
    }
  }
  return { N: N as number, r: r as number, p: p as number };
}
