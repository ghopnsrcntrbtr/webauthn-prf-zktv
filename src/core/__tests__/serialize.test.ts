import { describe, expect, it } from 'vitest';
import { parseRecord, serializeRecord } from '../serialize';
import type { WrappedSecretRecord } from '../types';
import { RecordFormatError } from '../../errors';

const prfRecord: WrappedSecretRecord = {
  scheme: 'prf-v1',
  ciphertext: new Uint8Array(48).fill(1),
  nonce: new Uint8Array(12).fill(2),
  salt: new Uint8Array(32).fill(3),
};

const pwRecord: WrappedSecretRecord = {
  scheme: 'pw-v1',
  ciphertext: new Uint8Array(48).fill(4),
  nonce: new Uint8Array(12).fill(5),
  salt: new Uint8Array(32).fill(6),
  kdfParams: { N: 131072, r: 8, p: 1 },
};

describe('serializeRecord / parseRecord', () => {
  it('round-trips prf-v1 and pw-v1 records', () => {
    expect(parseRecord(serializeRecord(prfRecord))).toEqual(prfRecord);
    expect(parseRecord(serializeRecord(pwRecord))).toEqual(pwRecord);
  });

  it('emits versioned JSON with base64url fields', () => {
    const parsed = JSON.parse(serializeRecord(prfRecord)) as Record<string, unknown>;
    expect(parsed.v).toBe(1);
    expect(typeof parsed.ciphertext).toBe('string');
    expect(parsed.ciphertext).not.toMatch(/[+/=]/);
  });

  it.each([
    ['not json', 'not-json{{{'],
    ['wrong version', JSON.stringify({ v: 2, scheme: 'prf-v1', ciphertext: 'AA', nonce: 'AA', salt: 'AA' })],
    ['unknown scheme', JSON.stringify({ v: 1, scheme: 'device-key', ciphertext: 'AA', nonce: 'AA', salt: 'AA' })],
    ['missing field', JSON.stringify({ v: 1, scheme: 'prf-v1', nonce: 'AA', salt: 'AA' })],
    ['non-string field', JSON.stringify({ v: 1, scheme: 'prf-v1', ciphertext: 7, nonce: 'AA', salt: 'AA' })],
  ])('rejects hostile input: %s', (_label, json) => {
    expect(() => parseRecord(json)).toThrow(RecordFormatError);
  });

  it('rejects wrong nonce length, short salt, tag-less ciphertext', () => {
    const bad = (patch: Partial<WrappedSecretRecord>) => serializeRecord({ ...prfRecord, ...patch });
    expect(() => parseRecord(bad({ nonce: new Uint8Array(11) }))).toThrow(RecordFormatError);
    expect(() => parseRecord(bad({ salt: new Uint8Array(8) }))).toThrow(RecordFormatError);
    expect(() => parseRecord(bad({ ciphertext: new Uint8Array(16) }))).toThrow(RecordFormatError);
  });

  it('rejects pw-v1 without kdfParams and prf-v1 with kdfParams', () => {
    const noParams = JSON.parse(serializeRecord(pwRecord)) as Record<string, unknown>;
    delete noParams.kdfParams;
    expect(() => parseRecord(JSON.stringify(noParams))).toThrow(RecordFormatError);

    const extraParams = JSON.parse(serializeRecord(prfRecord)) as Record<string, unknown>;
    extraParams.kdfParams = { N: 2, r: 1, p: 1 };
    expect(() => parseRecord(JSON.stringify(extraParams))).toThrow(RecordFormatError);
  });
});
