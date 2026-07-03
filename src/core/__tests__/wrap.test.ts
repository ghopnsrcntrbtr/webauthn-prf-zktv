import { describe, expect, it } from 'vitest';
import { unwrapSecret, unwrapSecretBytes, wrapSecret } from '../wrap';
import { DecryptError, RecordFormatError } from '../../errors';

const prfOutput = new Uint8Array(32).fill(7);
const prfSalt = new Uint8Array(32).fill(3);
const secret = new Uint8Array(32).fill(42); // a 32-byte vault key
const fastKdf = { N: 1024, r: 8, p: 1 };

describe('prf-v1 wrap/unwrap', () => {
  it('round-trips and returns a non-extractable session key', async () => {
    const record = await wrapSecret({ prfOutput, prfSalt, secret });
    expect(record.scheme).toBe('prf-v1');
    expect(record.salt).toEqual(prfSalt);
    expect(record.kdfParams).toBeUndefined();
    const key = await unwrapSecret({ record, prfOutput });
    expect(key.extractable).toBe(false);
  });

  it('unwrapSecretBytes returns the original secret', async () => {
    const record = await wrapSecret({ prfOutput, prfSalt, secret });
    expect(await unwrapSecretBytes({ record, prfOutput })).toEqual(secret);
  });

  it('wrong PRF output throws generic DecryptError', async () => {
    const record = await wrapSecret({ prfOutput, prfSalt, secret });
    await expect(
      unwrapSecret({ record, prfOutput: new Uint8Array(32).fill(8) }),
    ).rejects.toThrow(DecryptError);
  });

  it('nonces are unique across wraps of the same secret', async () => {
    const a = await wrapSecret({ prfOutput, prfSalt, secret });
    const b = await wrapSecret({ prfOutput, prfSalt, secret });
    expect(a.nonce).not.toEqual(b.nonce);
    expect(a.ciphertext).not.toEqual(b.ciphertext);
  });
});

describe('pw-v1 wrap/unwrap', () => {
  it('round-trips, generating salt and recording kdfParams', async () => {
    const record = await wrapSecret({ password: 'hunter2!', secret, kdfParams: fastKdf });
    expect(record.scheme).toBe('pw-v1');
    expect(record.salt).toHaveLength(32);
    expect(record.kdfParams).toEqual(fastKdf);
    expect(await unwrapSecretBytes({ record, password: 'hunter2!' })).toEqual(secret);
  });

  it('wrong password throws generic DecryptError', async () => {
    const record = await wrapSecret({ password: 'hunter2!', secret, kdfParams: fastKdf });
    await expect(unwrapSecret({ record, password: 'wrong' })).rejects.toThrow(DecryptError);
  });
});

describe('scheme/source mismatch and size guards', () => {
  it('rejects PRF unwrap of a pw-v1 record and vice versa', async () => {
    const pw = await wrapSecret({ password: 'x', secret, kdfParams: fastKdf });
    const prf = await wrapSecret({ prfOutput, prfSalt, secret });
    await expect(unwrapSecret({ record: pw, prfOutput })).rejects.toThrow(RecordFormatError);
    await expect(unwrapSecret({ record: prf, password: 'x' })).rejects.toThrow(RecordFormatError);
  });

  it('unwrapSecret rejects non-32-byte secrets (use unwrapSecretBytes)', async () => {
    const record = await wrapSecret({ prfOutput, prfSalt, secret: new Uint8Array(5) });
    await expect(unwrapSecret({ record, prfOutput })).rejects.toThrow(RecordFormatError);
    expect(await unwrapSecretBytes({ record, prfOutput })).toEqual(new Uint8Array(5));
  });
});
