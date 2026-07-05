import { describe, expect, it } from 'vitest';
import { DecryptError } from '../../errors';
import { fromBase64Url } from '../../utils/base64';
import type { WrappedSecretRecord } from '../types';
import { unwrapSecretBytes } from '../wrap';

/**
 * Known-answer interoperability vectors (docs/INTEROP-VECTORS.md).
 * These pin the v1 wire format: HKDF-SHA256(ikm=prfOutput, salt=empty,
 * info='webauthn-prf-zktv vault key wrap v1') and scrypt-based pw-v1.
 * If any of these tests fail, the implementation has diverged from every
 * record already in the wild — that is a release blocker, not a test bug.
 */

const SECRET = new Uint8Array(32).fill(0x03);

describe('prf-v1 known-answer vector', () => {
  const record: WrappedSecretRecord = {
    scheme: 'prf-v1',
    ciphertext: fromBase64Url('_8qmjSCDoMDF__kUdrvYgIonmlPj2ZZrWGTKmWAwJm9SoC1_U7QdM9QZ1XeVR0n-'),
    nonce: fromBase64Url('BAQEBAQEBAQEBAQE'),
    salt: fromBase64Url('AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI'),
  };

  it('unwraps to the pinned 32-byte secret', async () => {
    const prfOutput = fromBase64Url('AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE');
    const secret = await unwrapSecretBytes({ record, prfOutput });
    expect(Array.from(secret)).toEqual(Array.from(SECRET));
  });

  it('throws generic DecryptError under a wrong PRF output', async () => {
    const wrong = new Uint8Array(32).fill(0xff);
    await expect(unwrapSecretBytes({ record, prfOutput: wrong })).rejects.toBeInstanceOf(
      DecryptError,
    );
  });
});

describe('pw-v1 known-answer vector', () => {
  // Reduced-cost params for test speed only; DEFAULT_SCRYPT_PARAMS floor
  // (N=131072) is pinned separately in derive tests.
  const record: WrappedSecretRecord = {
    scheme: 'pw-v1',
    ciphertext: fromBase64Url('bmTKLnKMUiSx7H4BPTRTONutUzRAuUFw0eTmGNje_n7xu5ilOGEL81LybNgccTTR'),
    nonce: fromBase64Url('BAQEBAQEBAQEBAQE'),
    salt: fromBase64Url('BQUFBQUFBQUFBQUFBQUFBQ'),
    kdfParams: { N: 16384, r: 8, p: 1 },
  };

  it('unwraps to the pinned 32-byte secret', async () => {
    const secret = await unwrapSecretBytes({
      record,
      password: 'correct horse battery staple',
    });
    expect(Array.from(secret)).toEqual(Array.from(SECRET));
  });

  it('throws generic DecryptError under a wrong password', async () => {
    await expect(
      unwrapSecretBytes({ record, password: 'incorrect horse' }),
    ).rejects.toBeInstanceOf(DecryptError);
  });
});
