import { describe, expect, it } from 'vitest';
import {
  DEFAULT_SCRYPT_PARAMS,
  deriveWrapKeyFromPassword,
  deriveWrapKeyFromPrf,
  HKDF_INFO_V1,
} from '../derive';

const prfOutput = new Uint8Array(32).fill(7);

async function roundTrip(encKey: CryptoKey, decKey: CryptoKey): Promise<boolean> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, encKey, new Uint8Array([1, 2, 3]));
  try {
    await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, decKey, ct);
    return true;
  } catch {
    return false;
  }
}

describe('deriveWrapKeyFromPrf', () => {
  it('returns a non-extractable AES-GCM-256 key', async () => {
    const key = await deriveWrapKeyFromPrf(prfOutput);
    expect(key.extractable).toBe(false);
    expect(key.algorithm).toMatchObject({ name: 'AES-GCM', length: 256 });
    expect(key.usages).toEqual(expect.arrayContaining(['encrypt', 'decrypt']));
  });

  it('is deterministic: same PRF output derives interoperable keys', async () => {
    const a = await deriveWrapKeyFromPrf(prfOutput);
    const b = await deriveWrapKeyFromPrf(new Uint8Array(prfOutput));
    expect(await roundTrip(a, b)).toBe(true);
  });

  it('different PRF outputs derive non-interoperable keys', async () => {
    const a = await deriveWrapKeyFromPrf(prfOutput);
    const b = await deriveWrapKeyFromPrf(new Uint8Array(32).fill(8));
    expect(await roundTrip(a, b)).toBe(false);
  });

  it('different HKDF info labels derive non-interoperable keys (domain separation)', async () => {
    const a = await deriveWrapKeyFromPrf(prfOutput, HKDF_INFO_V1);
    const b = await deriveWrapKeyFromPrf(prfOutput, new TextEncoder().encode('other label'));
    expect(await roundTrip(a, b)).toBe(false);
  });
});

// Small params for test speed — production default is N=131072.
const fastParams = { N: 1024, r: 8, p: 1 };
const salt = new Uint8Array(32).fill(9);

describe('deriveWrapKeyFromPassword', () => {
  it('exposes TrustVault Finding-3 scrypt defaults', () => {
    expect(DEFAULT_SCRYPT_PARAMS).toEqual({ N: 131072, r: 8, p: 1 });
  });

  it('returns a deterministic non-extractable AES-GCM key', async () => {
    const a = await deriveWrapKeyFromPassword('correct horse', salt, fastParams);
    const b = await deriveWrapKeyFromPassword('correct horse', salt, fastParams);
    expect(a.extractable).toBe(false);
    expect(await roundTrip(a, b)).toBe(true);
  });

  it('wrong password or different salt derives non-interoperable keys', async () => {
    const good = await deriveWrapKeyFromPassword('correct horse', salt, fastParams);
    const wrongPw = await deriveWrapKeyFromPassword('wrong horse', salt, fastParams);
    const wrongSalt = await deriveWrapKeyFromPassword('correct horse', new Uint8Array(32), fastParams);
    expect(await roundTrip(good, wrongPw)).toBe(false);
    expect(await roundTrip(good, wrongSalt)).toBe(false);
  });
});
