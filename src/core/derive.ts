import { scrypt } from '@noble/hashes/scrypt';
import type { ScryptParams } from './types';

/** Domain-separation label — binds derived keys to this exact purpose. */
export const HKDF_INFO_V1: Uint8Array = new TextEncoder().encode(
  'webauthn-prf-zktv vault key wrap v1',
);

/**
 * HKDF-SHA256(prfOutput) → non-extractable AES-256-GCM wrap key.
 * The PRF output is Input Keying Material — never used as a key directly.
 * HKDF salt is empty (RFC 5869: valid, treated as zeros); per-credential
 * domain separation comes from the unique PRF salt → unique IKM.
 */
export async function deriveWrapKeyFromPrf(
  prfOutput: Uint8Array,
  info: Uint8Array = HKDF_INFO_V1,
): Promise<CryptoKey> {
  const ikm = await crypto.subtle.importKey('raw', prfOutput as BufferSource, 'HKDF', false, [
    'deriveKey',
  ]);
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0) as BufferSource,
      info: info as BufferSource,
    },
    ikm,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/** TrustVault Finding 3 (2026-06-11): memory-hard scrypt, not PBKDF2, bounds offline guessing. */
export const DEFAULT_SCRYPT_PARAMS: ScryptParams = { N: 131072, r: 8, p: 1 };

export async function deriveWrapKeyFromPassword(
  password: string,
  salt: Uint8Array,
  params: ScryptParams = DEFAULT_SCRYPT_PARAMS,
): Promise<CryptoKey> {
  const derived = scrypt(password, salt, { ...params, dkLen: 32 });
  try {
    return await crypto.subtle.importKey('raw', derived as BufferSource, { name: 'AES-GCM' }, false, [
      'encrypt',
      'decrypt',
    ]);
  } finally {
    derived.fill(0); // zeroize transient key bytes after non-extractable import
  }
}
