export type WrapScheme = 'prf-v1' | 'pw-v1';

export interface ScryptParams {
  N: number;
  r: number;
  p: number;
}

/**
 * The ONLY shape this package ever persists. In-memory key material
 * (CryptoKey, PRF output) has no serializable representation on purpose.
 */
export interface WrappedSecretRecord {
  scheme: WrapScheme;
  /** AES-256-GCM output, auth tag included. */
  ciphertext: Uint8Array;
  /** 96-bit random IV, unique per wrap. */
  nonce: Uint8Array;
  /** PRF salt (prf-v1) or scrypt salt (pw-v1). */
  salt: Uint8Array;
  /** Present iff scheme === 'pw-v1'. */
  kdfParams?: ScryptParams;
}

export const NONCE_LENGTH = 12;
export const MIN_SALT_LENGTH = 16;
export const GCM_TAG_LENGTH = 16;
