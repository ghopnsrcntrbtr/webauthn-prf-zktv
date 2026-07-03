import { DecryptError, RecordFormatError } from '../errors';
import { generateSalt } from '../utils/random';
import {
  DEFAULT_SCRYPT_PARAMS,
  deriveWrapKeyFromPassword,
  deriveWrapKeyFromPrf,
} from './derive';
import { NONCE_LENGTH, type ScryptParams, type WrapScheme, type WrappedSecretRecord } from './types';

export type WrapOptions =
  | { prfOutput: Uint8Array; prfSalt: Uint8Array; secret: Uint8Array }
  | { password: string; secret: Uint8Array; salt?: Uint8Array; kdfParams?: ScryptParams }
  | { wrapKey: CryptoKey; scheme: 'prf-v1'; salt: Uint8Array; secret: Uint8Array };

export type UnwrapOptions =
  | { record: WrappedSecretRecord; prfOutput: Uint8Array }
  | { record: WrappedSecretRecord; password: string }
  | { record: WrappedSecretRecord; wrapKey: CryptoKey };

export async function wrapSecret(options: WrapOptions): Promise<WrappedSecretRecord> {
  if ('prfOutput' in options) {
    const wrapKey = await deriveWrapKeyFromPrf(options.prfOutput);
    return encryptRecord(wrapKey, 'prf-v1', options.prfSalt, options.secret);
  }
  if ('password' in options) {
    const salt = options.salt ?? generateSalt();
    const kdfParams = options.kdfParams ?? DEFAULT_SCRYPT_PARAMS;
    const wrapKey = await deriveWrapKeyFromPassword(options.password, salt, kdfParams);
    const record = await encryptRecord(wrapKey, 'pw-v1', salt, options.secret);
    return { ...record, kdfParams };
  }
  return encryptRecord(options.wrapKey, options.scheme, options.salt, options.secret);
}

/**
 * Decrypts a record to raw bytes. The CALLER owns the returned buffer and
 * MUST zeroize() it when done. Prefer unwrapSecret() which never exposes bytes.
 */
export async function unwrapSecretBytes(options: UnwrapOptions): Promise<Uint8Array> {
  const { record } = options;
  let wrapKey: CryptoKey;
  if ('prfOutput' in options) {
    assertScheme(record, 'prf-v1', 'a PRF output');
    wrapKey = await deriveWrapKeyFromPrf(options.prfOutput);
  } else if ('password' in options) {
    assertScheme(record, 'pw-v1', 'a password');
    wrapKey = await deriveWrapKeyFromPassword(
      options.password,
      record.salt,
      record.kdfParams ?? DEFAULT_SCRYPT_PARAMS,
    );
  } else {
    wrapKey = options.wrapKey;
  }
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: record.nonce as BufferSource },
      wrapKey,
      record.ciphertext as BufferSource,
    );
    return new Uint8Array(plaintext);
  } catch {
    // Generic by invariant: never disclose wrong-key vs corrupt-data; never log the cause.
    throw new DecryptError();
  }
}

/**
 * Decrypts a wrapped 32-byte key and imports it as a NON-extractable
 * AES-256-GCM session key. Transient raw bytes are zeroized in finally.
 */
export async function unwrapSecret(options: UnwrapOptions): Promise<CryptoKey> {
  const bytes = await unwrapSecretBytes(options);
  try {
    if (bytes.length !== 32) {
      throw new RecordFormatError(
        'unwrapSecret requires a 32-byte wrapped secret (an AES-256 key); use unwrapSecretBytes for other payloads',
      );
    }
    return await crypto.subtle.importKey(
      'raw',
      bytes as BufferSource,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
  } finally {
    bytes.fill(0);
  }
}

async function encryptRecord(
  wrapKey: CryptoKey,
  scheme: WrapScheme,
  salt: Uint8Array,
  secret: Uint8Array,
): Promise<WrappedSecretRecord> {
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LENGTH));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce as BufferSource },
      wrapKey,
      secret as BufferSource,
    ),
  );
  return { scheme, ciphertext, nonce, salt: new Uint8Array(salt) };
}

function assertScheme(record: WrappedSecretRecord, expected: WrapScheme, source: string): void {
  if (record.scheme !== expected) {
    throw new RecordFormatError(
      `Record scheme '${record.scheme}' cannot be unwrapped with ${source}`,
    );
  }
}
