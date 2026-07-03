import { wrapSecret, unwrapSecret } from '../core/wrap';
import type { WrappedSecretRecord } from '../core/types';
import { RecordFormatError } from '../errors';
import { zeroize } from '../utils/zeroize';
import { enrollPrfCredential, evaluatePrf, type EnrollOptions } from './ceremonies';

export interface EnrollVaultOptions {
  enroll: EnrollOptions;
  /** The 32-byte vault key to wrap. NOT zeroized by this call — caller owns it. */
  secret: Uint8Array;
}

export interface EnrollVaultResult {
  record: WrappedSecretRecord;
  credentialId: string;
  counter: number;
  transports: string[];
  usedSingleCeremony: boolean;
}

/** Ceremony → HKDF → wrap → zeroize PRF output. One call to enroll a PRF-unlockable vault. */
export async function enrollVault(options: EnrollVaultOptions): Promise<EnrollVaultResult> {
  const result = await enrollPrfCredential(options.enroll);
  try {
    const record = await wrapSecret({
      prfOutput: result.prfOutput,
      prfSalt: result.prfSalt,
      secret: options.secret,
    });
    return {
      record,
      credentialId: result.credentialId,
      counter: result.counter,
      transports: result.transports,
      usedSingleCeremony: result.usedSingleCeremony,
    };
  } finally {
    zeroize(result.prfOutput);
  }
}

export interface UnlockVaultOptions {
  credentialId: string;
  record: WrappedSecretRecord;
  rpId: string;
  storedCounter?: number;
}

export interface UnlockVaultResult {
  /** Non-extractable AES-256-GCM session key. */
  key: CryptoKey;
  /** New signature counter — persist it for the next unlock. */
  counter: number;
}

/** Ceremony → HKDF → unwrap → zeroize PRF output. One call to unlock. */
export async function unlockVault(options: UnlockVaultOptions): Promise<UnlockVaultResult> {
  if (options.record.scheme !== 'prf-v1') {
    throw new RecordFormatError('unlockVault requires a prf-v1 record');
  }
  const { prfOutput, counter } = await evaluatePrf({
    credentialId: options.credentialId,
    salt: options.record.salt,
    rpId: options.rpId,
    storedCounter: options.storedCounter ?? -1,
  });
  try {
    const key = await unwrapSecret({ record: options.record, prfOutput });
    return { key, counter };
  } finally {
    zeroize(prfOutput);
  }
}
