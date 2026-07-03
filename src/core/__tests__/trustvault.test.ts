import { describe, expect, it } from 'vitest';
import { fromTrustVaultRecord, TRUSTVAULT_HKDF_INFO } from '../trustvault';
import { deriveWrapKeyFromPrf } from '../derive';
import { unwrapSecretBytes } from '../wrap';
import { toBase64 } from '../../utils/base64';
import { DecryptError, RecordFormatError } from '../../errors';

const prfOutput = new Uint8Array(32).fill(7);
const prfSalt = new Uint8Array(32).fill(3);
const vaultKeyRaw = new Uint8Array(32).fill(42);

/** Fixture generator mirroring TrustVault's wrapVaultKeyWithPRF exactly:
 *  AES-GCM( base64(vaultKeyRaw) as UTF-8 ) under HKDF(prfOutput, legacy info),
 *  serialized as EncryptedData JSON with standard-base64 fields. */
async function makeLegacyRecord(): Promise<string> {
  const legacyKey = await deriveWrapKeyFromPrf(prfOutput, TRUSTVAULT_HKDF_INFO);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(toBase64(vaultKeyRaw));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, legacyKey, plaintext),
  );
  return JSON.stringify({ ciphertext: toBase64(ct), iv: toBase64(iv) });
}

describe('fromTrustVaultRecord', () => {
  it('re-wraps a legacy TrustVault record into a v1 prf-v1 record holding the same key', async () => {
    const legacyJson = await makeLegacyRecord();
    const record = await fromTrustVaultRecord({ legacyJson, prfOutput, prfSalt });
    expect(record.scheme).toBe('prf-v1');
    expect(record.salt).toEqual(prfSalt);
    expect(await unwrapSecretBytes({ record, prfOutput })).toEqual(vaultKeyRaw);
  });

  it('throws DecryptError on wrong PRF output', async () => {
    const legacyJson = await makeLegacyRecord();
    await expect(
      fromTrustVaultRecord({ legacyJson, prfOutput: new Uint8Array(32).fill(9), prfSalt }),
    ).rejects.toThrow(DecryptError);
  });

  it('throws RecordFormatError on malformed legacy JSON', async () => {
    await expect(
      fromTrustVaultRecord({ legacyJson: '{"nope":1}', prfOutput, prfSalt }),
    ).rejects.toThrow(RecordFormatError);
    await expect(
      fromTrustVaultRecord({ legacyJson: 'not json', prfOutput, prfSalt }),
    ).rejects.toThrow(RecordFormatError);
  });
});
