import { DecryptError, RecordFormatError } from '../errors';
import { fromBase64 } from '../utils/base64';
import { deriveWrapKeyFromPrf } from './derive';
import { wrapSecret } from './wrap';
import type { WrappedSecretRecord } from './types';

/** TrustVault-PWA's legacy HKDF domain-separation label (verbatim). */
export const TRUSTVAULT_HKDF_INFO: Uint8Array = new TextEncoder().encode(
  'TrustVault Vault Key Wrapping v1',
);

interface TrustVaultEncryptedData {
  ciphertext: string; // standard base64
  iv: string; // standard base64
}

export interface FromTrustVaultOptions {
  /** TrustVault WebAuthnCredential.wrappedVaultKey JSON string. */
  legacyJson: string;
  /** PRF output evaluated with the credential's stored prfSalt. */
  prfOutput: Uint8Array;
  /** The credential's stored prfSalt (becomes the new record's salt). */
  prfSalt: Uint8Array;
}

/**
 * One-shot migration: unwraps a TrustVault legacy record under the legacy HKDF
 * label and re-wraps the same vault key under the webauthn-prf-zktv v1 format.
 * Same PRF output, new domain-separation label — no extra ceremony required.
 * All transient plaintext buffers are zeroized.
 */
export async function fromTrustVaultRecord(
  options: FromTrustVaultOptions,
): Promise<WrappedSecretRecord> {
  const legacy = parseLegacy(options.legacyJson);
  const legacyKey = await deriveWrapKeyFromPrf(options.prfOutput, TRUSTVAULT_HKDF_INFO);

  let plaintext: Uint8Array;
  try {
    plaintext = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: fromBase64(legacy.iv) as BufferSource },
        legacyKey,
        fromBase64(legacy.ciphertext) as BufferSource,
      ),
    );
  } catch {
    throw new DecryptError();
  }

  // Legacy plaintext is the base64 STRING of the raw vault key (TrustVault format).
  let raw: Uint8Array | null = null;
  try {
    raw = fromBase64(new TextDecoder().decode(plaintext));
    return await wrapSecret({
      prfOutput: options.prfOutput,
      prfSalt: options.prfSalt,
      secret: raw,
    });
  } catch (error) {
    if (error instanceof DecryptError || error instanceof RecordFormatError) throw error;
    throw new RecordFormatError('Legacy record plaintext is not a base64 vault key');
  } finally {
    plaintext.fill(0);
    raw?.fill(0);
  }
}

function parseLegacy(json: string): TrustVaultEncryptedData {
  let raw: unknown;
  try {
    raw = JSON.parse(json);
  } catch {
    throw new RecordFormatError('Legacy record is not valid JSON');
  }
  const obj = raw as Record<string, unknown>;
  if (typeof obj?.ciphertext !== 'string' || typeof obj?.iv !== 'string') {
    throw new RecordFormatError('Legacy record is not TrustVault EncryptedData');
  }
  return { ciphertext: obj.ciphertext, iv: obj.iv };
}
