import { afterEach, describe, expect, it, vi } from 'vitest';
import { enrollVault, unlockVault } from '../vault';
import { unwrapSecretBytes } from '../../core/wrap';
import { RecordFormatError } from '../../errors';
import { toBase64Url } from '../../utils/base64';

const ORIGIN = 'https://example.com';
const RAW_ID = new Uint8Array([9, 8, 7, 6]);

type CreateExt = { enabled?: boolean; first?: Uint8Array };

/** Mock authenticator (mirrors enroll.test.ts): createExt controls create-time
 *  PRF behavior; the get mock always returns a valid PRF assertion (fill(5)). */
function stubAuthenticator(
  createExt: CreateExt,
  opts: { createError?: Error } = {},
): { create: ReturnType<typeof vi.fn>; get: ReturnType<typeof vi.fn> } {
  const create = vi.fn(async () => {
    if (opts.createError) throw opts.createError;
    return {
      rawId: RAW_ID.buffer,
      id: toBase64Url(RAW_ID),
      type: 'public-key',
      response: {
        getTransports: () => ['internal'],
        getPublicKey: () => new Uint8Array([1, 1, 1]).buffer,
      },
      getClientExtensionResults: () => ({
        prf: {
          ...(createExt.enabled !== undefined ? { enabled: createExt.enabled } : {}),
          ...(createExt.first ? { results: { first: createExt.first } } : {}),
        },
      }),
    };
  });
  const get = vi.fn(async (request: { publicKey: PublicKeyCredentialRequestOptions }) => {
    const challenge = new Uint8Array(request.publicKey.challenge as Uint8Array);
    const authenticatorData = new Uint8Array(37);
    new DataView(authenticatorData.buffer).setUint32(33, 1, false);
    return {
      rawId: RAW_ID.buffer,
      id: toBase64Url(RAW_ID),
      type: 'public-key',
      response: {
        clientDataJSON: new TextEncoder().encode(
          JSON.stringify({
            type: 'webauthn.get',
            challenge: toBase64Url(challenge),
            origin: ORIGIN,
          }),
        ).buffer,
        authenticatorData: authenticatorData.buffer,
      },
      getClientExtensionResults: () => ({ prf: { results: { first: new Uint8Array(32).fill(5) } } }),
    };
  });
  vi.stubGlobal('window', {
    PublicKeyCredential: function PublicKeyCredential() {},
    location: { origin: ORIGIN },
  });
  vi.stubGlobal('navigator', { credentials: { create, get } });
  return { create, get };
}

afterEach(() => vi.unstubAllGlobals());

const enroll = {
  rpId: 'example.com',
  rpName: 'Example',
  userId: 'user-1',
  userName: 'user@example.com',
};
const secret = new Uint8Array(32).fill(42);

describe('enrollVault → unlockVault end-to-end (mock authenticator)', () => {
  it('wraps at enrollment and unlocks to a non-extractable session key', async () => {
    stubAuthenticator({ enabled: true }); // two-ceremony path; get returns PRF fill(5)
    const enrolled = await enrollVault({ enroll, secret });
    expect(enrolled.record.scheme).toBe('prf-v1');

    const unlocked = await unlockVault({
      credentialId: enrolled.credentialId,
      record: enrolled.record,
      rpId: 'example.com',
      storedCounter: 0,
    });
    expect(unlocked.key.extractable).toBe(false);
    expect(unlocked.counter).toBe(1);
  });

  it('single-ceremony enrollment also produces an unwrappable record', async () => {
    stubAuthenticator({ enabled: true, first: new Uint8Array(32).fill(6) });
    const enrolled = await enrollVault({ enroll, secret });
    expect(enrolled.usedSingleCeremony).toBe(true);
    expect(
      await unwrapSecretBytes({ record: enrolled.record, prfOutput: new Uint8Array(32).fill(6) }),
    ).toEqual(secret);
  });

  it('unlockVault rejects non prf-v1 records', async () => {
    stubAuthenticator({ enabled: true });
    await expect(
      unlockVault({
        credentialId: toBase64Url(RAW_ID),
        record: {
          scheme: 'pw-v1',
          ciphertext: new Uint8Array(48),
          nonce: new Uint8Array(12),
          salt: new Uint8Array(32),
          kdfParams: { N: 1024, r: 8, p: 1 },
        },
        rpId: 'example.com',
      }),
    ).rejects.toThrow(RecordFormatError);
  });
});
