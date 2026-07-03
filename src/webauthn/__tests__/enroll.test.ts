import { afterEach, describe, expect, it, vi } from 'vitest';
import { enrollPrfCredential } from '../ceremonies';
import { toBase64Url } from '../../utils/base64';
import { CeremonyCancelledError, PrfUnsupportedError } from '../../errors';

const ORIGIN = 'https://example.com';
const RAW_ID = new Uint8Array([9, 8, 7, 6]);

type CreateExt = { enabled?: boolean; first?: Uint8Array };

/** Mock authenticator. `createExt` controls create-time PRF behavior;
 *  the get mock (two-ceremony fallback) always returns a valid PRF assertion. */
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

const enrollOptions = {
  rpId: 'example.com',
  rpName: 'Example',
  userId: 'user-1',
  userName: 'user@example.com',
};

describe('enrollPrfCredential — adaptive', () => {
  it('finishes in ONE ceremony when create returns a PRF result (Chrome 147+ path)', async () => {
    const { get } = stubAuthenticator({ enabled: true, first: new Uint8Array(32).fill(6) });
    const result = await enrollPrfCredential(enrollOptions);
    expect(result.usedSingleCeremony).toBe(true);
    expect(result.prfOutput).toEqual(new Uint8Array(32).fill(6));
    expect(result.credentialId).toBe(toBase64Url(RAW_ID));
    expect(result.prfSalt).toHaveLength(32);
    expect(get).not.toHaveBeenCalled();
  });

  it('falls back to the SECOND ceremony when create only reports enabled', async () => {
    const { get } = stubAuthenticator({ enabled: true });
    const result = await enrollPrfCredential(enrollOptions);
    expect(result.usedSingleCeremony).toBe(false);
    expect(result.prfOutput).toEqual(new Uint8Array(32).fill(5));
    expect(result.counter).toBe(1);
    expect(get).toHaveBeenCalledTimes(1);
  });

  it('throws PrfUnsupportedError when PRF is not enabled at create', async () => {
    stubAuthenticator({ enabled: false });
    await expect(enrollPrfCredential(enrollOptions)).rejects.toThrow(PrfUnsupportedError);
  });

  it('translates NotAllowedError into CeremonyCancelledError', async () => {
    stubAuthenticator(
      {},
      { createError: Object.assign(new Error('x'), { name: 'NotAllowedError' }) },
    );
    await expect(enrollPrfCredential(enrollOptions)).rejects.toThrow(CeremonyCancelledError);
  });

  it('uses a caller-provided prfSalt verbatim', async () => {
    stubAuthenticator({ enabled: true, first: new Uint8Array(32).fill(6) });
    const prfSalt = new Uint8Array(32).fill(9);
    const result = await enrollPrfCredential({ ...enrollOptions, prfSalt });
    expect(result.prfSalt).toEqual(prfSalt);
  });
});
