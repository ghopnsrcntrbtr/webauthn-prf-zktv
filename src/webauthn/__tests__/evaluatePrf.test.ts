import { afterEach, describe, expect, it, vi } from 'vitest';
import { evaluatePrf, PRF_OUTPUT_LENGTH } from '../ceremonies';
import { toBase64Url } from '../../utils/base64';
import { CeremonyCancelledError, PrfResultMissingError, ReplayError } from '../../errors';

const ORIGIN = 'https://example.com';
const CRED_ID = toBase64Url(new Uint8Array([1, 2, 3, 4]));
const SALT = new Uint8Array(32).fill(3);

interface FakeOpts {
  prfFirst?: ArrayBuffer | Uint8Array | undefined;
  counter?: number;
}

/** Builds a navigator.credentials.get mock that echoes the request's challenge. */
function stubCeremony(opts: FakeOpts = {}): void {
  const get = vi.fn(async (request: { publicKey: PublicKeyCredentialRequestOptions }) => {
    const challenge = new Uint8Array(request.publicKey.challenge as ArrayBuffer | Uint8Array);
    const clientDataJSON = new TextEncoder().encode(
      JSON.stringify({ type: 'webauthn.get', challenge: toBase64Url(challenge), origin: ORIGIN }),
    );
    const authenticatorData = new Uint8Array(37);
    new DataView(authenticatorData.buffer).setUint32(33, opts.counter ?? 10, false);
    return {
      rawId: new Uint8Array([1, 2, 3, 4]).buffer,
      id: CRED_ID,
      type: 'public-key',
      response: {
        clientDataJSON: clientDataJSON.buffer,
        authenticatorData: authenticatorData.buffer,
      },
      getClientExtensionResults: () =>
        opts.prfFirst === undefined ? {} : { prf: { results: { first: opts.prfFirst } } },
    };
  });
  vi.stubGlobal('window', {
    PublicKeyCredential: function PublicKeyCredential() {},
    location: { origin: ORIGIN },
  });
  vi.stubGlobal('navigator', { credentials: { get } });
}

afterEach(() => vi.unstubAllGlobals());

describe('evaluatePrf', () => {
  it('returns 32-byte PRF output and verified counter', async () => {
    stubCeremony({ prfFirst: new Uint8Array(32).fill(7), counter: 11 });
    const result = await evaluatePrf({
      credentialId: CRED_ID,
      salt: SALT,
      rpId: 'example.com',
      storedCounter: 10,
    });
    expect(result.prfOutput).toHaveLength(PRF_OUTPUT_LENGTH);
    expect(result.counter).toBe(11);
  });

  it('throws PrfResultMissingError when the authenticator returns no PRF result', async () => {
    stubCeremony({ prfFirst: undefined });
    await expect(
      evaluatePrf({ credentialId: CRED_ID, salt: SALT, rpId: 'example.com' }),
    ).rejects.toThrow(PrfResultMissingError);
  });

  it('throws PrfResultMissingError on non-spec-compliant PRF length', async () => {
    stubCeremony({ prfFirst: new Uint8Array(16) });
    await expect(
      evaluatePrf({ credentialId: CRED_ID, salt: SALT, rpId: 'example.com' }),
    ).rejects.toThrow(PrfResultMissingError);
  });

  it('throws ReplayError when counter regresses', async () => {
    stubCeremony({ prfFirst: new Uint8Array(32).fill(7), counter: 5 });
    await expect(
      evaluatePrf({ credentialId: CRED_ID, salt: SALT, rpId: 'example.com', storedCounter: 9 }),
    ).rejects.toThrow(ReplayError);
  });

  it('translates NotAllowedError into CeremonyCancelledError', async () => {
    vi.stubGlobal('window', {
      PublicKeyCredential: function PublicKeyCredential() {},
      location: { origin: ORIGIN },
    });
    const err = Object.assign(new Error('denied'), { name: 'NotAllowedError' });
    vi.stubGlobal('navigator', { credentials: { get: vi.fn().mockRejectedValue(err) } });
    await expect(
      evaluatePrf({ credentialId: CRED_ID, salt: SALT, rpId: 'example.com' }),
    ).rejects.toThrow(CeremonyCancelledError);
  });
});
