import { afterEach, describe, expect, it, vi } from 'vitest';
import { detectPrfSupport, isPrfViableOnThisClient, isWebAuthnSupported } from '../support';

function stubBrowser(opts: {
  pkc?: object | undefined;
  userAgent?: string;
  platformAuthenticator?: boolean;
}): void {
  const pkc =
    opts.pkc === undefined
      ? undefined
      : Object.assign(function PublicKeyCredential() {}, {
          isUserVerifyingPlatformAuthenticatorAvailable: () =>
            Promise.resolve(opts.platformAuthenticator ?? true),
          ...opts.pkc,
        });
  vi.stubGlobal('window', pkc ? { PublicKeyCredential: pkc } : {});
  vi.stubGlobal('navigator', {
    userAgent:
      opts.userAgent ??
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/147.0',
  });
}

afterEach(() => vi.unstubAllGlobals());

describe('detectPrfSupport', () => {
  it("returns 'supported' when getClientCapabilities reports extension:prf", async () => {
    stubBrowser({ pkc: { getClientCapabilities: () => Promise.resolve({ 'extension:prf': true }) } });
    expect(await detectPrfSupport()).toBe('supported');
  });

  it("returns 'unsupported' when capabilities report prf false", async () => {
    stubBrowser({ pkc: { getClientCapabilities: () => Promise.resolve({ 'extension:prf': false }) } });
    expect(await detectPrfSupport()).toBe('unsupported');
  });

  it("returns 'unknown' when getClientCapabilities is absent or throws", async () => {
    stubBrowser({ pkc: {} });
    expect(await detectPrfSupport()).toBe('unknown');
    stubBrowser({ pkc: { getClientCapabilities: () => Promise.reject(new Error('nope')) } });
    expect(await detectPrfSupport()).toBe('unknown');
  });

  it("returns 'unsupported' when WebAuthn itself is absent", async () => {
    stubBrowser({ pkc: undefined });
    expect(isWebAuthnSupported()).toBe(false);
    expect(await detectPrfSupport()).toBe('unsupported');
  });
});

describe('isPrfViableOnThisClient', () => {
  it('flags Android WebView as non-viable with environment webview', async () => {
    stubBrowser({
      pkc: {},
      userAgent: 'Mozilla/5.0 (Linux; Android 14; wv) AppleWebKit/537.36 Chrome/147.0; wv)',
    });
    const result = await isPrfViableOnThisClient();
    expect(result.viable).toBe(false);
    expect(result.environment).toBe('webview');
  });

  it('non-viable when platform authenticator is unavailable', async () => {
    stubBrowser({ pkc: {}, platformAuthenticator: false });
    const result = await isPrfViableOnThisClient();
    expect(result).toMatchObject({ viable: false, environment: 'browser' });
  });

  it("viable with hard-verify caveat when support is 'unknown'", async () => {
    stubBrowser({ pkc: {} });
    const result = await isPrfViableOnThisClient();
    expect(result.viable).toBe(true);
    expect(result.reason).toMatch(/hard-verif/i);
  });
});
