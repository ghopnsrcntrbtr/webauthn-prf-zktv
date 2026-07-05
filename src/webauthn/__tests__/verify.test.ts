import { describe, expect, it } from 'vitest';
import { readAuthenticatorFlags, readCounter, verifyAssertionResponse } from '../verify';
import { ReplayError } from '../../errors';

function makeAuthData(counter: number): Uint8Array {
  const data = new Uint8Array(37);
  new DataView(data.buffer).setUint32(33, counter, false); // big-endian at bytes 33-36
  return data;
}

function makeClientData(
  overrides: Partial<Record<'type' | 'challenge' | 'origin', string>> = {},
): Uint8Array {
  return new TextEncoder().encode(
    JSON.stringify({
      type: 'webauthn.get',
      challenge: 'expected-challenge',
      origin: 'https://example.com',
      ...overrides,
    }),
  );
}

const valid = {
  clientDataJSON: makeClientData(),
  authenticatorData: makeAuthData(5),
  expectedChallenge: 'expected-challenge',
  expectedOrigin: 'https://example.com',
  storedCounter: 4,
};

describe('readCounter', () => {
  it('reads big-endian counter at bytes 33-36 including high-bit values', () => {
    expect(readCounter(makeAuthData(5))).toBe(5);
    expect(readCounter(makeAuthData(0x80000001))).toBe(0x80000001);
  });
});

describe('verifyAssertionResponse', () => {
  it('returns the new counter on valid input', () => {
    expect(verifyAssertionResponse(valid)).toBe(5);
  });

  it('throws ReplayError on challenge mismatch', () => {
    expect(() =>
      verifyAssertionResponse({ ...valid, clientDataJSON: makeClientData({ challenge: 'evil' }) }),
    ).toThrow(ReplayError);
  });

  it('throws ReplayError on origin mismatch and wrong type', () => {
    expect(() =>
      verifyAssertionResponse({
        ...valid,
        clientDataJSON: makeClientData({ origin: 'https://evil.com' }),
      }),
    ).toThrow(ReplayError);
    expect(() =>
      verifyAssertionResponse({
        ...valid,
        clientDataJSON: makeClientData({ type: 'webauthn.create' }),
      }),
    ).toThrow(ReplayError);
  });

  it('throws ReplayError when counter does not increase (cloned authenticator)', () => {
    expect(() =>
      verifyAssertionResponse({ ...valid, authenticatorData: makeAuthData(4) }),
    ).toThrow(ReplayError);
    expect(() =>
      verifyAssertionResponse({ ...valid, authenticatorData: makeAuthData(3) }),
    ).toThrow(ReplayError);
  });

  it('permits zero counters (authenticators that never increment)', () => {
    expect(verifyAssertionResponse({ ...valid, authenticatorData: makeAuthData(0) })).toBe(0);
  });

  it('permits any counter when storedCounter is -1 (enrollment)', () => {
    expect(verifyAssertionResponse({ ...valid, storedCounter: -1 })).toBe(5);
  });

  it('throws ReplayError on truncated authenticator data', () => {
    expect(() =>
      verifyAssertionResponse({ ...valid, authenticatorData: new Uint8Array(10) }),
    ).toThrow(ReplayError);
  });
});

describe('readAuthenticatorFlags', () => {
  it('decodes UP, UV, BE, BS bits from authenticatorData byte 32', () => {
    const authData = new Uint8Array(37);
    authData[32] = 0x01 | 0x04 | 0x08 | 0x10;
    expect(readAuthenticatorFlags(authData)).toEqual({
      userPresent: true,
      userVerified: true,
      backupEligible: true,
      backupState: true,
    });
  });

  it('decodes a synced-passkey pattern (BE set, BS set, no UV)', () => {
    const authData = new Uint8Array(37);
    authData[32] = 0x01 | 0x08 | 0x10;
    const flags = readAuthenticatorFlags(authData);
    expect(flags.backupEligible).toBe(true);
    expect(flags.backupState).toBe(true);
    expect(flags.userVerified).toBe(false);
  });

  it('returns all-false for empty input', () => {
    expect(readAuthenticatorFlags(new Uint8Array(0))).toEqual({
      userPresent: false,
      userVerified: false,
      backupEligible: false,
      backupState: false,
    });
  });
});
