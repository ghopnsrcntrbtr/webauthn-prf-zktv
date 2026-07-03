import { describe, expect, it } from 'vitest';
import { fromBase64, fromBase64Url, toBase64, toBase64Url } from '../base64';
import { zeroize } from '../zeroize';
import { generateSalt } from '../random';

describe('base64url', () => {
  it('round-trips arbitrary bytes', () => {
    const bytes = new Uint8Array([0, 1, 250, 251, 252, 253, 254, 255, 62, 63]);
    expect(fromBase64Url(toBase64Url(bytes))).toEqual(bytes);
  });
  it('produces URL-safe output without padding', () => {
    const encoded = toBase64Url(new Uint8Array([251, 255, 190]));
    expect(encoded).not.toMatch(/[+/=]/);
  });
  it('throws on invalid base64url input', () => {
    expect(() => fromBase64Url('!!!not-base64!!!')).toThrow();
  });
});

describe('base64 (standard, for TrustVault legacy records)', () => {
  it('round-trips arbitrary bytes', () => {
    const bytes = generateSalt();
    expect(fromBase64(toBase64(bytes))).toEqual(bytes);
  });
});

describe('zeroize', () => {
  it('fills the view with zeros', () => {
    const buf = new Uint8Array([9, 9, 9]);
    zeroize(buf);
    expect(Array.from(buf)).toEqual([0, 0, 0]);
  });
});

describe('generateSalt', () => {
  it('returns requested length and unique values', () => {
    const a = generateSalt();
    const b = generateSalt();
    expect(a).toHaveLength(32);
    expect(generateSalt(16)).toHaveLength(16);
    expect(a).not.toEqual(b);
  });
});
