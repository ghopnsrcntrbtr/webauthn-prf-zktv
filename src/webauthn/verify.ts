import { ReplayError } from '../errors';

/** Big-endian signature counter at authenticatorData bytes 33-36. */
export function readCounter(authData: Uint8Array): number {
  return (
    (((authData[33] ?? 0) << 24) |
      ((authData[34] ?? 0) << 16) |
      ((authData[35] ?? 0) << 8) |
      (authData[36] ?? 0)) >>>
    0
  );
}

/** Decoded WebAuthn authenticatorData flags byte (byte 32; WebAuthn L3 §6.1). */
export interface AuthenticatorFlags {
  userPresent: boolean;
  userVerified: boolean;
  /** BE: credential is eligible for multi-device sync (synced passkey). */
  backupEligible: boolean;
  /** BS: credential is currently backed up. When set, the signature counter is typically 0. */
  backupState: boolean;
}

/**
 * Advisory clone-detection signal: synced passkeys (BE/BS set) usually report
 * counter 0, which disables the counter check in verifyAssertionResponse.
 * Applications can surface these flags to inform risk decisions.
 */
export function readAuthenticatorFlags(authData: Uint8Array): AuthenticatorFlags {
  const flags = authData[32] ?? 0;
  return {
    userPresent: (flags & 0x01) !== 0,
    userVerified: (flags & 0x04) !== 0,
    backupEligible: (flags & 0x08) !== 0,
    backupState: (flags & 0x10) !== 0,
  };
}

export interface VerifyAssertionArgs {
  clientDataJSON: Uint8Array;
  authenticatorData: Uint8Array;
  /** base64url-encoded challenge we generated for this ceremony. */
  expectedChallenge: string;
  expectedOrigin: string;
  /** Pass -1 to skip the increase check (brand-new credential at enrollment). */
  storedCounter: number;
}

/** Replay protection: type/challenge/origin/counter. Throws ReplayError. */
export function verifyAssertionResponse(args: VerifyAssertionArgs): number {
  let clientData: { type?: unknown; challenge?: unknown; origin?: unknown };
  try {
    clientData = JSON.parse(new TextDecoder().decode(args.clientDataJSON)) as typeof clientData;
  } catch {
    throw new ReplayError('Client data is not valid JSON');
  }
  if (clientData.type !== 'webauthn.get') {
    throw new ReplayError('Unexpected client data type');
  }
  if (clientData.challenge !== args.expectedChallenge) {
    throw new ReplayError('Challenge mismatch — possible replay attack');
  }
  if (clientData.origin !== args.expectedOrigin) {
    throw new ReplayError('Origin mismatch');
  }
  if (args.authenticatorData.length < 37) {
    throw new ReplayError('Authenticator data too short');
  }
  const counter = readCounter(args.authenticatorData);
  if (counter <= args.storedCounter && counter !== 0) {
    throw new ReplayError('Signature counter did not increase — possible cloned authenticator');
  }
  return counter;
}
