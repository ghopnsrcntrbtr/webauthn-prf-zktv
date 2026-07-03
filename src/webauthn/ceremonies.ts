import { CeremonyCancelledError, PrfResultMissingError, PrfUnsupportedError } from '../errors';
import { fromBase64Url, toBase64Url } from '../utils/base64';
import { generateSalt } from '../utils/random';
import type { PrfExtensionInputs, PrfExtensionOutputs } from './prf-types';
import { isWebAuthnSupported } from './support';
import { readCounter, verifyAssertionResponse } from './verify';

export const PRF_OUTPUT_LENGTH = 32;

export interface EvaluatePrfOptions {
  /** base64url credential id (as returned by enrollPrfCredential). */
  credentialId: string;
  /** The credential's PRF salt (WrappedSecretRecord.salt for prf-v1). */
  salt: Uint8Array;
  rpId: string;
  /** Last stored signature counter; -1 (default) skips the increase check. */
  storedCounter?: number;
  timeout?: number;
}

export interface PrfEvaluation {
  prfOutput: Uint8Array;
  counter: number;
}

/** Assertion ceremony evaluating the PRF at `salt`, with replay verification. */
export async function evaluatePrf(options: EvaluatePrfOptions): Promise<PrfEvaluation> {
  if (!isWebAuthnSupported()) {
    throw new PrfUnsupportedError('WebAuthn is not available in this context.');
  }
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const expectedChallenge = toBase64Url(challenge);

  const publicKey: PublicKeyCredentialRequestOptions = {
    challenge: challenge as BufferSource,
    timeout: options.timeout ?? 60_000,
    rpId: options.rpId,
    allowCredentials: [
      { id: fromBase64Url(options.credentialId) as BufferSource, type: 'public-key' },
    ],
    userVerification: 'required',
    extensions: {
      prf: { eval: { first: options.salt as BufferSource } },
    } satisfies PrfExtensionInputs as AuthenticationExtensionsClientInputs,
  };

  let assertion: PublicKeyCredential | null;
  try {
    assertion = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential | null;
  } catch (error) {
    if (error instanceof Error && error.name === 'NotAllowedError') {
      throw new CeremonyCancelledError(
        'Authentication was cancelled or timed out. Try again or use the password fallback.',
      );
    }
    throw new CeremonyCancelledError(
      'Authentication failed. Try again or use the password fallback.',
    );
  }
  if (!assertion) throw new CeremonyCancelledError('Authentication returned no assertion.');

  const prfOutput = tryExtractPrfOutput(assertion);
  if (!prfOutput) {
    throw new PrfResultMissingError(
      'The authenticator did not return a PRF result. Use the password fallback on this device.',
    );
  }

  const response = assertion.response as AuthenticatorAssertionResponse;
  const counter = verifyAssertionResponse({
    clientDataJSON: new Uint8Array(response.clientDataJSON),
    authenticatorData: new Uint8Array(response.authenticatorData),
    expectedChallenge,
    expectedOrigin: window.location.origin,
    storedCounter: options.storedCounter ?? -1,
  });

  return { prfOutput, counter };
}

/**
 * Returns the PRF result bytes, null when absent, and throws on malformed
 * results (guards non-spec-compliant implementations, e.g. wrong length).
 */
export function tryExtractPrfOutput(credential: PublicKeyCredential): Uint8Array | null {
  const ext = credential.getClientExtensionResults() as PrfExtensionOutputs;
  const first = ext.prf?.results?.first;
  if (first === undefined) return null;
  const bytes = first instanceof Uint8Array ? new Uint8Array(first) : new Uint8Array(first);
  if (bytes.length !== PRF_OUTPUT_LENGTH) {
    throw new PrfResultMissingError(
      `Authenticator returned a ${bytes.length}-byte PRF result; expected ${PRF_OUTPUT_LENGTH}. Non-spec-compliant implementation.`,
    );
  }
  return bytes;
}

export interface EnrollOptions {
  rpId: string;
  rpName: string;
  userId: string;
  userName: string;
  userDisplayName?: string;
  /** Random 32 bytes generated when omitted. */
  prfSalt?: Uint8Array;
  timeout?: number;
}

export interface EnrollResult {
  credentialId: string;
  /** Transient — the caller MUST zeroize() after deriving the wrap key. */
  prfOutput: Uint8Array;
  prfSalt: Uint8Array;
  transports: string[];
  publicKey: Uint8Array | null;
  counter: number;
  usedSingleCeremony: boolean;
}

/**
 * Adaptive PRF enrollment:
 * 1. Creation requests prf.eval with the salt. Authenticators that evaluate PRF
 *    at create (Chrome 147+/Windows Hello v8) finish in ONE ceremony.
 * 2. Otherwise, hard-verify prf.enabled — abort with PrfUnsupportedError if false —
 *    then run the assertion ceremony to obtain the PRF output.
 */
export async function enrollPrfCredential(options: EnrollOptions): Promise<EnrollResult> {
  if (!isWebAuthnSupported()) {
    throw new PrfUnsupportedError('WebAuthn is not available in this context.');
  }
  const prfSalt = options.prfSalt ?? generateSalt();
  const challenge = crypto.getRandomValues(new Uint8Array(32));

  const publicKey: PublicKeyCredentialCreationOptions = {
    rp: { name: options.rpName, id: options.rpId },
    user: {
      id: new TextEncoder().encode(options.userId) as BufferSource,
      name: options.userName,
      displayName: options.userDisplayName ?? options.userName,
    },
    challenge: challenge as BufferSource,
    pubKeyCredParams: [
      { type: 'public-key', alg: -7 }, // ES256
      { type: 'public-key', alg: -257 }, // RS256
    ],
    timeout: options.timeout ?? 60_000,
    attestation: 'none',
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      residentKey: 'preferred',
      requireResidentKey: false,
      userVerification: 'required',
    },
    extensions: {
      prf: { eval: { first: prfSalt as BufferSource } },
    } satisfies PrfExtensionInputs as AuthenticationExtensionsClientInputs,
  };

  let credential: PublicKeyCredential | null;
  try {
    credential = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null;
  } catch (error) {
    throw translateCreateError(error);
  }
  if (!credential) throw new CeremonyCancelledError('Registration returned no credential.');

  const credentialId = toBase64Url(new Uint8Array(credential.rawId));
  const response = credential.response as AuthenticatorAttestationResponse;
  const transports =
    typeof response.getTransports === 'function' ? (response.getTransports() as string[]) : [];
  const spki = typeof response.getPublicKey === 'function' ? response.getPublicKey() : null;
  const publicKeyBytes = spki ? new Uint8Array(spki) : null;

  const createTimePrf = tryExtractPrfOutput(credential);
  if (createTimePrf) {
    return {
      credentialId,
      prfOutput: createTimePrf,
      prfSalt,
      transports,
      publicKey: publicKeyBytes,
      counter: parseAttestationCounter(response),
      usedSingleCeremony: true,
    };
  }

  const ext = credential.getClientExtensionResults() as PrfExtensionOutputs;
  if (ext.prf?.enabled !== true) {
    throw new PrfUnsupportedError(
      'The authenticator did not enable the PRF extension. Remove this credential and use the password scheme.',
    );
  }

  const { prfOutput, counter } = await evaluatePrf({
    credentialId,
    salt: prfSalt,
    rpId: options.rpId,
    ...(options.timeout !== undefined ? { timeout: options.timeout } : {}),
  });
  return {
    credentialId,
    prfOutput,
    prfSalt,
    transports,
    publicKey: publicKeyBytes,
    counter,
    usedSingleCeremony: false,
  };
}

function parseAttestationCounter(response: AuthenticatorAttestationResponse): number {
  if (typeof response.getAuthenticatorData !== 'function') return 0;
  const data = new Uint8Array(response.getAuthenticatorData());
  return data.length >= 37 ? readCounter(data) : 0;
}

function translateCreateError(error: unknown): Error {
  if (error instanceof Error) {
    if (error.name === 'NotAllowedError') {
      return new CeremonyCancelledError(
        'Registration was cancelled or not allowed. Ensure HTTPS (or localhost) and try again.',
      );
    }
    if (error.name === 'InvalidStateError') {
      return new CeremonyCancelledError('This authenticator is already registered here.');
    }
    if (error.name === 'NotSupportedError') {
      return new PrfUnsupportedError('This device does not support the requested authenticator.');
    }
  }
  return new CeremonyCancelledError('Registration failed. Please try again.');
}
