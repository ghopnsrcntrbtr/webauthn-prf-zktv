import { CeremonyCancelledError, PrfResultMissingError, PrfUnsupportedError } from '../errors';
import { fromBase64Url, toBase64Url } from '../utils/base64';
import type { PrfExtensionInputs, PrfExtensionOutputs } from './prf-types';
import { isWebAuthnSupported } from './support';
import { verifyAssertionResponse } from './verify';

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
