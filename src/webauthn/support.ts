export function isWebAuthnSupported(): boolean {
  return typeof window !== 'undefined' && typeof window.PublicKeyCredential === 'function';
}

/**
 * Tri-state PRF capability detection via getClientCapabilities().
 * NEVER probes with throwaway credentials. 'unknown' clients should still
 * attempt enrollment — enrollPrfCredential hard-verifies PRF and aborts cleanly.
 */
export type PrfSupport = 'supported' | 'unsupported' | 'unknown';

export async function detectPrfSupport(): Promise<PrfSupport> {
  if (!isWebAuthnSupported()) return 'unsupported';
  try {
    const pkc = window.PublicKeyCredential as unknown as {
      getClientCapabilities?: () => Promise<Record<string, boolean | undefined>>;
    };
    if (typeof pkc.getClientCapabilities === 'function') {
      const caps = await pkc.getClientCapabilities();
      const prf = caps['extension:prf'] ?? caps['prf'];
      if (typeof prf === 'boolean') return prf ? 'supported' : 'unsupported';
    }
  } catch {
    // capability query failed — unknown, not a hard no
  }
  return 'unknown';
}

export interface PrfViability {
  viable: boolean;
  reason: string;
  environment: 'browser' | 'webview';
}

export async function isPrfViableOnThisClient(): Promise<PrfViability> {
  if (isAndroidWebView()) {
    return {
      viable: false,
      environment: 'webview',
      reason:
        'PRF does not pass through the Android WebView → Credential Manager path; use the password scheme.',
    };
  }
  if (!isWebAuthnSupported()) {
    return { viable: false, environment: 'browser', reason: 'WebAuthn is not available here.' };
  }
  const platformAvailable = await window.PublicKeyCredential
    .isUserVerifyingPlatformAuthenticatorAvailable()
    .catch(() => false);
  if (!platformAvailable) {
    return {
      viable: false,
      environment: 'browser',
      reason: 'No user-verifying platform authenticator is available.',
    };
  }
  const support = await detectPrfSupport();
  if (support === 'unsupported') {
    return {
      viable: false,
      environment: 'browser',
      reason: 'This client reports the WebAuthn PRF extension is unavailable.',
    };
  }
  return {
    viable: true,
    environment: 'browser',
    reason:
      support === 'supported'
        ? 'PRF capability positively reported by the client.'
        : 'PRF capability unknown; enrollment will hard-verify PRF support.',
  };
}

function isAndroidWebView(): boolean {
  return typeof navigator !== 'undefined' && /; wv\)/.test(navigator.userAgent);
}
