# Security

## Threat model

### Attacker with a full storage dump (primary threat)

An attacker who obtains everything this package ever persists — IndexedDB dump,
backup file, synced `WrappedSecretRecord` JSON — holds only:

- AES-256-GCM ciphertexts (auth tag included)
- random salts (PRF inputs / scrypt salts — non-secret by design)
- random 96-bit nonces
- credential metadata (credential IDs, signature counters, transports)

Reconstructing the vault key requires either:

- **the PRF output** — computed inside the authenticator hardware, released only
  after user verification (biometric/PIN), never stored anywhere, and bound to
  the relying-party ID; or
- **the master password** — stretched with memory-hard scrypt
  (`N=131072, r=8, p=1` default), which bounds offline guessing throughput.

There are no stored recomputable key inputs. This is the defining invariant:
storage compromise alone is never sufficient.

### Runtime attacker (XSS)

Script running in the page can call this package's APIs while the vault is
unlocked. Session and wrap keys are **non-extractable `CryptoKey`s** — their raw
bytes cannot be exfiltrated through any WebCrypto path. An XSS payload can
*misuse* an unlocked key while the page is open (encrypt/decrypt on the
attacker's behalf); it cannot steal the key material itself or unlock future
sessions. This residual is inherent to the web platform.

### Post-quantum note

The wrap path uses only symmetric primitives — AES-256-GCM, HKDF-SHA256,
scrypt. Grover's algorithm halves effective symmetric strength, leaving a
~128-bit post-quantum margin for AES-256. No asymmetric secrecy dependency
exists in the wrap path (WebAuthn's ECDSA signatures authenticate; they never
protect key material confidentiality).

## Guarantees

1. No `exportKey` path exists in the public API; every derived/imported key is
   non-extractable.
2. PRF outputs, raw key bytes, and derived keys are never persisted; only
   `WrappedSecretRecord` shapes are storable.
3. Transient key material is zeroized (`fill(0)`) in `finally` blocks.
4. Decrypt failures throw a generic `DecryptError` — no oracle distinguishing
   wrong key from corrupted data, and the cause is never logged.
5. Every assertion is replay-checked: client-data type, challenge, origin, and
   signature counter (cloned-authenticator detection).
6. PRF results are strictly validated (exactly 32 bytes, correct buffer type)
   to guard against non-spec-compliant authenticator implementations.

## Known residuals and limitations

- **Zeroization is best-effort.** JavaScript gives no memory control; the GC or
  engine may hold copies of buffers that `fill(0)` cannot reach. Zeroization
  shrinks the exposure window; it is not a hard erase.
- **PRF output transits JS memory.** By spec design the PRF result surfaces to
  script transiently before HKDF import; this package zeroizes it immediately
  after use.
- **Plaintext metadata.** Credential IDs, signature counters, transports, salts,
  and timestamps are stored unencrypted. All are non-secret; none contribute to
  key derivation without the PRF output or password.
- **Passkey deletion destroys the PRF path permanently.** The PRF output cannot
  be recomputed without the credential. **Always maintain a `pw-v1` (password)
  wrap of the same vault key.** The `hybrid-v1` scheme name is reserved for a
  future combined-factor design and is not implemented in v1.
- **Android WebView.** PRF does not traverse the WebView → Credential Manager
  path; `isPrfViableOnThisClient()` reports this and apps must use `pw-v1` there.

## Reporting a vulnerability

Please open a private security advisory on the GitHub repository
(Security → Advisories → "Report a vulnerability"). Do not open public issues
for suspected vulnerabilities.
