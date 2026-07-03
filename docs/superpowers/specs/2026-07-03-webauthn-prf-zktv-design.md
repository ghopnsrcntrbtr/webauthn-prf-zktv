# Design: `webauthn-prf-zktv` v1

**Date:** 2026-07-03
**Status:** Approved (brainstorming session, 2026-07-03)
**Source:** Extracted and generalized from [TrustVault-PWA](https://github.com/opnsrcntrbtr/TrustVault-PWA) production code.

## 1. Purpose

`webauthn-prf-zktv` (Zero-Knowledge TrustVault) is a public npm package providing
WebAuthn-PRF-backed vault-key wrapping with optional PWA IndexedDB storage
patterns. It packages TrustVault-PWA's production-proven security engine —
PRF ceremony handling, HKDF-SHA256 → AES-256-GCM key wrapping, and
zero-knowledge storage discipline — in a reusable, documented form that also
serves as the reference implementation for the planned arXiv paper.

The npm name `webauthn-prf-zktv` is unclaimed (verified 2026-07-03).

## 2. Validation findings that shaped this design

Deep research (2026-07-03) corrected the original development plan on four points:

1. **Browser support is broad now.** Safari (macOS 15+/iCloud Keychain),
   Firefox 147/148+, Chrome/Edge, and Windows Hello (WebAuthn API v8,
   Windows 11 25H2) all support PRF. Chrome 147+ additionally evaluates PRF
   **during registration** (PRF-on-create). The plan's "Firefox/Safari
   unsupported" framing and two-ceremony-only enrollment were outdated.
2. **No throwaway-credential probing.** Capability detection uses
   `PublicKeyCredential.getClientCapabilities()` (tri-state), exactly as
   TrustVault's `detectPRFSupport()` does — never a test registration.
3. **No SimpleWebAuthn dependency.** SimpleWebAuthn deliberately offers only
   minimal PRF support, and TrustVault already bypasses it for PRF (v10 does
   not surface binary PRF results). The package uses native
   `navigator.credentials` APIs. The plan's server-side option helpers are
   dropped: PRF evaluation is entirely client-side in a zero-knowledge design;
   the server never sees PRF outputs and salts need no server round-trip.
4. **Carry TrustVault's hard-won lessons.** scrypt (not PBKDF2) for the
   password wrap path (Finding 3, 2026-06-11); challenge/origin/type/counter
   replay verification on every assertion; Android WebView/Capacitor PRF
   limitation documented; strict runtime validation of PRF outputs (guards
   non-compliant authenticator implementations).

## 3. Security invariants (non-negotiable)

- A DB dump/backup alone must never suffice to reconstruct a vault key: no
  recomputable key inputs (device IDs, unencrypted seeds, derivable salts+ids
  combos) are ever persisted.
- PRF outputs, raw vault-key bytes, and derived wrap keys are never persisted;
  transient buffers are zeroized (`fill(0)`) in `finally` blocks after use.
- Session/wrap keys are non-extractable `CryptoKey`s. The public API exposes
  no `exportKey` path.
- AES-GCM decrypt failure throws a generic `DecryptError` — no oracle
  distinguishing wrong-key from corrupt-data, and the underlying error is
  never logged.
- Enrollment must hard-verify PRF (`prf.enabled` / PRF result present) and
  abort otherwise; a forged or wrong PRF output can never unlock (AES-GCM
  authentication failure is the only gate — no fallback path inside prf-v1).

## 4. Scope decisions (from brainstorming Q&A)

| Decision | Choice |
|---|---|
| v1 modules | Core + WebAuthn PRF + IndexedDB; **no server module** |
| Wrap schemes | `prf-v1` + `pw-v1` (scrypt); `hybrid-v1` documented as reserved, not implemented |
| Enrollment | Adaptive: PRF-on-create when available, auto-fallback to two-ceremony |
| TrustVault compat | Clean new record format + `fromTrustVaultRecord()` migration adapter |
| Naming/publish | zktv = Zero-Knowledge TrustVault; public npm; README cites TrustVault-PWA repo and arXiv paper |
| Architecture | Single package, sub-path exports (`.`, `./webauthn`, `./indexeddb`) |
| Runtime deps | `@noble/hashes` only (scrypt); raw IndexedDB, no Dexie |

## 5. Module layout

```
src/core/       → export "."            crypto engine (WebCrypto + @noble/hashes scrypt); Node ≥20 safe
src/webauthn/   → export "./webauthn"   PRF ceremonies + capability detection (browser only)
src/indexeddb/  → export "./indexeddb"  raw-IndexedDB vault storage (browser only)
src/types/      internal                shared type definitions
src/utils/      internal                base64url, zeroize, buffer/type guards
```

- ESM-only, `"sideEffects": false`, exports map with `types` conditions.
- TypeScript strict per TrustVault config: `strict`, `noUncheckedIndexedAccess`,
  `exactOptionalPropertyTypes`, `noImplicitReturns`.
- Node ≥20 (global WebCrypto). Tooling: tsup (build), Vitest (+ fake-indexeddb),
  ESLint flat config with `--max-warnings 0`, Prettier.

## 6. Core crypto (`webauthn-prf-zktv`)

### 6.1 Record model

```ts
interface WrappedSecretRecord {
  scheme: 'prf-v1' | 'pw-v1';   // 'hybrid-v1' reserved for a future version
  ciphertext: Uint8Array;        // AES-256-GCM output (auth tag included)
  nonce: Uint8Array;             // 96-bit random IV, unique per wrap
  salt: Uint8Array;              // PRF salt (prf-v1) or scrypt salt (pw-v1); 32 bytes
  kdfParams?: { N: number; r: number; p: number }; // pw-v1 only
}
```

Only `WrappedSecretRecord` is ever persisted. In-memory key material
(`CryptoKey`, PRF output) has no serializable representation.

### 6.2 API

- `generateSalt(length = 32): Uint8Array`
- `deriveWrapKeyFromPrf(prfOutput: Uint8Array, info?: Uint8Array): Promise<CryptoKey>`
  — HKDF-SHA256 with empty HKDF salt (RFC 5869: valid, treated as zeros;
  per-credential domain separation comes from the unique PRF salt → unique IKM),
  info label default `'webauthn-prf-zktv vault key wrap v1'`, derived into
  non-extractable AES-GCM-256 `['encrypt','decrypt']`.
- `deriveWrapKeyFromPassword(password: string, salt: Uint8Array, params?): Promise<CryptoKey>`
  — scrypt N=2^17, r=8, p=1, dkLen=32 (TrustVault Finding-3 params); derived
  bytes zeroized after non-extractable import.
- `wrapSecret({ prfOutput | password | wrapKey, secret: Uint8Array }): Promise<WrappedSecretRecord>`
  — random 96-bit nonce per wrap; caller's `secret` is NOT zeroized by the
  package (documented caller contract), but all internal copies are.
- `unwrapSecret({ record, prfOutput | password | wrapKey }): Promise<CryptoKey>`
  — returns non-extractable AES-GCM-256 session key; transient raw bytes
  zeroized in `finally`.
- `unwrapSecretBytes(...): Promise<Uint8Array>` — escape hatch for callers
  needing raw bytes (e.g. to re-wrap); docs state the caller MUST zeroize.
- `serializeRecord(record): string` / `parseRecord(json: string): WrappedSecretRecord`
  — versioned JSON envelope (`v: 1`), base64url fields, strict runtime
  validation (lengths, types, scheme whitelist); malformed input throws
  `RecordFormatError`.
- `fromTrustVaultRecord(legacyJson: string, opts): Promise<WrappedSecretRecord>`
  — migration adapter for TrustVault's legacy `EncryptedData` JSON (base64
  fields, HKDF info `'TrustVault Vault Key Wrapping v1'`): unwraps under the
  legacy label with a caller-supplied PRF output, re-wraps under the new
  format. Tested against fixtures generated from real TrustVault code.
- `zeroize(view: Uint8Array): void`

## 7. WebAuthn PRF module (`webauthn-prf-zktv/webauthn`)

Native `navigator.credentials` only. Minimal local typings for PRF extension
inputs/outputs (avoids lib.dom version drift), as in TrustVault.

- `detectPrfSupport(): Promise<'supported' | 'unsupported' | 'unknown'>`
  — `getClientCapabilities()` (`extension:prf` / `prf` keys); capability query
  failure → `'unknown'`, never a hard no. `'unknown'` clients may still attempt
  enrollment, which hard-verifies PRF.
- `isPrfViableOnThisClient(): Promise<{ viable: boolean; reason: string; environment: 'browser' | 'webview' }>`
  — combines support detection with platform-authenticator availability and
  WebView detection; documents that PRF does not traverse the Android
  WebView → Credential Manager path (Capacitor apps must use password unlock).
- `enrollPrfCredential(options: EnrollOptions): Promise<EnrollResult>`
  — **adaptive enrollment**: creation request includes
  `prf: { eval: { first: salt } }`.
  - If the authenticator returns a PRF result at creation (Chrome 147+,
    Windows Hello v8): single ceremony, done.
  - Else: verify `prf.enabled === true` (abort with `PrfUnsupportedError` if
    false), then run the assertion ceremony to obtain the PRF output.
  - Returns `{ credentialId, prfOutput, transports, publicKey, usedSingleCeremony }`.
  - Registration params per TrustVault: platform attachment, `residentKey:
    'preferred'`, `userVerification: 'required'`, ES256 + RS256, attestation
    `'none'`.
- `evaluatePrf({ credentialId, salt, rpId, storedCounter = -1 }): Promise<{ prfOutput: Uint8Array; counter: number }>`
  — assertion ceremony with random 32-byte challenge; validates PRF output
  (present, correct buffer type, 32-byte length — guards non-compliant
  implementations); replay protection via challenge/origin/type/counter
  verification (counter check is a no-op at -1 for the enrollment second
  ceremony).
- High-level composition (webauthn + core):
  - `enrollVault({ enrollOptions, secret }): Promise<{ record, credentialId, counter, ... }>`
  - `unlockVault({ credentialId, record, rpId, storedCounter }): Promise<{ key: CryptoKey; counter: number }>`
  — each is ceremony → HKDF → wrap/unwrap → zeroize, so app integration is
  ~5 lines per flow.

## 8. IndexedDB module (`webauthn-prf-zktv/indexeddb`)

Raw IndexedDB, database name configurable (default `zktv`). Stores:

- `vaults` — key `vaultId`; value: serialized `WrappedSecretRecord` + scheme
  tag + timestamps. Multiple records per vault are supported by composite key
  `[vaultId, scheme]` so PRF and password wraps of the same vault key coexist.
- `credentials` — key `credentialId`; value: WebAuthn credential metadata
  (counter, prfSalt, transports, createdAt, vaultId). All non-secret.
- `meta` — schema version, created-at.

The original plan's `hibpPrefixes` and `sessions` stores are **out of scope**
(TrustVault app concerns, not vault-engine concerns); the docs show how to
extend the schema for app-specific stores instead.

API: `openVaultDb(config?)`, `saveWrappedVault(vaultId, record)`,
`loadWrappedVault(vaultId, scheme?)`, `saveCredentialRecord(cred)`,
`updateCounter(credentialId, counter)`, `clearVault(vaultId)` (vault records +
associated credentials), `securityWipe()` (all stores).

Migrations: integer-versioned `onUpgrade` hooks; documentation states the
invariant every migration must respect (never introduce stored recomputable
key inputs) and shows the TrustVault-style "strip legacy scheme" migration as
the worked example.

## 9. Error handling

Typed hierarchy, every public API throws only these:

```
ZktvError (base, has .code)
├── PrfUnsupportedError      // detection says no / prf.enabled false
├── CeremonyCancelledError   // NotAllowedError: user cancel / timeout
├── PrfResultMissingError    // assertion returned no PRF result
├── ReplayError              // challenge/origin/type/counter mismatch
├── DecryptError             // generic; no wrong-key vs corrupt oracle
├── RecordFormatError        // parse/validation failure
└── StorageError             // IndexedDB failures
```

DOMExceptions from WebAuthn are translated with actionable, de-branded
messages (TrustVault's UX-tested wording). No error message or property ever
contains key material, PRF bytes, or plaintext.

## 10. Testing

- Vitest; `fake-indexeddb` for the storage module; real WebCrypto (Node ≥20)
  for all crypto tests; `navigator.credentials` mocked at the boundary for
  ceremony tests.
- Required coverage: HKDF derivation vectors; wrap/unwrap round-trips both
  schemes; wrong PRF output / wrong password must throw `DecryptError`;
  nonce uniqueness across wraps; zeroization assertions (buffers all-zero
  after ops); record parse fuzzing (truncated/wrong-type/hostile JSON);
  counter replay cases (decrease, equal, zero-counter authenticators);
  adaptive enrollment on both single- and two-ceremony mock authenticators;
  `fromTrustVaultRecord` against fixtures generated by real TrustVault code.
- TDD per module (superpowers test-driven-development flow).
- CI (GitHub Actions): type-check → lint (0 warnings) → test → build →
  `npm publish --dry-run` size/content check.

## 11. Documentation & examples

- `README.md` — positioning ("WebAuthn PRF-backed zero-knowledge vault key
  wrapping with optional PWA IndexedDB patterns"), browser-support matrix
  (2026), quickstart (~20 lines enroll + unlock), links to TrustVault-PWA and
  the arXiv paper.
- `SECURITY.md` — threat model (DB-dump attacker, XSS attacker, post-quantum
  note on symmetric primitives), guarantees, documented residuals, the
  passkey-deletion ⇒ data-loss hazard and why `pw-v1` fallback is the default
  recommendation.
- `MIGRATION.md` — TrustVault legacy adapter usage; IndexedDB schema
  versioning guidance; the "never persist recomputable inputs" migration rule.
- `examples/pwa-vite/` — minimal Vite PWA: enroll, unlock, wipe.
- `examples/node-unwrap/` — Node CLI proving the core is browser-independent:
  parse + re-wrap a record file.
- `CLAUDE.md` for this repo — build commands, module map, security invariants
  as hard rules, Definition of Done. Authored in the writing-plans step.

## 12. Out of scope for v1

- Server-side WebAuthn option/verification helpers (use any RP library;
  PRF stays client-side).
- `hybrid-v1` scheme (reserved; requires its own design pass).
- HIBP/breach storage, session stores (app-level concerns).
- Dexie integration (raw IndexedDB keeps zero browser deps).
- CBOR/attestation parsing (attestation is `'none'`; SPKI public key captured
  best-effort via `getPublicKey()` only).
