# webauthn-prf-zktv — Claude Code Guide

**What this is:** Zero-Knowledge TrustVault (zktv) — WebAuthn PRF-backed vault key
wrapping (HKDF-SHA256 → AES-256-GCM) + optional PWA IndexedDB storage. Public npm
package extracted from TrustVault-PWA. Reference implementation for the arXiv paper.

**Stack:** TypeScript (strict) · ESM-only · tsup · Vitest + fake-indexeddb ·
`@noble/hashes` (ONLY runtime dep) · Node ≥20.

## Commands

```bash
npm run verify       # type-check → lint → test → build (run before EVERY commit)
npm run test         # vitest run
npm run test:watch   # vitest watch
npm run type-check   # tsc --noEmit
npm run lint         # eslint . --max-warnings 0
npm run build        # tsup → dist/
npm publish --dry-run --access public   # inspect package size/contents before release
```

## Module map (sub-path exports)

| Entry | Source | Runs in | Purpose |
|---|---|---|---|
| `webauthn-prf-zktv` | `src/core/` + `src/errors.ts` + `src/utils/` | Node ≥20 + browsers | wrap/unwrap, HKDF/scrypt derivation, record (de)serialization, TrustVault adapter |
| `webauthn-prf-zktv/webauthn` | `src/webauthn/` | browsers only | PRF detection, adaptive enrollment, evaluatePrf, enrollVault/unlockVault |
| `webauthn-prf-zktv/indexeddb` | `src/indexeddb/` | browsers only | ZktvDb storage (vaults/credentials/meta) |

Tests are co-located: `src/**/__tests__/*.test.ts`. WebAuthn tests stub
`window`/`navigator` with `vi.stubGlobal` (no jsdom); IndexedDB tests import
`fake-indexeddb/auto`; crypto tests use real WebCrypto.

## HARD security rules (violating any of these is a bug, full stop)

1. **Never** call `crypto.subtle.exportKey` in `src/`. All derived/imported keys
   are created with `extractable: false`.
2. **Never** persist PRF outputs, raw key bytes, or anything recomputable into a
   key. Only `WrappedSecretRecord` shapes are stored.
3. Zeroize transient key material (`.fill(0)`) in `finally` blocks — see
   `src/core/wrap.ts` and `src/webauthn/vault.ts` for the pattern.
4. `DecryptError` stays generic: no wrong-key vs corrupt-data distinction, no
   cause logging, no key material in any error message.
5. HKDF info labels are frozen constants: `'webauthn-prf-zktv vault key wrap v1'`
   (new records), `'TrustVault Vault Key Wrapping v1'` (legacy adapter only).
   Changing either breaks every existing record.
6. scrypt defaults `{ N: 131072, r: 8, p: 1 }` are a security floor — never lower
   them (TrustVault Finding 3: the wrap KDF is what an offline attacker attacks).
7. WebAuthn via native `navigator.credentials` only. No SimpleWebAuthn. Detection
   via `getClientCapabilities()` — never create throwaway credentials to probe.
8. IndexedDB migrations must never add stored recomputable key inputs.

## Definition of Done

1. `npm run verify` passes (0 type errors, 0 lint warnings, all tests, clean build).
2. New public API has tests covering the failure paths (wrong key → DecryptError,
   malformed input → RecordFormatError, replay → ReplayError).
3. README/SECURITY/MIGRATION updated if the API or threat model moved.
4. No new runtime dependencies without explicit maintainer sign-off.

## Gotchas

- `exactOptionalPropertyTypes` is ON: build optional props conditionally
  (`...(x ? { x } : {})`), never assign `undefined`.
- `noUncheckedIndexedAccess` is ON: `bytes[i]` is `number | undefined` — use `?? 0`.
- TypeScript is pinned to 5.x: TS 6 breaks tsup's dts build (baseUrl deprecation).
- PRF output is exactly 32 bytes; enforce via `PRF_OUTPUT_LENGTH`, don't assume.
- pw-v1 records REQUIRE `kdfParams`; prf-v1 records REJECT it (`parseRecord` enforces).
- Android WebView: PRF does not reach Credential Manager — `isPrfViableOnThisClient()`
  reports `environment: 'webview'`; apps must fall back to `pw-v1` there.
