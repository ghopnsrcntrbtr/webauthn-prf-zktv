# webauthn-prf-zktv

**Zero-Knowledge TrustVault** — WebAuthn PRF-backed vault key wrapping
(HKDF-SHA256 → AES-256-GCM) with optional PWA IndexedDB storage patterns.

A stored record dump alone can **never** reconstruct your vault key. The wrap key
is derived from the authenticator's PRF (hmac-secret) output — produced by hardware
only after user verification (biometric/PIN) and never persisted — or from a
master password via memory-hard scrypt. Extracted from the production-proven
[TrustVault-PWA](https://github.com/opnsrcntrbtr/TrustVault-PWA) security engine;
this package is also the reference implementation for the accompanying research
paper (arXiv link TBA on publication).

```bash
npm install webauthn-prf-zktv
```

- **ESM-only**, Node ≥ 20 for the core (browsers for the WebAuthn/IndexedDB modules)
- **One runtime dependency**: [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) (scrypt)
- **No SimpleWebAuthn**: native `navigator.credentials` APIs, strict PRF validation

## Browser support (2026)

| Platform | PRF status |
|---|---|
| Chrome / Edge | ✅ (PRF evaluated **during registration** from Chrome 147 → single-ceremony enrollment) |
| Safari | ✅ macOS 15+ / iOS 18+ via iCloud Keychain |
| Firefox | ✅ 147/148+ |
| Android (Credential Manager) | ✅ robust |
| Windows Hello | ✅ Windows 11 25H2+ (WebAuthn API v8) |
| Android WebView / Capacitor | ❌ PRF does not traverse WebView → Credential Manager; use the password scheme |

`detectPrfSupport()` returns `'supported' | 'unsupported' | 'unknown'` via
`getClientCapabilities()` — enrollment hard-verifies PRF on `'unknown'` clients,
so no throwaway probe credentials are ever created.

## Quickstart

```ts
import { wrapSecret, zeroize } from 'webauthn-prf-zktv';
import { enrollVault, unlockVault, isPrfViableOnThisClient } from 'webauthn-prf-zktv/webauthn';
import { openVaultDb } from 'webauthn-prf-zktv/indexeddb';

// 1. Create a vault key and enroll a PRF credential that wraps it
const vaultKey = crypto.getRandomValues(new Uint8Array(32));
const { record, credentialId, counter } = await enrollVault({
  enroll: { rpId: 'example.com', rpName: 'Example', userId: 'user-1', userName: 'me@example.com' },
  secret: vaultKey,
});

// 2. ALWAYS also wrap under the master password — a deleted passkey must never mean data loss
const pwRecord = await wrapSecret({ password: 'master-password', secret: vaultKey });
zeroize(vaultKey);

// 3. Persist both records (IndexedDB helper shown; any storage works via serializeRecord)
const db = await openVaultDb();
await db.saveWrappedVault('vault-1', record);
await db.saveWrappedVault('vault-1', pwRecord);

// 4. Later: biometric unlock
const stored = await db.loadWrappedVault('vault-1', 'prf-v1');
const { key, counter: newCounter } = await unlockVault({
  credentialId, record: stored!, rpId: 'example.com', storedCounter: counter,
});
// `key` is a non-extractable AES-256-GCM CryptoKey — use it with crypto.subtle
```

## API

### `webauthn-prf-zktv` (core — Node + browser)

| Export | Description |
|---|---|
| `wrapSecret(options)` | Wrap a secret under a PRF output (`prf-v1`), password (`pw-v1`, scrypt), or pre-derived key |
| `unwrapSecret(options)` | Decrypt a wrapped 32-byte key → **non-extractable** AES-256-GCM `CryptoKey` |
| `unwrapSecretBytes(options)` | Decrypt to raw bytes (caller must `zeroize()`) |
| `deriveWrapKeyFromPrf(prfOutput, info?)` | HKDF-SHA256 → non-extractable AES-GCM-256 key |
| `deriveWrapKeyFromPassword(password, salt, params?)` | scrypt (default `N=131072, r=8, p=1`) → non-extractable key |
| `serializeRecord(record)` / `parseRecord(json)` | Versioned JSON envelope with strict validation |
| `fromTrustVaultRecord(options)` | Migrate a legacy TrustVault-PWA record to the v1 format |
| `generateSalt(length?)` / `zeroize(view)` | Utilities |
| `ZktvError` + subclasses | Typed errors with stable `.code` values |

### `webauthn-prf-zktv/webauthn` (browser)

| Export | Description |
|---|---|
| `isPrfViableOnThisClient()` | Viability + reason + `browser`/`webview` environment |
| `detectPrfSupport()` | Tri-state capability detection (no probe credentials) |
| `enrollPrfCredential(options)` | **Adaptive** enrollment: single ceremony when the authenticator evaluates PRF at create, two otherwise |
| `evaluatePrf(options)` | Assertion ceremony → PRF output, with challenge/origin/counter replay verification |
| `enrollVault(options)` / `unlockVault(options)` | One-call compositions: ceremony → HKDF → wrap/unwrap → zeroize |
| `readAuthenticatorFlags(authenticatorData)` | Decode UP/UV/BE/BS bits (advisory clone-detection signal) |

#### Cloned-credential signals and synced passkeys

Synced passkeys commonly report a signature counter of 0, which disables the
counter-increase replay check. `readAuthenticatorFlags(authenticatorData)`
decodes the BE (backup-eligible) and BS (backup-state) flags so applications
can distinguish device-bound credentials (where the counter check is
meaningful) from synced passkeys (where it is not) and apply their own risk
policy. This is an advisory signal — it does not change library behavior.

### `webauthn-prf-zktv/indexeddb` (browser)

| Export | Description |
|---|---|
| `openVaultDb(config?)` | Open/create the vault DB (stores: `vaults`, `credentials`, `meta`) |
| `ZktvDb#saveWrappedVault` / `loadWrappedVault` | Persist/load records; PRF and password wraps of one vault coexist |
| `ZktvDb#saveCredentialRecord` / `getCredentialRecord` / `updateCounter` | Credential metadata + signature counter |
| `ZktvDb#clearVault(vaultId)` / `securityWipe()` | Targeted and full wipes |

## Why two schemes?

Tying encryption to a passkey alone is dangerous: **deleting the passkey destroys
the data**. This package treats the password wrap (`pw-v1`) as the safety net that
makes PRF unlock safe to deploy — the same posture TrustVault-PWA ships in
production. Enroll PRF for convenience; always keep a password wrap of the same
vault key.

## Docs

- [SECURITY.md](./SECURITY.md) — threat model, guarantees, residuals
- [MIGRATION.md](./MIGRATION.md) — TrustVault legacy migration, IndexedDB versioning
- [docs/INTEROP-VECTORS.md](./docs/INTEROP-VECTORS.md) — known-answer vectors for independent implementations

## License

MIT © opnsrcntrbtr
