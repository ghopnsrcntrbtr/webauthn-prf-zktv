# Graph Report - webauthn-prf-zktv  (2026-07-05)

## Corpus Check
- 31 files · ~8,029 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 157 nodes · 438 edges · 9 communities
- Extraction: 100% EXTRACTED · 0% INFERRED · 0% AMBIGUOUS
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `9ab60783`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- [[_COMMUNITY_WebAuthn PRF Ceremonies|WebAuthn PRF Ceremonies]]
- [[_COMMUNITY_Core Key Derivation & Wrap|Core Key Derivation & Wrap]]
- [[_COMMUNITY_Errors & Assertion Verification|Errors & Assertion Verification]]
- [[_COMMUNITY_Record Serialization & IndexedDB Schema|Record Serialization & IndexedDB Schema]]
- [[_COMMUNITY_Base64 Utils & WebAuthn Tests|Base64 Utils & WebAuthn Tests]]
- [[_COMMUNITY_ZktvDb Storage Operations|ZktvDb Storage Operations]]
- [[_COMMUNITY_vectors.test.ts|vectors.test.ts]]
- [[_COMMUNITY_support.ts|support.ts]]
- [[_COMMUNITY_verify.ts|verify.ts]]

## God Nodes (most connected - your core abstractions)
1. `WrappedSecretRecord` - 14 edges
2. `toBase64Url()` - 14 edges
3. `RecordFormatError` - 13 edges
4. `ZktvDb` - 13 edges
5. `enrollPrfCredential()` - 12 edges
6. `wrapSecret()` - 11 edges
7. `ZktvError` - 11 edges
8. `evaluatePrf()` - 11 edges
9. `deriveWrapKeyFromPrf()` - 10 edges
10. `unwrapSecretBytes()` - 10 edges

## Surprising Connections (you probably didn't know these)
- `StoredVaultRow` --references--> `WrapScheme`  [EXTRACTED]
  src/indexeddb/db.ts → src/core/types.ts
- `stubCeremony()` --calls--> `toBase64Url()`  [EXTRACTED]
  src/webauthn/__tests__/evaluatePrf.test.ts → src/utils/base64.ts
- `makeLegacyRecord()` --calls--> `toBase64()`  [EXTRACTED]
  src/core/__tests__/trustvault.test.ts → src/utils/base64.ts
- `SerializedRecordV1` --references--> `ScryptParams`  [EXTRACTED]
  src/core/serialize.ts → src/core/types.ts
- `serializeRecord()` --calls--> `toBase64Url()`  [EXTRACTED]
  src/core/serialize.ts → src/utils/base64.ts

## Import Cycles
- None detected.

## Communities (9 total, 0 thin omitted)

### Community 0 - "WebAuthn PRF Ceremonies"
Cohesion: 0.25
Nodes (12): enrollPrfCredential(), EnrollResult, evaluatePrf(), EvaluatePrfOptions, parseAttestationCounter(), PrfEvaluation, translateCreateError(), tryExtractPrfOutput() (+4 more)

### Community 1 - "Core Key Derivation & Wrap"
Cohesion: 0.13
Nodes (28): DEFAULT_SCRYPT_PARAMS, deriveWrapKeyFromPassword(), deriveWrapKeyFromPrf(), HKDF_INFO_V1, fastParams, prfOutput, salt, makeLegacyRecord() (+20 more)

### Community 2 - "Errors & Assertion Verification"
Cohesion: 0.12
Nodes (16): fastKdf, prfOutput, prfSalt, secret, CeremonyCancelledError, DecryptError, PrfResultMissingError, PrfUnsupportedError (+8 more)

### Community 3 - "Record Serialization & IndexedDB Schema"
Cohesion: 0.17
Nodes (9): openVaultDb(), StoredCredentialMeta, StoredVaultRow, ZktvDb, ZktvDbConfig, cred, fresh(), prfRecord (+1 more)

### Community 4 - "Base64 Utils & WebAuthn Tests"
Cohesion: 0.19
Nodes (13): fromBase64(), fromBase64Url(), toBase64(), toBase64Url(), CreateExt, enrollOptions, RAW_ID, stubAuthenticator() (+5 more)

### Community 5 - "ZktvDb Storage Operations"
Cohesion: 0.38
Nodes (8): zeroize(), EnrollOptions, enrollVault(), EnrollVaultOptions, EnrollVaultResult, unlockVault(), UnlockVaultOptions, UnlockVaultResult

### Community 6 - "vectors.test.ts"
Cohesion: 0.31
Nodes (8): decodeField(), parseKdfParams(), parseRecord(), SerializedRecordV1, serializeRecord(), prfRecord, pwRecord, ScryptParams

### Community 7 - "support.ts"
Cohesion: 0.42
Nodes (6): detectPrfSupport(), isAndroidWebView(), isPrfViableOnThisClient(), isWebAuthnSupported(), PrfSupport, PrfViability

### Community 8 - "verify.ts"
Cohesion: 0.29
Nodes (4): valid, AuthenticatorFlags, readAuthenticatorFlags(), VerifyAssertionArgs

## Knowledge Gaps
- **28 isolated node(s):** `prfOutput`, `fastParams`, `salt`, `prfRecord`, `pwRecord` (+23 more)
  These have ≤1 connection - possible missing edges or undocumented components.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `ZktvDb` connect `Record Serialization & IndexedDB Schema` to `Core Key Derivation & Wrap`?**
  _High betweenness centrality (0.091) - this node is a cross-community bridge._
- **Why does `WrappedSecretRecord` connect `Core Key Derivation & Wrap` to `Record Serialization & IndexedDB Schema`, `ZktvDb Storage Operations`, `vectors.test.ts`?**
  _High betweenness centrality (0.056) - this node is a cross-community bridge._
- **Why does `toBase64Url()` connect `Base64 Utils & WebAuthn Tests` to `WebAuthn PRF Ceremonies`, `Errors & Assertion Verification`, `vectors.test.ts`?**
  _High betweenness centrality (0.040) - this node is a cross-community bridge._
- **What connects `prfOutput`, `fastParams`, `salt` to the rest of the system?**
  _28 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Core Key Derivation & Wrap` be split into smaller, more focused modules?**
  _Cohesion score 0.1282051282051282 - nodes in this community are weakly interconnected._
- **Should `Errors & Assertion Verification` be split into smaller, more focused modules?**
  _Cohesion score 0.12433862433862433 - nodes in this community are weakly interconnected._