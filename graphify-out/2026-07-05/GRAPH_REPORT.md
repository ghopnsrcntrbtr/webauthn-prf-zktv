# Graph Report - webauthn-prf-zktv  (2026-07-05)

## Corpus Check
- 31 files · ~8,029 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 157 nodes · 414 edges · 8 communities (7 shown, 1 thin omitted)
- Extraction: 100% EXTRACTED · 0% INFERRED · 0% AMBIGUOUS
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `db3f58bf`
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
- [[_COMMUNITY_verify.ts|verify.ts]]

## God Nodes (most connected - your core abstractions)
1. `WrappedSecretRecord` - 14 edges
2. `toBase64Url()` - 14 edges
3. `RecordFormatError` - 13 edges
4. `ZktvDb` - 13 edges
5. `wrapSecret()` - 11 edges
6. `ZktvError` - 11 edges
7. `enrollPrfCredential()` - 11 edges
8. `deriveWrapKeyFromPrf()` - 10 edges
9. `unwrapSecretBytes()` - 10 edges
10. `DecryptError` - 10 edges

## Surprising Connections (you probably didn't know these)
- `stubAuthenticator()` --calls--> `toBase64Url()`  [EXTRACTED]
  src/webauthn/__tests__/vault.test.ts → src/utils/base64.ts
- `parseAttestationCounter()` --calls--> `readCounter()`  [EXTRACTED]
  src/webauthn/ceremonies.ts → src/webauthn/verify.ts
- `evaluatePrf()` --calls--> `verifyAssertionResponse()`  [EXTRACTED]
  src/webauthn/ceremonies.ts → src/webauthn/verify.ts
- `makeLegacyRecord()` --calls--> `toBase64()`  [EXTRACTED]
  src/core/__tests__/trustvault.test.ts → src/utils/base64.ts
- `SerializedRecordV1` --references--> `ScryptParams`  [EXTRACTED]
  src/core/serialize.ts → src/core/types.ts

## Import Cycles
- None detected.

## Communities (8 total, 1 thin omitted)

### Community 0 - "WebAuthn PRF Ceremonies"
Cohesion: 0.18
Nodes (16): enrollPrfCredential(), EnrollResult, evaluatePrf(), EvaluatePrfOptions, parseAttestationCounter(), PrfEvaluation, translateCreateError(), tryExtractPrfOutput() (+8 more)

### Community 1 - "Core Key Derivation & Wrap"
Cohesion: 0.14
Nodes (25): DEFAULT_SCRYPT_PARAMS, deriveWrapKeyFromPassword(), deriveWrapKeyFromPrf(), HKDF_INFO_V1, fastParams, prfOutput, salt, makeLegacyRecord() (+17 more)

### Community 2 - "Errors & Assertion Verification"
Cohesion: 0.14
Nodes (13): fastKdf, prfOutput, prfSalt, secret, CeremonyCancelledError, DecryptError, PrfResultMissingError, PrfUnsupportedError (+5 more)

### Community 3 - "Record Serialization & IndexedDB Schema"
Cohesion: 0.16
Nodes (17): decodeField(), parseKdfParams(), parseRecord(), SerializedRecordV1, serializeRecord(), prfRecord, pwRecord, ScryptParams (+9 more)

### Community 4 - "Base64 Utils & WebAuthn Tests"
Cohesion: 0.21
Nodes (12): fromBase64(), fromBase64Url(), toBase64(), toBase64Url(), CreateExt, enrollOptions, RAW_ID, stubAuthenticator() (+4 more)

### Community 5 - "ZktvDb Storage Operations"
Cohesion: 0.18
Nodes (14): WrappedSecretRecord, zeroize(), EnrollOptions, CreateExt, enroll, RAW_ID, secret, stubAuthenticator() (+6 more)

### Community 8 - "verify.ts"
Cohesion: 0.35
Nodes (6): valid, AuthenticatorFlags, readAuthenticatorFlags(), readCounter(), VerifyAssertionArgs, verifyAssertionResponse()

## Knowledge Gaps
- **34 isolated node(s):** `valid`, `prfOutput`, `fastParams`, `salt`, `prfRecord` (+29 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **1 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `ZktvDb` connect `vectors.test.ts` to `Record Serialization & IndexedDB Schema`?**
  _High betweenness centrality (0.091) - this node is a cross-community bridge._
- **Why does `WrappedSecretRecord` connect `ZktvDb Storage Operations` to `Core Key Derivation & Wrap`, `Record Serialization & IndexedDB Schema`, `vectors.test.ts`?**
  _High betweenness centrality (0.051) - this node is a cross-community bridge._
- **Why does `toBase64Url()` connect `Base64 Utils & WebAuthn Tests` to `WebAuthn PRF Ceremonies`, `Record Serialization & IndexedDB Schema`, `ZktvDb Storage Operations`?**
  _High betweenness centrality (0.046) - this node is a cross-community bridge._
- **What connects `valid`, `prfOutput`, `fastParams` to the rest of the system?**
  _34 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Core Key Derivation & Wrap` be split into smaller, more focused modules?**
  _Cohesion score 0.1408199643493761 - nodes in this community are weakly interconnected._
- **Should `Errors & Assertion Verification` be split into smaller, more focused modules?**
  _Cohesion score 0.14492753623188406 - nodes in this community are weakly interconnected._