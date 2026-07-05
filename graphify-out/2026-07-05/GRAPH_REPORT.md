# Graph Report - webauthn-prf-zktv  (2026-07-05)

## Corpus Check
- 31 files · ~7,806 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 155 nodes · 425 edges · 7 communities (5 shown, 2 thin omitted)
- Extraction: 100% EXTRACTED · 0% INFERRED · 0% AMBIGUOUS
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `542d6d7e`
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

## God Nodes (most connected - your core abstractions)
1. `toBase64Url()` - 14 edges
2. `WrappedSecretRecord` - 13 edges
3. `RecordFormatError` - 13 edges
4. `ZktvDb` - 13 edges
5. `enrollPrfCredential()` - 12 edges
6. `wrapSecret()` - 11 edges
7. `ZktvError` - 11 edges
8. `evaluatePrf()` - 11 edges
9. `deriveWrapKeyFromPrf()` - 10 edges
10. `unwrapSecretBytes()` - 9 edges

## Surprising Connections (you probably didn't know these)
- `makeLegacyRecord()` --calls--> `toBase64()`  [EXTRACTED]
  src/core/__tests__/trustvault.test.ts → src/utils/base64.ts
- `SerializedRecordV1` --references--> `ScryptParams`  [EXTRACTED]
  src/core/serialize.ts → src/core/types.ts
- `serializeRecord()` --calls--> `toBase64Url()`  [EXTRACTED]
  src/core/serialize.ts → src/utils/base64.ts
- `decodeField()` --calls--> `fromBase64Url()`  [EXTRACTED]
  src/core/serialize.ts → src/utils/base64.ts
- `fromTrustVaultRecord()` --calls--> `fromBase64()`  [EXTRACTED]
  src/core/trustvault.ts → src/utils/base64.ts

## Import Cycles
- None detected.

## Communities (7 total, 2 thin omitted)

### Community 0 - "WebAuthn PRF Ceremonies"
Cohesion: 0.14
Nodes (27): zeroize(), EnrollOptions, enrollPrfCredential(), EnrollResult, evaluatePrf(), EvaluatePrfOptions, parseAttestationCounter(), PrfEvaluation (+19 more)

### Community 1 - "Core Key Derivation & Wrap"
Cohesion: 0.15
Nodes (24): DEFAULT_SCRYPT_PARAMS, deriveWrapKeyFromPassword(), deriveWrapKeyFromPrf(), HKDF_INFO_V1, fastParams, prfOutput, salt, makeLegacyRecord() (+16 more)

### Community 2 - "Errors & Assertion Verification"
Cohesion: 0.12
Nodes (14): fastKdf, prfOutput, prfSalt, secret, CeremonyCancelledError, DecryptError, PrfResultMissingError, PrfUnsupportedError (+6 more)

### Community 3 - "Record Serialization & IndexedDB Schema"
Cohesion: 0.16
Nodes (18): decodeField(), parseKdfParams(), parseRecord(), SerializedRecordV1, serializeRecord(), prfRecord, pwRecord, ScryptParams (+10 more)

### Community 4 - "Base64 Utils & WebAuthn Tests"
Cohesion: 0.14
Nodes (17): fromBase64(), fromBase64Url(), toBase64(), toBase64Url(), CreateExt, enrollOptions, RAW_ID, stubAuthenticator() (+9 more)

## Knowledge Gaps
- **28 isolated node(s):** `SECRET`, `prfOutput`, `fastParams`, `salt`, `prfRecord` (+23 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **2 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `ZktvDb` connect `ZktvDb Storage Operations` to `Record Serialization & IndexedDB Schema`?**
  _High betweenness centrality (0.091) - this node is a cross-community bridge._
- **Why does `WrappedSecretRecord` connect `Record Serialization & IndexedDB Schema` to `WebAuthn PRF Ceremonies`, `Core Key Derivation & Wrap`, `ZktvDb Storage Operations`?**
  _High betweenness centrality (0.054) - this node is a cross-community bridge._
- **Why does `toBase64Url()` connect `Base64 Utils & WebAuthn Tests` to `WebAuthn PRF Ceremonies`, `Record Serialization & IndexedDB Schema`?**
  _High betweenness centrality (0.041) - this node is a cross-community bridge._
- **What connects `SECRET`, `prfOutput`, `fastParams` to the rest of the system?**
  _28 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `WebAuthn PRF Ceremonies` be split into smaller, more focused modules?**
  _Cohesion score 0.14126984126984127 - nodes in this community are weakly interconnected._
- **Should `Errors & Assertion Verification` be split into smaller, more focused modules?**
  _Cohesion score 0.11904761904761904 - nodes in this community are weakly interconnected._
- **Should `Base64 Utils & WebAuthn Tests` be split into smaller, more focused modules?**
  _Cohesion score 0.14285714285714285 - nodes in this community are weakly interconnected._