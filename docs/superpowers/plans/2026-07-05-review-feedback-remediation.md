# Review-Feedback Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Address the validated findings of `paper/review.md` with non-breaking library hardening (interop test vectors, backup-state flags) and paper revisions (related work, design rationale, honest scrypt performance claims).

**Architecture:** Two code tasks land first so the paper can truthfully describe shipped behavior; four paper tasks follow (bibliography, related work, design-rationale subsection, evaluation/threat-model fixes). All v1 record-format-breaking reviewer suggestions (HKDF salt change, GCM AAD) are deliberately **not** implemented — they are answered in the paper as frozen-v1 rationale plus a reserved `prf-v2` migration path.

**Tech Stack:** TypeScript (strict, ESM) · Vitest · `@noble/hashes` · LaTeX (llncs) compiled with Tectonic.

## Global Constraints

- HARD security rules in `CLAUDE.md` apply to every task. In particular: HKDF info labels are frozen (`'webauthn-prf-zktv vault key wrap v1'` / `'TrustVault Vault Key Wrapping v1'`); scrypt floor `{ N: 131072, r: 8, p: 1 }` never lowered in defaults; no `crypto.subtle.exportKey` in `src/`; no new runtime dependencies.
- `npm run verify` must pass before every commit that touches `src/`.
- Paper compiles with `tectonic paper/main.tex` — zero errors required before every commit that touches `paper/`.
- `exactOptionalPropertyTypes` is ON: build optional props conditionally, never assign `undefined`. `noUncheckedIndexedAccess` is ON: `bytes[i]` is `number | undefined`, use `?? 0`.
- Do NOT change the v1 wire format, the HKDF construction (`salt = empty`), or add AAD to v1 records — that silently invalidates every published record (library is live on npm as 0.1.0).
- End every commit message with: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`
- After code changes, run `graphify update .` to keep the knowledge graph current.

## Validation Triage (what the review got right and wrong)

| # | Review claim | Verdict | Disposition |
|---|---|---|---|
| 1 | Label inconsistency: Listing 1.2 uses underscores | **INVALID** — `paper/main.tex` Listing 1.2 and `src/core/derive.ts:6` both read `'webauthn-prf-zktv vault key wrap v1'` (spaces). Reviewer read a stale draft. | No paper fix. Pin with test vector (Task 1) to answer reviewer Q1's "commit to a test vector set". |
| 2 | "Sect. 8 reads scrypt with N=217" | **INVALID in source** — main.tex uses `$N{=}2^{17}$`; "217" is a text-extraction artifact of `2^17`. | Defensive fix: write `N=2^{17}=131{,}072` once in Evaluation (Task 6). |
| 3 | HKDF empty salt; PRF salt could be HKDF salt | **VALID observation** — `derive.ts:26` uses `new Uint8Array(0)`. Changing derivation breaks all v1 records. | Paper rationale + `prf-v2` reservation (Task 5). No code change. |
| 4 | No GCM AAD binding (scheme, salt, vaultId) | **VALID** — `encryptRecord` (`wrap.ts:98–105`) passes no `additionalData`. Adding AAD to v1 breaks decryption of existing records. | Paper rationale: v1 compensates via `assertScheme` + `parseRecord` invariants; `prf-v2` will bind AAD (Task 5). No code change. |
| 5 | Counters unreliable for synced passkeys; use devicePubKey / BE-BS flags | **VALID** — `verify.ts:45` skips the check when counter = 0; flags byte (`authData[32]`) is never parsed; devicePubKey not implemented. | Non-breaking code: `readAuthenticatorFlags` (Task 2) + paper discussion (Task 6). devicePubKey = future work (no shipping browser support to rely on). |
| 6 | Bounded exposure under browser compromise underemphasized | **VALID (presentation)** — threat model states it once, tersely. | Strengthen threat-model text (Task 6). |
| 7 | "Few hundred ms" scrypt claim vs ~128 MiB memory | **VALID** — 128·N·r = 128·131072·8 bytes = 128 MiB working set; low-end mobile will be slower and memory-pressured. | Honest rewrite of the Evaluation performance sentence (Task 6). |
| 8 | Missing related work (7 arXiv papers) | **VALID** — none are in `references.bib`. All 7 IDs verified real via arXiv API on 2026-07-05, titles/authors fetched. | Add bib entries (Task 3) + related-work subsection (Task 4). |
| 9 | No interop/known-answer vectors (reviewer Q7) | **VALID** — no KAT tests exist (`grep -ri vector src/` empty). | Task 1: pinned vectors, generated 2026-07-05 with Node WebCrypto + `scryptSync` (RFC 7914-compatible with `@noble/hashes`). |
| 10 | Crash-consistency of counter writes (reviewer Q6) | **VALID question** — answerable from design: IndexedDB writes are transactional; a lost counter update only leaves a stale (lower) stored counter, which can never brick the vault. | One clarifying sentence (Task 6). |
| 11 | No formal game-based model; no cross-device benchmarks | **VALID but out of scope** for this revision. | Sharpen the existing future-work sentence (Task 6). |

---

### Task 1: Interop Known-Answer Vectors

**Files:**
- Create: `src/core/__tests__/vectors.test.ts`
- Create: `docs/INTEROP-VECTORS.md`

**Interfaces:**
- Consumes: `unwrapSecretBytes(options: UnwrapOptions): Promise<Uint8Array>` from `src/core/wrap.ts`; `fromBase64Url(s: string): Uint8Array` from `src/utils/base64.ts`; `DecryptError` from `src/errors.ts`; `WrappedSecretRecord` from `src/core/types.ts`.
- Produces: nothing consumed by later tasks; Task 6 paper text cites the existence of `docs/INTEROP-VECTORS.md`.

The vectors below were generated on 2026-07-05 with Node 20 WebCrypto (HKDF-SHA256, empty salt, info = the frozen v1 label) and `node:crypto.scryptSync` (RFC 7914 scrypt — bit-identical to `@noble/hashes/scrypt`). All byte strings are unpadded base64url.

- [ ] **Step 1: Write the vector test file**

```typescript
// src/core/__tests__/vectors.test.ts
import { describe, expect, it } from 'vitest';
import { DecryptError } from '../../errors';
import { fromBase64Url } from '../../utils/base64';
import type { WrappedSecretRecord } from '../types';
import { unwrapSecretBytes } from '../wrap';

/**
 * Known-answer interoperability vectors (docs/INTEROP-VECTORS.md).
 * These pin the v1 wire format: HKDF-SHA256(ikm=prfOutput, salt=empty,
 * info='webauthn-prf-zktv vault key wrap v1') and scrypt-based pw-v1.
 * If any of these tests fail, the implementation has diverged from every
 * record already in the wild — that is a release blocker, not a test bug.
 */

const SECRET = new Uint8Array(32).fill(0x03);

describe('prf-v1 known-answer vector', () => {
  const record: WrappedSecretRecord = {
    scheme: 'prf-v1',
    ciphertext: fromBase64Url('_8qmjSCDoMDF__kUdrvYgIonmlPj2ZZrWGTKmWAwJm9SoC1_U7QdM9QZ1XeVR0n-'),
    nonce: fromBase64Url('BAQEBAQEBAQEBAQE'),
    salt: fromBase64Url('AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI'),
  };

  it('unwraps to the pinned 32-byte secret', async () => {
    const prfOutput = fromBase64Url('AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE');
    const secret = await unwrapSecretBytes({ record, prfOutput });
    expect(Array.from(secret)).toEqual(Array.from(SECRET));
  });

  it('throws generic DecryptError under a wrong PRF output', async () => {
    const wrong = new Uint8Array(32).fill(0xff);
    await expect(unwrapSecretBytes({ record, prfOutput: wrong })).rejects.toBeInstanceOf(
      DecryptError,
    );
  });
});

describe('pw-v1 known-answer vector', () => {
  // Reduced-cost params for test speed only; DEFAULT_SCRYPT_PARAMS floor
  // (N=131072) is pinned separately in derive tests.
  const record: WrappedSecretRecord = {
    scheme: 'pw-v1',
    ciphertext: fromBase64Url('bmTKLnKMUiSx7H4BPTRTONutUzRAuUFw0eTmGNje_n7xu5ilOGEL81LybNgccTTR'),
    nonce: fromBase64Url('BAQEBAQEBAQEBAQE'),
    salt: fromBase64Url('BQUFBQUFBQUFBQUFBQUFBQ'),
    kdfParams: { N: 16384, r: 8, p: 1 },
  };

  it('unwraps to the pinned 32-byte secret', async () => {
    const secret = await unwrapSecretBytes({
      record,
      password: 'correct horse battery staple',
    });
    expect(Array.from(secret)).toEqual(Array.from(SECRET));
  });

  it('throws generic DecryptError under a wrong password', async () => {
    await expect(
      unwrapSecretBytes({ record, password: 'incorrect horse' }),
    ).rejects.toBeInstanceOf(DecryptError);
  });
});
```

- [ ] **Step 2: Run the vector tests — they must pass immediately**

Run: `npx vitest run src/core/__tests__/vectors.test.ts`
Expected: 4 passed. These are pinning tests against the shipped implementation; a failure means the wire format diverged (stop and investigate — do not adjust the vectors).

- [ ] **Step 3: Write `docs/INTEROP-VECTORS.md`**

```markdown
# Interoperability Test Vectors (v1 record format)

Independent implementations can validate compatibility against these
known-answer vectors. All byte values are **unpadded base64url**.
Pinned in `src/core/__tests__/vectors.test.ts`.

## prf-v1

HKDF-SHA256(ikm = prfOutput, salt = *empty*, info = UTF-8
`"webauthn-prf-zktv vault key wrap v1"`) → 256-bit AES-GCM wrap key;
AES-256-GCM(nonce, secret) → ciphertext (16-byte tag appended).

| field | value |
|---|---|
| prfOutput (32 × `0x01`) | `AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE` |
| prfSalt / record salt (32 × `0x02`) | `AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI` |
| secret / vault key (32 × `0x03`) | `AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM` |
| nonce (12 × `0x04`) | `BAQEBAQEBAQEBAQE` |
| ciphertext | `_8qmjSCDoMDF__kUdrvYgIonmlPj2ZZrWGTKmWAwJm9SoC1_U7QdM9QZ1XeVR0n-` |

## pw-v1

scrypt(password, salt, N=16384, r=8, p=1, dkLen=32) → AES-256-GCM key.
**These reduced-cost parameters are for vector verification only** — the
production floor is `{ N: 131072, r: 8, p: 1 }` and MUST NOT be lowered.

| field | value |
|---|---|
| password (UTF-8) | `correct horse battery staple` |
| salt (16 × `0x05`) | `BQUFBQUFBQUFBQUFBQUFBQ` |
| secret (32 × `0x03`) | `AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM` |
| nonce (12 × `0x04`) | `BAQEBAQEBAQEBAQE` |
| kdfParams | `{ "N": 16384, "r": 8, "p": 1 }` |
| ciphertext | `bmTKLnKMUiSx7H4BPTRTONutUzRAuUFw0eTmGNje_n7xu5ilOGEL81LybNgccTTR` |
```

- [ ] **Step 4: Full verify**

Run: `npm run verify`
Expected: 0 type errors, 0 lint warnings, all tests pass, clean build.

- [ ] **Step 5: Commit**

```bash
git add src/core/__tests__/vectors.test.ts docs/INTEROP-VECTORS.md
git commit -m "test: pin v1 interop known-answer vectors (prf-v1, pw-v1)

Answers reviewer Q1/Q7: fixed vectors prevent silent divergence of the
frozen v1 wire format and let other implementations validate compatibility.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: Backup-State Flags (`readAuthenticatorFlags`)

**Files:**
- Modify: `src/webauthn/verify.ts` (append after `readCounter`, `verify.ts:12`)
- Modify: `src/webauthn/__tests__/verify.test.ts` (append a `describe` block)
- Modify: `src/webauthn/index.ts` (extend the `./verify` re-export)
- Modify: `README.md` (add a short "Cloned-credential signals" note)

**Interfaces:**
- Consumes: nothing new.
- Produces: `interface AuthenticatorFlags { userPresent: boolean; userVerified: boolean; backupEligible: boolean; backupState: boolean }` and `readAuthenticatorFlags(authData: Uint8Array): AuthenticatorFlags`, exported from `webauthn-prf-zktv/webauthn`. Task 6 paper text describes this function — keep names exactly as written here.

- [ ] **Step 1: Write the failing test**

Append to `src/webauthn/__tests__/verify.test.ts`:

```typescript
describe('readAuthenticatorFlags', () => {
  it('decodes UP, UV, BE, BS bits from authenticatorData byte 32', () => {
    const authData = new Uint8Array(37);
    authData[32] = 0x01 | 0x04 | 0x08 | 0x10;
    expect(readAuthenticatorFlags(authData)).toEqual({
      userPresent: true,
      userVerified: true,
      backupEligible: true,
      backupState: true,
    });
  });

  it('decodes a synced-passkey pattern (BE set, BS set, no UV)', () => {
    const authData = new Uint8Array(37);
    authData[32] = 0x01 | 0x08 | 0x10;
    const flags = readAuthenticatorFlags(authData);
    expect(flags.backupEligible).toBe(true);
    expect(flags.backupState).toBe(true);
    expect(flags.userVerified).toBe(false);
  });

  it('returns all-false for empty input', () => {
    expect(readAuthenticatorFlags(new Uint8Array(0))).toEqual({
      userPresent: false,
      userVerified: false,
      backupEligible: false,
      backupState: false,
    });
  });
});
```

Also add `readAuthenticatorFlags` to the existing import from `'../verify'` at the top of the test file.

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/webauthn/__tests__/verify.test.ts`
Expected: FAIL — `readAuthenticatorFlags` is not exported.

- [ ] **Step 3: Implement in `src/webauthn/verify.ts`**

Append after the `readCounter` function:

```typescript
/** Decoded WebAuthn authenticatorData flags byte (byte 32; WebAuthn L3 §6.1). */
export interface AuthenticatorFlags {
  userPresent: boolean;
  userVerified: boolean;
  /** BE: credential is eligible for multi-device sync (synced passkey). */
  backupEligible: boolean;
  /** BS: credential is currently backed up. When set, the signature counter is typically 0. */
  backupState: boolean;
}

/**
 * Advisory clone-detection signal: synced passkeys (BE/BS set) usually report
 * counter 0, which disables the counter check in verifyAssertionResponse.
 * Applications can surface these flags to inform risk decisions.
 */
export function readAuthenticatorFlags(authData: Uint8Array): AuthenticatorFlags {
  const flags = authData[32] ?? 0;
  return {
    userPresent: (flags & 0x01) !== 0,
    userVerified: (flags & 0x04) !== 0,
    backupEligible: (flags & 0x08) !== 0,
    backupState: (flags & 0x10) !== 0,
  };
}
```

- [ ] **Step 4: Export from `src/webauthn/index.ts`**

Find the existing re-export from `'./verify'` and extend it to include the new names, e.g.:

```typescript
export {
  readAuthenticatorFlags,
  readCounter,
  verifyAssertionResponse,
  type AuthenticatorFlags,
  type VerifyAssertionArgs,
} from './verify';
```

(Preserve whatever names the file already re-exports; only add `readAuthenticatorFlags` and `AuthenticatorFlags`.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `npx vitest run src/webauthn/__tests__/verify.test.ts`
Expected: PASS (all, including pre-existing tests).

- [ ] **Step 6: README note**

Add under the section of `README.md` that documents replay verification / `verifyAssertionResponse` (locate by searching `verifyAssertionResponse` in README.md):

```markdown
### Cloned-credential signals and synced passkeys

Synced passkeys commonly report a signature counter of 0, which disables the
counter-increase replay check. `readAuthenticatorFlags(authenticatorData)`
decodes the BE (backup-eligible) and BS (backup-state) flags so applications
can distinguish device-bound credentials (where the counter check is
meaningful) from synced passkeys (where it is not) and apply their own risk
policy. This is an advisory signal — it does not change library behavior.
```

- [ ] **Step 7: Full verify, graph update, commit**

Run: `npm run verify` — expected all green. Then `graphify update .`

```bash
git add src/webauthn/verify.ts src/webauthn/__tests__/verify.test.ts src/webauthn/index.ts README.md graphify-out
git commit -m "feat: expose authenticator BE/BS flags via readAuthenticatorFlags

Synced passkeys defeat the signature-counter clone check (counter=0);
surfacing backup-eligible/backup-state bits lets applications gate on
device-bound vs synced credentials. Advisory only — no behavior change.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: Bibliography Additions

**Files:**
- Modify: `paper/references.bib` (append at end)

**Interfaces:**
- Produces: bib keys `injection-attacks`, `horcrux`, `authstore`, `safekeeper`, `mfkdf2`, `mfdpg`, `pq-cloud-survey` — Tasks 4–6 cite exactly these keys.

- [ ] **Step 1: Append seven entries to `paper/references.bib`**

All metadata verified against the arXiv API on 2026-07-05:

```bibtex
@misc{injection-attacks,
  author       = {F\'{a}brega, Andr\'{e}s and Namavari, Armin and Agarwal, Rachit and Nassi, Ben and Ristenpart, Thomas},
  title        = {Exploiting Leakage in Password Managers via Injection Attacks},
  howpublished = {arXiv:2408.07054},
  year         = {2024},
  url          = {https://arxiv.org/abs/2408.07054}
}

@misc{horcrux,
  author       = {Li, Hannah and Evans, David},
  title        = {Horcrux: A Password Manager for Paranoids},
  howpublished = {arXiv:1706.05085},
  year         = {2017},
  url          = {https://arxiv.org/abs/1706.05085}
}

@misc{authstore,
  author       = {Zeidler, Clemens and Asghar, Muhammad Rizwan},
  title        = {{AuthStore}: Password-based Authentication and Encrypted Data Storage in Untrusted Environments},
  howpublished = {arXiv:1805.05033},
  year         = {2018},
  url          = {https://arxiv.org/abs/1805.05033}
}

@misc{safekeeper,
  author       = {Krawiecka, Klaudia and Kurnikov, Arseny and Paverd, Andrew and Mannan, Mohammad and Asokan, N.},
  title        = {{SafeKeeper}: Protecting Web Passwords using Trusted Execution Environments},
  howpublished = {arXiv:1709.01261},
  year         = {2017},
  url          = {https://arxiv.org/abs/1709.01261}
}

@misc{mfkdf2,
  author       = {Roberts, Colin and Nair, Vivek and Song, Dawn},
  title        = {Wrangling Entropy: Next-Generation Multi-Factor Key Derivation, Credential Hashing, and Credential Generation Functions},
  howpublished = {arXiv:2509.05893},
  year         = {2025},
  url          = {https://arxiv.org/abs/2509.05893}
}

@misc{mfdpg,
  author       = {Nair, Vivek and Song, Dawn},
  title        = {{MFDPG}: Multi-Factor Authenticated Password Management With Zero Stored Secrets},
  howpublished = {arXiv:2306.14746},
  year         = {2023},
  url          = {https://arxiv.org/abs/2306.14746}
}

@misc{pq-cloud-survey,
  author       = {Baseri, Yaser and Hafid, Abdelhakim and Lashkari, Arash Habibi},
  title        = {Future-Proofing Cloud Security Against Quantum Attacks: Risk, Transition, and Mitigation Strategies},
  howpublished = {arXiv:2509.15653},
  year         = {2025},
  url          = {https://arxiv.org/abs/2509.15653}
}
```

- [ ] **Step 2: Compile check**

Run: `tectonic paper/main.tex`
Expected: success. (New entries are not yet cited — `plain` style only emits cited entries, so no layout change yet.)

- [ ] **Step 3: Commit**

```bash
git add paper/references.bib
git commit -m "docs(paper): add seven related-work references (verified via arXiv API)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: Related-Work Subsection

**Files:**
- Modify: `paper/main.tex` — insert a new subsection after `\subsection{PRF-Based Vault Encryption in Existing Systems}` (i.e., after the paragraph ending `...fallback, migration, and storage semantics.` around line 99) and before `\subsection{IndexedDB and Client-Side Storage}`.

**Interfaces:**
- Consumes: bib keys from Task 3.

- [ ] **Step 1: Insert the subsection**

```latex
\subsection{Password-Manager and Vault Architectures}
Web credential vaults have explored several trust models orthogonal to this work's.
Horcrux~\cite{horcrux} secret-shares credentials across multiple keystores so that no single server compromise reveals passwords; AuthStore~\cite{authstore} strengthens password-derived keys with a PAKE against untrusted storage servers; and SafeKeeper~\cite{safekeeper} anchors password confidentiality in a server-side trusted execution environment.
These designs distribute or harden \emph{server-side} trust, whereas the present scheme removes the server from the confidentiality boundary entirely: the unlock secret never leaves the authenticator, and the persisted client state is the only attack surface.
Multi-factor derivation frameworks --- MFDPG~\cite{mfdpg} and the MFKDF2 family~\cite{mfkdf2}, the latter of which explicitly contemplates the WebAuthn PRF as a derivation factor --- are complementary: the wrapping scheme presented here can serve as the PRF-factor envelope inside such constructions without changing the record format.
Finally, F\'{a}brega et al.~\cite{injection-attacks} demonstrate that end-to-end encrypted password managers leak through non-cryptographic system surfaces (telemetry, caching, and pre-encryption compression or deduplication) under adversarial data injection.
Those channels are out of scope for the storage layer formalized here, but Sect.~\ref{sec:zk} is deliberately scoped to \emph{persisted state} for exactly this reason: applications adopting the library must still avoid pre-encryption compression, unpadded record sizes correlated to secrets, and metadata-bearing telemetry.
```

- [ ] **Step 2: Compile and inspect**

Run: `tectonic paper/main.tex`
Expected: success, no undefined citations (check the log for `Warning: Citation`), no new overfull hbox worse than baseline.

- [ ] **Step 3: Commit**

```bash
git add paper/main.tex
git commit -m "docs(paper): add related-work subsection positioning against vault architectures

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 5: Design-Rationale Subsection (HKDF salt, AAD, frozen v1, prf-v2)

**Files:**
- Modify: `paper/main.tex` — insert a new subsection immediately after the `\subsection{Zero-Knowledge Argument}` block (after the paragraph ending `...the derived keys would be independent.` around line 196) and before `\section{IndexedDB Storage Architecture}`.

**Interfaces:**
- Consumes: bib key `rfc5869` (existing).
- Produces: `\label{sec:rationale}` — Task 6 references it.

- [ ] **Step 1: Insert the subsection**

```latex
\subsection{Design Rationale: Deliberate Omissions and the Frozen v1 Format}
\label{sec:rationale}
Two natural hardening measures are deliberately absent from the v1 record format, and both omissions are governed by the same constraint: v1 is frozen, because any change to the key-derivation inputs or the ciphertext computation silently invalidates every record already persisted by deployed applications.

\emph{HKDF salt.}
RFC~5869~\cite{rfc5869} recommends a salt where one is available, and the PRF salt $s$ is a natural candidate for the HKDF salt field.
v1 instead extracts with an empty salt and relies on $s$ for per-credential separation \emph{via the IKM}: distinct salts yield independent PRF outputs, so distinct credentials already derive independent wrap keys, and the versioned info label provides domain separation across schemes.
The security loss is confined to extractor robustness against adversarially structured IKM --- a non-concern here, since the IKM is the output of a PRF evaluated inside the authenticator.
A future \texttt{prf-v2} scheme will nevertheless move $s$ into the HKDF salt field to align with common practice, at the cost of a re-wrap migration.

\emph{AEAD context binding.}
v1 passes no additional authenticated data (AAD) to AES-GCM.
GCM's authentication tag already rejects any modification of nonce or ciphertext; what AAD would add is \emph{context} binding --- preventing a valid record from being replayed in a different slot (e.g.\ swapping a \texttt{pw-v1} record into a \texttt{prf-v1} position, or moving a record between vaults).
v1 compensates structurally: \texttt{parseRecord} enforces scheme-specific invariants (\texttt{kdfParams} present iff \texttt{pw-v1}), unwrapping asserts the record's scheme against the supplied key material before touching the cipher, and the IndexedDB composite key \texttt{[vaultId, scheme]} fixes each record's position.
A context swap therefore fails before or at decryption, but the binding is enforced by the validation layer rather than the AEAD.
\texttt{prf-v2} is reserved to bind $(\mathrm{version}, \mathrm{scheme}, \mathrm{salt}, \mathrm{vaultId})$ as AAD, converting this structural argument into a cryptographic one.
```

- [ ] **Step 2: Compile check**

Run: `tectonic paper/main.tex`
Expected: success; `\ref{sec:rationale}` resolves after the second pass (Tectonic reruns automatically).

- [ ] **Step 3: Commit**

```bash
git add paper/main.tex
git commit -m "docs(paper): add design-rationale subsection (HKDF salt, AAD, frozen v1, prf-v2)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 6: Threat-Model and Evaluation Fixes (counters, bounded exposure, scrypt honesty, crash consistency, future work)

**Files:**
- Modify: `paper/main.tex` — four targeted edits (exact old → new text below).

**Interfaces:**
- Consumes: `readAuthenticatorFlags` (Task 2 — must be merged first so the paper describes shipped code); bib keys `injection-attacks`, `pq-cloud-survey` (Task 3); `\label{sec:rationale}` (Task 5).

- [ ] **Step 1: Rewrite the security-goals sentence in the Threat Model (counters + bounded exposure)**

Replace (currently around line 115):

```latex
The corresponding security goals are: \emph{zero-knowledge storage} --- stored-data compromise alone yields no secrets (Sect.~\ref{sec:zk}); \emph{bounded exposure} under browser compromise --- a script obtains at most the secrets unlocked during its window of control, since wrap keys are non-extractable and PRF outputs are zeroized after use; \emph{cloned-credential detection} via signature-counter verification; and \emph{PQ-adequate} symmetric primitives at the storage layer (Sect.~\ref{sec:pq}).
```

with:

```latex
The corresponding security goals are: \emph{zero-knowledge storage} --- stored-data compromise alone yields no secrets (Sect.~\ref{sec:zk}); \emph{bounded exposure} under browser compromise; \emph{best-effort cloned-credential detection}; and \emph{PQ-adequate} symmetric primitives at the storage layer (Sect.~\ref{sec:pq}).
Two of these goals deserve sharper statements than they usually receive.
\emph{Bounded exposure} is a real but coarse bound: non-extractable wrap keys and zeroized PRF outputs prevent a malicious in-origin script from exfiltrating key material for later offline use, but nothing prevents such a script from \emph{using} an unlocked key --- during its window of control it can decrypt every record the user unlocks, and applications should treat origin compromise as full compromise of the unlocked session, mitigable only by compartmentalization (short unlock windows, per-record unlock ceremonies for high-value secrets).
\emph{Cloned-credential detection} via signature counters is likewise best-effort: synced passkeys commonly report a constant counter of zero, which disables the increase check entirely (Algorithm~\ref{alg:unwrap} skips it when $c'{=}0$).
The library therefore exposes the authenticator's backup-eligibility (BE) and backup-state (BS) flags via \texttt{readAuthenticatorFlags}, letting applications distinguish device-bound credentials --- where a non-increasing counter is a strong clone signal --- from synced passkeys, where it is vacuous; per-device continuity via the WebAuthn Level~3 \texttt{devicePubKey} extension is a natural upgrade once client support matures.
```

- [ ] **Step 2: Fix the Evaluation performance sentence (scrypt memory honesty + explicit N)**

Replace (currently around line 321, inside Sect.\ Evaluation and Discussion):

```latex
\emph{Performance}: unlock cost is dominated by the WebAuthn ceremony itself (user verification takes seconds), against which one HKDF derivation and one AES-GCM decryption of a 32-byte payload are negligible; on the password fallback path, scrypt with $N{=}2^{17}$ deliberately costs a few hundred milliseconds on commodity hardware, a floor chosen so that offline guessing, not interactive unlock, bears the cost.
```

with:

```latex
\emph{Performance}: unlock cost is dominated by the WebAuthn ceremony itself (user verification takes seconds), against which one HKDF derivation and one AES-GCM decryption of a 32-byte payload are negligible.
The password fallback is deliberately expensive: scrypt with $N{=}2^{17}{=}131{,}072$, $r{=}8$, $p{=}1$ requires a $128 \cdot N \cdot r = 128$\,MiB working set and costs a few hundred milliseconds on desktop-class hardware, but can reach multi-second latency and cause memory pressure on low-end mobile devices and WebViews.
These parameters are a security floor, not a tunable: the wrap KDF is precisely what an offline attacker attacks, so adaptive parameter selection is admissible only \emph{upward}; applications targeting constrained devices should prefer the PRF path, whose cost is independent of the KDF floor.
```

- [ ] **Step 3: Add crash-consistency and side-channel sentences to the Evaluation**

Replace the closing sentence of the Evaluation section (currently around line 323):

```latex
A quantitative cross-device benchmark of ceremony latency and PRF availability is left as future work.
```

with:

```latex
\emph{Failure semantics}: record and counter writes are single IndexedDB transactions, so a crash mid-operation leaves either the old or the new row, never a torn one; a lost counter update leaves a stale (lower) stored counter, which can only widen the acceptance window of the next unlock by one assertion --- it can never render the vault un-unlockable, so replay protection degrades toward availability rather than lockout.
\emph{Scope of the zero-knowledge claim}: the guarantee of Sect.~\ref{sec:zk} covers persisted state only; system-level channels demonstrated against E2EE password managers --- telemetry, caching, and pre-encryption compression or deduplication~\cite{injection-attacks} --- as well as record-size and timing patterns in IndexedDB remain application responsibilities (Sect.~\ref{sec:rationale} lists the corresponding app-layer rules).
A quantitative cross-device benchmark of ceremony latency, PRF availability, and scrypt cost on constrained devices, together with a game-based formalization of the wrapping scheme, is left as future work; interoperability test vectors for both record schemes are published with the library to let independent implementations validate compatibility.
```

- [ ] **Step 4: Cite the PQ survey in the Post-Quantum section**

Replace (currently around line 311):

```latex
Against a quantum adversary, Grover-type speedups at most halve the effective security exponent, leaving AES-256 and SHA-256-based constructions with comfortable margins; NIST's transition guidance accordingly treats AES-256 and SHA-256/384 as quantum-adequate~\cite{nist-pqc}.
```

with:

```latex
Against a quantum adversary, Grover-type speedups at most halve the effective security exponent, leaving AES-256 and SHA-256-based constructions with comfortable margins; NIST's transition guidance accordingly treats AES-256 and SHA-256/384 as quantum-adequate~\cite{nist-pqc}, a position echoed by recent post-quantum migration surveys~\cite{pq-cloud-survey}.
```

- [ ] **Step 5: Compile and inspect**

Run: `tectonic paper/main.tex`
Expected: success; zero undefined references/citations; overfull warnings not materially worse than the pre-task baseline (`\emergencystretch` is already set).

- [ ] **Step 6: Commit**

```bash
git add paper/main.tex
git commit -m "docs(paper): sharpen bounded-exposure and counter claims, fix scrypt cost honesty

Addresses validated review findings: 128 MiB scrypt working set stated
explicitly, synced-passkey counter limitation + BE/BS flags documented,
crash-consistency semantics and ZK-claim scope clarified.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 7: Final Verification Sweep

**Files:** none created; verification only.

- [ ] **Step 1: Full library verify**

Run: `npm run verify`
Expected: 0 type errors, 0 lint warnings, all tests (including 4 new vector tests + 3 new flags tests) pass, clean build.

- [ ] **Step 2: Full paper compile from clean state**

Run: `tectonic paper/main.tex`
Expected: PDF produced; grep the log output for `undefined` — no undefined citations or references.

- [ ] **Step 3: Cross-check paper claims against code one last time**

Confirm: (a) the paper's `readAuthenticatorFlags` mention matches the exported name in `src/webauthn/verify.ts`; (b) `docs/INTEROP-VECTORS.md` exists and matches `src/core/__tests__/vectors.test.ts` values; (c) no paper text now claims AAD or an HKDF salt is *used* (they are described as deliberate v1 omissions).

- [ ] **Step 4: Commit anything outstanding, then update graph**

```bash
git status --short   # expect clean or only graphify-out changes
graphify update .
```

## Explicitly Rejected / Deferred Review Items

- **Change HKDF salt to the PRF salt (v1):** rejected — breaks every published record; addressed as `prf-v2` reservation in Sect.~\ref{sec:rationale}.
- **Add GCM AAD (v1):** rejected — same reason; `prf-v2` reservation.
- **Implement devicePubKey:** deferred — WebAuthn L3 extension without dependable client support; discussed in the paper.
- **Game-based formal proof, cross-device empirical benchmarks, red-teaming:** deferred — declared future work explicitly in the revised Evaluation text.
- **Lower/adapt scrypt params downward for mobile:** rejected — violates the hard security floor; paper now says adaptation is upward-only and points constrained devices to the PRF path.
