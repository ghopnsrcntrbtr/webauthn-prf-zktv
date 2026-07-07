# Clone-Detection Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Convert the largely-inoperative signature-counter replay check into an honest, composed clone-detection signal, make freshness inputs explicit (no silent skip), and close the counter-persistence TOCTOU gap with atomic storage operations.

**Architecture:** `verifyAssertionResponse` becomes the single source of truth for a `CloneDetectionOutcome` verdict that composes the counter check with the authenticator backup flags (BE/BS). The verdict flows up unchanged through `evaluatePrf` → `unlockVault`. `ZktvDb` gains an atomic `saveEnrollment` (vault record + credential meta in ONE IndexedDB transaction) and a monotonic single-transaction `updateCounter`. The v1 record format, HKDF labels, and all cryptography are untouched — this is an API/verification/storage change only (AAD binding stays reserved for prf-v2).

**Tech Stack:** TypeScript strict ESM, Vitest (`vi.stubGlobal` WebAuthn mocks, `fake-indexeddb/auto`), tsup, Tectonic for the paper.

**Security assessment driving this plan (2026-07-07):** counter-based clone detection is silently disabled for synced passkeys (counter 0), `storedCounter` defaults to "skip", and counter persistence is neither atomic nor monotonic → detection-control gap (CWE-602 / CWE-367), severity Medium. This plan implements assessment remediation steps 1–3 and 5–6; step 4 (AAD binding) is explicitly deferred to a future prf-v2 scheme.

## Global Constraints

- `npm run verify` (type-check → lint → test → build) must pass before EVERY commit.
- **Breaking API release**: this plan targets v0.3.0 (semver 0.x — breaking allowed in minor). `storedCounter` becomes required on `EvaluatePrfOptions` and `UnlockVaultOptions`; `verifyAssertionResponse` return type changes from `number` to `AssertionVerification`.
- HARD security rules from CLAUDE.md apply verbatim: no `exportKey`, no persisted PRF outputs/key bytes, zeroize in `finally`, generic `DecryptError`, frozen HKDF info labels, scrypt floor `{N:131072,r:8,p:1}`, native `navigator.credentials` only, no migration may add stored recomputable key inputs.
- **The `WrappedSecretRecord` v1 format and `parseRecord`/`serializeRecord` must NOT change** — existing records and interop vectors must keep passing.
- No new runtime dependencies (`@noble/hashes` stays the only one).
- `exactOptionalPropertyTypes` is ON: build optional props conditionally, never assign `undefined`. `noUncheckedIndexedAccess` is ON: `bytes[i]` needs `?? 0`.
- IndexedDB schema stays at version 1 — no new stores or indexes are needed.
- End every commit message with: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`
- After the final task, run `graphify update .` to refresh the knowledge graph.

---

### Task 1: Composed clone-detection verdict in `verifyAssertionResponse`

**Files:**
- Modify: `src/webauthn/verify.ts`
- Test: `src/webauthn/__tests__/verify.test.ts`

**Interfaces:**
- Consumes: existing `readCounter(authData)`, `readAuthenticatorFlags(authData)`, `ReplayError`.
- Produces (later tasks rely on these exact names):
  - `type CloneDetectionOutcome = 'counter-ok' | 'no-counter-synced' | 'no-counter-unexpected' | 'not-checked'`
  - `interface AssertionVerification { counter: number; flags: AuthenticatorFlags; cloneDetection: CloneDetectionOutcome }`
  - `verifyAssertionResponse(args: VerifyAssertionArgs): AssertionVerification` (was `: number`). Throw behavior unchanged: still throws `ReplayError` on bad type/challenge/origin/short authData/regressed non-zero counter.

Verdict semantics (the whole point of this task — copy into the doc comment):
- `counter-ok` — check ran (`storedCounter >= 0`) and the counter advanced. Only affirmative outcome.
- `no-counter-synced` — counter is 0 and BE flag set: expected for synced passkeys; counter check is vacuous.
- `no-counter-unexpected` — counter is 0 but BE clear: a device-bound credential reporting no counter is a weak anomaly signal.
- `not-checked` — caller passed `storedCounter: -1` (explicit opt-out, e.g. enrollment).

- [ ] **Step 1: Update the test helper and rewrite counter/verdict tests (failing first)**

In `src/webauthn/__tests__/verify.test.ts`, change `makeAuthData` to accept a flags byte, and update every `verifyAssertionResponse` return-value assertion from a bare number to the new object. Replace the existing `describe('verifyAssertionResponse', ...)` block's return-value tests with:

```ts
function makeAuthData(counter: number, flagsByte = 0): Uint8Array {
  const data = new Uint8Array(37);
  data[32] = flagsByte;
  new DataView(data.buffer).setUint32(33, counter, false); // big-endian at bytes 33-36
  return data;
}
```

```ts
  it('returns counter, flags, and counter-ok verdict on valid input', () => {
    const result = verifyAssertionResponse(valid);
    expect(result.counter).toBe(5);
    expect(result.cloneDetection).toBe('counter-ok');
    expect(result.flags.backupEligible).toBe(false);
  });

  it('zero counter with BE flag → no-counter-synced (synced passkey, check vacuous)', () => {
    const result = verifyAssertionResponse({
      ...valid,
      authenticatorData: makeAuthData(0, 0x01 | 0x08 | 0x10),
    });
    expect(result.counter).toBe(0);
    expect(result.cloneDetection).toBe('no-counter-synced');
  });

  it('zero counter without BE flag → no-counter-unexpected (weak anomaly signal)', () => {
    expect(
      verifyAssertionResponse({ ...valid, authenticatorData: makeAuthData(0) }).cloneDetection,
    ).toBe('no-counter-unexpected');
  });

  it('storedCounter -1 → not-checked even when the counter is positive', () => {
    const result = verifyAssertionResponse({ ...valid, storedCounter: -1 });
    expect(result.counter).toBe(5);
    expect(result.cloneDetection).toBe('not-checked');
  });
```

Keep all existing `toThrow(ReplayError)` tests unchanged (challenge/origin/type mismatch, regressed counter, truncated authData) — they must still pass. Delete the old `it('returns the new counter on valid input', ...)`, `it('permits zero counters ...)`, and `it('permits any counter when storedCounter is -1 ...)` tests (superseded by the four above).

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/webauthn/__tests__/verify.test.ts`
Expected: FAIL — `result.cloneDetection` is `undefined` / type errors (return is still `number`).

- [ ] **Step 3: Implement the verdict in `src/webauthn/verify.ts`**

Add above `VerifyAssertionArgs`:

```ts
/**
 * How clone detection resolved. Only 'counter-ok' is affirmative; the other
 * outcomes tell the application WHY no counter assurance exists:
 * - 'no-counter-synced': counter 0 + BE flag — synced passkey, counter check vacuous.
 * - 'no-counter-unexpected': counter 0 without BE — weak anomaly for a device-bound credential.
 * - 'not-checked': caller explicitly opted out with storedCounter -1.
 */
export type CloneDetectionOutcome =
  | 'counter-ok'
  | 'no-counter-synced'
  | 'no-counter-unexpected'
  | 'not-checked';

export interface AssertionVerification {
  counter: number;
  flags: AuthenticatorFlags;
  cloneDetection: CloneDetectionOutcome;
}
```

Change the signature to `export function verifyAssertionResponse(args: VerifyAssertionArgs): AssertionVerification` and replace the final two lines (`const counter = ...; ... return counter;`) with:

```ts
  const counter = readCounter(args.authenticatorData);
  if (counter <= args.storedCounter && counter !== 0) {
    throw new ReplayError('Signature counter did not increase — possible cloned authenticator');
  }
  const flags = readAuthenticatorFlags(args.authenticatorData);
  let cloneDetection: CloneDetectionOutcome;
  if (args.storedCounter < 0) {
    cloneDetection = 'not-checked';
  } else if (counter > 0) {
    cloneDetection = 'counter-ok';
  } else {
    cloneDetection = flags.backupEligible ? 'no-counter-synced' : 'no-counter-unexpected';
  }
  return { counter, flags, cloneDetection };
```

Also update the `/** Replay protection ... */` doc comment on the function to: `/** Replay checks (type/challenge/origin/counter) throw ReplayError; returns the counter plus a composed clone-detection verdict. Client-side and therefore ADVISORY — a compromised client can bypass it. */`

- [ ] **Step 4: Run the file's tests**

Run: `npx vitest run src/webauthn/__tests__/verify.test.ts`
Expected: PASS. (Other webauthn tests will fail until Tasks 2–3 — that is expected; do NOT run the full suite yet.)

- [ ] **Step 5: Commit**

```bash
git add src/webauthn/verify.ts src/webauthn/__tests__/verify.test.ts
git commit -m "feat(webauthn)!: verifyAssertionResponse returns composed clone-detection verdict

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: Explicit freshness in `evaluatePrf`; verdict flows through `PrfEvaluation`

**Files:**
- Modify: `src/webauthn/ceremonies.ts`
- Test: `src/webauthn/__tests__/evaluatePrf.test.ts`

**Interfaces:**
- Consumes (Task 1): `AssertionVerification`, `CloneDetectionOutcome`, `AuthenticatorFlags`, `verifyAssertionResponse(args): AssertionVerification`.
- Produces:
  - `EvaluatePrfOptions.storedCounter: number` — **required** (no `?`, no default).
  - `interface PrfEvaluation { prfOutput: Uint8Array; counter: number; flags: AuthenticatorFlags; cloneDetection: CloneDetectionOutcome }`
  - `evaluatePrf(options: EvaluatePrfOptions): Promise<PrfEvaluation>` — unchanged name; enriched result.

- [ ] **Step 1: Update tests (failing first)**

In `src/webauthn/__tests__/evaluatePrf.test.ts`:
1. Extend the first test's assertions:

```ts
    expect(result.prfOutput).toHaveLength(PRF_OUTPUT_LENGTH);
    expect(result.counter).toBe(11);
    expect(result.cloneDetection).toBe('counter-ok');
    expect(result.flags.userPresent).toBe(false); // stub sets no flag bits
```

2. Add `storedCounter: -1` to the four `evaluatePrf({ credentialId: CRED_ID, salt: SALT, rpId: 'example.com' })` calls that omit it (the `PrfResultMissingError` ×2, `NotAllowedError`, and — leave the `ReplayError` test as-is, it already passes `storedCounter: 9`).
3. Add one new test:

```ts
  it("reports 'not-checked' when the caller explicitly skips with storedCounter -1", async () => {
    stubCeremony({ prfFirst: new Uint8Array(32).fill(7), counter: 11 });
    const result = await evaluatePrf({
      credentialId: CRED_ID,
      salt: SALT,
      rpId: 'example.com',
      storedCounter: -1,
    });
    expect(result.cloneDetection).toBe('not-checked');
  });
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/webauthn/__tests__/evaluatePrf.test.ts`
Expected: FAIL — `cloneDetection` undefined on the result.

- [ ] **Step 3: Implement in `src/webauthn/ceremonies.ts`**

1. Import types: change the verify import line to
   `import { readCounter, verifyAssertionResponse, type AuthenticatorFlags, type CloneDetectionOutcome } from './verify';`
2. In `EvaluatePrfOptions`, replace the optional field with a required one:

```ts
  /**
   * Last persisted signature counter for this credential. REQUIRED so that
   * skipping clone detection is always an explicit caller decision:
   * pass -1 ONLY when no stored counter exists yet (enrollment).
   */
  storedCounter: number;
```

3. Enrich the result type:

```ts
export interface PrfEvaluation {
  prfOutput: Uint8Array;
  counter: number;
  flags: AuthenticatorFlags;
  /** Composed clone-detection verdict — 'counter-ok' is the only affirmative outcome. */
  cloneDetection: CloneDetectionOutcome;
}
```

4. In `evaluatePrf`, replace the `const counter = verifyAssertionResponse({...})` call and return with:

```ts
  const verification = verifyAssertionResponse({
    clientDataJSON: new Uint8Array(response.clientDataJSON),
    authenticatorData: new Uint8Array(response.authenticatorData),
    expectedChallenge,
    expectedOrigin: window.location.origin,
    storedCounter: options.storedCounter,
  });

  return { prfOutput, ...verification };
```

5. In `enrollPrfCredential`, the two-ceremony fallback call must now opt out explicitly — add `storedCounter: -1`:

```ts
  const { prfOutput, counter } = await evaluatePrf({
    credentialId,
    salt: prfSalt,
    rpId: options.rpId,
    storedCounter: -1, // brand-new credential: no stored counter exists yet
    ...(options.timeout !== undefined ? { timeout: options.timeout } : {}),
  });
```

(`EnrollResult` keeps its existing shape — enrollment has nothing meaningful to report.)

- [ ] **Step 4: Run the file's tests**

Run: `npx vitest run src/webauthn/__tests__/evaluatePrf.test.ts src/webauthn/__tests__/enroll.test.ts`
Expected: PASS both files. (`vault.test.ts` still fails until Task 3.)

- [ ] **Step 5: Commit**

```bash
git add src/webauthn/ceremonies.ts src/webauthn/__tests__/evaluatePrf.test.ts
git commit -m "feat(webauthn)!: evaluatePrf requires explicit storedCounter, returns clone verdict

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: `unlockVault` surfaces the verdict; export the new types

**Files:**
- Modify: `src/webauthn/vault.ts`
- Modify: `src/webauthn/index.ts`
- Test: `src/webauthn/__tests__/vault.test.ts`

**Interfaces:**
- Consumes (Tasks 1–2): `PrfEvaluation` with `flags`/`cloneDetection`; `CloneDetectionOutcome`, `AuthenticatorFlags` from `./verify`.
- Produces:
  - `UnlockVaultOptions.storedCounter: number` — **required**.
  - `UnlockVaultResult { key: CryptoKey; counter: number; flags: AuthenticatorFlags; cloneDetection: CloneDetectionOutcome }`
  - Public exports from `webauthn-prf-zktv/webauthn`: `AssertionVerification`, `CloneDetectionOutcome` types.

- [ ] **Step 1: Update tests (failing first)**

In `src/webauthn/__tests__/vault.test.ts`:
1. First test — the mock's counter is 1 and `storedCounter: 0` is passed, so assert the affirmative verdict:

```ts
    expect(unlocked.key.extractable).toBe(false);
    expect(unlocked.counter).toBe(1);
    expect(unlocked.cloneDetection).toBe('counter-ok');
```

2. Third test (`rejects non prf-v1 records`) — `storedCounter` is now required; add `storedCounter: -1,` after `rpId: 'example.com',`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/webauthn/__tests__/vault.test.ts`
Expected: FAIL — `unlocked.cloneDetection` undefined.

- [ ] **Step 3: Implement in `src/webauthn/vault.ts`**

1. Add import: `import type { AuthenticatorFlags, CloneDetectionOutcome } from './verify';`
2. `UnlockVaultOptions` — make the counter required:

```ts
  /**
   * Last persisted signature counter for this credential (see
   * ZktvDb.updateCounter). REQUIRED: pass -1 ONLY to explicitly opt out of
   * clone detection, e.g. when no counter has been stored yet. NOTE: for
   * synced passkeys the counter is typically 0 and detection reports
   * 'no-counter-synced' — treat cloneDetection as an advisory signal.
   */
  storedCounter: number;
```

3. `UnlockVaultResult` — add the two fields:

```ts
  /** Decoded authenticator flags (UP/UV/BE/BS) from this assertion. */
  flags: AuthenticatorFlags;
  /** Composed clone-detection verdict — 'counter-ok' is the only affirmative outcome. */
  cloneDetection: CloneDetectionOutcome;
```

4. `unlockVault` body:

```ts
  const { prfOutput, counter, flags, cloneDetection } = await evaluatePrf({
    credentialId: options.credentialId,
    salt: options.record.salt,
    rpId: options.rpId,
    storedCounter: options.storedCounter,
  });
  try {
    const key = await unwrapSecret({ record: options.record, prfOutput });
    return { key, counter, flags, cloneDetection };
  } finally {
    zeroize(prfOutput);
  }
```

5. In `src/webauthn/index.ts`, extend the verify type export line to:

```ts
export type {
  AssertionVerification,
  AuthenticatorFlags,
  CloneDetectionOutcome,
  VerifyAssertionArgs,
} from './verify';
```

- [ ] **Step 4: Run the FULL suite + type-check (all webauthn breakage is now resolved)**

Run: `npm run type-check && npm run test`
Expected: 0 type errors, all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/webauthn/vault.ts src/webauthn/index.ts src/webauthn/__tests__/vault.test.ts
git commit -m "feat(webauthn)!: unlockVault requires storedCounter and returns clone verdict

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: Atomic + monotonic counter persistence in `ZktvDb`

**Files:**
- Modify: `src/indexeddb/db.ts`
- Test: `src/indexeddb/__tests__/db.test.ts`

**Interfaces:**
- Consumes: existing `StoredCredentialMeta`, `StoredVaultRow`, `serializeRecord`, `StorageError`.
- Produces:
  - `ZktvDb.saveEnrollment(vaultId: string, record: WrappedSecretRecord, meta: StoredCredentialMeta): Promise<void>` — vault row + credential meta in ONE transaction.
  - `ZktvDb.updateCounter(credentialId: string, counter: number): Promise<void>` — same signature, now a single read-modify-write transaction that NEVER lowers a stored counter (monotonic).

- [ ] **Step 1: Add failing tests**

Append inside `describe('ZktvDb', ...)` in `src/indexeddb/__tests__/db.test.ts`:

```ts
  it('updateCounter is a monotonic single write — never lowers a stored counter', async () => {
    db = await fresh();
    await db.saveCredentialRecord(cred); // counter 3
    await db.updateCounter('cred-1', 9);
    await db.updateCounter('cred-1', 5); // stale value must be ignored
    expect((await db.getCredentialRecord('cred-1'))?.counter).toBe(9);
    await db.updateCounter('cred-1', 9); // equal value is a no-op, not an error
    expect((await db.getCredentialRecord('cred-1'))?.counter).toBe(9);
  });

  it('saveEnrollment persists the vault record and credential meta together', async () => {
    db = await fresh();
    await db.saveEnrollment('vault-1', prfRecord, cred);
    expect(await db.loadWrappedVault('vault-1', 'prf-v1')).toEqual(prfRecord);
    expect((await db.getCredentialRecord('cred-1'))?.vaultId).toBe('vault-1');
  });
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/indexeddb/__tests__/db.test.ts`
Expected: FAIL — monotonic test gets counter 5; `saveEnrollment` is not a function.

- [ ] **Step 3: Implement in `src/indexeddb/db.ts`**

Replace the existing `updateCounter` (which is two separate transactions — a read-then-write race) with a single-transaction monotonic version, and add `saveEnrollment` directly below `saveCredentialRecord`:

```ts
  /**
   * Atomically persists the wrapped vault record and its credential metadata
   * in ONE transaction, so a crash can never leave a vault row without the
   * counter/salt metadata that clone detection and unlock depend on.
   */
  async saveEnrollment(
    vaultId: string,
    record: WrappedSecretRecord,
    meta: StoredCredentialMeta,
  ): Promise<void> {
    const row: StoredVaultRow = {
      vaultId,
      scheme: record.scheme,
      record: serializeRecord(record),
      updatedAt: Date.now(),
    };
    return new Promise<void>((resolve, reject) => {
      let tx: IDBTransaction;
      try {
        tx = this.db.transaction([VAULTS, CREDENTIALS], 'readwrite');
      } catch (error) {
        reject(new StorageError(error instanceof Error ? error.message : 'Transaction failed'));
        return;
      }
      tx.objectStore(VAULTS).put(row);
      tx.objectStore(CREDENTIALS).put(meta);
      tx.oncomplete = () => resolve();
      tx.onabort = () => reject(new StorageError(tx.error?.message ?? 'Transaction aborted'));
      tx.onerror = () => reject(new StorageError(tx.error?.message ?? 'Transaction failed'));
    });
  }

  /**
   * Persists a verified signature counter in one read-modify-write
   * transaction. Monotonic: a stale (lower or equal) value is ignored, so a
   * lost or reordered update can never widen the replay-acceptance window.
   */
  async updateCounter(credentialId: string, counter: number): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      let tx: IDBTransaction;
      try {
        tx = this.db.transaction(CREDENTIALS, 'readwrite');
      } catch (error) {
        reject(new StorageError(error instanceof Error ? error.message : 'Transaction failed'));
        return;
      }
      const store = tx.objectStore(CREDENTIALS);
      const getRequest = store.get(credentialId) as IDBRequest<StoredCredentialMeta | undefined>;
      getRequest.onsuccess = () => {
        const existing = getRequest.result;
        if (!existing) {
          reject(new StorageError(`No credential record: ${credentialId}`));
          tx.abort();
          return;
        }
        if (counter > existing.counter) store.put({ ...existing, counter });
      };
      tx.oncomplete = () => resolve();
      tx.onabort = () => reject(new StorageError(tx.error?.message ?? 'Transaction aborted'));
      tx.onerror = () => reject(new StorageError(tx.error?.message ?? 'Transaction failed'));
    });
  }
```

(The `reject` before `tx.abort()` is deliberate: the promise settles with the specific "No credential record" error before the generic onabort handler fires — later `reject`s are no-ops. The existing `rejects.toThrow(StorageError)` test for `'ghost'` must still pass.)

- [ ] **Step 4: Run tests**

Run: `npx vitest run src/indexeddb/__tests__/db.test.ts`
Expected: PASS, including the pre-existing `stores credential metadata and updates counters` test.

- [ ] **Step 5: Commit**

```bash
git add src/indexeddb/db.ts src/indexeddb/__tests__/db.test.ts
git commit -m "feat(indexeddb): atomic saveEnrollment and monotonic single-tx updateCounter

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 5: Documentation — README, SECURITY.md, MIGRATION.md

**Files:**
- Modify: `README.md` (section `#### Cloned-credential signals and synced passkeys`, around line 95)
- Modify: `SECURITY.md` (section `## Known residuals and limitations`, around line 57)
- Modify: `MIGRATION.md` (append new section)

**Interfaces:**
- Consumes: names from Tasks 1–4 exactly as shipped: `cloneDetection`, `CloneDetectionOutcome`, the four outcome strings, `storedCounter`, `saveEnrollment`, `updateCounter`.
- Produces: user-facing docs only; no code.

- [ ] **Step 1: Replace the README subsection body**

Replace the body of `#### Cloned-credential signals and synced passkeys` (keep the heading; replace the prose/code under it, up to the next heading) with:

```markdown
Counter-based clone detection is **advisory**. It runs client-side, and synced
passkeys (iCloud Keychain, Google Password Manager) report a constant counter
of `0`, which makes the increase-check vacuous for the most common credential
type. The API is therefore explicit about what it could and could not check:

- `unlockVault`/`evaluatePrf` **require** `storedCounter`. Pass the counter you
  persisted after the last unlock (`ZktvDb.getCredentialRecord(...).counter`),
  or `-1` to explicitly opt out (enrollment, no stored state yet).
- Results carry a composed verdict, `cloneDetection`:
  - `'counter-ok'` — the counter advanced. The only affirmative outcome.
  - `'no-counter-synced'` — counter `0` with the backup-eligible flag: a synced
    passkey; the counter check proves nothing. Expected and common.
  - `'no-counter-unexpected'` — counter `0` on a credential that is *not*
    backup-eligible: weak anomaly signal worth surfacing to risk logic.
  - `'not-checked'` — you passed `-1`.
- A regressed non-zero counter still throws `ReplayError`.

Persist the returned counter with `ZktvDb.updateCounter(credentialId, counter)`
after every successful unlock — it is monotonic and single-transaction. At
enrollment, use `ZktvDb.saveEnrollment(vaultId, record, meta)` so the vault
record and its counter metadata are written atomically.
```

- [ ] **Step 2: Update SECURITY.md known residuals**

In `## Known residuals and limitations`, add this bullet (or replace the existing counter/clone bullet if one exists — read the section first and merge, don't duplicate):

```markdown
- **Clone detection is advisory, and vacuous for synced passkeys.** All
  assertion verification (challenge, origin, signature counter) executes
  client-side in the same context that produced the data; a compromised client
  bypasses it entirely (CWE-602). Synced passkeys report counter `0`, which
  disables the increase check — the library reports this honestly via
  `cloneDetection: 'no-counter-synced'` instead of implying protection. The
  wrapped secret's confidentiality does NOT depend on this check; it rests on
  the authenticator-held PRF secret and AES-256-GCM.
```

- [ ] **Step 3: Append the migration section to MIGRATION.md**

```markdown
## 0.2.x → 0.3.0

Breaking API changes (record format is unchanged — stored `prf-v1`/`pw-v1`
records need no migration):

1. `verifyAssertionResponse` returns `AssertionVerification`
   (`{ counter, flags, cloneDetection }`) instead of a bare number.
   Replace `const counter = verifyAssertionResponse(...)` with
   `const { counter } = verifyAssertionResponse(...)`.
2. `storedCounter` is now **required** on `EvaluatePrfOptions` and
   `UnlockVaultOptions`. Previous implicit default was "skip the check";
   to keep that behavior, pass `storedCounter: -1` explicitly — but prefer
   passing the persisted counter and acting on `result.cloneDetection`.
3. `ZktvDb.updateCounter` is now monotonic: a value lower than or equal to the
   stored counter is ignored instead of overwriting. If you relied on lowering
   counters (e.g. in tests), reset the credential record instead.
4. New: `ZktvDb.saveEnrollment(vaultId, record, meta)` persists the vault
   record and credential metadata in one transaction. Prefer it over separate
   `saveWrappedVault` + `saveCredentialRecord` calls at enrollment.
```

- [ ] **Step 4: Verify docs build nothing — run lint/type-check as a smoke gate**

Run: `npm run verify`
Expected: PASS (docs don't affect it; this is the pre-commit gate).

- [ ] **Step 5: Commit**

```bash
git add README.md SECURITY.md MIGRATION.md
git commit -m "docs: advisory clone-detection semantics, storedCounter requirement, 0.3.0 migration

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 6: Paper sync (`paper/main.tex`)

**Files:**
- Modify: `paper/main.tex` (the paper claims to describe the actual implementation — CLAUDE.md requires sync)

**Interfaces:**
- Consumes: final API names from Tasks 1–4.
- Produces: updated LaTeX; compiled PDF via Tectonic.

The paper already states the synced-passkey limitation (lines ~127–128) and single-transaction failure semantics (~line 369). Three targeted edits keep it truthful:

- [ ] **Step 1: Extend the clone-detection paragraph (after the sentence ending `...where it is vacuous;` around line 128)**

Insert before `per-device continuity via the WebAuthn Level~3`:

```latex
the unlock API composes these signals into a single verdict (\texttt{cloneDetection} $\in$ \{\texttt{counter-ok}, \texttt{no-counter-synced}, \texttt{no-counter-unexpected}, \texttt{not-checked}\}) and makes the stored counter a \emph{required} input, so skipping the check is always an explicit caller decision rather than a silent default;
```

- [ ] **Step 2: Update the counter-persistence sentence (~line 304)**

Replace the clause `the signature counter persisted in \texttt{credentials} is updated after each verified assertion (\texttt{updateCounter}) to feed the replay check of Algorithm~\ref{alg:unwrap}` with:

```latex
the signature counter persisted in \texttt{credentials} is updated after each verified assertion by a monotonic single-transaction \texttt{updateCounter} (a stale value can never lower the stored counter), and enrollment persists the vault record and credential metadata atomically in one transaction (\texttt{saveEnrollment}) to feed the replay check of Algorithm~\ref{alg:unwrap}
```

- [ ] **Step 3: Compile and check**

Run: `tectonic paper/main.tex`
Expected: clean compile, zero errors; skim the two edited paragraphs in the PDF for overfull boxes (`grep -i "overfull" ` on the log if Tectonic reports warnings).

- [ ] **Step 4: Commit**

```bash
git add paper/main.tex
git commit -m "docs(paper): sync clone-detection verdict API and atomic counter persistence with src

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 7: Version bump, full verification, graph refresh

**Files:**
- Modify: `package.json`, `package-lock.json` (version 0.2.0 → 0.3.0)

**Interfaces:** none — release mechanics.

- [ ] **Step 1: Bump the version**

Run: `npm version 0.3.0 --no-git-tag-version`
Expected: `package.json` and `package-lock.json` show `0.3.0`.

- [ ] **Step 2: Full verification (Definition of Done gate)**

Run: `npm run verify`
Expected: 0 type errors, 0 lint warnings, ALL tests pass (including the interop vectors in `src/core/__tests__/vectors.test.ts` — proving the frozen v1 record format is untouched), clean tsup build.

- [ ] **Step 3: Package sanity check**

Run: `npm publish --dry-run --access public`
Expected: tarball lists `dist/` outputs for all three entry points; no unexpected files; size in line with 0.2.0.

- [ ] **Step 4: Refresh the knowledge graph**

Run: `graphify update .`
Expected: graph updated without errors (AST-only).

- [ ] **Step 5: Commit and tag**

```bash
git add package.json package-lock.json graphify-out
git commit -m "chore: bump version to 0.3.0

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
git tag v0.3.0
```

Do NOT push or `npm publish` — the maintainer releases manually (npm auth uses a granular token; see 0.2.0 release notes).

---

## Validation summary (maps back to the 2026-07-07 assessment)

| Assessment remediation step | Task | Validated by |
|---|---|---|
| 1. Reclassify counter check as advisory signal | 1, 5 | verdict tests in `verify.test.ts`; SECURITY.md wording |
| 2a. No silent skip-by-default | 2, 3 | `storedCounter` required → type-check fails on omission; `not-checked` tests |
| 2b. Composed risk signal (counter × backup flags) | 1–3 | four-outcome verdict tests incl. `no-counter-synced` vs `no-counter-unexpected` |
| 3. Atomic/monotonic counter persistence | 4 | monotonic + `saveEnrollment` tests on fake-indexeddb |
| 4. AAD binding | — | **Deferred to prf-v2 by design** (frozen v1 format; tracked in paper §future work) |
| 5. Docs/paper state the limitation | 5, 6 | README/SECURITY/MIGRATION diff; Tectonic clean compile |
| 6. Negative-path tests + full verify | all | stale-counter, zero-counter±BE, skipped-check tests; `npm run verify`; vectors.test.ts unchanged |
