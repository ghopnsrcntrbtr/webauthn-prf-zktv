# webauthn-prf-zktv v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `webauthn-prf-zktv` v0.1.0 — a public npm package for WebAuthn-PRF-backed zero-knowledge vault-key wrapping with optional PWA IndexedDB storage, per the approved spec at `docs/superpowers/specs/2026-07-03-webauthn-prf-zktv-design.md`.

**Architecture:** Single ESM package with three sub-path exports: `.` (crypto core: HKDF-SHA256 → AES-256-GCM wrap, scrypt password wrap — Node ≥20 safe), `./webauthn` (native-API PRF ceremonies with adaptive single/two-ceremony enrollment and replay verification), `./indexeddb` (raw-IndexedDB vault storage). Extracted and generalized from TrustVault-PWA production code.

**Tech Stack:** TypeScript 5.x (strict), tsup (build), Vitest + fake-indexeddb (test), ESLint flat config + Prettier, `@noble/hashes` (only runtime dep, for scrypt).

## Global Constraints

- Node ≥ 20 (global WebCrypto). ESM-only (`"type": "module"`). Runtime dependency: `@noble/hashes` ONLY.
- tsconfig flags (verbatim): `strict: true`, `noUncheckedIndexedAccess: true`, `exactOptionalPropertyTypes: true`, `noImplicitReturns: true`.
- Lint gate: `eslint . --max-warnings 0`.
- Security invariants (every task): no `crypto.subtle.exportKey` anywhere in `src/`; all derived/imported keys non-extractable; transient key-material buffers zeroized with `.fill(0)` in `finally` blocks; `DecryptError` message is generic (never distinguishes wrong-key from corrupt data, never logs the cause); no error message contains key material, PRF bytes, or plaintext.
- HKDF info label (verbatim): `webauthn-prf-zktv vault key wrap v1`. Legacy TrustVault label (verbatim): `TrustVault Vault Key Wrapping v1`. HKDF salt: empty (`new Uint8Array(0)`) — RFC 5869 valid; domain separation comes from the unique per-credential PRF salt.
- scrypt defaults (verbatim): `N: 131072, r: 8, p: 1, dkLen: 32`.
- Record constants: nonce 12 bytes, salts 32 bytes (min 16 accepted on parse), PRF output exactly 32 bytes, AES-GCM-256.
- Wrap schemes in v1: `'prf-v1' | 'pw-v1'`. `hybrid-v1` is docs-only (reserved).
- WebAuthn: native `navigator.credentials` only — no SimpleWebAuthn. Capability detection via `PublicKeyCredential.getClientCapabilities()`; never create throwaway credentials to probe.
- Commits: conventional commits (`feat:`, `test:`, `docs:`, `chore:`, `ci:`).

---

## File Structure (locked)

```
package.json, tsconfig.json, tsup.config.ts, vitest.config.ts, eslint.config.js,
.prettierrc.json, .gitignore, LICENSE
src/index.ts                     core public entry
src/errors.ts                    typed error hierarchy
src/core/types.ts                WrappedSecretRecord, ScryptParams, WrapScheme
src/core/derive.ts               deriveWrapKeyFromPrf, deriveWrapKeyFromPassword
src/core/wrap.ts                 wrapSecret, unwrapSecret, unwrapSecretBytes
src/core/serialize.ts            serializeRecord, parseRecord
src/core/trustvault.ts           fromTrustVaultRecord (legacy adapter)
src/utils/base64.ts              base64url + base64 codecs
src/utils/zeroize.ts             zeroize()
src/utils/random.ts              generateSalt()
src/webauthn/index.ts            webauthn public entry
src/webauthn/support.ts          isWebAuthnSupported, detectPrfSupport, isPrfViableOnThisClient
src/webauthn/verify.ts           verifyAssertionResponse, readCounter
src/webauthn/prf-types.ts        local PRF extension typings
src/webauthn/ceremonies.ts       enrollPrfCredential, evaluatePrf
src/webauthn/vault.ts            enrollVault, unlockVault
src/indexeddb/index.ts           indexeddb public entry
src/indexeddb/db.ts              openVaultDb, ZktvDb
tests co-located: src/**/__tests__/*.test.ts
CLAUDE.md, README.md, SECURITY.md, MIGRATION.md
examples/node-unwrap/, examples/pwa-vite/
.github/workflows/ci.yml
```

---

### Task 1: Package scaffold & toolchain

**Files:**
- Create: `package.json`, `tsconfig.json`, `tsup.config.ts`, `vitest.config.ts`, `eslint.config.js`, `.prettierrc.json`, `.gitignore`, `LICENSE`, `src/index.ts` (stub), `src/webauthn/index.ts` (stub), `src/indexeddb/index.ts` (stub)

**Interfaces:**
- Produces: working `npm run verify` pipeline (type-check → lint → test → build); sub-path exports map every later task publishes through.

- [ ] **Step 1: Write `package.json`**

```json
{
  "name": "webauthn-prf-zktv",
  "version": "0.1.0",
  "description": "Zero-Knowledge TrustVault: WebAuthn PRF-backed vault key wrapping (HKDF-SHA256 → AES-256-GCM) with optional PWA IndexedDB storage patterns.",
  "type": "module",
  "license": "MIT",
  "author": "opnsrcntrbtr",
  "repository": { "type": "git", "url": "git+https://github.com/opnsrcntrbtr/webauthn-prf-zktv.git" },
  "keywords": ["webauthn", "prf", "hmac-secret", "passkey", "zero-knowledge", "vault", "aes-gcm", "hkdf", "indexeddb", "pwa", "e2ee"],
  "engines": { "node": ">=20.0.0" },
  "sideEffects": false,
  "files": ["dist", "README.md", "SECURITY.md", "MIGRATION.md", "LICENSE"],
  "exports": {
    ".": { "types": "./dist/index.d.ts", "import": "./dist/index.js" },
    "./webauthn": { "types": "./dist/webauthn/index.d.ts", "import": "./dist/webauthn/index.js" },
    "./indexeddb": { "types": "./dist/indexeddb/index.d.ts", "import": "./dist/indexeddb/index.js" }
  },
  "scripts": {
    "build": "tsup",
    "type-check": "tsc --noEmit",
    "lint": "eslint . --max-warnings 0",
    "format": "prettier --write \"src/**/*.ts\"",
    "test": "vitest run",
    "test:watch": "vitest",
    "verify": "npm run type-check && npm run lint && npm run test && npm run build",
    "prepublishOnly": "npm run verify"
  },
  "dependencies": { "@noble/hashes": "^1.5.0" },
  "devDependencies": {}
}
```

- [ ] **Step 2: Install dev dependencies**

Run:
```bash
npm install --save-dev typescript tsup vitest fake-indexeddb eslint @eslint/js typescript-eslint prettier @types/node
```
Expected: `package.json` devDependencies populated; `node_modules/` created.

- [ ] **Step 3: Write `tsconfig.json`**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "Bundler",
    "lib": ["ES2022", "DOM"],
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "exactOptionalPropertyTypes": true,
    "noImplicitReturns": true,
    "noEmit": true,
    "skipLibCheck": true,
    "types": ["node"]
  },
  "include": ["src", "tsup.config.ts", "vitest.config.ts"]
}
```

- [ ] **Step 4: Write `tsup.config.ts`**

```ts
import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'webauthn/index': 'src/webauthn/index.ts',
    'indexeddb/index': 'src/indexeddb/index.ts',
  },
  format: ['esm'],
  dts: true,
  clean: true,
  target: 'es2022',
  sourcemap: true,
});
```

- [ ] **Step 5: Write `vitest.config.ts`**

```ts
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['src/**/__tests__/**/*.test.ts'],
  },
});
```

- [ ] **Step 6: Write `eslint.config.js`**

```js
import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['dist/', 'examples/', 'coverage/', 'docs/'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
);
```

- [ ] **Step 7: Write `.prettierrc.json`, `.gitignore`, `LICENSE`**

`.prettierrc.json`:
```json
{ "singleQuote": true, "trailingComma": "all", "printWidth": 100 }
```

`.gitignore`:
```
node_modules/
dist/
coverage/
*.tsbuildinfo
```

`LICENSE`: standard MIT text, `Copyright (c) 2026 opnsrcntrbtr`.

- [ ] **Step 8: Write entry stubs**

`src/index.ts`:
```ts
export const VERSION = '0.1.0';
```
`src/webauthn/index.ts`:
```ts
export {};
```
`src/indexeddb/index.ts`:
```ts
export {};
```

- [ ] **Step 9: Verify the pipeline runs**

Run: `npm run verify`
Expected: type-check passes, lint passes, vitest reports "no test files found" without failing (if vitest exits non-zero on no tests, add `passWithNoTests: true` to `vitest.config.ts` test block), tsup emits `dist/index.js`, `dist/webauthn/index.js`, `dist/indexeddb/index.js` + `.d.ts` files.

- [ ] **Step 10: Commit**

```bash
git add -A
git commit -m "chore: scaffold webauthn-prf-zktv package (tsup, vitest, eslint, strict TS)"
```

---

### Task 2: Utils — base64/base64url, zeroize, generateSalt

**Files:**
- Create: `src/utils/base64.ts`, `src/utils/zeroize.ts`, `src/utils/random.ts`
- Test: `src/utils/__tests__/utils.test.ts`

**Interfaces:**
- Produces: `toBase64Url(bytes: Uint8Array): string`, `fromBase64Url(text: string): Uint8Array`, `toBase64(bytes: Uint8Array): string`, `fromBase64(text: string): Uint8Array`, `zeroize(view: Uint8Array): void`, `generateSalt(length = 32): Uint8Array`. Every later task uses these.

- [ ] **Step 1: Write the failing tests**

`src/utils/__tests__/utils.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { fromBase64, fromBase64Url, toBase64, toBase64Url } from '../base64';
import { zeroize } from '../zeroize';
import { generateSalt } from '../random';

describe('base64url', () => {
  it('round-trips arbitrary bytes', () => {
    const bytes = new Uint8Array([0, 1, 250, 251, 252, 253, 254, 255, 62, 63]);
    expect(fromBase64Url(toBase64Url(bytes))).toEqual(bytes);
  });
  it('produces URL-safe output without padding', () => {
    const encoded = toBase64Url(new Uint8Array([251, 255, 190]));
    expect(encoded).not.toMatch(/[+/=]/);
  });
  it('throws on invalid base64url input', () => {
    expect(() => fromBase64Url('!!!not-base64!!!')).toThrow();
  });
});

describe('base64 (standard, for TrustVault legacy records)', () => {
  it('round-trips arbitrary bytes', () => {
    const bytes = generateSalt();
    expect(fromBase64(toBase64(bytes))).toEqual(bytes);
  });
});

describe('zeroize', () => {
  it('fills the view with zeros', () => {
    const buf = new Uint8Array([9, 9, 9]);
    zeroize(buf);
    expect(Array.from(buf)).toEqual([0, 0, 0]);
  });
});

describe('generateSalt', () => {
  it('returns requested length and unique values', () => {
    const a = generateSalt();
    const b = generateSalt();
    expect(a).toHaveLength(32);
    expect(generateSalt(16)).toHaveLength(16);
    expect(a).not.toEqual(b);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/utils`
Expected: FAIL — "Cannot find module '../base64'" (and siblings).

- [ ] **Step 3: Implement**

`src/utils/base64.ts`:
```ts
export function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function fromBase64(text: string): Uint8Array {
  const binary = atob(text); // throws DOMException on invalid input
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/u, '');
}

export function fromBase64Url(text: string): Uint8Array {
  const base64 = text.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=');
  return fromBase64(padded);
}
```

`src/utils/zeroize.ts`:
```ts
/** Overwrites a typed-array view with zeros. Best-effort in JS — see SECURITY.md. */
export function zeroize(view: Uint8Array): void {
  view.fill(0);
}
```

`src/utils/random.ts`:
```ts
/** Cryptographically random salt (default 32 bytes — PRF input / scrypt salt size). */
export function generateSalt(length = 32): Uint8Array {
  const salt = new Uint8Array(length);
  crypto.getRandomValues(salt);
  return salt;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run src/utils`
Expected: PASS (7 tests).

- [ ] **Step 5: Commit**

```bash
git add src/utils
git commit -m "feat: base64url/base64 codecs, zeroize, generateSalt utilities"
```

---

### Task 3: Typed error hierarchy

**Files:**
- Create: `src/errors.ts`
- Test: `src/__tests__/errors.test.ts`

**Interfaces:**
- Produces: `ZktvError` (base, `.code: ZktvErrorCode`), `PrfUnsupportedError`, `CeremonyCancelledError`, `PrfResultMissingError`, `ReplayError`, `DecryptError`, `RecordFormatError`, `StorageError`. All later tasks throw ONLY these from public APIs.

- [ ] **Step 1: Write the failing tests**

`src/__tests__/errors.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import {
  CeremonyCancelledError,
  DecryptError,
  PrfResultMissingError,
  PrfUnsupportedError,
  RecordFormatError,
  ReplayError,
  StorageError,
  ZktvError,
} from '../errors';

describe('error hierarchy', () => {
  it('every subclass extends ZktvError and Error with a stable code', () => {
    const cases: Array<[ZktvError, string]> = [
      [new PrfUnsupportedError(), 'PRF_UNSUPPORTED'],
      [new CeremonyCancelledError(), 'CEREMONY_CANCELLED'],
      [new PrfResultMissingError(), 'PRF_RESULT_MISSING'],
      [new ReplayError('challenge mismatch'), 'REPLAY'],
      [new DecryptError(), 'DECRYPT_FAILED'],
      [new RecordFormatError('bad'), 'RECORD_FORMAT'],
      [new StorageError('idb'), 'STORAGE'],
    ];
    for (const [err, code] of cases) {
      expect(err).toBeInstanceOf(ZktvError);
      expect(err).toBeInstanceOf(Error);
      expect(err.code).toBe(code);
      expect(err.name).toBe(err.constructor.name);
    }
  });

  it('DecryptError message is generic (no wrong-key vs corrupt-data oracle)', () => {
    expect(new DecryptError().message).toBe('Failed to decrypt record');
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/__tests__/errors.test.ts`
Expected: FAIL — "Cannot find module '../errors'".

- [ ] **Step 3: Implement `src/errors.ts`**

```ts
export type ZktvErrorCode =
  | 'PRF_UNSUPPORTED'
  | 'CEREMONY_CANCELLED'
  | 'PRF_RESULT_MISSING'
  | 'REPLAY'
  | 'DECRYPT_FAILED'
  | 'RECORD_FORMAT'
  | 'STORAGE';

export class ZktvError extends Error {
  readonly code: ZktvErrorCode;
  constructor(code: ZktvErrorCode, message: string) {
    super(message);
    this.name = new.target.name;
    this.code = code;
  }
}

export class PrfUnsupportedError extends ZktvError {
  constructor(message = 'The WebAuthn PRF extension is not supported here.') {
    super('PRF_UNSUPPORTED', message);
  }
}

export class CeremonyCancelledError extends ZktvError {
  constructor(message = 'The authentication ceremony was cancelled or timed out.') {
    super('CEREMONY_CANCELLED', message);
  }
}

export class PrfResultMissingError extends ZktvError {
  constructor(message = 'The authenticator did not return a valid PRF result.') {
    super('PRF_RESULT_MISSING', message);
  }
}

export class ReplayError extends ZktvError {
  constructor(message: string) {
    super('REPLAY', message);
  }
}

/** Generic by design: never distinguishes wrong key from corrupt data. */
export class DecryptError extends ZktvError {
  constructor() {
    super('DECRYPT_FAILED', 'Failed to decrypt record');
  }
}

export class RecordFormatError extends ZktvError {
  constructor(message: string) {
    super('RECORD_FORMAT', message);
  }
}

export class StorageError extends ZktvError {
  constructor(message: string) {
    super('STORAGE', message);
  }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run src/__tests__/errors.test.ts`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add src/errors.ts src/__tests__/errors.test.ts
git commit -m "feat: typed ZktvError hierarchy with stable codes"
```

---

### Task 4: Core types + record serialization

**Files:**
- Create: `src/core/types.ts`, `src/core/serialize.ts`
- Test: `src/core/__tests__/serialize.test.ts`

**Interfaces:**
- Consumes: `toBase64Url`/`fromBase64Url` (Task 2), `RecordFormatError` (Task 3).
- Produces:
  ```ts
  type WrapScheme = 'prf-v1' | 'pw-v1';
  interface ScryptParams { N: number; r: number; p: number }
  interface WrappedSecretRecord {
    scheme: WrapScheme;
    ciphertext: Uint8Array;
    nonce: Uint8Array;      // 12 bytes
    salt: Uint8Array;       // ≥16 bytes (32 default)
    kdfParams?: ScryptParams; // present iff scheme === 'pw-v1'
  }
  serializeRecord(record: WrappedSecretRecord): string
  parseRecord(json: string): WrappedSecretRecord
  ```

- [ ] **Step 1: Write the failing tests**

`src/core/__tests__/serialize.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { parseRecord, serializeRecord } from '../serialize';
import type { WrappedSecretRecord } from '../types';
import { RecordFormatError } from '../../errors';

const prfRecord: WrappedSecretRecord = {
  scheme: 'prf-v1',
  ciphertext: new Uint8Array(48).fill(1),
  nonce: new Uint8Array(12).fill(2),
  salt: new Uint8Array(32).fill(3),
};

const pwRecord: WrappedSecretRecord = {
  scheme: 'pw-v1',
  ciphertext: new Uint8Array(48).fill(4),
  nonce: new Uint8Array(12).fill(5),
  salt: new Uint8Array(32).fill(6),
  kdfParams: { N: 131072, r: 8, p: 1 },
};

describe('serializeRecord / parseRecord', () => {
  it('round-trips prf-v1 and pw-v1 records', () => {
    expect(parseRecord(serializeRecord(prfRecord))).toEqual(prfRecord);
    expect(parseRecord(serializeRecord(pwRecord))).toEqual(pwRecord);
  });

  it('emits versioned JSON with base64url fields', () => {
    const parsed = JSON.parse(serializeRecord(prfRecord)) as Record<string, unknown>;
    expect(parsed.v).toBe(1);
    expect(typeof parsed.ciphertext).toBe('string');
    expect(parsed.ciphertext).not.toMatch(/[+/=]/);
  });

  it.each([
    ['not json', 'not-json{{{'],
    ['wrong version', JSON.stringify({ v: 2, scheme: 'prf-v1', ciphertext: 'AA', nonce: 'AA', salt: 'AA' })],
    ['unknown scheme', JSON.stringify({ v: 1, scheme: 'device-key', ciphertext: 'AA', nonce: 'AA', salt: 'AA' })],
    ['missing field', JSON.stringify({ v: 1, scheme: 'prf-v1', nonce: 'AA', salt: 'AA' })],
    ['non-string field', JSON.stringify({ v: 1, scheme: 'prf-v1', ciphertext: 7, nonce: 'AA', salt: 'AA' })],
  ])('rejects hostile input: %s', (_label, json) => {
    expect(() => parseRecord(json)).toThrow(RecordFormatError);
  });

  it('rejects wrong nonce length, short salt, tag-less ciphertext', () => {
    const bad = (patch: Partial<WrappedSecretRecord>) =>
      serializeRecord({ ...prfRecord, ...patch });
    expect(() => parseRecord(bad({ nonce: new Uint8Array(11) }))).toThrow(RecordFormatError);
    expect(() => parseRecord(bad({ salt: new Uint8Array(8) }))).toThrow(RecordFormatError);
    expect(() => parseRecord(bad({ ciphertext: new Uint8Array(16) }))).toThrow(RecordFormatError);
  });

  it('rejects pw-v1 without kdfParams and prf-v1 with kdfParams', () => {
    const noParams = JSON.parse(serializeRecord(pwRecord)) as Record<string, unknown>;
    delete noParams.kdfParams;
    expect(() => parseRecord(JSON.stringify(noParams))).toThrow(RecordFormatError);

    const extraParams = JSON.parse(serializeRecord(prfRecord)) as Record<string, unknown>;
    extraParams.kdfParams = { N: 2, r: 1, p: 1 };
    expect(() => parseRecord(JSON.stringify(extraParams))).toThrow(RecordFormatError);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/core`
Expected: FAIL — "Cannot find module '../serialize'".

- [ ] **Step 3: Implement**

`src/core/types.ts`:
```ts
export type WrapScheme = 'prf-v1' | 'pw-v1';

export interface ScryptParams {
  N: number;
  r: number;
  p: number;
}

/**
 * The ONLY shape this package ever persists. In-memory key material
 * (CryptoKey, PRF output) has no serializable representation on purpose.
 */
export interface WrappedSecretRecord {
  scheme: WrapScheme;
  /** AES-256-GCM output, auth tag included. */
  ciphertext: Uint8Array;
  /** 96-bit random IV, unique per wrap. */
  nonce: Uint8Array;
  /** PRF salt (prf-v1) or scrypt salt (pw-v1). */
  salt: Uint8Array;
  /** Present iff scheme === 'pw-v1'. */
  kdfParams?: ScryptParams;
}

export const NONCE_LENGTH = 12;
export const MIN_SALT_LENGTH = 16;
export const GCM_TAG_LENGTH = 16;
```

`src/core/serialize.ts`:
```ts
import { fromBase64Url, toBase64Url } from '../utils/base64';
import { RecordFormatError } from '../errors';
import {
  GCM_TAG_LENGTH,
  MIN_SALT_LENGTH,
  NONCE_LENGTH,
  type ScryptParams,
  type WrappedSecretRecord,
} from './types';

interface SerializedRecordV1 {
  v: 1;
  scheme: string;
  ciphertext: string;
  nonce: string;
  salt: string;
  kdfParams?: ScryptParams;
}

export function serializeRecord(record: WrappedSecretRecord): string {
  const out: SerializedRecordV1 = {
    v: 1,
    scheme: record.scheme,
    ciphertext: toBase64Url(record.ciphertext),
    nonce: toBase64Url(record.nonce),
    salt: toBase64Url(record.salt),
    ...(record.kdfParams ? { kdfParams: record.kdfParams } : {}),
  };
  return JSON.stringify(out);
}

export function parseRecord(json: string): WrappedSecretRecord {
  let raw: unknown;
  try {
    raw = JSON.parse(json);
  } catch {
    throw new RecordFormatError('Record is not valid JSON');
  }
  if (typeof raw !== 'object' || raw === null) {
    throw new RecordFormatError('Record is not a JSON object');
  }
  const obj = raw as Record<string, unknown>;
  if (obj.v !== 1) throw new RecordFormatError('Unsupported record version');
  if (obj.scheme !== 'prf-v1' && obj.scheme !== 'pw-v1') {
    throw new RecordFormatError('Unknown wrap scheme');
  }
  const ciphertext = decodeField(obj, 'ciphertext');
  const nonce = decodeField(obj, 'nonce');
  const salt = decodeField(obj, 'salt');
  if (nonce.length !== NONCE_LENGTH) throw new RecordFormatError('Invalid nonce length');
  if (salt.length < MIN_SALT_LENGTH) throw new RecordFormatError('Salt too short');
  if (ciphertext.length <= GCM_TAG_LENGTH) throw new RecordFormatError('Ciphertext too short');

  if (obj.scheme === 'pw-v1') {
    const kdfParams = parseKdfParams(obj.kdfParams);
    return { scheme: 'pw-v1', ciphertext, nonce, salt, kdfParams };
  }
  if (obj.kdfParams !== undefined) {
    throw new RecordFormatError('prf-v1 records must not carry kdfParams');
  }
  return { scheme: 'prf-v1', ciphertext, nonce, salt };
}

function decodeField(obj: Record<string, unknown>, field: string): Uint8Array {
  const value = obj[field];
  if (typeof value !== 'string') {
    throw new RecordFormatError(`Missing or non-string field: ${field}`);
  }
  try {
    return fromBase64Url(value);
  } catch {
    throw new RecordFormatError(`Field is not valid base64url: ${field}`);
  }
}

function parseKdfParams(value: unknown): ScryptParams {
  if (typeof value !== 'object' || value === null) {
    throw new RecordFormatError('pw-v1 records require kdfParams');
  }
  const { N, r, p } = value as Record<string, unknown>;
  for (const [name, candidate] of Object.entries({ N, r, p })) {
    if (typeof candidate !== 'number' || !Number.isInteger(candidate) || candidate <= 0) {
      throw new RecordFormatError(`kdfParams.${name} must be a positive integer`);
    }
  }
  return { N: N as number, r: r as number, p: p as number };
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run src/core`
Expected: PASS (all serialize tests).

- [ ] **Step 5: Commit**

```bash
git add src/core
git commit -m "feat: WrappedSecretRecord types + strict versioned serialization"
```

---

### Task 5: HKDF wrap-key derivation from PRF output

**Files:**
- Create: `src/core/derive.ts` (PRF half)
- Test: `src/core/__tests__/derive.test.ts`

**Interfaces:**
- Produces:
  ```ts
  const HKDF_INFO_V1: Uint8Array; // TextEncoder bytes of 'webauthn-prf-zktv vault key wrap v1'
  deriveWrapKeyFromPrf(prfOutput: Uint8Array, info?: Uint8Array): Promise<CryptoKey>
  ```
  Non-extractable AES-GCM-256 `['encrypt','decrypt']` key.

- [ ] **Step 1: Write the failing tests**

`src/core/__tests__/derive.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { deriveWrapKeyFromPrf, HKDF_INFO_V1 } from '../derive';

const prfOutput = new Uint8Array(32).fill(7);

async function roundTrip(encKey: CryptoKey, decKey: CryptoKey): Promise<boolean> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, encKey, new Uint8Array([1, 2, 3]));
  try {
    await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, decKey, ct);
    return true;
  } catch {
    return false;
  }
}

describe('deriveWrapKeyFromPrf', () => {
  it('returns a non-extractable AES-GCM-256 key', async () => {
    const key = await deriveWrapKeyFromPrf(prfOutput);
    expect(key.extractable).toBe(false);
    expect(key.algorithm).toMatchObject({ name: 'AES-GCM', length: 256 });
    expect(key.usages).toEqual(expect.arrayContaining(['encrypt', 'decrypt']));
  });

  it('is deterministic: same PRF output derives interoperable keys', async () => {
    const a = await deriveWrapKeyFromPrf(prfOutput);
    const b = await deriveWrapKeyFromPrf(new Uint8Array(prfOutput));
    expect(await roundTrip(a, b)).toBe(true);
  });

  it('different PRF outputs derive non-interoperable keys', async () => {
    const a = await deriveWrapKeyFromPrf(prfOutput);
    const b = await deriveWrapKeyFromPrf(new Uint8Array(32).fill(8));
    expect(await roundTrip(a, b)).toBe(false);
  });

  it('different HKDF info labels derive non-interoperable keys (domain separation)', async () => {
    const a = await deriveWrapKeyFromPrf(prfOutput, HKDF_INFO_V1);
    const b = await deriveWrapKeyFromPrf(prfOutput, new TextEncoder().encode('other label'));
    expect(await roundTrip(a, b)).toBe(false);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/core/__tests__/derive.test.ts`
Expected: FAIL — "Cannot find module '../derive'".

- [ ] **Step 3: Implement `src/core/derive.ts`**

```ts
/** Domain-separation label — binds derived keys to this exact purpose. */
export const HKDF_INFO_V1: Uint8Array = new TextEncoder().encode(
  'webauthn-prf-zktv vault key wrap v1',
);

/**
 * HKDF-SHA256(prfOutput) → non-extractable AES-256-GCM wrap key.
 * The PRF output is Input Keying Material — never used as a key directly.
 * HKDF salt is empty (RFC 5869: valid, treated as zeros); per-credential
 * domain separation comes from the unique PRF salt → unique IKM.
 */
export async function deriveWrapKeyFromPrf(
  prfOutput: Uint8Array,
  info: Uint8Array = HKDF_INFO_V1,
): Promise<CryptoKey> {
  const ikm = await crypto.subtle.importKey('raw', prfOutput as BufferSource, 'HKDF', false, [
    'deriveKey',
  ]);
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0) as BufferSource,
      info: info as BufferSource,
    },
    ikm,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run src/core/__tests__/derive.test.ts`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add src/core/derive.ts src/core/__tests__/derive.test.ts
git commit -m "feat: HKDF-SHA256 wrap-key derivation from PRF output"
```

---

### Task 6: scrypt wrap-key derivation from password

**Files:**
- Modify: `src/core/derive.ts` (append)
- Test: `src/core/__tests__/derive.test.ts` (append)

**Interfaces:**
- Consumes: `ScryptParams` (Task 4).
- Produces:
  ```ts
  const DEFAULT_SCRYPT_PARAMS: ScryptParams; // { N: 131072, r: 8, p: 1 }
  deriveWrapKeyFromPassword(password: string, salt: Uint8Array, params?: ScryptParams): Promise<CryptoKey>
  ```

- [ ] **Step 1: Write the failing tests (append to `derive.test.ts`)**

```ts
import { DEFAULT_SCRYPT_PARAMS, deriveWrapKeyFromPassword } from '../derive';

// Small params for test speed — production default is N=131072.
const fastParams = { N: 1024, r: 8, p: 1 };
const salt = new Uint8Array(32).fill(9);

describe('deriveWrapKeyFromPassword', () => {
  it('exposes TrustVault Finding-3 scrypt defaults', () => {
    expect(DEFAULT_SCRYPT_PARAMS).toEqual({ N: 131072, r: 8, p: 1 });
  });

  it('returns a deterministic non-extractable AES-GCM key', async () => {
    const a = await deriveWrapKeyFromPassword('correct horse', salt, fastParams);
    const b = await deriveWrapKeyFromPassword('correct horse', salt, fastParams);
    expect(a.extractable).toBe(false);
    expect(await roundTrip(a, b)).toBe(true);
  });

  it('wrong password or different salt derives non-interoperable keys', async () => {
    const good = await deriveWrapKeyFromPassword('correct horse', salt, fastParams);
    const wrongPw = await deriveWrapKeyFromPassword('wrong horse', salt, fastParams);
    const wrongSalt = await deriveWrapKeyFromPassword('correct horse', new Uint8Array(32), fastParams);
    expect(await roundTrip(good, wrongPw)).toBe(false);
    expect(await roundTrip(good, wrongSalt)).toBe(false);
  });
});
```

- [ ] **Step 2: Run tests to verify the new ones fail**

Run: `npx vitest run src/core/__tests__/derive.test.ts`
Expected: FAIL — `deriveWrapKeyFromPassword` is not exported.

- [ ] **Step 3: Implement (append to `src/core/derive.ts`)**

```ts
import { scrypt } from '@noble/hashes/scrypt';
import type { ScryptParams } from './types';

/** TrustVault Finding 3 (2026-06-11): memory-hard scrypt, not PBKDF2, bounds offline guessing. */
export const DEFAULT_SCRYPT_PARAMS: ScryptParams = { N: 131072, r: 8, p: 1 };

export async function deriveWrapKeyFromPassword(
  password: string,
  salt: Uint8Array,
  params: ScryptParams = DEFAULT_SCRYPT_PARAMS,
): Promise<CryptoKey> {
  const derived = scrypt(password, salt, { ...params, dkLen: 32 });
  try {
    return await crypto.subtle.importKey('raw', derived as BufferSource, { name: 'AES-GCM' }, false, [
      'encrypt',
      'decrypt',
    ]);
  } finally {
    derived.fill(0); // zeroize transient key bytes after non-extractable import
  }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run src/core/__tests__/derive.test.ts`
Expected: PASS (7 tests).

- [ ] **Step 5: Commit**

```bash
git add src/core/derive.ts src/core/__tests__/derive.test.ts
git commit -m "feat: scrypt wrap-key derivation for pw-v1 fallback scheme"
```

---

### Task 7: wrapSecret / unwrapSecret / unwrapSecretBytes

**Files:**
- Create: `src/core/wrap.ts`
- Modify: `src/index.ts` (export core API)
- Test: `src/core/__tests__/wrap.test.ts`

**Interfaces:**
- Consumes: `deriveWrapKeyFromPrf`, `deriveWrapKeyFromPassword`, `DEFAULT_SCRYPT_PARAMS` (Tasks 5–6), types (Task 4), `generateSalt` (Task 2), `DecryptError`/`RecordFormatError` (Task 3).
- Produces:
  ```ts
  type WrapOptions =
    | { prfOutput: Uint8Array; prfSalt: Uint8Array; secret: Uint8Array }
    | { password: string; secret: Uint8Array; salt?: Uint8Array; kdfParams?: ScryptParams }
    | { wrapKey: CryptoKey; scheme: 'prf-v1'; salt: Uint8Array; secret: Uint8Array };
  type UnwrapOptions =
    | { record: WrappedSecretRecord; prfOutput: Uint8Array }
    | { record: WrappedSecretRecord; password: string }
    | { record: WrappedSecretRecord; wrapKey: CryptoKey };
  wrapSecret(options: WrapOptions): Promise<WrappedSecretRecord>
  unwrapSecretBytes(options: UnwrapOptions): Promise<Uint8Array>   // caller MUST zeroize
  unwrapSecret(options: UnwrapOptions): Promise<CryptoKey>         // secret must be 32 bytes
  ```

- [ ] **Step 1: Write the failing tests**

`src/core/__tests__/wrap.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { unwrapSecret, unwrapSecretBytes, wrapSecret } from '../wrap';
import { DecryptError, RecordFormatError } from '../../errors';

const prfOutput = new Uint8Array(32).fill(7);
const prfSalt = new Uint8Array(32).fill(3);
const secret = new Uint8Array(32).fill(42); // a 32-byte vault key
const fastKdf = { N: 1024, r: 8, p: 1 };

describe('prf-v1 wrap/unwrap', () => {
  it('round-trips and returns a non-extractable session key', async () => {
    const record = await wrapSecret({ prfOutput, prfSalt, secret });
    expect(record.scheme).toBe('prf-v1');
    expect(record.salt).toEqual(prfSalt);
    expect(record.kdfParams).toBeUndefined();
    const key = await unwrapSecret({ record, prfOutput });
    expect(key.extractable).toBe(false);
  });

  it('unwrapSecretBytes returns the original secret', async () => {
    const record = await wrapSecret({ prfOutput, prfSalt, secret });
    expect(await unwrapSecretBytes({ record, prfOutput })).toEqual(secret);
  });

  it('wrong PRF output throws generic DecryptError', async () => {
    const record = await wrapSecret({ prfOutput, prfSalt, secret });
    await expect(
      unwrapSecret({ record, prfOutput: new Uint8Array(32).fill(8) }),
    ).rejects.toThrow(DecryptError);
  });

  it('nonces are unique across wraps of the same secret', async () => {
    const a = await wrapSecret({ prfOutput, prfSalt, secret });
    const b = await wrapSecret({ prfOutput, prfSalt, secret });
    expect(a.nonce).not.toEqual(b.nonce);
    expect(a.ciphertext).not.toEqual(b.ciphertext);
  });
});

describe('pw-v1 wrap/unwrap', () => {
  it('round-trips, generating salt and recording kdfParams', async () => {
    const record = await wrapSecret({ password: 'hunter2!', secret, kdfParams: fastKdf });
    expect(record.scheme).toBe('pw-v1');
    expect(record.salt).toHaveLength(32);
    expect(record.kdfParams).toEqual(fastKdf);
    expect(await unwrapSecretBytes({ record, password: 'hunter2!' })).toEqual(secret);
  });

  it('wrong password throws generic DecryptError', async () => {
    const record = await wrapSecret({ password: 'hunter2!', secret, kdfParams: fastKdf });
    await expect(unwrapSecret({ record, password: 'wrong' })).rejects.toThrow(DecryptError);
  });
});

describe('scheme/source mismatch and size guards', () => {
  it('rejects PRF unwrap of a pw-v1 record and vice versa', async () => {
    const pw = await wrapSecret({ password: 'x', secret, kdfParams: fastKdf });
    const prf = await wrapSecret({ prfOutput, prfSalt, secret });
    await expect(unwrapSecret({ record: pw, prfOutput })).rejects.toThrow(RecordFormatError);
    await expect(unwrapSecret({ record: prf, password: 'x' })).rejects.toThrow(RecordFormatError);
  });

  it('unwrapSecret rejects non-32-byte secrets (use unwrapSecretBytes)', async () => {
    const record = await wrapSecret({ prfOutput, prfSalt, secret: new Uint8Array(5) });
    await expect(unwrapSecret({ record, prfOutput })).rejects.toThrow(RecordFormatError);
    expect(await unwrapSecretBytes({ record, prfOutput })).toEqual(new Uint8Array(5));
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/core/__tests__/wrap.test.ts`
Expected: FAIL — "Cannot find module '../wrap'".

- [ ] **Step 3: Implement `src/core/wrap.ts`**

```ts
import { DecryptError, RecordFormatError } from '../errors';
import { generateSalt } from '../utils/random';
import {
  DEFAULT_SCRYPT_PARAMS,
  deriveWrapKeyFromPassword,
  deriveWrapKeyFromPrf,
} from './derive';
import { NONCE_LENGTH, type ScryptParams, type WrapScheme, type WrappedSecretRecord } from './types';

export type WrapOptions =
  | { prfOutput: Uint8Array; prfSalt: Uint8Array; secret: Uint8Array }
  | { password: string; secret: Uint8Array; salt?: Uint8Array; kdfParams?: ScryptParams }
  | { wrapKey: CryptoKey; scheme: 'prf-v1'; salt: Uint8Array; secret: Uint8Array };

export type UnwrapOptions =
  | { record: WrappedSecretRecord; prfOutput: Uint8Array }
  | { record: WrappedSecretRecord; password: string }
  | { record: WrappedSecretRecord; wrapKey: CryptoKey };

export async function wrapSecret(options: WrapOptions): Promise<WrappedSecretRecord> {
  if ('prfOutput' in options) {
    const wrapKey = await deriveWrapKeyFromPrf(options.prfOutput);
    return encryptRecord(wrapKey, 'prf-v1', options.prfSalt, options.secret);
  }
  if ('password' in options) {
    const salt = options.salt ?? generateSalt();
    const kdfParams = options.kdfParams ?? DEFAULT_SCRYPT_PARAMS;
    const wrapKey = await deriveWrapKeyFromPassword(options.password, salt, kdfParams);
    const record = await encryptRecord(wrapKey, 'pw-v1', salt, options.secret);
    return { ...record, kdfParams };
  }
  return encryptRecord(options.wrapKey, options.scheme, options.salt, options.secret);
}

/**
 * Decrypts a record to raw bytes. The CALLER owns the returned buffer and
 * MUST zeroize() it when done. Prefer unwrapSecret() which never exposes bytes.
 */
export async function unwrapSecretBytes(options: UnwrapOptions): Promise<Uint8Array> {
  const { record } = options;
  let wrapKey: CryptoKey;
  if ('prfOutput' in options) {
    assertScheme(record, 'prf-v1', 'a PRF output');
    wrapKey = await deriveWrapKeyFromPrf(options.prfOutput);
  } else if ('password' in options) {
    assertScheme(record, 'pw-v1', 'a password');
    wrapKey = await deriveWrapKeyFromPassword(
      options.password,
      record.salt,
      record.kdfParams ?? DEFAULT_SCRYPT_PARAMS,
    );
  } else {
    wrapKey = options.wrapKey;
  }
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: record.nonce as BufferSource },
      wrapKey,
      record.ciphertext as BufferSource,
    );
    return new Uint8Array(plaintext);
  } catch {
    // Generic by invariant: never disclose wrong-key vs corrupt-data; never log the cause.
    throw new DecryptError();
  }
}

/**
 * Decrypts a wrapped 32-byte key and imports it as a NON-extractable
 * AES-256-GCM session key. Transient raw bytes are zeroized in finally.
 */
export async function unwrapSecret(options: UnwrapOptions): Promise<CryptoKey> {
  const bytes = await unwrapSecretBytes(options);
  try {
    if (bytes.length !== 32) {
      throw new RecordFormatError(
        'unwrapSecret requires a 32-byte wrapped secret (an AES-256 key); use unwrapSecretBytes for other payloads',
      );
    }
    return await crypto.subtle.importKey(
      'raw',
      bytes as BufferSource,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
  } finally {
    bytes.fill(0);
  }
}

async function encryptRecord(
  wrapKey: CryptoKey,
  scheme: WrapScheme,
  salt: Uint8Array,
  secret: Uint8Array,
): Promise<WrappedSecretRecord> {
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LENGTH));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce as BufferSource },
      wrapKey,
      secret as BufferSource,
    ),
  );
  return { scheme, ciphertext, nonce, salt: new Uint8Array(salt) };
}

function assertScheme(record: WrappedSecretRecord, expected: WrapScheme, source: string): void {
  if (record.scheme !== expected) {
    throw new RecordFormatError(
      `Record scheme '${record.scheme}' cannot be unwrapped with ${source}`,
    );
  }
}
```

- [ ] **Step 4: Update `src/index.ts` to the real core surface**

```ts
export {
  DEFAULT_SCRYPT_PARAMS,
  HKDF_INFO_V1,
  deriveWrapKeyFromPassword,
  deriveWrapKeyFromPrf,
} from './core/derive';
export { unwrapSecret, unwrapSecretBytes, wrapSecret } from './core/wrap';
export type { UnwrapOptions, WrapOptions } from './core/wrap';
export { parseRecord, serializeRecord } from './core/serialize';
export type { ScryptParams, WrapScheme, WrappedSecretRecord } from './core/types';
export {
  CeremonyCancelledError,
  DecryptError,
  PrfResultMissingError,
  PrfUnsupportedError,
  RecordFormatError,
  ReplayError,
  StorageError,
  ZktvError,
} from './errors';
export type { ZktvErrorCode } from './errors';
export { generateSalt } from './utils/random';
export { zeroize } from './utils/zeroize';
```

- [ ] **Step 5: Run all tests + type-check**

Run: `npx vitest run && npm run type-check`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/core src/index.ts
git commit -m "feat: wrapSecret/unwrapSecret core with prf-v1 and pw-v1 schemes"
```

---

### Task 8: TrustVault legacy migration adapter

**Files:**
- Create: `src/core/trustvault.ts`
- Modify: `src/index.ts` (add export)
- Test: `src/core/__tests__/trustvault.test.ts`

**Interfaces:**
- Consumes: `deriveWrapKeyFromPrf` (Task 5), `wrapSecret` (Task 7), `fromBase64`/`toBase64` (Task 2), errors (Task 3).
- Produces:
  ```ts
  const TRUSTVAULT_HKDF_INFO: Uint8Array; // bytes of 'TrustVault Vault Key Wrapping v1'
  fromTrustVaultRecord(options: {
    legacyJson: string;     // TrustVault EncryptedData JSON: { ciphertext, iv } base64
    prfOutput: Uint8Array;  // from the SAME credential + prfSalt
    prfSalt: Uint8Array;    // the credential's stored prfSalt
  }): Promise<WrappedSecretRecord>
  ```

- [ ] **Step 1: Write the failing tests**

`src/core/__tests__/trustvault.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { fromTrustVaultRecord, TRUSTVAULT_HKDF_INFO } from '../trustvault';
import { deriveWrapKeyFromPrf } from '../derive';
import { unwrapSecretBytes } from '../wrap';
import { toBase64 } from '../../utils/base64';
import { DecryptError, RecordFormatError } from '../../errors';

const prfOutput = new Uint8Array(32).fill(7);
const prfSalt = new Uint8Array(32).fill(3);
const vaultKeyRaw = new Uint8Array(32).fill(42);

/** Fixture generator mirroring TrustVault's wrapVaultKeyWithPRF exactly:
 *  AES-GCM( base64(vaultKeyRaw) as UTF-8 ) under HKDF(prfOutput, legacy info),
 *  serialized as EncryptedData JSON with standard-base64 fields. */
async function makeLegacyRecord(): Promise<string> {
  const legacyKey = await deriveWrapKeyFromPrf(prfOutput, TRUSTVAULT_HKDF_INFO);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(toBase64(vaultKeyRaw));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, legacyKey, plaintext),
  );
  return JSON.stringify({ ciphertext: toBase64(ct), iv: toBase64(iv) });
}

describe('fromTrustVaultRecord', () => {
  it('re-wraps a legacy TrustVault record into a v1 prf-v1 record holding the same key', async () => {
    const legacyJson = await makeLegacyRecord();
    const record = await fromTrustVaultRecord({ legacyJson, prfOutput, prfSalt });
    expect(record.scheme).toBe('prf-v1');
    expect(record.salt).toEqual(prfSalt);
    expect(await unwrapSecretBytes({ record, prfOutput })).toEqual(vaultKeyRaw);
  });

  it('throws DecryptError on wrong PRF output', async () => {
    const legacyJson = await makeLegacyRecord();
    await expect(
      fromTrustVaultRecord({ legacyJson, prfOutput: new Uint8Array(32).fill(9), prfSalt }),
    ).rejects.toThrow(DecryptError);
  });

  it('throws RecordFormatError on malformed legacy JSON', async () => {
    await expect(
      fromTrustVaultRecord({ legacyJson: '{"nope":1}', prfOutput, prfSalt }),
    ).rejects.toThrow(RecordFormatError);
    await expect(
      fromTrustVaultRecord({ legacyJson: 'not json', prfOutput, prfSalt }),
    ).rejects.toThrow(RecordFormatError);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/core/__tests__/trustvault.test.ts`
Expected: FAIL — "Cannot find module '../trustvault'".

- [ ] **Step 3: Implement `src/core/trustvault.ts`**

```ts
import { DecryptError, RecordFormatError } from '../errors';
import { fromBase64 } from '../utils/base64';
import { deriveWrapKeyFromPrf } from './derive';
import { wrapSecret } from './wrap';
import type { WrappedSecretRecord } from './types';

/** TrustVault-PWA's legacy HKDF domain-separation label (verbatim). */
export const TRUSTVAULT_HKDF_INFO: Uint8Array = new TextEncoder().encode(
  'TrustVault Vault Key Wrapping v1',
);

interface TrustVaultEncryptedData {
  ciphertext: string; // standard base64
  iv: string; // standard base64
}

export interface FromTrustVaultOptions {
  /** TrustVault WebAuthnCredential.wrappedVaultKey JSON string. */
  legacyJson: string;
  /** PRF output evaluated with the credential's stored prfSalt. */
  prfOutput: Uint8Array;
  /** The credential's stored prfSalt (becomes the new record's salt). */
  prfSalt: Uint8Array;
}

/**
 * One-shot migration: unwraps a TrustVault legacy record under the legacy HKDF
 * label and re-wraps the same vault key under the webauthn-prf-zktv v1 format.
 * Same PRF output, new domain-separation label — no extra ceremony required.
 * All transient plaintext buffers are zeroized.
 */
export async function fromTrustVaultRecord(
  options: FromTrustVaultOptions,
): Promise<WrappedSecretRecord> {
  const legacy = parseLegacy(options.legacyJson);
  const legacyKey = await deriveWrapKeyFromPrf(options.prfOutput, TRUSTVAULT_HKDF_INFO);

  let plaintext: Uint8Array;
  try {
    plaintext = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: fromBase64(legacy.iv) as BufferSource },
        legacyKey,
        fromBase64(legacy.ciphertext) as BufferSource,
      ),
    );
  } catch {
    throw new DecryptError();
  }

  // Legacy plaintext is the base64 STRING of the raw vault key (TrustVault format).
  let raw: Uint8Array | null = null;
  try {
    raw = fromBase64(new TextDecoder().decode(plaintext));
    return await wrapSecret({
      prfOutput: options.prfOutput,
      prfSalt: options.prfSalt,
      secret: raw,
    });
  } catch (error) {
    if (error instanceof DecryptError || error instanceof RecordFormatError) throw error;
    throw new RecordFormatError('Legacy record plaintext is not a base64 vault key');
  } finally {
    plaintext.fill(0);
    raw?.fill(0);
  }
}

function parseLegacy(json: string): TrustVaultEncryptedData {
  let raw: unknown;
  try {
    raw = JSON.parse(json);
  } catch {
    throw new RecordFormatError('Legacy record is not valid JSON');
  }
  const obj = raw as Record<string, unknown>;
  if (typeof obj?.ciphertext !== 'string' || typeof obj?.iv !== 'string') {
    throw new RecordFormatError('Legacy record is not TrustVault EncryptedData');
  }
  return { ciphertext: obj.ciphertext, iv: obj.iv };
}
```

- [ ] **Step 4: Add export to `src/index.ts`**

```ts
export { fromTrustVaultRecord, TRUSTVAULT_HKDF_INFO } from './core/trustvault';
export type { FromTrustVaultOptions } from './core/trustvault';
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `npx vitest run src/core/__tests__/trustvault.test.ts && npm run type-check`
Expected: PASS (3 tests).

- [ ] **Step 6: Commit**

```bash
git add src/core/trustvault.ts src/core/__tests__/trustvault.test.ts src/index.ts
git commit -m "feat: TrustVault legacy record migration adapter"
```

---

### Task 9: WebAuthn support & viability detection

**Files:**
- Create: `src/webauthn/support.ts`
- Test: `src/webauthn/__tests__/support.test.ts`

**Interfaces:**
- Produces:
  ```ts
  isWebAuthnSupported(): boolean
  type PrfSupport = 'supported' | 'unsupported' | 'unknown';
  detectPrfSupport(): Promise<PrfSupport>
  interface PrfViability { viable: boolean; reason: string; environment: 'browser' | 'webview' }
  isPrfViableOnThisClient(): Promise<PrfViability>
  ```

- [ ] **Step 1: Write the failing tests**

`src/webauthn/__tests__/support.test.ts`:
```ts
import { afterEach, describe, expect, it, vi } from 'vitest';
import { detectPrfSupport, isPrfViableOnThisClient, isWebAuthnSupported } from '../support';

function stubBrowser(opts: {
  pkc?: object | undefined;
  userAgent?: string;
  platformAuthenticator?: boolean;
}): void {
  const pkc =
    opts.pkc === undefined
      ? undefined
      : Object.assign(function PublicKeyCredential() {}, {
          isUserVerifyingPlatformAuthenticatorAvailable: () =>
            Promise.resolve(opts.platformAuthenticator ?? true),
          ...opts.pkc,
        });
  vi.stubGlobal('window', pkc ? { PublicKeyCredential: pkc } : {});
  vi.stubGlobal('navigator', {
    userAgent:
      opts.userAgent ??
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/147.0',
  });
}

afterEach(() => vi.unstubAllGlobals());

describe('detectPrfSupport', () => {
  it("returns 'supported' when getClientCapabilities reports extension:prf", async () => {
    stubBrowser({ pkc: { getClientCapabilities: () => Promise.resolve({ 'extension:prf': true }) } });
    expect(await detectPrfSupport()).toBe('supported');
  });

  it("returns 'unsupported' when capabilities report prf false", async () => {
    stubBrowser({ pkc: { getClientCapabilities: () => Promise.resolve({ 'extension:prf': false }) } });
    expect(await detectPrfSupport()).toBe('unsupported');
  });

  it("returns 'unknown' when getClientCapabilities is absent or throws", async () => {
    stubBrowser({ pkc: {} });
    expect(await detectPrfSupport()).toBe('unknown');
    stubBrowser({ pkc: { getClientCapabilities: () => Promise.reject(new Error('nope')) } });
    expect(await detectPrfSupport()).toBe('unknown');
  });

  it("returns 'unsupported' when WebAuthn itself is absent", async () => {
    stubBrowser({ pkc: undefined });
    expect(isWebAuthnSupported()).toBe(false);
    expect(await detectPrfSupport()).toBe('unsupported');
  });
});

describe('isPrfViableOnThisClient', () => {
  it('flags Android WebView as non-viable with environment webview', async () => {
    stubBrowser({
      pkc: {},
      userAgent: 'Mozilla/5.0 (Linux; Android 14; wv) AppleWebKit/537.36 Chrome/147.0; wv)',
    });
    const result = await isPrfViableOnThisClient();
    expect(result.viable).toBe(false);
    expect(result.environment).toBe('webview');
  });

  it('non-viable when platform authenticator is unavailable', async () => {
    stubBrowser({ pkc: {}, platformAuthenticator: false });
    const result = await isPrfViableOnThisClient();
    expect(result).toMatchObject({ viable: false, environment: 'browser' });
  });

  it("viable with hard-verify caveat when support is 'unknown'", async () => {
    stubBrowser({ pkc: {} });
    const result = await isPrfViableOnThisClient();
    expect(result.viable).toBe(true);
    expect(result.reason).toMatch(/hard-verif/i);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/webauthn`
Expected: FAIL — "Cannot find module '../support'".

- [ ] **Step 3: Implement `src/webauthn/support.ts`**

```ts
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run src/webauthn`
Expected: PASS (7 tests).

- [ ] **Step 5: Commit**

```bash
git add src/webauthn
git commit -m "feat: PRF capability detection and client viability check"
```

---

### Task 10: Assertion verification + evaluatePrf

**Files:**
- Create: `src/webauthn/verify.ts`, `src/webauthn/prf-types.ts`, `src/webauthn/ceremonies.ts` (evaluatePrf half)
- Test: `src/webauthn/__tests__/verify.test.ts`, `src/webauthn/__tests__/evaluatePrf.test.ts`

**Interfaces:**
- Consumes: base64 utils (Task 2), errors (Task 3), `isWebAuthnSupported` (Task 9), `generateSalt` (Task 2).
- Produces:
  ```ts
  // verify.ts
  readCounter(authData: Uint8Array): number
  verifyAssertionResponse(args: {
    clientDataJSON: Uint8Array; authenticatorData: Uint8Array;
    expectedChallenge: string;   // base64url
    expectedOrigin: string; storedCounter: number;
  }): number   // throws ReplayError
  // ceremonies.ts
  const PRF_OUTPUT_LENGTH = 32;
  interface EvaluatePrfOptions { credentialId: string; salt: Uint8Array; rpId: string; storedCounter?: number; timeout?: number }
  interface PrfEvaluation { prfOutput: Uint8Array; counter: number }
  evaluatePrf(options: EvaluatePrfOptions): Promise<PrfEvaluation>
  ```

- [ ] **Step 1: Write the failing verify tests**

`src/webauthn/__tests__/verify.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { readCounter, verifyAssertionResponse } from '../verify';
import { ReplayError } from '../../errors';

function makeAuthData(counter: number): Uint8Array {
  const data = new Uint8Array(37);
  new DataView(data.buffer).setUint32(33, counter, false); // big-endian at bytes 33-36
  return data;
}

function makeClientData(overrides: Partial<Record<'type' | 'challenge' | 'origin', string>> = {}): Uint8Array {
  return new TextEncoder().encode(
    JSON.stringify({
      type: 'webauthn.get',
      challenge: 'expected-challenge',
      origin: 'https://example.com',
      ...overrides,
    }),
  );
}

const valid = {
  clientDataJSON: makeClientData(),
  authenticatorData: makeAuthData(5),
  expectedChallenge: 'expected-challenge',
  expectedOrigin: 'https://example.com',
  storedCounter: 4,
};

describe('readCounter', () => {
  it('reads big-endian counter at bytes 33-36 including high-bit values', () => {
    expect(readCounter(makeAuthData(5))).toBe(5);
    expect(readCounter(makeAuthData(0x80000001))).toBe(0x80000001);
  });
});

describe('verifyAssertionResponse', () => {
  it('returns the new counter on valid input', () => {
    expect(verifyAssertionResponse(valid)).toBe(5);
  });

  it('throws ReplayError on challenge mismatch', () => {
    expect(() =>
      verifyAssertionResponse({ ...valid, clientDataJSON: makeClientData({ challenge: 'evil' }) }),
    ).toThrow(ReplayError);
  });

  it('throws ReplayError on origin mismatch and wrong type', () => {
    expect(() =>
      verifyAssertionResponse({ ...valid, clientDataJSON: makeClientData({ origin: 'https://evil.com' }) }),
    ).toThrow(ReplayError);
    expect(() =>
      verifyAssertionResponse({ ...valid, clientDataJSON: makeClientData({ type: 'webauthn.create' }) }),
    ).toThrow(ReplayError);
  });

  it('throws ReplayError when counter does not increase (cloned authenticator)', () => {
    expect(() =>
      verifyAssertionResponse({ ...valid, authenticatorData: makeAuthData(4) }),
    ).toThrow(ReplayError);
    expect(() =>
      verifyAssertionResponse({ ...valid, authenticatorData: makeAuthData(3) }),
    ).toThrow(ReplayError);
  });

  it('permits zero counters (authenticators that never increment)', () => {
    expect(verifyAssertionResponse({ ...valid, authenticatorData: makeAuthData(0) })).toBe(0);
  });

  it('permits any counter when storedCounter is -1 (enrollment)', () => {
    expect(verifyAssertionResponse({ ...valid, storedCounter: -1 })).toBe(5);
  });

  it('throws ReplayError on truncated authenticator data', () => {
    expect(() =>
      verifyAssertionResponse({ ...valid, authenticatorData: new Uint8Array(10) }),
    ).toThrow(ReplayError);
  });
});
```

- [ ] **Step 2: Run verify tests to see them fail**

Run: `npx vitest run src/webauthn/__tests__/verify.test.ts`
Expected: FAIL — "Cannot find module '../verify'".

- [ ] **Step 3: Implement `src/webauthn/verify.ts` and `src/webauthn/prf-types.ts`**

`src/webauthn/verify.ts`:
```ts
import { ReplayError } from '../errors';

/** Big-endian signature counter at authenticatorData bytes 33-36. */
export function readCounter(authData: Uint8Array): number {
  return (
    (((authData[33] ?? 0) << 24) |
      ((authData[34] ?? 0) << 16) |
      ((authData[35] ?? 0) << 8) |
      (authData[36] ?? 0)) >>>
    0
  );
}

export interface VerifyAssertionArgs {
  clientDataJSON: Uint8Array;
  authenticatorData: Uint8Array;
  /** base64url-encoded challenge we generated for this ceremony. */
  expectedChallenge: string;
  expectedOrigin: string;
  /** Pass -1 to skip the increase check (brand-new credential at enrollment). */
  storedCounter: number;
}

/** Replay protection: type/challenge/origin/counter. Throws ReplayError. */
export function verifyAssertionResponse(args: VerifyAssertionArgs): number {
  let clientData: { type?: unknown; challenge?: unknown; origin?: unknown };
  try {
    clientData = JSON.parse(new TextDecoder().decode(args.clientDataJSON)) as typeof clientData;
  } catch {
    throw new ReplayError('Client data is not valid JSON');
  }
  if (clientData.type !== 'webauthn.get') {
    throw new ReplayError('Unexpected client data type');
  }
  if (clientData.challenge !== args.expectedChallenge) {
    throw new ReplayError('Challenge mismatch — possible replay attack');
  }
  if (clientData.origin !== args.expectedOrigin) {
    throw new ReplayError('Origin mismatch');
  }
  if (args.authenticatorData.length < 37) {
    throw new ReplayError('Authenticator data too short');
  }
  const counter = readCounter(args.authenticatorData);
  if (counter <= args.storedCounter && counter !== 0) {
    throw new ReplayError('Signature counter did not increase — possible cloned authenticator');
  }
  return counter;
}
```

`src/webauthn/prf-types.ts`:
```ts
/** Minimal local PRF extension typings — avoids lib.dom version drift. */
export interface PrfExtensionInputs {
  prf?: { eval?: { first: BufferSource; second?: BufferSource } };
}

export interface PrfExtensionOutputs {
  prf?: {
    enabled?: boolean;
    results?: { first?: ArrayBuffer | Uint8Array; second?: ArrayBuffer | Uint8Array };
  };
}
```

- [ ] **Step 4: Run verify tests to see them pass**

Run: `npx vitest run src/webauthn/__tests__/verify.test.ts`
Expected: PASS (8 tests).

- [ ] **Step 5: Write the failing evaluatePrf tests**

`src/webauthn/__tests__/evaluatePrf.test.ts`:
```ts
import { afterEach, describe, expect, it, vi } from 'vitest';
import { evaluatePrf, PRF_OUTPUT_LENGTH } from '../ceremonies';
import { toBase64Url } from '../../utils/base64';
import { CeremonyCancelledError, PrfResultMissingError, ReplayError } from '../../errors';

const ORIGIN = 'https://example.com';
const CRED_ID = toBase64Url(new Uint8Array([1, 2, 3, 4]));
const SALT = new Uint8Array(32).fill(3);

interface FakeOpts {
  prfFirst?: ArrayBuffer | Uint8Array | undefined;
  counter?: number;
  challengeOverride?: Uint8Array;
}

/** Builds a navigator.credentials.get mock that echoes the request's challenge. */
function stubCeremony(opts: FakeOpts = {}): void {
  const get = vi.fn(async (request: { publicKey: PublicKeyCredentialRequestOptions }) => {
    const challenge = new Uint8Array(
      (opts.challengeOverride ?? request.publicKey.challenge) as ArrayBuffer | Uint8Array,
    );
    const clientDataJSON = new TextEncoder().encode(
      JSON.stringify({ type: 'webauthn.get', challenge: toBase64Url(challenge), origin: ORIGIN }),
    );
    const authenticatorData = new Uint8Array(37);
    new DataView(authenticatorData.buffer).setUint32(33, opts.counter ?? 10, false);
    return {
      rawId: new Uint8Array([1, 2, 3, 4]).buffer,
      id: CRED_ID,
      type: 'public-key',
      response: { clientDataJSON: clientDataJSON.buffer, authenticatorData: authenticatorData.buffer },
      getClientExtensionResults: () =>
        opts.prfFirst === undefined ? {} : { prf: { results: { first: opts.prfFirst } } },
    };
  });
  vi.stubGlobal('window', {
    PublicKeyCredential: function PublicKeyCredential() {},
    location: { origin: ORIGIN },
  });
  vi.stubGlobal('navigator', { credentials: { get } });
}

afterEach(() => vi.unstubAllGlobals());

describe('evaluatePrf', () => {
  it('returns 32-byte PRF output and verified counter', async () => {
    stubCeremony({ prfFirst: new Uint8Array(32).fill(7), counter: 11 });
    const result = await evaluatePrf({ credentialId: CRED_ID, salt: SALT, rpId: 'example.com', storedCounter: 10 });
    expect(result.prfOutput).toHaveLength(PRF_OUTPUT_LENGTH);
    expect(result.counter).toBe(11);
  });

  it('throws PrfResultMissingError when the authenticator returns no PRF result', async () => {
    stubCeremony({ prfFirst: undefined });
    await expect(
      evaluatePrf({ credentialId: CRED_ID, salt: SALT, rpId: 'example.com' }),
    ).rejects.toThrow(PrfResultMissingError);
  });

  it('throws PrfResultMissingError on non-spec-compliant PRF length', async () => {
    stubCeremony({ prfFirst: new Uint8Array(16) });
    await expect(
      evaluatePrf({ credentialId: CRED_ID, salt: SALT, rpId: 'example.com' }),
    ).rejects.toThrow(PrfResultMissingError);
  });

  it('throws ReplayError when counter regresses', async () => {
    stubCeremony({ prfFirst: new Uint8Array(32).fill(7), counter: 5 });
    await expect(
      evaluatePrf({ credentialId: CRED_ID, salt: SALT, rpId: 'example.com', storedCounter: 9 }),
    ).rejects.toThrow(ReplayError);
  });

  it('translates NotAllowedError into CeremonyCancelledError', async () => {
    vi.stubGlobal('window', {
      PublicKeyCredential: function PublicKeyCredential() {},
      location: { origin: ORIGIN },
    });
    const err = Object.assign(new Error('denied'), { name: 'NotAllowedError' });
    vi.stubGlobal('navigator', { credentials: { get: vi.fn().mockRejectedValue(err) } });
    await expect(
      evaluatePrf({ credentialId: CRED_ID, salt: SALT, rpId: 'example.com' }),
    ).rejects.toThrow(CeremonyCancelledError);
  });
});
```

- [ ] **Step 6: Run evaluatePrf tests to see them fail**

Run: `npx vitest run src/webauthn/__tests__/evaluatePrf.test.ts`
Expected: FAIL — "Cannot find module '../ceremonies'".

- [ ] **Step 7: Implement `src/webauthn/ceremonies.ts` (evaluatePrf half)**

```ts
import { CeremonyCancelledError, PrfResultMissingError, PrfUnsupportedError } from '../errors';
import { fromBase64Url, toBase64Url } from '../utils/base64';
import type { PrfExtensionInputs, PrfExtensionOutputs } from './prf-types';
import { isWebAuthnSupported } from './support';
import { verifyAssertionResponse } from './verify';

export const PRF_OUTPUT_LENGTH = 32;

export interface EvaluatePrfOptions {
  /** base64url credential id (as returned by enrollPrfCredential). */
  credentialId: string;
  /** The credential's PRF salt (WrappedSecretRecord.salt for prf-v1). */
  salt: Uint8Array;
  rpId: string;
  /** Last stored signature counter; -1 (default) skips the increase check. */
  storedCounter?: number;
  timeout?: number;
}

export interface PrfEvaluation {
  prfOutput: Uint8Array;
  counter: number;
}

/** Assertion ceremony evaluating the PRF at `salt`, with replay verification. */
export async function evaluatePrf(options: EvaluatePrfOptions): Promise<PrfEvaluation> {
  if (!isWebAuthnSupported()) {
    throw new PrfUnsupportedError('WebAuthn is not available in this context.');
  }
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const expectedChallenge = toBase64Url(challenge);

  const publicKey: PublicKeyCredentialRequestOptions = {
    challenge: challenge as BufferSource,
    timeout: options.timeout ?? 60_000,
    rpId: options.rpId,
    allowCredentials: [
      { id: fromBase64Url(options.credentialId) as BufferSource, type: 'public-key' },
    ],
    userVerification: 'required',
    extensions: {
      prf: { eval: { first: options.salt as BufferSource } },
    } satisfies PrfExtensionInputs as AuthenticationExtensionsClientInputs,
  };

  let assertion: PublicKeyCredential | null;
  try {
    assertion = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential | null;
  } catch (error) {
    if (error instanceof Error && error.name === 'NotAllowedError') {
      throw new CeremonyCancelledError(
        'Authentication was cancelled or timed out. Try again or use the password fallback.',
      );
    }
    throw new CeremonyCancelledError('Authentication failed. Try again or use the password fallback.');
  }
  if (!assertion) throw new CeremonyCancelledError('Authentication returned no assertion.');

  const prfOutput = tryExtractPrfOutput(assertion);
  if (!prfOutput) {
    throw new PrfResultMissingError(
      'The authenticator did not return a PRF result. Use the password fallback on this device.',
    );
  }

  const response = assertion.response as AuthenticatorAssertionResponse;
  const counter = verifyAssertionResponse({
    clientDataJSON: new Uint8Array(response.clientDataJSON),
    authenticatorData: new Uint8Array(response.authenticatorData),
    expectedChallenge,
    expectedOrigin: window.location.origin,
    storedCounter: options.storedCounter ?? -1,
  });

  return { prfOutput, counter };
}

/**
 * Returns the PRF result bytes, null when absent, and throws on malformed
 * results (guards non-spec-compliant implementations, e.g. wrong length).
 */
export function tryExtractPrfOutput(credential: PublicKeyCredential): Uint8Array | null {
  const ext = credential.getClientExtensionResults() as PrfExtensionOutputs;
  const first = ext.prf?.results?.first;
  if (first === undefined) return null;
  const bytes = first instanceof Uint8Array ? new Uint8Array(first) : new Uint8Array(first);
  if (bytes.length !== PRF_OUTPUT_LENGTH) {
    throw new PrfResultMissingError(
      `Authenticator returned a ${bytes.length}-byte PRF result; expected ${PRF_OUTPUT_LENGTH}. Non-spec-compliant implementation.`,
    );
  }
  return bytes;
}
```

- [ ] **Step 8: Run all webauthn tests**

Run: `npx vitest run src/webauthn && npm run type-check`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add src/webauthn
git commit -m "feat: evaluatePrf assertion ceremony with replay verification"
```

---

### Task 11: Adaptive enrollment (enrollPrfCredential)

**Files:**
- Modify: `src/webauthn/ceremonies.ts` (append enrollment half)
- Test: `src/webauthn/__tests__/enroll.test.ts`

**Interfaces:**
- Consumes: `evaluatePrf`, `tryExtractPrfOutput`, `PRF_OUTPUT_LENGTH` (Task 10), `readCounter` (Task 10), `generateSalt` (Task 2).
- Produces:
  ```ts
  interface EnrollOptions {
    rpId: string; rpName: string; userId: string; userName: string;
    userDisplayName?: string; prfSalt?: Uint8Array; timeout?: number;
  }
  interface EnrollResult {
    credentialId: string;        // base64url
    prfOutput: Uint8Array;       // caller must zeroize (enrollVault does)
    prfSalt: Uint8Array;
    transports: string[];
    publicKey: Uint8Array | null; // best-effort SPKI
    counter: number;
    usedSingleCeremony: boolean;
  }
  enrollPrfCredential(options: EnrollOptions): Promise<EnrollResult>
  ```

- [ ] **Step 1: Write the failing tests**

`src/webauthn/__tests__/enroll.test.ts`:
```ts
import { afterEach, describe, expect, it, vi } from 'vitest';
import { enrollPrfCredential } from '../ceremonies';
import { toBase64Url } from '../../utils/base64';
import { CeremonyCancelledError, PrfUnsupportedError } from '../../errors';

const ORIGIN = 'https://example.com';
const RAW_ID = new Uint8Array([9, 8, 7, 6]);

type CreateExt = { enabled?: boolean; first?: Uint8Array };

/** Mock authenticator. `createExt` controls create-time PRF behavior;
 *  the get mock (two-ceremony fallback) always returns a valid PRF assertion. */
function stubAuthenticator(createExt: CreateExt, opts: { createError?: Error } = {}): {
  create: ReturnType<typeof vi.fn>;
  get: ReturnType<typeof vi.fn>;
} {
  const create = vi.fn(async () => {
    if (opts.createError) throw opts.createError;
    return {
      rawId: RAW_ID.buffer,
      id: toBase64Url(RAW_ID),
      type: 'public-key',
      response: {
        getTransports: () => ['internal'],
        getPublicKey: () => new Uint8Array([1, 1, 1]).buffer,
      },
      getClientExtensionResults: () => ({
        prf: {
          ...(createExt.enabled !== undefined ? { enabled: createExt.enabled } : {}),
          ...(createExt.first ? { results: { first: createExt.first } } : {}),
        },
      }),
    };
  });
  const get = vi.fn(async (request: { publicKey: PublicKeyCredentialRequestOptions }) => {
    const challenge = new Uint8Array(request.publicKey.challenge as Uint8Array);
    const authenticatorData = new Uint8Array(37);
    new DataView(authenticatorData.buffer).setUint32(33, 1, false);
    return {
      rawId: RAW_ID.buffer,
      id: toBase64Url(RAW_ID),
      type: 'public-key',
      response: {
        clientDataJSON: new TextEncoder().encode(
          JSON.stringify({ type: 'webauthn.get', challenge: toBase64Url(challenge), origin: ORIGIN }),
        ).buffer,
        authenticatorData: authenticatorData.buffer,
      },
      getClientExtensionResults: () => ({ prf: { results: { first: new Uint8Array(32).fill(5) } } }),
    };
  });
  vi.stubGlobal('window', {
    PublicKeyCredential: function PublicKeyCredential() {},
    location: { origin: ORIGIN },
  });
  vi.stubGlobal('navigator', { credentials: { create, get } });
  return { create, get };
}

afterEach(() => vi.unstubAllGlobals());

const enrollOptions = {
  rpId: 'example.com',
  rpName: 'Example',
  userId: 'user-1',
  userName: 'user@example.com',
};

describe('enrollPrfCredential — adaptive', () => {
  it('finishes in ONE ceremony when create returns a PRF result (Chrome 147+ path)', async () => {
    const { get } = stubAuthenticator({ enabled: true, first: new Uint8Array(32).fill(6) });
    const result = await enrollPrfCredential(enrollOptions);
    expect(result.usedSingleCeremony).toBe(true);
    expect(result.prfOutput).toEqual(new Uint8Array(32).fill(6));
    expect(result.credentialId).toBe(toBase64Url(RAW_ID));
    expect(result.prfSalt).toHaveLength(32);
    expect(get).not.toHaveBeenCalled();
  });

  it('falls back to the SECOND ceremony when create only reports enabled', async () => {
    const { get } = stubAuthenticator({ enabled: true });
    const result = await enrollPrfCredential(enrollOptions);
    expect(result.usedSingleCeremony).toBe(false);
    expect(result.prfOutput).toEqual(new Uint8Array(32).fill(5));
    expect(result.counter).toBe(1);
    expect(get).toHaveBeenCalledTimes(1);
  });

  it('throws PrfUnsupportedError when PRF is not enabled at create', async () => {
    stubAuthenticator({ enabled: false });
    await expect(enrollPrfCredential(enrollOptions)).rejects.toThrow(PrfUnsupportedError);
  });

  it('translates NotAllowedError into CeremonyCancelledError', async () => {
    stubAuthenticator({}, { createError: Object.assign(new Error('x'), { name: 'NotAllowedError' }) });
    await expect(enrollPrfCredential(enrollOptions)).rejects.toThrow(CeremonyCancelledError);
  });

  it('uses a caller-provided prfSalt verbatim', async () => {
    stubAuthenticator({ enabled: true, first: new Uint8Array(32).fill(6) });
    const prfSalt = new Uint8Array(32).fill(9);
    const result = await enrollPrfCredential({ ...enrollOptions, prfSalt });
    expect(result.prfSalt).toEqual(prfSalt);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/webauthn/__tests__/enroll.test.ts`
Expected: FAIL — `enrollPrfCredential` is not exported.

- [ ] **Step 3: Implement (append to `src/webauthn/ceremonies.ts`)**

```ts
import { generateSalt } from '../utils/random';
import { readCounter } from './verify';

export interface EnrollOptions {
  rpId: string;
  rpName: string;
  userId: string;
  userName: string;
  userDisplayName?: string;
  /** Random 32 bytes generated when omitted. */
  prfSalt?: Uint8Array;
  timeout?: number;
}

export interface EnrollResult {
  credentialId: string;
  /** Transient — the caller MUST zeroize() after deriving the wrap key. */
  prfOutput: Uint8Array;
  prfSalt: Uint8Array;
  transports: string[];
  publicKey: Uint8Array | null;
  counter: number;
  usedSingleCeremony: boolean;
}

/**
 * Adaptive PRF enrollment:
 * 1. Creation requests prf.eval with the salt. Authenticators that evaluate PRF
 *    at create (Chrome 147+/Windows Hello v8) finish in ONE ceremony.
 * 2. Otherwise, hard-verify prf.enabled — abort with PrfUnsupportedError if false —
 *    then run the assertion ceremony to obtain the PRF output.
 */
export async function enrollPrfCredential(options: EnrollOptions): Promise<EnrollResult> {
  if (!isWebAuthnSupported()) {
    throw new PrfUnsupportedError('WebAuthn is not available in this context.');
  }
  const prfSalt = options.prfSalt ?? generateSalt();
  const challenge = crypto.getRandomValues(new Uint8Array(32));

  const publicKey: PublicKeyCredentialCreationOptions = {
    rp: { name: options.rpName, id: options.rpId },
    user: {
      id: new TextEncoder().encode(options.userId) as BufferSource,
      name: options.userName,
      displayName: options.userDisplayName ?? options.userName,
    },
    challenge: challenge as BufferSource,
    pubKeyCredParams: [
      { type: 'public-key', alg: -7 }, // ES256
      { type: 'public-key', alg: -257 }, // RS256
    ],
    timeout: options.timeout ?? 60_000,
    attestation: 'none',
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      residentKey: 'preferred',
      requireResidentKey: false,
      userVerification: 'required',
    },
    extensions: {
      prf: { eval: { first: prfSalt as BufferSource } },
    } satisfies PrfExtensionInputs as AuthenticationExtensionsClientInputs,
  };

  let credential: PublicKeyCredential | null;
  try {
    credential = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null;
  } catch (error) {
    throw translateCreateError(error);
  }
  if (!credential) throw new CeremonyCancelledError('Registration returned no credential.');

  const credentialId = toBase64Url(new Uint8Array(credential.rawId));
  const response = credential.response as AuthenticatorAttestationResponse;
  const transports =
    typeof response.getTransports === 'function' ? (response.getTransports() as string[]) : [];
  const spki = typeof response.getPublicKey === 'function' ? response.getPublicKey() : null;
  const publicKeyBytes = spki ? new Uint8Array(spki) : null;

  const createTimePrf = tryExtractPrfOutput(credential);
  if (createTimePrf) {
    return {
      credentialId,
      prfOutput: createTimePrf,
      prfSalt,
      transports,
      publicKey: publicKeyBytes,
      counter: parseAttestationCounter(response),
      usedSingleCeremony: true,
    };
  }

  const ext = credential.getClientExtensionResults() as PrfExtensionOutputs;
  if (ext.prf?.enabled !== true) {
    throw new PrfUnsupportedError(
      'The authenticator did not enable the PRF extension. Remove this credential and use the password scheme.',
    );
  }

  const { prfOutput, counter } = await evaluatePrf({
    credentialId,
    salt: prfSalt,
    rpId: options.rpId,
    ...(options.timeout !== undefined ? { timeout: options.timeout } : {}),
  });
  return {
    credentialId,
    prfOutput,
    prfSalt,
    transports,
    publicKey: publicKeyBytes,
    counter,
    usedSingleCeremony: false,
  };
}

function parseAttestationCounter(response: AuthenticatorAttestationResponse): number {
  if (typeof response.getAuthenticatorData !== 'function') return 0;
  const data = new Uint8Array(response.getAuthenticatorData());
  return data.length >= 37 ? readCounter(data) : 0;
}

function translateCreateError(error: unknown): Error {
  if (error instanceof Error) {
    if (error.name === 'NotAllowedError') {
      return new CeremonyCancelledError(
        'Registration was cancelled or not allowed. Ensure HTTPS (or localhost) and try again.',
      );
    }
    if (error.name === 'InvalidStateError') {
      return new CeremonyCancelledError('This authenticator is already registered here.');
    }
    if (error.name === 'NotSupportedError') {
      return new PrfUnsupportedError('This device does not support the requested authenticator.');
    }
  }
  return new CeremonyCancelledError('Registration failed. Please try again.');
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run src/webauthn && npm run type-check`
Expected: PASS (all webauthn tests).

- [ ] **Step 5: Commit**

```bash
git add src/webauthn
git commit -m "feat: adaptive single/two-ceremony PRF enrollment"
```

---

### Task 12: High-level enrollVault/unlockVault + webauthn entry point

**Files:**
- Create: `src/webauthn/vault.ts`
- Modify: `src/webauthn/index.ts` (real exports)
- Test: `src/webauthn/__tests__/vault.test.ts`

**Interfaces:**
- Consumes: `enrollPrfCredential`, `evaluatePrf` (Tasks 10–11), `wrapSecret`, `unwrapSecret` (Task 7), `zeroize` (Task 2), `RecordFormatError` (Task 3).
- Produces:
  ```ts
  enrollVault(options: { enroll: EnrollOptions; secret: Uint8Array }): Promise<{
    record: WrappedSecretRecord; credentialId: string; counter: number;
    transports: string[]; usedSingleCeremony: boolean;
  }>
  unlockVault(options: { credentialId: string; record: WrappedSecretRecord; rpId: string; storedCounter?: number }): Promise<{ key: CryptoKey; counter: number }>
  ```

- [ ] **Step 1: Write the failing tests**

`src/webauthn/__tests__/vault.test.ts` — reuse the mock authenticator from Task 11's test (copy the `stubAuthenticator` helper and constants into this file; tests must be readable standalone):
```ts
import { afterEach, describe, expect, it, vi } from 'vitest';
import { enrollVault, unlockVault } from '../vault';
import { unwrapSecretBytes } from '../../core/wrap';
import { RecordFormatError } from '../../errors';
import { toBase64Url } from '../../utils/base64';

// [paste the stubAuthenticator helper, ORIGIN, RAW_ID from enroll.test.ts here verbatim]

afterEach(() => vi.unstubAllGlobals());

const enroll = {
  rpId: 'example.com',
  rpName: 'Example',
  userId: 'user-1',
  userName: 'user@example.com',
};
const secret = new Uint8Array(32).fill(42);

describe('enrollVault → unlockVault end-to-end (mock authenticator)', () => {
  it('wraps at enrollment and unlocks to a non-extractable session key', async () => {
    stubAuthenticator({ enabled: true }); // two-ceremony path; get returns PRF fill(5)
    const enrolled = await enrollVault({ enroll, secret });
    expect(enrolled.record.scheme).toBe('prf-v1');

    const unlocked = await unlockVault({
      credentialId: enrolled.credentialId,
      record: enrolled.record,
      rpId: 'example.com',
      storedCounter: 0,
    });
    expect(unlocked.key.extractable).toBe(false);
    expect(unlocked.counter).toBe(1);
  });

  it('single-ceremony enrollment also produces an unwrappable record', async () => {
    stubAuthenticator({ enabled: true, first: new Uint8Array(32).fill(6) });
    const enrolled = await enrollVault({ enroll, secret });
    expect(enrolled.usedSingleCeremony).toBe(true);
    expect(
      await unwrapSecretBytes({ record: enrolled.record, prfOutput: new Uint8Array(32).fill(6) }),
    ).toEqual(secret);
  });

  it('unlockVault rejects non prf-v1 records', async () => {
    stubAuthenticator({ enabled: true });
    await expect(
      unlockVault({
        credentialId: toBase64Url(RAW_ID),
        record: {
          scheme: 'pw-v1',
          ciphertext: new Uint8Array(48),
          nonce: new Uint8Array(12),
          salt: new Uint8Array(32),
          kdfParams: { N: 1024, r: 8, p: 1 },
        },
        rpId: 'example.com',
      }),
    ).rejects.toThrow(RecordFormatError);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/webauthn/__tests__/vault.test.ts`
Expected: FAIL — "Cannot find module '../vault'".

- [ ] **Step 3: Implement `src/webauthn/vault.ts`**

```ts
import { wrapSecret, unwrapSecret } from '../core/wrap';
import type { WrappedSecretRecord } from '../core/types';
import { RecordFormatError } from '../errors';
import { zeroize } from '../utils/zeroize';
import { enrollPrfCredential, evaluatePrf, type EnrollOptions } from './ceremonies';

export interface EnrollVaultOptions {
  enroll: EnrollOptions;
  /** The 32-byte vault key to wrap. NOT zeroized by this call — caller owns it. */
  secret: Uint8Array;
}

export interface EnrollVaultResult {
  record: WrappedSecretRecord;
  credentialId: string;
  counter: number;
  transports: string[];
  usedSingleCeremony: boolean;
}

/** Ceremony → HKDF → wrap → zeroize PRF output. One call to enroll a PRF-unlockable vault. */
export async function enrollVault(options: EnrollVaultOptions): Promise<EnrollVaultResult> {
  const result = await enrollPrfCredential(options.enroll);
  try {
    const record = await wrapSecret({
      prfOutput: result.prfOutput,
      prfSalt: result.prfSalt,
      secret: options.secret,
    });
    return {
      record,
      credentialId: result.credentialId,
      counter: result.counter,
      transports: result.transports,
      usedSingleCeremony: result.usedSingleCeremony,
    };
  } finally {
    zeroize(result.prfOutput);
  }
}

export interface UnlockVaultOptions {
  credentialId: string;
  record: WrappedSecretRecord;
  rpId: string;
  storedCounter?: number;
}

export interface UnlockVaultResult {
  /** Non-extractable AES-256-GCM session key. */
  key: CryptoKey;
  /** New signature counter — persist it for the next unlock. */
  counter: number;
}

/** Ceremony → HKDF → unwrap → zeroize PRF output. One call to unlock. */
export async function unlockVault(options: UnlockVaultOptions): Promise<UnlockVaultResult> {
  if (options.record.scheme !== 'prf-v1') {
    throw new RecordFormatError('unlockVault requires a prf-v1 record');
  }
  const { prfOutput, counter } = await evaluatePrf({
    credentialId: options.credentialId,
    salt: options.record.salt,
    rpId: options.rpId,
    storedCounter: options.storedCounter ?? -1,
  });
  try {
    const key = await unwrapSecret({ record: options.record, prfOutput });
    return { key, counter };
  } finally {
    zeroize(prfOutput);
  }
}
```

- [ ] **Step 4: Write the real `src/webauthn/index.ts`**

```ts
export {
  detectPrfSupport,
  isPrfViableOnThisClient,
  isWebAuthnSupported,
} from './support';
export type { PrfSupport, PrfViability } from './support';
export {
  PRF_OUTPUT_LENGTH,
  enrollPrfCredential,
  evaluatePrf,
} from './ceremonies';
export type {
  EnrollOptions,
  EnrollResult,
  EvaluatePrfOptions,
  PrfEvaluation,
} from './ceremonies';
export { readCounter, verifyAssertionResponse } from './verify';
export type { VerifyAssertionArgs } from './verify';
export { enrollVault, unlockVault } from './vault';
export type {
  EnrollVaultOptions,
  EnrollVaultResult,
  UnlockVaultOptions,
  UnlockVaultResult,
} from './vault';
```

- [ ] **Step 5: Run the full suite**

Run: `npm run verify`
Expected: PASS — type-check, lint, all tests, build.

- [ ] **Step 6: Commit**

```bash
git add src/webauthn
git commit -m "feat: enrollVault/unlockVault high-level composition + webauthn entry"
```

---

### Task 13: IndexedDB module

**Files:**
- Create: `src/indexeddb/db.ts`
- Modify: `src/indexeddb/index.ts` (real exports)
- Test: `src/indexeddb/__tests__/db.test.ts`

**Interfaces:**
- Consumes: `serializeRecord`/`parseRecord` (Task 4), `WrappedSecretRecord`/`WrapScheme` (Task 4), `StorageError` (Task 3).
- Produces:
  ```ts
  interface ZktvDbConfig { name?: string; version?: number; onUpgrade?: (db: IDBDatabase, oldVersion: number, tx: IDBTransaction) => void }
  interface StoredCredentialMeta { credentialId: string; vaultId: string; counter: number; prfSalt: string /* base64url */; transports: string[]; createdAt: number }
  openVaultDb(config?: ZktvDbConfig): Promise<ZktvDb>
  class ZktvDb {
    saveWrappedVault(vaultId: string, record: WrappedSecretRecord): Promise<void>
    loadWrappedVault(vaultId: string, scheme?: WrapScheme): Promise<WrappedSecretRecord | undefined>
    saveCredentialRecord(meta: StoredCredentialMeta): Promise<void>
    getCredentialRecord(credentialId: string): Promise<StoredCredentialMeta | undefined>
    updateCounter(credentialId: string, counter: number): Promise<void>
    clearVault(vaultId: string): Promise<void>
    securityWipe(): Promise<void>
    close(): void
  }
  ```

- [ ] **Step 1: Write the failing tests**

`src/indexeddb/__tests__/db.test.ts`:
```ts
import 'fake-indexeddb/auto';
import { afterEach, describe, expect, it } from 'vitest';
import { openVaultDb, type ZktvDb } from '../db';
import type { WrappedSecretRecord } from '../../core/types';
import { StorageError } from '../../errors';

const prfRecord: WrappedSecretRecord = {
  scheme: 'prf-v1',
  ciphertext: new Uint8Array(48).fill(1),
  nonce: new Uint8Array(12).fill(2),
  salt: new Uint8Array(32).fill(3),
};
const pwRecord: WrappedSecretRecord = {
  scheme: 'pw-v1',
  ciphertext: new Uint8Array(48).fill(4),
  nonce: new Uint8Array(12).fill(5),
  salt: new Uint8Array(32).fill(6),
  kdfParams: { N: 131072, r: 8, p: 1 },
};
const cred = {
  credentialId: 'cred-1',
  vaultId: 'vault-1',
  counter: 3,
  prfSalt: 'AwMD',
  transports: ['internal'],
  createdAt: Date.now(),
};

let db: ZktvDb;
afterEach(() => db?.close());

// unique DB name per test to isolate fake-indexeddb state
const fresh = () => openVaultDb({ name: `test-${crypto.randomUUID()}` });

describe('ZktvDb', () => {
  it('saves and loads both wraps of the same vault, preferring prf-v1', async () => {
    db = await fresh();
    await db.saveWrappedVault('vault-1', prfRecord);
    await db.saveWrappedVault('vault-1', pwRecord);
    expect(await db.loadWrappedVault('vault-1')).toEqual(prfRecord);
    expect(await db.loadWrappedVault('vault-1', 'pw-v1')).toEqual(pwRecord);
    expect(await db.loadWrappedVault('missing')).toBeUndefined();
  });

  it('stores credential metadata and updates counters', async () => {
    db = await fresh();
    await db.saveCredentialRecord(cred);
    await db.updateCounter('cred-1', 9);
    expect((await db.getCredentialRecord('cred-1'))?.counter).toBe(9);
    await expect(db.updateCounter('ghost', 1)).rejects.toThrow(StorageError);
  });

  it('clearVault removes the vault records and its credentials only', async () => {
    db = await fresh();
    await db.saveWrappedVault('vault-1', prfRecord);
    await db.saveWrappedVault('vault-2', prfRecord);
    await db.saveCredentialRecord(cred);
    await db.saveCredentialRecord({ ...cred, credentialId: 'cred-2', vaultId: 'vault-2' });
    await db.clearVault('vault-1');
    expect(await db.loadWrappedVault('vault-1')).toBeUndefined();
    expect(await db.getCredentialRecord('cred-1')).toBeUndefined();
    expect(await db.loadWrappedVault('vault-2')).toEqual(prfRecord);
    expect(await db.getCredentialRecord('cred-2')).toBeDefined();
  });

  it('securityWipe clears every store', async () => {
    db = await fresh();
    await db.saveWrappedVault('vault-1', prfRecord);
    await db.saveCredentialRecord(cred);
    await db.securityWipe();
    expect(await db.loadWrappedVault('vault-1')).toBeUndefined();
    expect(await db.getCredentialRecord('cred-1')).toBeUndefined();
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/indexeddb`
Expected: FAIL — "Cannot find module '../db'".

- [ ] **Step 3: Implement `src/indexeddb/db.ts`**

```ts
import { parseRecord, serializeRecord } from '../core/serialize';
import type { WrapScheme, WrappedSecretRecord } from '../core/types';
import { StorageError } from '../errors';

export interface ZktvDbConfig {
  name?: string;
  version?: number;
  /** Runs inside onupgradeneeded AFTER the built-in stores are ensured. */
  onUpgrade?: (db: IDBDatabase, oldVersion: number, tx: IDBTransaction) => void;
}

export interface StoredCredentialMeta {
  credentialId: string;
  vaultId: string;
  counter: number;
  /** base64url PRF salt — non-secret. */
  prfSalt: string;
  transports: string[];
  createdAt: number;
}

interface StoredVaultRow {
  vaultId: string;
  scheme: WrapScheme;
  record: string; // serializeRecord() output
  updatedAt: number;
}

const VAULTS = 'vaults';
const CREDENTIALS = 'credentials';
const META = 'meta';

export async function openVaultDb(config: ZktvDbConfig = {}): Promise<ZktvDb> {
  const name = config.name ?? 'zktv';
  const version = config.version ?? 1;
  const db = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open(name, version);
    request.onupgradeneeded = (event) => {
      const database = request.result;
      if (!database.objectStoreNames.contains(VAULTS)) {
        database.createObjectStore(VAULTS, { keyPath: ['vaultId', 'scheme'] });
      }
      if (!database.objectStoreNames.contains(CREDENTIALS)) {
        const store = database.createObjectStore(CREDENTIALS, { keyPath: 'credentialId' });
        store.createIndex('vaultId', 'vaultId', { unique: false });
      }
      if (!database.objectStoreNames.contains(META)) {
        database.createObjectStore(META, { keyPath: 'key' });
      }
      if (config.onUpgrade && request.transaction) {
        config.onUpgrade(database, event.oldVersion, request.transaction);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new StorageError(request.error?.message ?? 'Failed to open database'));
    request.onblocked = () => reject(new StorageError('Database open blocked by another connection'));
  });
  return new ZktvDb(db);
}

export class ZktvDb {
  constructor(private readonly db: IDBDatabase) {}

  async saveWrappedVault(vaultId: string, record: WrappedSecretRecord): Promise<void> {
    const row: StoredVaultRow = {
      vaultId,
      scheme: record.scheme,
      record: serializeRecord(record),
      updatedAt: Date.now(),
    };
    await this.request((tx) => tx.objectStore(VAULTS).put(row), VAULTS, 'readwrite');
  }

  async loadWrappedVault(
    vaultId: string,
    scheme?: WrapScheme,
  ): Promise<WrappedSecretRecord | undefined> {
    const schemes: WrapScheme[] = scheme ? [scheme] : ['prf-v1', 'pw-v1'];
    for (const candidate of schemes) {
      const row = await this.request<StoredVaultRow | undefined>(
        (tx) => tx.objectStore(VAULTS).get([vaultId, candidate]),
        VAULTS,
        'readonly',
      );
      if (row) return parseRecord(row.record);
    }
    return undefined;
  }

  async saveCredentialRecord(meta: StoredCredentialMeta): Promise<void> {
    await this.request((tx) => tx.objectStore(CREDENTIALS).put(meta), CREDENTIALS, 'readwrite');
  }

  async getCredentialRecord(credentialId: string): Promise<StoredCredentialMeta | undefined> {
    return this.request<StoredCredentialMeta | undefined>(
      (tx) => tx.objectStore(CREDENTIALS).get(credentialId),
      CREDENTIALS,
      'readonly',
    );
  }

  async updateCounter(credentialId: string, counter: number): Promise<void> {
    const existing = await this.getCredentialRecord(credentialId);
    if (!existing) throw new StorageError(`No credential record: ${credentialId}`);
    await this.saveCredentialRecord({ ...existing, counter });
  }

  /** Deletes the vault's wrapped records and every credential bound to it. */
  async clearVault(vaultId: string): Promise<void> {
    await this.request(
      (tx) => tx.objectStore(VAULTS).delete([vaultId, 'prf-v1']),
      VAULTS,
      'readwrite',
    );
    await this.request(
      (tx) => tx.objectStore(VAULTS).delete([vaultId, 'pw-v1']),
      VAULTS,
      'readwrite',
    );
    const credentialIds = await this.request<string[]>(
      (tx) => tx.objectStore(CREDENTIALS).index('vaultId').getAllKeys(vaultId) as IDBRequest<string[]>,
      CREDENTIALS,
      'readonly',
    );
    for (const id of credentialIds) {
      await this.request((tx) => tx.objectStore(CREDENTIALS).delete(id), CREDENTIALS, 'readwrite');
    }
  }

  /** Wipes every store — mirror of TrustVault's security wipe semantics. */
  async securityWipe(): Promise<void> {
    for (const store of [VAULTS, CREDENTIALS, META]) {
      await this.request((tx) => tx.objectStore(store).clear(), store, 'readwrite');
    }
  }

  close(): void {
    this.db.close();
  }

  private request<T>(
    operation: (tx: IDBTransaction) => IDBRequest<T>,
    store: string,
    mode: IDBTransactionMode,
  ): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      let tx: IDBTransaction;
      try {
        tx = this.db.transaction(store, mode);
      } catch (error) {
        reject(new StorageError(error instanceof Error ? error.message : 'Transaction failed'));
        return;
      }
      const request = operation(tx);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () =>
        reject(new StorageError(request.error?.message ?? 'IndexedDB request failed'));
    });
  }
}
```

- [ ] **Step 4: Write the real `src/indexeddb/index.ts`**

```ts
export { ZktvDb, openVaultDb } from './db';
export type { StoredCredentialMeta, ZktvDbConfig } from './db';
```

- [ ] **Step 5: Run tests and the full suite**

Run: `npx vitest run src/indexeddb && npm run verify`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/indexeddb
git commit -m "feat: raw-IndexedDB vault storage with clearVault and securityWipe"
```

---

### Task 14: Documentation — CLAUDE.md, README.md, SECURITY.md, MIGRATION.md

**Files:**
- Create: `CLAUDE.md`, `README.md`, `SECURITY.md`, `MIGRATION.md`

**Interfaces:**
- Consumes: the entire public API (Tasks 7, 8, 12, 13) — code samples must compile against it.
- Produces: the four docs; `CLAUDE.md` is the optimized agent guide requested for this repo.

- [ ] **Step 1: Write `CLAUDE.md`**

```markdown
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
- PRF output is exactly 32 bytes; enforce via `PRF_OUTPUT_LENGTH`, don't assume.
- pw-v1 records REQUIRE `kdfParams`; prf-v1 records REJECT it (`parseRecord` enforces).
- Android WebView: PRF does not reach Credential Manager — `isPrfViableOnThisClient()`
  reports `environment: 'webview'`; apps must fall back to `pw-v1` there.
```

- [ ] **Step 2: Write `README.md`**

Content requirements (write in full, real prose):
- Title + one-paragraph pitch: WebAuthn PRF-backed zero-knowledge vault key wrapping; DB dump alone can never unlock; extracted from TrustVault-PWA; reference implementation for the arXiv paper (link repo `https://github.com/opnsrcntrbtr/TrustVault-PWA`; paper link placeholder marked "paper link TBA on publication" is acceptable ONLY here since publication is a future external event).
- Install: `npm install webauthn-prf-zktv`.
- Browser support matrix (2026): Chrome/Edge (PRF-on-create 147+), Safari (macOS 15+/iOS 18+ iCloud Keychain), Firefox 147/148+, Android robust, Windows Hello (Win11 25H2+); Android WebView unsupported → pw-v1 fallback.
- Quickstart code block (enroll + unlock + password fallback), exactly this:

```ts
import { generateSalt, serializeRecord, parseRecord, wrapSecret, zeroize } from 'webauthn-prf-zktv';
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

- API reference tables per entry point (function, one-line description).
- "Why both schemes" callout: SimpleWebAuthn's warning that PRF ties encryption to passkey lifetime; pw-v1 is the mandatory-in-practice fallback.
- Link to SECURITY.md and MIGRATION.md.

- [ ] **Step 3: Write `SECURITY.md`**

Content requirements (write in full):
- **Threat model:** (a) attacker with full DB dump/backup: sees only AES-GCM ciphertexts, random salts, nonces, credential metadata — vault key requires PRF output (hardware, user-verification-gated) or master password (memory-hard scrypt); (b) XSS attacker at runtime: can call APIs but keys are non-extractable CryptoKeys; cannot exfiltrate key bytes; can misuse keys while page is open — documented residual; (c) post-quantum note: AES-256/HKDF-SHA256/scrypt are symmetric — Grover-bounded, 128-bit PQ margin; no asymmetric secrecy dependency in the wrap path (WebAuthn signatures are authentication only).
- **Guarantees:** the five invariants from CLAUDE.md, stated for users.
- **Residuals:** counter metadata and credential IDs are plaintext (non-secret); zeroization is best-effort in JS (GC copies may survive — cite as known limitation); PRF output enters JS memory transiently by spec design.
- **Passkey-deletion hazard:** deleting the passkey destroys the PRF path permanently; always maintain a `pw-v1` record.
- **Reporting:** open a GitHub security advisory on the repo.

- [ ] **Step 4: Write `MIGRATION.md`**

Content requirements (write in full):
- From TrustVault-PWA: `fromTrustVaultRecord({ legacyJson, prfOutput, prfSalt })` usage example: evaluate PRF with the credential's stored `prfSalt` via `evaluatePrf`, feed the legacy `wrappedVaultKey` JSON, store the returned record, delete the legacy row.
- IndexedDB versioning: bump `version` in `openVaultDb`, do schema work in `onUpgrade`; rule: migrations must never persist recomputable key inputs; worked example: "strip legacy scheme" migration that deletes any row whose `scheme` is not in the v1 whitelist.
- Record format stability: `v: 1` envelope; future versions parse old records forever or provide an explicit adapter.

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md README.md SECURITY.md MIGRATION.md
git commit -m "docs: CLAUDE.md agent guide, README, SECURITY threat model, MIGRATION guide"
```

---

### Task 15: Examples

**Files:**
- Create: `examples/node-unwrap/package.json`, `examples/node-unwrap/index.mjs`, `examples/pwa-vite/package.json`, `examples/pwa-vite/index.html`, `examples/pwa-vite/src/main.ts`, `examples/pwa-vite/vite.config.ts`

**Interfaces:**
- Consumes: built `dist/` via `"webauthn-prf-zktv": "file:../.."`.

- [ ] **Step 1: Write the Node example**

`examples/node-unwrap/package.json`:
```json
{
  "name": "zktv-example-node-unwrap",
  "private": true,
  "type": "module",
  "dependencies": { "webauthn-prf-zktv": "file:../.." },
  "scripts": { "start": "node index.mjs" }
}
```

`examples/node-unwrap/index.mjs`:
```js
// Proves the core is browser-independent: wrap under a password in Node,
// serialize to disk, parse it back, unwrap, verify.
import { parseRecord, serializeRecord, unwrapSecretBytes, wrapSecret, zeroize } from 'webauthn-prf-zktv';
import { readFile, writeFile } from 'node:fs/promises';

const secret = crypto.getRandomValues(new Uint8Array(32));
const original = new Uint8Array(secret);

const record = await wrapSecret({
  password: 'demo-master-password',
  secret,
  kdfParams: { N: 16384, r: 8, p: 1 }, // demo-speed params; production default is N=131072
});
zeroize(secret);

await writeFile('vault-record.json', serializeRecord(record));
const restored = parseRecord(await readFile('vault-record.json', 'utf8'));
const bytes = await unwrapSecretBytes({ record: restored, password: 'demo-master-password' });

console.log('round-trip ok:', bytes.every((b, i) => b === original[i]));
zeroize(bytes);
```

- [ ] **Step 2: Run the Node example**

Run: `npm run build && cd examples/node-unwrap && npm install && npm start && cd ../..`
Expected: prints `round-trip ok: true`.

- [ ] **Step 3: Write the PWA example**

`examples/pwa-vite/package.json`:
```json
{
  "name": "zktv-example-pwa",
  "private": true,
  "type": "module",
  "dependencies": { "webauthn-prf-zktv": "file:../.." },
  "devDependencies": { "vite": "^6.0.0", "typescript": "^5.7.0" },
  "scripts": { "dev": "vite", "build": "vite build" }
}
```

`examples/pwa-vite/vite.config.ts`:
```ts
import { defineConfig } from 'vite';
export default defineConfig({ server: { host: 'localhost' } });
```

`examples/pwa-vite/index.html`:
```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>zktv demo — PRF vault unlock</title>
  </head>
  <body>
    <h1>webauthn-prf-zktv demo</h1>
    <p id="viability">checking PRF viability…</p>
    <button id="enroll" disabled>Enroll biometric vault</button>
    <button id="unlock" disabled>Unlock vault</button>
    <button id="wipe">Security wipe</button>
    <pre id="log"></pre>
    <script type="module" src="/src/main.ts"></script>
  </body>
</html>
```

`examples/pwa-vite/src/main.ts`:
```ts
import { zeroize } from 'webauthn-prf-zktv';
import { enrollVault, unlockVault, isPrfViableOnThisClient } from 'webauthn-prf-zktv/webauthn';
import { openVaultDb } from 'webauthn-prf-zktv/indexeddb';

const rpId = location.hostname; // localhost during dev
const log = (msg: string) => {
  (document.getElementById('log') as HTMLPreElement).textContent += `${msg}\n`;
};
const el = (id: string) => document.getElementById(id) as HTMLButtonElement;

const db = await openVaultDb({ name: 'zktv-demo' });
const viability = await isPrfViableOnThisClient();
(document.getElementById('viability') as HTMLParagraphElement).textContent =
  `${viability.viable ? '✅' : '❌'} ${viability.reason}`;
el('enroll').disabled = !viability.viable;

el('enroll').onclick = async () => {
  const vaultKey = crypto.getRandomValues(new Uint8Array(32));
  try {
    const { record, credentialId, counter } = await enrollVault({
      enroll: { rpId, rpName: 'zktv demo', userId: 'demo-user', userName: 'demo@example.com' },
      secret: vaultKey,
    });
    await db.saveWrappedVault('demo-vault', record);
    await db.saveCredentialRecord({
      credentialId,
      vaultId: 'demo-vault',
      counter,
      prfSalt: '',
      transports: [],
      createdAt: Date.now(),
    });
    localStorage.setItem('demo-credential-id', credentialId);
    el('unlock').disabled = false;
    log(`enrolled ✔ credential=${credentialId.slice(0, 12)}…`);
  } catch (error) {
    log(`enroll failed: ${(error as Error).message}`);
  } finally {
    zeroize(vaultKey);
  }
};

el('unlock').onclick = async () => {
  const credentialId = localStorage.getItem('demo-credential-id');
  const record = await db.loadWrappedVault('demo-vault', 'prf-v1');
  if (!credentialId || !record) return log('nothing enrolled yet');
  const stored = await db.getCredentialRecord(credentialId);
  try {
    const { key, counter } = await unlockVault({
      credentialId,
      record,
      rpId,
      storedCounter: stored?.counter ?? -1,
    });
    await db.updateCounter(credentialId, counter);
    log(`unlocked ✔ non-extractable=${!key.extractable}`);
  } catch (error) {
    log(`unlock failed: ${(error as Error).message}`);
  }
};

el('wipe').onclick = async () => {
  await db.securityWipe();
  localStorage.removeItem('demo-credential-id');
  el('unlock').disabled = true;
  log('wiped all stores');
};
```

- [ ] **Step 4: Verify the PWA example builds**

Run: `cd examples/pwa-vite && npm install && npm run build && cd ../..`
Expected: Vite build succeeds. (Manual biometric testing happens on real hardware; the example is exercised by maintainers, not CI.)

- [ ] **Step 5: Commit**

```bash
git add examples
git commit -m "docs: node-unwrap and pwa-vite examples"
```

---

### Task 16: CI workflow + publish dry-run

**Files:**
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: `npm run verify` (Task 1).

- [ ] **Step 1: Write `.github/workflows/ci.yml`**

```yaml
name: CI
on:
  push:
    branches: [main]
  pull_request:

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: npm
      - run: npm ci
      - run: npm run verify
      - name: Publish dry-run (size & contents gate)
        run: npm publish --dry-run --access public
```

- [ ] **Step 2: Verify locally what CI will run**

Run: `npm run verify && npm publish --dry-run --access public`
Expected: verify passes; dry-run lists ONLY `dist/`, `README.md`, `SECURITY.md`, `MIGRATION.md`, `LICENSE`, `package.json`; no `src/`, no examples, no docs/superpowers. Note the reported package size in the commit message.

- [ ] **Step 3: Commit**

```bash
git add .github
git commit -m "ci: verify pipeline + npm publish dry-run gate"
```

---

## Self-Review (completed during planning)

- **Spec coverage:** §3 invariants → Tasks 5–7, 12 + CLAUDE.md hard rules; §6 core API → Tasks 4–8; §7 webauthn → Tasks 9–12; §8 indexeddb → Task 13; §9 errors → Task 3 (used throughout); §10 testing → each task's test steps (vectors, round-trips, wrong-key, nonce uniqueness, fuzzing, replay, both enrollment modes, adapter fixtures); §11 docs/examples → Tasks 14–15; CI → Task 16. `zeroize` export (spec §6.2) → Task 7 Step 4.
- **Type consistency:** `WrappedSecretRecord`/`ScryptParams`/`WrapScheme` defined once (Task 4), consumed by name everywhere; `EnrollOptions`/`EnrollResult` (Task 11) consumed by Task 12; `PRF_OUTPUT_LENGTH`/`tryExtractPrfOutput` (Task 10) consumed by Task 11; `readCounter` (Task 10) consumed by Task 11.
- **Placeholders:** none. The single "TBA" (arXiv paper link in README) is an external future event, explicitly scoped in Task 14 Step 2.
```
