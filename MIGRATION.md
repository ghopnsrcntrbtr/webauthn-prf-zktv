# Migration Guide

## From TrustVault-PWA legacy records

TrustVault-PWA stores its PRF-wrapped vault key as an `EncryptedData` JSON string
(`{ ciphertext, iv }`, standard base64) wrapped under the HKDF label
`'TrustVault Vault Key Wrapping v1'`. This package uses a different, versioned
record format and its own HKDF label, so legacy records need a one-shot re-wrap —
**no new WebAuthn ceremony beyond the normal unlock is required**, because the
same PRF output unlocks both labels.

```ts
import { fromTrustVaultRecord, serializeRecord, zeroize } from 'webauthn-prf-zktv';
import { evaluatePrf } from 'webauthn-prf-zktv/webauthn';
import { fromBase64 } from './your-app-utils'; // TrustVault stored prfSalt as base64

// 1. One assertion ceremony with the credential's STORED prfSalt
const prfSalt = fromBase64(credential.prfSalt);
const { prfOutput } = await evaluatePrf({
  credentialId: credential.id,
  salt: prfSalt,
  rpId: 'your-rp-id',
  storedCounter: credential.counter,
});

// 2. Re-wrap the legacy record into the v1 format
try {
  const record = await fromTrustVaultRecord({
    legacyJson: credential.wrappedVaultKey, // TrustVault EncryptedData JSON
    prfOutput,
    prfSalt,
  });

  // 3. Persist the new record, then DELETE the legacy row
  await saveNewRecord(serializeRecord(record));
  await deleteLegacyRecord(credential.id);
} finally {
  zeroize(prfOutput);
}
```

The adapter zeroizes all transient plaintext internally, throws a generic
`DecryptError` on a wrong PRF output, and `RecordFormatError` on malformed input.

## IndexedDB schema versioning

`openVaultDb` creates three stores at version 1: `vaults` (key
`[vaultId, scheme]`), `credentials` (key `credentialId`, index `vaultId`), and
`meta`. To evolve the schema, bump `version` and do the work in `onUpgrade`:

```ts
const db = await openVaultDb({
  version: 2,
  onUpgrade: (database, oldVersion, tx) => {
    if (oldVersion < 2) {
      // Example: strip records with schemes outside the v1 whitelist
      // (mirrors TrustVault's legacy device-key purge).
      const store = tx.objectStore('vaults');
      store.openCursor().onsuccess = (event) => {
        const cursor = (event.target as IDBRequest<IDBCursorWithValue>).result;
        if (!cursor) return;
        const row = cursor.value as { scheme: string };
        if (row.scheme !== 'prf-v1' && row.scheme !== 'pw-v1') cursor.delete();
        cursor.continue();
      };
    }
  },
});
```

**The one rule every migration must respect:** never introduce stored values
from which a wrap key could be recomputed (device IDs, unencrypted seeds, key
derivation inputs beyond random salts). If a legacy scheme violated this —
as TrustVault's original device-key scheme did — the migration must *delete*
those records and require re-enrollment, not carry them forward.

## Record format stability

Serialized records carry a version envelope (`"v": 1`). Future format versions
will either parse `v: 1` records indefinitely or ship an explicit adapter like
`fromTrustVaultRecord` — stored records will never be silently invalidated.
