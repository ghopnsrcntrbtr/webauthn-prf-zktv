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
    request.onerror = () =>
      reject(new StorageError(request.error?.message ?? 'Failed to open database'));
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
      (tx) =>
        tx.objectStore(CREDENTIALS).index('vaultId').getAllKeys(vaultId) as IDBRequest<string[]>,
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
