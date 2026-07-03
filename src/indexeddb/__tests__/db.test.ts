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
