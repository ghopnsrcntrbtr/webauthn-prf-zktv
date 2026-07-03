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
el('unlock').disabled = localStorage.getItem('demo-credential-id') === null;

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
  if (!credentialId || !record) {
    log('nothing enrolled yet');
    return;
  }
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
