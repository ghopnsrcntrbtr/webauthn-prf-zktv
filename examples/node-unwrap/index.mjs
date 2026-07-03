// Proves the core is browser-independent: wrap under a password in Node,
// serialize to disk, parse it back, unwrap, verify.
import {
  parseRecord,
  serializeRecord,
  unwrapSecretBytes,
  wrapSecret,
  zeroize,
} from 'webauthn-prf-zktv';
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
