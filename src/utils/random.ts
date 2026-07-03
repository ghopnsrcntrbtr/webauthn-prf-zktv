/** Cryptographically random salt (default 32 bytes — PRF input / scrypt salt size). */
export function generateSalt(length = 32): Uint8Array {
  const salt = new Uint8Array(length);
  crypto.getRandomValues(salt);
  return salt;
}
