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
export { fromTrustVaultRecord, TRUSTVAULT_HKDF_INFO } from './core/trustvault';
export type { FromTrustVaultOptions } from './core/trustvault';
export { generateSalt } from './utils/random';
export { zeroize } from './utils/zeroize';
