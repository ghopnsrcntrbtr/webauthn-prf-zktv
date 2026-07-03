export { detectPrfSupport, isPrfViableOnThisClient, isWebAuthnSupported } from './support';
export type { PrfSupport, PrfViability } from './support';
export { PRF_OUTPUT_LENGTH, enrollPrfCredential, evaluatePrf } from './ceremonies';
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
