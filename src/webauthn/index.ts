export { detectPrfSupport, isPrfViableOnThisClient, isWebAuthnSupported } from './support';
export type { PrfSupport, PrfViability } from './support';
export { PRF_OUTPUT_LENGTH, enrollPrfCredential, evaluatePrf } from './ceremonies';
export type {
  EnrollOptions,
  EnrollResult,
  EvaluatePrfOptions,
  PrfEvaluation,
} from './ceremonies';
export { readAuthenticatorFlags, readCounter, verifyAssertionResponse } from './verify';
export type { AuthenticatorFlags, VerifyAssertionArgs } from './verify';
export { enrollVault, unlockVault } from './vault';
export type {
  EnrollVaultOptions,
  EnrollVaultResult,
  UnlockVaultOptions,
  UnlockVaultResult,
} from './vault';
