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
