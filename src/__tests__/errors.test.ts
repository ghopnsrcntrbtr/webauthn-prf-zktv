import { describe, expect, it } from 'vitest';
import {
  CeremonyCancelledError,
  DecryptError,
  PrfResultMissingError,
  PrfUnsupportedError,
  RecordFormatError,
  ReplayError,
  StorageError,
  ZktvError,
} from '../errors';

describe('error hierarchy', () => {
  it('every subclass extends ZktvError and Error with a stable code', () => {
    const cases: Array<[ZktvError, string]> = [
      [new PrfUnsupportedError(), 'PRF_UNSUPPORTED'],
      [new CeremonyCancelledError(), 'CEREMONY_CANCELLED'],
      [new PrfResultMissingError(), 'PRF_RESULT_MISSING'],
      [new ReplayError('challenge mismatch'), 'REPLAY'],
      [new DecryptError(), 'DECRYPT_FAILED'],
      [new RecordFormatError('bad'), 'RECORD_FORMAT'],
      [new StorageError('idb'), 'STORAGE'],
    ];
    for (const [err, code] of cases) {
      expect(err).toBeInstanceOf(ZktvError);
      expect(err).toBeInstanceOf(Error);
      expect(err.code).toBe(code);
      expect(err.name).toBe(err.constructor.name);
    }
  });

  it('DecryptError message is generic (no wrong-key vs corrupt-data oracle)', () => {
    expect(new DecryptError().message).toBe('Failed to decrypt record');
  });
});
