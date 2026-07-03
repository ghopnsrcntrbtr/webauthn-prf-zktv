/** Minimal local PRF extension typings — avoids lib.dom version drift. */
export interface PrfExtensionInputs {
  prf?: { eval?: { first: BufferSource; second?: BufferSource } };
}

export interface PrfExtensionOutputs {
  prf?: {
    enabled?: boolean;
    results?: { first?: ArrayBuffer | Uint8Array; second?: ArrayBuffer | Uint8Array };
  };
}
