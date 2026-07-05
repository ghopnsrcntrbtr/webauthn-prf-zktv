# Interoperability Test Vectors (v1 record format)

Independent implementations can validate compatibility against these
known-answer vectors. All byte values are **unpadded base64url**.
Pinned in `src/core/__tests__/vectors.test.ts`.

## prf-v1

HKDF-SHA256(ikm = prfOutput, salt = *empty*, info = UTF-8
`"webauthn-prf-zktv vault key wrap v1"`) → 256-bit AES-GCM wrap key;
AES-256-GCM(nonce, secret) → ciphertext (16-byte tag appended).

| field | value |
|---|---|
| prfOutput (32 × `0x01`) | `AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE` |
| prfSalt / record salt (32 × `0x02`) | `AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI` |
| secret / vault key (32 × `0x03`) | `AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM` |
| nonce (12 × `0x04`) | `BAQEBAQEBAQEBAQE` |
| ciphertext | `_8qmjSCDoMDF__kUdrvYgIonmlPj2ZZrWGTKmWAwJm9SoC1_U7QdM9QZ1XeVR0n-` |

## pw-v1

scrypt(password, salt, N=16384, r=8, p=1, dkLen=32) → AES-256-GCM key.
**These reduced-cost parameters are for vector verification only** — the
production floor is `{ N: 131072, r: 8, p: 1 }` and MUST NOT be lowered.

| field | value |
|---|---|
| password (UTF-8) | `correct horse battery staple` |
| salt (16 × `0x05`) | `BQUFBQUFBQUFBQUFBQUFBQ` |
| secret (32 × `0x03`) | `AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM` |
| nonce (12 × `0x04`) | `BAQEBAQEBAQEBAQE` |
| kdfParams | `{ "N": 16384, "r": 8, "p": 1 }` |
| ciphertext | `bmTKLnKMUiSx7H4BPTRTONutUzRAuUFw0eTmGNje_n7xu5ilOGEL81LybNgccTTR` |
