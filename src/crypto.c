#include "crypto.h"
#include "common.h"

static BYTE aes_key[KEYSIZE] = {0x3E, 0x31, 0xF4, 0x00, 0x50, 0xB6, 0x6E, 0xB8,
                                0xF6, 0x98, 0x95, 0x27, 0x43, 0x27, 0xC0, 0x55,
                                0xEB, 0xDB, 0xE1, 0x7F, 0x05, 0xFE, 0x65, 0x6D,
                                0x0F, 0xA6, 0x5B, 0x00, 0x33, 0xE6, 0xD9, 0x0B};
static BYTE aes_iv[IVSIZE] = {0xB4, 0xC8, 0x1D, 0x1D, 0x14, 0x7C, 0xCB, 0xFA,
                              0x07, 0x42, 0xD9, 0xED, 0x1A, 0x86, 0xD9, 0xCD};

// helper: dump first N bytes as hex
static VOID hex_dump(const char *label, const BYTE *data, DWORD len,
                     DWORD maxBytes) {
  printf("[CRYPTO] %s (%lu bytes): ", label, len);
  DWORD show = (len < maxBytes) ? len : maxBytes;
  for (DWORD i = 0; i < show; i++)
    printf("%02X", data[i]);
  if (len > maxBytes)
    printf("...");
  printf("\n");
}

static BOOL InstallAesEncryption(PAES pAes) {
  BOOL bSTATE = TRUE;
  BCRYPT_ALG_HANDLE hAlgorithm = NULL;
  BCRYPT_KEY_HANDLE hKeyHandle = NULL;
  ULONG cbResult = 0;
  DWORD dwBlockSize = 0;
  DWORD cbKeyObject = 0;
  PBYTE pbKeyObject = NULL;
  PBYTE pbCipher = NULL;
  DWORD cbCipher = 0;
  NTSTATUS STATUS = 0;

  printf("[CRYPTO] === InstallAesEncryption ===\n");
  hex_dump("Key", pAes->pKey, KEYSIZE, 32);
  hex_dump("IV (before)", pAes->pIv, IVSIZE, 16);
  hex_dump("Plaintext", pAes->pPlainText, pAes->dwPlainSize, 64);

  STATUS =
      BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
  if (!NT_SUCCESS(STATUS)) {
    printf("[CRYPTO] BCryptOpenAlgorithmProvider FAILED: 0x%08lX\n", STATUS);
    bSTATE = FALSE;
    goto _End;
  }

  STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH,
                             (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
  if (!NT_SUCCESS(STATUS)) {
    printf("[CRYPTO] BCryptGetProperty(OBJECT_LENGTH) FAILED: 0x%08lX\n",
           STATUS);
    bSTATE = FALSE;
    goto _End;
  }

  STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH,
                             (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
  if (!NT_SUCCESS(STATUS)) {
    printf("[CRYPTO] BCryptGetProperty(BLOCK_LENGTH) FAILED: 0x%08lX\n",
           STATUS);
    bSTATE = FALSE;
    goto _End;
  }

  printf("[CRYPTO] BlockSize=%lu  KeyObjectSize=%lu\n", dwBlockSize,
         cbKeyObject);
  if (dwBlockSize != 16) {
    printf("[CRYPTO] UNEXPECTED block size %lu != 16\n", dwBlockSize);
    bSTATE = FALSE;
    goto _End;
  }

  pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
  if (!pbKeyObject) {
    printf("[CRYPTO] HeapAlloc(KeyObject) FAILED\n");
    bSTATE = FALSE;
    goto _End;
  }

  STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE,
                             (PBYTE)BCRYPT_CHAIN_MODE_CBC,
                             sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
  if (!NT_SUCCESS(STATUS)) {
    printf("[CRYPTO] BCryptSetProperty(CBC) FAILED: 0x%08lX\n", STATUS);
    bSTATE = FALSE;
    goto _End;
  }

  STATUS =
      BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject,
                                 cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
  if (!NT_SUCCESS(STATUS)) {
    printf("[CRYPTO] BCryptGenerateSymmetricKey FAILED: 0x%08lX\n", STATUS);
    bSTATE = FALSE;
    goto _End;
  }

  // sizing call — use throwaway IV copy so real IV stays clean
  BYTE ivTmp[IVSIZE];
  memcpy(ivTmp, pAes->pIv, IVSIZE);
  STATUS = BCryptEncrypt(hKeyHandle, (PUCHAR)pAes->pPlainText,
                         (ULONG)pAes->dwPlainSize, NULL, ivTmp, IVSIZE, NULL, 0,
                         &cbCipher, BCRYPT_BLOCK_PADDING);
  if (!NT_SUCCESS(STATUS)) {
    printf("[CRYPTO] BCryptEncrypt(sizing) FAILED: 0x%08lX\n", STATUS);
    bSTATE = FALSE;
    goto _End;
  }

  printf("[CRYPTO] Cipher output size will be %lu bytes\n", cbCipher);

  pbCipher = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbCipher);
  if (!pbCipher) {
    printf("[CRYPTO] HeapAlloc(Cipher) FAILED\n");
    bSTATE = FALSE;
    goto _End;
  }

  // real encrypt — IV is still intact
  hex_dump("IV (before real encrypt)", pAes->pIv, IVSIZE, 16);
  STATUS = BCryptEncrypt(hKeyHandle, (PUCHAR)pAes->pPlainText,
                         (ULONG)pAes->dwPlainSize, NULL, pAes->pIv, IVSIZE,
                         pbCipher, cbCipher, &cbResult, BCRYPT_BLOCK_PADDING);
  if (!NT_SUCCESS(STATUS)) {
    printf("[CRYPTO] BCryptEncrypt(real) FAILED: 0x%08lX\n", STATUS);
    bSTATE = FALSE;
    goto _End;
  }

  hex_dump("IV (after encrypt)", pAes->pIv, IVSIZE, 16);
  hex_dump("Ciphertext", pbCipher, cbCipher, 64);
  printf("[CRYPTO] Encrypt SUCCESS — %lu bytes in, %lu bytes out\n",
         pAes->dwPlainSize, cbCipher);

_End:
  if (hKeyHandle)
    BCryptDestroyKey(hKeyHandle);
  if (hAlgorithm)
    BCryptCloseAlgorithmProvider(hAlgorithm, 0);
  if (pbKeyObject)
    HeapFree(GetProcessHeap(), 0, pbKeyObject);
  if (pbCipher != NULL && bSTATE) {
    pAes->pCipherText = pbCipher;
    pAes->dwCipherSize = cbCipher;
  } else if (pbCipher) {
    HeapFree(GetProcessHeap(), 0, pbCipher);
  }
  return bSTATE;
}

static BOOL InstallAesDecryption(PAES pAes) {
  BOOL bSTATE = TRUE;
  BCRYPT_ALG_HANDLE hAlgorithm = NULL;
  BCRYPT_KEY_HANDLE hKeyHandle = NULL;
  ULONG cbResult = 0;
  DWORD dwBlockSize = 0;
  DWORD cbKeyObject = 0;
  PBYTE pbKeyObject = NULL;
  PBYTE pbPlain = NULL;
  DWORD cbPlain = 0;
  NTSTATUS STATUS = 0;

  printf("[CRYPTO] === InstallAesDecryption ===\n");
  hex_dump("Key", pAes->pKey, KEYSIZE, 32);
  hex_dump("IV (before)", pAes->pIv, IVSIZE, 16);
  hex_dump("Ciphertext", pAes->pCipherText, pAes->dwCipherSize, 64);

  STATUS =
      BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
  if (!NT_SUCCESS(STATUS)) {
    printf("[CRYPTO] BCryptOpenAlgorithmProvider FAILED: 0x%08lX\n", STATUS);
    bSTATE = FALSE;
    goto _End;
  }

  STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH,
                             (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
  if (!NT_SUCCESS(STATUS)) {
    printf("[CRYPTO] BCryptGetProperty(OBJECT_LENGTH) FAILED: 0x%08lX\n",
           STATUS);
    bSTATE = FALSE;
    goto _End;
  }

  STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH,
                             (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
  if (!NT_SUCCESS(STATUS)) {
    printf("[CRYPTO] BCryptGetProperty(BLOCK_LENGTH) FAILED: 0x%08lX\n",
           STATUS);
    bSTATE = FALSE;
    goto _End;
  }

  printf("[CRYPTO] BlockSize=%lu  KeyObjectSize=%lu\n", dwBlockSize,
         cbKeyObject);
  if (dwBlockSize != 16) {
    printf("[CRYPTO] UNEXPECTED block size %lu != 16\n", dwBlockSize);
    bSTATE = FALSE;
    goto _End;
  }

  pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
  if (!pbKeyObject) {
    printf("[CRYPTO] HeapAlloc(KeyObject) FAILED\n");
    bSTATE = FALSE;
    goto _End;
  }

  STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE,
                             (PBYTE)BCRYPT_CHAIN_MODE_CBC,
                             sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
  if (!NT_SUCCESS(STATUS)) {
    printf("[CRYPTO] BCryptSetProperty(CBC) FAILED: 0x%08lX\n", STATUS);
    bSTATE = FALSE;
    goto _End;
  }

  STATUS =
      BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject,
                                 cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
  if (!NT_SUCCESS(STATUS)) {
    printf("[CRYPTO] BCryptGenerateSymmetricKey FAILED: 0x%08lX\n", STATUS);
    bSTATE = FALSE;
    goto _End;
  }

  // sizing call — throwaway IV copy
  BYTE ivTmp[IVSIZE];
  memcpy(ivTmp, pAes->pIv, IVSIZE);
  STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText,
                         (ULONG)pAes->dwCipherSize, NULL, ivTmp, IVSIZE, NULL,
                         0, &cbPlain, BCRYPT_BLOCK_PADDING);
  if (!NT_SUCCESS(STATUS)) {
    printf("[CRYPTO] BCryptDecrypt(sizing) FAILED: 0x%08lX\n", STATUS);
    bSTATE = FALSE;
    goto _End;
  }

  printf("[CRYPTO] Plaintext output size will be %lu bytes\n", cbPlain);

  pbPlain = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlain);
  if (!pbPlain) {
    printf("[CRYPTO] HeapAlloc(Plain) FAILED\n");
    bSTATE = FALSE;
    goto _End;
  }

  // real decrypt — IV is still intact
  hex_dump("IV (before real decrypt)", pAes->pIv, IVSIZE, 16);
  STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText,
                         (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE,
                         pbPlain, cbPlain, &cbResult, BCRYPT_BLOCK_PADDING);
  if (!NT_SUCCESS(STATUS)) {
    printf("[CRYPTO] BCryptDecrypt(real) FAILED: 0x%08lX\n", STATUS);
    bSTATE = FALSE;
    goto _End;
  }

  hex_dump("IV (after decrypt)", pAes->pIv, IVSIZE, 16);
  hex_dump("Plaintext", pbPlain, cbResult, 64);
  printf("[CRYPTO] Decrypt SUCCESS — %lu bytes in, %lu bytes out\n",
         pAes->dwCipherSize, cbResult);

_End:
  if (hKeyHandle)
    BCryptDestroyKey(hKeyHandle);
  if (hAlgorithm)
    BCryptCloseAlgorithmProvider(hAlgorithm, 0);
  if (pbKeyObject)
    HeapFree(GetProcessHeap(), 0, pbKeyObject);
  if (pbPlain != NULL && bSTATE) {
    pAes->pPlainText = pbPlain;
    pAes->dwPlainSize = cbResult; // use actual decrypted size, not padded
  } else if (pbPlain) {
    HeapFree(GetProcessHeap(), 0, pbPlain);
  }
  return bSTATE;
}

static BOOL SimpleEncryption(PVOID plain, DWORD plainLen, PBYTE key, PBYTE iv,
                             PVOID *outCipher, DWORD *outLen) {
  AES aes = {0};
  BYTE ivCopy[IVSIZE];
  memcpy(ivCopy, iv, IVSIZE);

  printf("[CRYPTO] SimpleEncryption: %lu bytes\n", plainLen);
  hex_dump("Static IV check", iv, IVSIZE, 16);

  aes.pKey = key;
  aes.pIv = ivCopy;
  aes.pPlainText = (PBYTE)plain;
  aes.dwPlainSize = plainLen;
  if (!InstallAesEncryption(&aes)) {
    printf("[CRYPTO] SimpleEncryption FAILED\n");
    return FALSE;
  }
  *outCipher = aes.pCipherText;
  *outLen = aes.dwCipherSize;
  printf("[CRYPTO] SimpleEncryption OK — %lu -> %lu bytes\n", plainLen,
         *outLen);
  return TRUE;
}

static BOOL SimpleDecryption(PVOID cipher, DWORD cipherLen, PBYTE key, PBYTE iv,
                             PVOID *outPlain, DWORD *outLen) {
  AES aes = {0};
  BYTE ivCopy[IVSIZE];
  memcpy(ivCopy, iv, IVSIZE);

  printf("[CRYPTO] SimpleDecryption: %lu bytes\n", cipherLen);
  hex_dump("Static IV check", iv, IVSIZE, 16);

  aes.pKey = key;
  aes.pIv = ivCopy;
  aes.pCipherText = (PBYTE)cipher;
  aes.dwCipherSize = cipherLen;
  if (!InstallAesDecryption(&aes)) {
    printf("[CRYPTO] SimpleDecryption FAILED\n");
    return FALSE;
  }
  *outPlain = aes.pPlainText;
  *outLen = aes.dwPlainSize;
  printf("[CRYPTO] SimpleDecryption OK — %lu -> %lu bytes\n", cipherLen,
         *outLen);
  return TRUE;
}

BOOL aes_encrypt_payload(PBYTE plain, DWORD plainLen, PVOID *outCipher,
                         DWORD *outLen) {
  printf("[CRYPTO] >>>>>> aes_encrypt_payload called <<<<<<\n");
  return SimpleEncryption(plain, plainLen, aes_key, aes_iv, outCipher, outLen);
}

BOOL aes_decrypt_payload(PBYTE cipher, DWORD cipherLen, PVOID *outPlain,
                         DWORD *outLen) {
  printf("[CRYPTO] >>>>>> aes_decrypt_payload called <<<<<<\n");
  return SimpleDecryption(cipher, cipherLen, aes_key, aes_iv, outPlain, outLen);
}

VOID crypto_wipe_keys(VOID) {
  printf("[CRYPTO] Wiping keys from memory\n");
  SecureZeroMemory(aes_key, KEYSIZE);
  SecureZeroMemory(aes_iv, IVSIZE);
}