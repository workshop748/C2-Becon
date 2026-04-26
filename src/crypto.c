#include "common.h"
#include "crypto.h"

static BYTE aes_key[KEYSIZE] = {
    0x3E,0x31,0xF4,0x00,0x50,0xB6,0x6E,0xB8,
    0xF6,0x98,0x95,0x27,0x43,0x27,0xC0,0x55,
    0xEB,0xDB,0xE1,0x7F,0x05,0xFE,0x65,0x6D,
    0x0F,0xA6,0x5B,0x00,0x33,0xE6,0xD9,0x0B
};
static BYTE aes_iv[IVSIZE] = {
    0xB4,0xC8,0x1D,0x1D,0x14,0x7C,0xCB,0xFA,
    0x07,0x42,0xD9,0xED,0x1A,0x86,0xD9,0xCD
};

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

    STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(STATUS)) { bSTATE = FALSE; goto _End; }

    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(STATUS)) { bSTATE = FALSE; goto _End; }

    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(STATUS)) { bSTATE = FALSE; goto _End; }

    if (dwBlockSize != 16) { bSTATE = FALSE; goto _End; }

    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (!pbKeyObject) { bSTATE = FALSE; goto _End; }

    STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE,
                               (PBYTE)BCRYPT_CHAIN_MODE_CBC,
                               sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(STATUS)) { bSTATE = FALSE; goto _End; }

    STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle,
                                        pbKeyObject, cbKeyObject,
                                        (PBYTE)pAes->pKey, KEYSIZE, 0);
    if (!NT_SUCCESS(STATUS)) { bSTATE = FALSE; goto _End; }

    STATUS = BCryptEncrypt(hKeyHandle, (PUCHAR)pAes->pPlainText,
                           (ULONG)pAes->dwPlainSize, NULL,
                           pAes->pIv, IVSIZE, NULL, 0,
                           &cbCipher, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS)) { bSTATE = FALSE; goto _End; }

    pbCipher = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbCipher);
    if (!pbCipher) { bSTATE = FALSE; goto _End; }

    STATUS = BCryptEncrypt(hKeyHandle, (PUCHAR)pAes->pPlainText,
                           (ULONG)pAes->dwPlainSize, NULL,
                           pAes->pIv, IVSIZE, pbCipher, cbCipher,
                           &cbResult, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS)) { bSTATE = FALSE; goto _End; }

_End:
    if (hKeyHandle)  BCryptDestroyKey(hKeyHandle);
    if (hAlgorithm)  BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    if (pbKeyObject) HeapFree(GetProcessHeap(), 0, pbKeyObject);
    if (pbCipher != NULL && bSTATE) {
        pAes->pCipherText  = pbCipher;
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

    STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(STATUS)) { bSTATE = FALSE; goto _End; }

    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(STATUS)) { bSTATE = FALSE; goto _End; }

    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(STATUS)) { bSTATE = FALSE; goto _End; }

    if (dwBlockSize != 16) { bSTATE = FALSE; goto _End; }

    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (!pbKeyObject) { bSTATE = FALSE; goto _End; }

    STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE,
                               (PBYTE)BCRYPT_CHAIN_MODE_CBC,
                               sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(STATUS)) { bSTATE = FALSE; goto _End; }

    STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle,
                                        pbKeyObject, cbKeyObject,
                                        (PBYTE)pAes->pKey, KEYSIZE, 0);
    if (!NT_SUCCESS(STATUS)) { bSTATE = FALSE; goto _End; }

    STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText,
                           (ULONG)pAes->dwCipherSize, NULL,
                           pAes->pIv, IVSIZE, NULL, 0,
                           &cbPlain, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS)) { bSTATE = FALSE; goto _End; }

    pbPlain = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlain);
    if (!pbPlain) { bSTATE = FALSE; goto _End; }

    STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText,
                           (ULONG)pAes->dwCipherSize, NULL,
                           pAes->pIv, IVSIZE, pbPlain, cbPlain,
                           &cbResult, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS)) { bSTATE = FALSE; goto _End; }

_End:
    if (hKeyHandle)  BCryptDestroyKey(hKeyHandle);
    if (hAlgorithm)  BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    if (pbKeyObject) HeapFree(GetProcessHeap(), 0, pbKeyObject);
    if (pbPlain != NULL && bSTATE) {
        pAes->pPlainText  = pbPlain;
        pAes->dwPlainSize = cbPlain;
    } else if (pbPlain) {
        HeapFree(GetProcessHeap(), 0, pbPlain);
    }
    return bSTATE;
}

static BOOL SimpleEncryption(PVOID plain, DWORD plainLen, PBYTE key, PBYTE iv,
                              PVOID *outCipher, DWORD *outLen) {
    AES aes = {0};
    aes.pKey = key; aes.pIv = iv;
    aes.pPlainText = (PBYTE)plain; aes.dwPlainSize = plainLen;
    if (!InstallAesEncryption(&aes)) return FALSE;
    *outCipher = aes.pCipherText; *outLen = aes.dwCipherSize;
    return TRUE;
}

static BOOL SimpleDecryption(PVOID cipher, DWORD cipherLen, PBYTE key, PBYTE iv,
                              PVOID *outPlain, DWORD *outLen) {
    AES aes = {0};
    aes.pKey = key; aes.pIv = iv;
    aes.pCipherText = (PBYTE)cipher; aes.dwCipherSize = cipherLen;
    if (!InstallAesDecryption(&aes)) return FALSE;
    *outPlain = aes.pPlainText; *outLen = aes.dwPlainSize;
    return TRUE;
}

BOOL aes_encrypt_payload(PBYTE plain, DWORD plainLen, PVOID *outCipher, DWORD *outLen) {
    return SimpleEncryption(plain, plainLen, aes_key, aes_iv, outCipher, outLen);
}

BOOL aes_decrypt_payload(PBYTE cipher, DWORD cipherLen, PVOID *outPlain, DWORD *outLen) {
    return SimpleDecryption(cipher, cipherLen, aes_key, aes_iv, outPlain, outLen);
}

VOID crypto_wipe_keys(VOID) {
    SecureZeroMemory(aes_key, KEYSIZE);
    SecureZeroMemory(aes_iv,  IVSIZE);
}
