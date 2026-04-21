// include/crypto.h
#pragma once
#include <windows.h>

// AES-256-CBC encrypt/decrypt
BOOL SimpleEncryption(PVOID pPlaintext, DWORD dwPlainSize,
                      PBYTE pKey, PBYTE pIv,
                      PVOID* pCipherText, DWORD* dwCipherSize);

BOOL SimpleDecryption(PVOID pCipherText, DWORD dwCipherSize,
                      PBYTE pKey, PBYTE pIv,
                      PVOID* pPlainText, DWORD* dwPlainSize);
