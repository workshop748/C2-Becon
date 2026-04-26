#include "anti_analysis.h"
#include "common.h"

BOOL anti_debug_check(VOID) {
    if (IsDebuggerPresent()) {
        printf("[!] anti_debug: IsDebuggerPresent() = TRUE\n");
        return TRUE;
    }

    BOOL remoteDebugger = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger);
    if (remoteDebugger) {
        printf("[!] anti_debug: Remote debugger detected\n");
        return TRUE;
    }

#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    DWORD ntGlobalFlag = *(DWORD *)((PBYTE)pPeb + 0xBC);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
    DWORD ntGlobalFlag = *(DWORD *)((PBYTE)pPeb + 0x68);
#endif
    if (ntGlobalFlag & 0x70) {
        printf("[!] anti_debug: NtGlobalFlag = 0x%X\n", ntGlobalFlag);
        return TRUE;
    }

    return FALSE;
}

BOOL anti_vm_check(VOID) {
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1);
    if (cpuInfo[2] & (1 << 31)) {
        printf("[!] anti_vm: CPUID hypervisor bit set\n");
        return TRUE;
    }

    if (GetTickCount64() < 300000ULL) {
        printf("[!] anti_vm: Uptime < 5 min\n");
        return TRUE;
    }

    MEMORYSTATUSEX mem = {0};
    mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);
    if (mem.ullTotalPhys < (1ULL * 1024 * 1024 * 1024)) {
        printf("[!] anti_vm: Physical memory < 1 GB\n");
        return TRUE;
    }

    SYSTEM_INFO SysInfo = {0};
    GetSystemInfo(&SysInfo);
    if (SysInfo.dwNumberOfProcessors < 2) {
        printf("[!] anti_vm: Single processor detected\n");
        return TRUE;
    }

    HKEY hKey = NULL;
    DWORD dwUsb = 0;

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SYSTEM\\ControlSet001\\Enum\\USBSTOR", 0,
                      KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryInfoKeyA(hKey, NULL, NULL, NULL, &dwUsb, NULL, NULL, NULL, NULL,
                         NULL, NULL, NULL);
        RegCloseKey(hKey);
        hKey = NULL;
        if (dwUsb == 0) {
            printf("[!] anti_vm: No USB history\n");
            return TRUE;
        }
    }

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\VMware, Inc.\\VMware Tools",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        printf("[!] anti_vm: VMware Tools detected\n");
        return TRUE;
    }

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\Oracle\\VirtualBox Guest Additions", 0,
                      KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        printf("[!] anti_vm: VirtualBox detected\n");
        return TRUE;
    }

    return FALSE;
}

BOOL anti_analysis_run(BOOL bEnforce) {
    if (anti_debug_check()) {
        printf("[!] Debugger detected\n");
        if (bEnforce) ExitProcess(0);
    }
    if (anti_vm_check()) {
        printf("[!] VM/sandbox detected\n");
        if (bEnforce) ExitProcess(0);
    }
    printf("[+] Anti-analysis checks complete\n");
    return TRUE;
}
