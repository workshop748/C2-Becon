// include/injection.h
#pragma once
#include <windows.h>

// Mod 130: Ghost process injection (T1055.012)
BOOL ghost_inject(LPCSTR targetExe, PBYTE payload, DWORD payloadSize);

// Mod 114: Classic DLL injection (T1055.001)
BOOL dll_inject(DWORD targetPid, LPCSTR dllPath);
