// include/beacon.h
#pragma once
#include "common.h"


VOID beacon_run();

// Task dispatcher — called when C2 sends a task blob
VOID dispatch_task(BYTE* taskBlob, DWORD taskBlobLen);
