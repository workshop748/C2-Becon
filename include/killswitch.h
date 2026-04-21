#pragma once
#include <windows.h>

// Hard kill — beacon self-destructs immediately
// Deletes own file on disk, zeroes heap, exits
VOID killswitch_hard();

// Soft kill — beacon stops checking in, idles silently
// Used for RoE violations or out-of-scope task detection
VOID killswitch_soft();

// Check if soft kill is active (called in beacon_run loop)
BOOL killswitch_is_active();

// Scope gate check — call before executing any task
// Returns FALSE if target is out of RoE scope
BOOL scope_gate_check(LPCSTR targetHost);