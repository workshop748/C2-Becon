#include "killswitch.h"
#include <stdio.h>

// ── Hard kill ────────────────────────────────────────────────────
// Triggered by: C2 sending CMD_KILL, or operator panic button
VOID killswitch_hard() {
  printf("[!] KILLSWITCH: hard kill triggered\n");

  // get own path and delete from disk
  CHAR szPath[MAX_PATH] = {0};
  GetModuleFileNameA(NULL, szPath, MAX_PATH);
  DeleteFileA(szPath);

  // zero the AES key in memory before exit
  extern BYTE aes_key[];
  SecureZeroMemory(aes_key, 32);

  ExitProcess(0);
}

// ── Soft kill ────────────────────────────────────────────────────
// Triggered by: RoE violation, scope gate failure, operator pause
static volatile BOOL g_softKill = FALSE;

VOID killswitch_soft() {
  printf("[!] KILLSWITCH: soft kill — beacon going dormant\n");
  g_softKill = TRUE;
  // beacon_run() loop checks this flag each iteration
}

BOOL killswitch_is_active() { return g_softKill; }

// ── Scope gate ───────────────────────────────────────────────────
// Loaded from engagement_config.json at runtime (your RoE doc)
// Hardcoded fallback for capstone demo
static LPCSTR g_scopedSubnet = "10.10."; // only hit 10.10.x.x

BOOL scope_gate_check(LPCSTR targetHost) {
  if (!targetHost)
    return FALSE;

  // simple prefix check — extend with full CIDR for production
  if (strncmp(targetHost, g_scopedSubnet, strlen(g_scopedSubnet)) == 0) {
    return TRUE;
  }

  printf("[!] SCOPE VIOLATION: %s is out of scope — task refused\n",
         targetHost);
  killswitch_soft();
  return FALSE;
}