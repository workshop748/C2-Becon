// linux-agent/include/recon_linux.h
#pragma once
#include <stddef.h>

#define MAX_PORTS_L    64
#define MAX_SERVICES_L 32

typedef struct {
    char os[32];
    char privilege_level[16];
    int  open_ports[MAX_PORTS_L];
    int  port_count;
    char running_services[MAX_SERVICES_L][64];
    int  service_count;
    int  domain_joined;
    int  antivirus_running;
    int  writable_cron;
    int  setuid_binaries;
    int  sudo_misconfigured;
    char hostname[256];
    char username[256];
    char os_version[128];
    int  pid;
    char arch[8];
    char ip[46];
    int  is_debugged;
    int  is_vm;
    char current_phase[32];
} checkin_info_linux;

// Collect all recon data
int recon_collect_linux(checkin_info_linux* info);

// Serialize to JSON matching AgentFindings schema
int recon_serialize_linux(const checkin_info_linux* info,
                          char** json_out, size_t* json_len);

// Print recon info to stdout
void recon_print_linux(const checkin_info_linux* info);
