// include/ntdefs.h — Custom PEB/LDR struct definitions for MinGW
// MinGW's <winternl.h> exposes a minimal LDR_DATA_TABLE_ENTRY that
// lacks the fields we need for PEB walking (BaseDllName, DllBase,
// InMemoryOrderLinks). We define the full layouts here.
//
// These match the actual Windows x64/x86 memory layout.
#pragma once
#include <windows.h>

// Prevent conflict if <winternl.h> is also included
#ifndef _NTDEF_CUSTOM_
#define _NTDEF_CUSTOM_

// ── UNICODE_STRING ──────────────────────────────────────────────
#ifndef _UNICODE_STRING_DEFINED
#define _UNICODE_STRING_DEFINED
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
#endif

// ── LDR_DATA_TABLE_ENTRY (full) ─────────────────────────────────
typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY  InLoadOrderLinks;
    LIST_ENTRY  InMemoryOrderLinks;
    LIST_ENTRY  InInitializationOrderLinks;
    PVOID       DllBase;
    PVOID       EntryPoint;
    ULONG       SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG       Flags;
    USHORT      LoadCount;
    USHORT      TlsIndex;
    LIST_ENTRY  HashLinks;
    PVOID       SectionPointer;
    ULONG       CheckSum;
    ULONG       TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

// ── PEB_LDR_DATA ────────────────────────────────────────────────
typedef struct _PEB_LDR_DATA {
    ULONG       Length;
    BOOLEAN     Initialized;
    HANDLE      SsHandle;
    LIST_ENTRY  InLoadOrderModuleList;
    LIST_ENTRY  InMemoryOrderModuleList;
    LIST_ENTRY  InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

// ── PEB (minimal — only the fields we access) ───────────────────
typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN SpareBool;
    HANDLE  Mutant;
    PVOID   ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    // ... many more fields follow but we don't need them
} PEB, *PPEB;

// ── OBJECT_ATTRIBUTES (needed by Nt* function typedefs) ─────────
#ifndef _OBJECT_ATTRIBUTES_DEFINED
#define _OBJECT_ATTRIBUTES_DEFINED
typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
#endif

// ── NT status / calling convention ──────────────────────────────
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

#ifndef NTAPI
#define NTAPI __stdcall
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#endif // _NTDEF_CUSTOM_
