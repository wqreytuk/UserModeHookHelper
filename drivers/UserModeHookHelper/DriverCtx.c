#include "DriverCtx.h"
#include "PE.h"
#include "Trace.h"
#include "StrLib.h"
#include "MacroDef.h"
#include <ntddk.h>
#include "../../Shared/SharedMacroDef.h"

static PFLT_FILTER s_Filter = NULL;

static PFLT_PORT s_ServerPort = NULL;
static PWSTR s_UserDir = NULL;
static BOOLEAN s_GlobalHookMode = FALSE;
static DWORD64 s_ssdt;
static DRIVERCTX_OSVER s_OsVer = {0}; 
// Protected process PIDs (small fixed array)
static DWORD s_ProtectedPids[DRIVERCTX_MAX_PROTECTED_PIDS] = {0};
static KSPIN_LOCK s_ProtectedPidLock;
// Registry-backed blocked DLL list
static PUNICODE_STRING g_BlockedDllList = NULL;
static ULONG g_BlockedDllCount = 0;

static VOID DriverCtx_FreeBlockedDllList() {
    if (g_BlockedDllList) {
        for (ULONG i = 0; i < g_BlockedDllCount; ++i) {
            if (g_BlockedDllList[i].Buffer) ExFreePoolWithTag(g_BlockedDllList[i].Buffer, tag_ctx);
        }
        ExFreePoolWithTag(g_BlockedDllList, tag_ctx);
        g_BlockedDllList = NULL; g_BlockedDllCount = 0;
    }
}

NTSTATUS DriverCtx_LoadBlockedDllListFromRegistry() {
    // Open HKLM\... per REG_PERSIST_REGPATH
    OBJECT_ATTRIBUTES oa; UNICODE_STRING regPath;
    RtlInitUnicodeString(&regPath, REG_PERSIST_REGPATH L"\\");
    InitializeObjectAttributes(&oa, &regPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    HANDLE hKey = NULL; NTSTATUS st = ZwOpenKey(&hKey, KEY_READ, &oa);
    if (!NT_SUCCESS(st)) return st;
    UNICODE_STRING valName; RtlInitUnicodeString(&valName, REG_BLOCKED_DLL_NAME);
    ULONG len = 0; st = ZwQueryValueKey(hKey, &valName, KeyValueFullInformation, NULL, 0, &len);
    if (st != STATUS_BUFFER_TOO_SMALL && st != STATUS_BUFFER_OVERFLOW) { ZwClose(hKey); return STATUS_NOT_FOUND; }
    PKEY_VALUE_FULL_INFORMATION info = (PKEY_VALUE_FULL_INFORMATION)ExAllocatePoolWithTag(PagedPool, len, tag_ctx);
    if (!info) { ZwClose(hKey); return STATUS_INSUFFICIENT_RESOURCES; }
    st = ZwQueryValueKey(hKey, &valName, KeyValueFullInformation, info, len, &len);
    if (!NT_SUCCESS(st) || info->Type != REG_MULTI_SZ) { ExFreePoolWithTag(info, tag_ctx); ZwClose(hKey); return STATUS_INVALID_PARAMETER; }
    // Count entries
    ULONG count = 0; WCHAR* p = (WCHAR*)((PUCHAR)info + info->DataOffset);
    while (*p) { UNICODE_STRING u; RtlInitUnicodeString(&u, p); count++; p += u.Length / sizeof(WCHAR) + 1; }
    // Allocate array
    PUNICODE_STRING arr = (PUNICODE_STRING)ExAllocatePoolWithTag(NonPagedPool, sizeof(UNICODE_STRING) * count, tag_ctx);
    if (!arr) { ExFreePoolWithTag(info, tag_ctx); ZwClose(hKey); return STATUS_INSUFFICIENT_RESOURCES; }
    RtlZeroMemory(arr, sizeof(UNICODE_STRING) * count);
    // Fill entries
    p = (WCHAR*)((PUCHAR)info + info->DataOffset); ULONG idx = 0;
    while (*p && idx < count) {
        UNICODE_STRING u; RtlInitUnicodeString(&u, p);
        USHORT bytes = u.Length + sizeof(WCHAR);
        PWSTR buf = (PWSTR)ExAllocatePoolWithTag(NonPagedPool, bytes, tag_ctx);
        if (!buf) { ExFreePoolWithTag(info, tag_ctx); ExFreePoolWithTag(arr, tag_ctx); ZwClose(hKey); return STATUS_INSUFFICIENT_RESOURCES; }
        RtlCopyMemory(buf, u.Buffer, u.Length); buf[u.Length/sizeof(WCHAR)] = L'\0';
        arr[idx].Buffer = buf; arr[idx].Length = u.Length; arr[idx].MaximumLength = bytes;
        idx++; p += u.Length / sizeof(WCHAR) + 1;
    }
    ExFreePoolWithTag(info, tag_ctx); ZwClose(hKey);
    // Set-once assignment (no hot updates during runtime)
    if (g_BlockedDllList) {
        for (ULONG i = 0; i < g_BlockedDllCount; ++i) if (g_BlockedDllList[i].Buffer) ExFreePoolWithTag(g_BlockedDllList[i].Buffer, tag_ctx);
        ExFreePoolWithTag(g_BlockedDllList, tag_ctx);
    }
    g_BlockedDllList = arr; g_BlockedDllCount = count;
    return STATUS_SUCCESS;
}
VOID DriverCtx_SetFilter(PFLT_FILTER Filter) {
    s_Filter = Filter;
}
PFLT_FILTER DriverCtx_GetFilter(VOID) {
    return s_Filter;
}
DWORD64 DriverCtx_GetSSDT() {
	return s_ssdt;
}
VOID DriverCtx_SetSSDT(DWORD64 ssdt) {
	s_ssdt = ssdt;
}  
VOID DriverCtx_SetServerPort(PFLT_PORT ServerPort) {
    s_ServerPort = ServerPort;
}
PFLT_PORT DriverCtx_GetServerPort(VOID) {
    return s_ServerPort;
}
VOID DriverCtx_ClearServerPort(VOID) {
    s_ServerPort = NULL;
}
VOID DriverCtx_ClearFilter(VOID) {
    s_Filter = NULL;
}

NTSTATUS DriverCtx_SetUserDir(PCWSTR dir, SIZE_T bytes) {
    if (!dir || bytes == 0) return STATUS_INVALID_PARAMETER;
    if (bytes % sizeof(WCHAR) != 0) return STATUS_INVALID_PARAMETER;
    PWSTR buf = ExAllocatePoolWithTag(NonPagedPool, bytes, tag_ctx);
    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;
    RtlCopyMemory(buf, dir, bytes);
    // Free old one
    if (s_UserDir) ExFreePoolWithTag(s_UserDir, tag_ctx);
    s_UserDir = buf;
    return STATUS_SUCCESS;
}

PWSTR DriverCtx_GetUserDir(VOID) {
    return s_UserDir;
}

VOID DriverCtx_ClearUserDir(VOID) {
    if (s_UserDir) {
        ExFreePoolWithTag(s_UserDir, tag_ctx);
        s_UserDir = NULL;
    }
}

VOID DriverCtx_SetGlobalHookMode(BOOLEAN Enabled) {
    s_GlobalHookMode = Enabled ? TRUE : FALSE;
}

BOOLEAN DriverCtx_GetGlobalHookMode(VOID) {
    return s_GlobalHookMode;
}

VOID DriverCtx_AddProtectedPid(DWORD pid) {
    KIRQL irql; KeAcquireSpinLock(&s_ProtectedPidLock, &irql);
    for (int i = 0; i < DRIVERCTX_MAX_PROTECTED_PIDS; ++i) {
        if (s_ProtectedPids[i] == pid) { KeReleaseSpinLock(&s_ProtectedPidLock, irql); return; }
    }
    for (int i = 0; i < DRIVERCTX_MAX_PROTECTED_PIDS; ++i) {
        if (s_ProtectedPids[i] == 0) { s_ProtectedPids[i] = pid; break; }
    }
    KeReleaseSpinLock(&s_ProtectedPidLock, irql);
}

VOID DriverCtx_RemoveProtectedPid(DWORD pid) {
    KIRQL irql; KeAcquireSpinLock(&s_ProtectedPidLock, &irql);
    for (int i = 0; i < DRIVERCTX_MAX_PROTECTED_PIDS; ++i) {
        if (s_ProtectedPids[i] == pid) { s_ProtectedPids[i] = 0; break; }
    }
    KeReleaseSpinLock(&s_ProtectedPidLock, irql);
}

BOOLEAN DriverCtx_IsProtectedPid(DWORD pid) {
    KIRQL irql; KeAcquireSpinLock(&s_ProtectedPidLock, &irql);
    for (int i = 0; i < DRIVERCTX_MAX_PROTECTED_PIDS; ++i) {
        if (s_ProtectedPids[i] == pid) { KeReleaseSpinLock(&s_ProtectedPidLock, irql); return TRUE; }
    }
    KeReleaseSpinLock(&s_ProtectedPidLock, irql);
    return FALSE;
}

VOID DriverCtx_SetOsVersion(ULONG Major, ULONG Minor, ULONG Build) {
    s_OsVer.Major = Major;
    s_OsVer.Minor = Minor;
    s_OsVer.Build = Build;
}

DRIVERCTX_OSVER DriverCtx_GetOsVersion(VOID) {
    return s_OsVer;
}

// Registry-backed blocked DLL list; compare by final component (case-insensitive)
BOOLEAN DriverCtx_IsBlockedDllName(_In_ PFLT_FILE_NAME_INFORMATION nameInfo) {
	if (nameInfo == NULL) return FALSE;

    for (ULONG i = 0; i < g_BlockedDllCount; ++i) {
        if (SL_RtlSuffixUnicodeString(&g_BlockedDllList[i], &nameInfo->FinalComponent, TRUE)) {
            return TRUE;
        }
    }
    return FALSE;
}
