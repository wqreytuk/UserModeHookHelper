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
static DWORD s_ControllerPid = 0;
// Protected PID tracking
static DWORD s_ProtectedPids[DRIVERCTX_MAX_PROTECTED_PIDS] = { 0 };
static KSPIN_LOCK s_ProtectedPidLock;
// Registry-backed blocked DLL list
static PUNICODE_STRING g_BlockedDllList = NULL;
static ULONG g_BlockedDllCount = 0;
static KSPIN_LOCK g_BlockedDllLock;
// Protected process name list
static PUNICODE_STRING g_ProtectedProcList = NULL;
static ULONG g_ProtectedProcCount = 0;
static KSPIN_LOCK g_ProtectedProcLock;

static VOID DriverCtx_FreeBlockedDllList() {
    KIRQL irql; KeAcquireSpinLock(&g_BlockedDllLock, &irql);
    if (g_BlockedDllList) {
        for (ULONG i = 0; i < g_BlockedDllCount; ++i) {
            if (g_BlockedDllList[i].Buffer) ExFreePoolWithTag(g_BlockedDllList[i].Buffer, tag_ctx);
        }
        ExFreePoolWithTag(g_BlockedDllList, tag_ctx);
        g_BlockedDllList = NULL; g_BlockedDllCount = 0;
    }
    KeReleaseSpinLock(&g_BlockedDllLock, irql);
}

static VOID DriverCtx_FreeProtectedProcList() {
    KIRQL irql; KeAcquireSpinLock(&g_ProtectedProcLock, &irql);
    if (g_ProtectedProcList) {
        for (ULONG i = 0; i < g_ProtectedProcCount; ++i) {
            if (g_ProtectedProcList[i].Buffer) ExFreePoolWithTag(g_ProtectedProcList[i].Buffer, tag_ctx);
        }
        ExFreePoolWithTag(g_ProtectedProcList, tag_ctx);
        g_ProtectedProcList = NULL; g_ProtectedProcCount = 0;
    }
    KeReleaseSpinLock(&g_ProtectedProcLock, irql);
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
    // Swap under lock
    KIRQL irql; KeAcquireSpinLock(&g_BlockedDllLock, &irql);
    if (g_BlockedDllList) {
        for (ULONG i = 0; i < g_BlockedDllCount; ++i) if (g_BlockedDllList[i].Buffer) ExFreePoolWithTag(g_BlockedDllList[i].Buffer, tag_ctx);
        ExFreePoolWithTag(g_BlockedDllList, tag_ctx);
    }
    g_BlockedDllList = arr; g_BlockedDllCount = count;
    KeReleaseSpinLock(&g_BlockedDllLock, irql);
    return STATUS_SUCCESS;
}

NTSTATUS DriverCtx_LoadProtectedProcListFromRegistry() {
    OBJECT_ATTRIBUTES oa; UNICODE_STRING regPath;
    RtlInitUnicodeString(&regPath, REG_PERSIST_REGPATH L"\\");
    InitializeObjectAttributes(&oa, &regPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    HANDLE hKey = NULL; NTSTATUS st = ZwOpenKey(&hKey, KEY_READ, &oa);
    if (!NT_SUCCESS(st)) return st;
    UNICODE_STRING valName; RtlInitUnicodeString(&valName, REG_PROTECTED_PROCESS_NAME);
    ULONG len = 0; st = ZwQueryValueKey(hKey, &valName, KeyValueFullInformation, NULL, 0, &len);
    if (st != STATUS_BUFFER_TOO_SMALL && st != STATUS_BUFFER_OVERFLOW) { ZwClose(hKey); return STATUS_NOT_FOUND; }
    PKEY_VALUE_FULL_INFORMATION info = (PKEY_VALUE_FULL_INFORMATION)ExAllocatePoolWithTag(PagedPool, len, tag_ctx);
    if (!info) { ZwClose(hKey); return STATUS_INSUFFICIENT_RESOURCES; }
    st = ZwQueryValueKey(hKey, &valName, KeyValueFullInformation, info, len, &len);
    if (!NT_SUCCESS(st) || info->Type != REG_MULTI_SZ) { ExFreePoolWithTag(info, tag_ctx); ZwClose(hKey); return STATUS_INVALID_PARAMETER; }
    // Count entries
    ULONG count = 0; WCHAR* p = (WCHAR*)((PUCHAR)info + info->DataOffset);
    while (*p) { UNICODE_STRING u; RtlInitUnicodeString(&u, p); count++; p += u.Length / sizeof(WCHAR) + 1; }
    PUNICODE_STRING arr = (PUNICODE_STRING)ExAllocatePoolWithTag(NonPagedPool, sizeof(UNICODE_STRING) * count, tag_ctx);
    if (!arr) { ExFreePoolWithTag(info, tag_ctx); ZwClose(hKey); return STATUS_INSUFFICIENT_RESOURCES; }
    RtlZeroMemory(arr, sizeof(UNICODE_STRING) * count);
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
    KIRQL irql; KeAcquireSpinLock(&g_ProtectedProcLock, &irql);
    if (g_ProtectedProcList) {
        for (ULONG i = 0; i < g_ProtectedProcCount; ++i) if (g_ProtectedProcList[i].Buffer) ExFreePoolWithTag(g_ProtectedProcList[i].Buffer, tag_ctx);
        ExFreePoolWithTag(g_ProtectedProcList, tag_ctx);
    }
    g_ProtectedProcList = arr; g_ProtectedProcCount = count;
    KeReleaseSpinLock(&g_ProtectedProcLock, irql);
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

VOID DriverCtx_SetControllerPid(DWORD Pid) {
    s_ControllerPid = Pid;
}

DWORD DriverCtx_GetControllerPid(VOID) {
    return s_ControllerPid;
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

    KIRQL irql; KeAcquireSpinLock(&g_BlockedDllLock, &irql);
    for (ULONG i = 0; i < g_BlockedDllCount; ++i) {
        if (SL_RtlSuffixUnicodeString(&g_BlockedDllList[i], &nameInfo->FinalComponent, TRUE)) {
            KeReleaseSpinLock(&g_BlockedDllLock, irql);
            return TRUE;
        }
    }
    KeReleaseSpinLock(&g_BlockedDllLock, irql);
    return FALSE;
}
// Protected PID helpers
VOID DriverCtx_AddProtectedPid(DWORD pid) {
    if (pid == 0) return;
    KIRQL irql; KeAcquireSpinLock(&s_ProtectedPidLock, &irql);
    // If already present, skip
    for (int i = 0; i < DRIVERCTX_MAX_PROTECTED_PIDS; ++i) {
        if (s_ProtectedPids[i] == pid) { KeReleaseSpinLock(&s_ProtectedPidLock, irql); return; }
    }
    // Insert into first empty slot, or replace oldest (slot 0) if full
    for (int i = 0; i < DRIVERCTX_MAX_PROTECTED_PIDS; ++i) {
        if (s_ProtectedPids[i] == 0) { s_ProtectedPids[i] = pid; KeReleaseSpinLock(&s_ProtectedPidLock, irql); return; }
    }
    s_ProtectedPids[0] = pid;
    KeReleaseSpinLock(&s_ProtectedPidLock, irql);
}

VOID DriverCtx_RemoveProtectedPid(DWORD pid) {
    if (pid == 0) return;
    KIRQL irql; KeAcquireSpinLock(&s_ProtectedPidLock, &irql);
    for (int i = 0; i < DRIVERCTX_MAX_PROTECTED_PIDS; ++i) {
        if (s_ProtectedPids[i] == pid) { s_ProtectedPids[i] = 0; break; }
    }
    KeReleaseSpinLock(&s_ProtectedPidLock, irql);
}

BOOLEAN DriverCtx_IsProtectedPid(DWORD pid) {
    if (pid == 0) return FALSE;
    KIRQL irql; KeAcquireSpinLock(&s_ProtectedPidLock, &irql);
    for (int i = 0; i < DRIVERCTX_MAX_PROTECTED_PIDS; ++i) {
        if (s_ProtectedPids[i] == pid) { KeReleaseSpinLock(&s_ProtectedPidLock, irql); return TRUE; }
    }
    KeReleaseSpinLock(&s_ProtectedPidLock, irql);
    return FALSE;
}

// Initialize locks for protected PIDs and blocked DLLs at load time
 VOID DriverCtx_InitLocksOnce() {
    static LONG initialized = 0;
    if (InterlockedCompareExchange(&initialized, 1, 0) == 0) {
        KeInitializeSpinLock(&s_ProtectedPidLock);
        KeInitializeSpinLock(&g_BlockedDllLock);
        KeInitializeSpinLock(&g_ProtectedProcLock);
    }
}

BOOLEAN DriverCtx_IsProtectedProcessName(_In_ PUNICODE_STRING imageName) {
    if (!imageName) return FALSE;
    KIRQL irql; KeAcquireSpinLock(&g_ProtectedProcLock, &irql);
    for (ULONG i = 0; i < g_ProtectedProcCount; ++i) {
        if (SL_RtlSuffixUnicodeString(&g_ProtectedProcList[i], imageName, TRUE)) {
            KeReleaseSpinLock(&g_ProtectedProcLock, irql);
            return TRUE;
        }
    }
    KeReleaseSpinLock(&g_ProtectedProcLock, irql);
    return FALSE;
}
