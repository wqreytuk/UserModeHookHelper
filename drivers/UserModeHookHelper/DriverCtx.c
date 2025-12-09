#include "DriverCtx.h"
#include "PE.h"
#include "Trace.h"
#include "StrLib.h"

static PFLT_FILTER s_Filter = NULL;

static PFLT_PORT s_ServerPort = NULL;
static PWSTR s_UserDir = NULL;
static BOOLEAN s_GlobalHookMode = FALSE;
static DWORD64 s_ssdt;
static DRIVERCTX_OSVER s_OsVer = {0}; 
static DWORD s_ControllerPid = 0;
static UNICODE_STRING BlockedDll[] = {
   RTL_CONSTANT_STRING(L"TmUmEvt64.dll"),
   RTL_CONSTANT_STRING(L"tmmon64.dll"),
   RTL_CONSTANT_STRING(L"TmAMSIProvider64.dll")
};
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

// Simple built-in blocked DLL list; compare by final component (case-insensitive)
BOOLEAN DriverCtx_IsBlockedDllName(_In_ PFLT_FILE_NAME_INFORMATION nameInfo) {
	if (nameInfo == NULL) return FALSE;

	BOOLEAN should_block = FALSE;
	for (size_t i = 0; i < ARRAYSIZE(BlockedDll); i++) {
		should_block = SL_RtlSuffixUnicodeString(&BlockedDll[i], &nameInfo->FinalComponent, TRUE);
		if (should_block) {
			// Log(L"third party dll Path=%wZ%wZ is trying to load into our process, blocked\n", &nameInfo->ParentDir, &nameInfo->FinalComponent);
			return should_block;
		}
	}
	return FALSE;
}
