#include "DriverCtx.h"
#include "PE.h"
#include "Trace.h"

static PFLT_FILTER s_Filter = NULL;
static PFLT_PORT s_ServerPort = NULL;
static PWSTR s_UserDir = NULL;
static BOOLEAN s_GlobalHookMode = FALSE;
static DWORD64 s_ssdt;
static DRIVERCTX_OSVER s_OsVer = {0}; 
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

VOID DriverCtx_SetOsVersion(ULONG Major, ULONG Minor, ULONG Build) {
    s_OsVer.Major = Major;
    s_OsVer.Minor = Minor;
    s_OsVer.Build = Build;
}

DRIVERCTX_OSVER DriverCtx_GetOsVersion(VOID) {
    return s_OsVer;
}
