#ifndef DRIVERCTX_H
#define DRIVERCTX_H

#include "Common.h"

/*
 * DriverCtx module
 *
 * Purpose:
 *   Provide a minimal, well-documented accessor layer for driver-level
 *   global handles (filter and server port). This reduces direct global
 *   access and centralizes ownership semantics.
 *
 * API contract:
 *   - DriverCtx_SetFilter / DriverCtx_GetFilter: set/get the PFLT_FILTER
 *     handle. Typically set once during DriverEntry and cleared during unload.
 *   - DriverCtx_SetServerPort / DriverCtx_GetServerPort: set/get the
 *     communication server port handle. Set when the port is created and
 *     cleared on close/unload.
 *   - DriverCtx_Clear* helpers reset stored pointers to NULL.
 *
 * Thread-safety:
 *   These are simple setters/getters; the typical driver lifecycle (set in
 *   DriverEntry, cleared during unload) makes them safe without additional
 *   synchronization. If you plan concurrent mutations, add synchronization.
 */

typedef struct _ResolveAcgWork_WORKITEM {
	WORK_QUEUE_ITEM Item;
} ResolveAcgWork_WORKITEM, *PResolveAcgWork_WORKITEM;
 
VOID DriverCtx_SetFilter(PFLT_FILTER Filter);
PFLT_FILTER DriverCtx_GetFilter(VOID);
DWORD64 DriverCtx_GetSSDT(); 
VOID DriverCtx_SetSSDT(DWORD64 ssdt);
VOID DriverCtx_SetServerPort(PFLT_PORT ServerPort);
PFLT_PORT DriverCtx_GetServerPort(VOID);
VOID DriverCtx_ClearServerPort(VOID);
VOID DriverCtx_ClearFilter(VOID);

// User-mode base directory where DLLs are located (UTF-16LE string allocated
// from NonPagedPool). These helpers set/get/clear a single global value.
NTSTATUS DriverCtx_SetUserDir(PCWSTR dir, SIZE_T bytes);
PWSTR DriverCtx_GetUserDir(VOID);
VOID DriverCtx_ClearUserDir(VOID);

// Global hook mode state stored in DriverCtx (avoid raw globals)
VOID DriverCtx_SetGlobalHookMode(BOOLEAN Enabled);
BOOLEAN DriverCtx_GetGlobalHookMode(VOID);

// Track controller process id (UMController.exe)
VOID DriverCtx_SetControllerPid(DWORD Pid);
DWORD DriverCtx_GetControllerPid(VOID);

// DLL block list lookup (final component case-insensitive)
BOOLEAN DriverCtx_IsBlockedDllName(_In_ PFLT_FILE_NAME_INFORMATION nameinfo);

// OS version info stored in driver context
typedef struct _DRIVERCTX_OSVER {
	ULONG Major;
	ULONG Minor;
	ULONG Build;
} DRIVERCTX_OSVER, *PDRIVERCTX_OSVER;

NTSTATUS DriverCtx_LoadBlockedDllListFromRegistry();
VOID DriverCtx_SetOsVersion(ULONG Major, ULONG Minor, ULONG Build);
DRIVERCTX_OSVER DriverCtx_GetOsVersion(VOID);

#endif
