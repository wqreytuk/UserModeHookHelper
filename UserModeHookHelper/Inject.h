#ifndef INJECT_H
#define INJECT_H

#include "Common.h"
// only x64 machine have wow64
#ifdef _M_AMD64
#define INJ_CONFIG_SUPPORTS_WOW64
#endif
typedef enum _INJ_SYSTEM_DLL
{
	INJ_NOTHING_LOADED = 0x0000,
	INJ_SYSARM32_NTDLL_LOADED = 0x0001,
	INJ_SYCHPE32_NTDLL_LOADED = 0x0002,
	INJ_SYSWOW64_NTDLL_LOADED = 0x0004,
	INJ_SYSTEM32_NTDLL_LOADED = 0x0008,
	INJ_SYSTEM32_WOW64_LOADED = 0x0010,
	INJ_SYSTEM32_WOW64WIN_LOADED = 0x0020,
	INJ_SYSTEM32_WOW64CPU_LOADED = 0x0040,
	INJ_SYSTEM32_WOWARMHW_LOADED = 0x0080,
	INJ_SYSTEM32_XTAJIT_LOADED = 0x0100,
} INJ_SYSTEM_DLL; 

VOID Inject_CheckWin7();
// Pending-inject list: holds referenced PEPROCESS pointers for processes
// that need DLL injection when ntdll.dll is loaded.
typedef struct _PENDING_INJECT {
	LIST_ENTRY ListEntry;
	ULONG       LoadedDlls;
	PVOID       LdrLoadDllRoutineAddress;
	BOOLEAN IsInjected;
	PEPROCESS Process; // referenced
	BOOLEAN x64;
} PENDING_INJECT, *PPENDING_INJECT;

typedef
VOID
(NTAPI* PKNORMAL_ROUTINE)(
	_In_ PVOID NormalContext,
	_In_ PVOID SystemArgument1,
	_In_ PVOID SystemArgument2
	);

NTSTATUS
NTAPI
Inject_QueueInjectionApc(
	_In_ KPROCESSOR_MODE ApcMode,
	_In_ PKNORMAL_ROUTINE NormalRoutine,
	_In_ PVOID NormalContext,
	_In_ PVOID SystemArgument1,
	_In_ PVOID SystemArgument2
);
VOID
KeInitializeApc(
	PVOID Apc,
	PVOID Thread,
	PVOID ApcStateIndex,
	PVOID KernelRoutine,
	PVOID  RundownRoutine,
	PVOID NormalRoutine,
	KPROCESSOR_MODE ApcMode,
	PVOID NormalContext
);
VOID Inject_RemovePendingInject(PEPROCESS Process);

// Initialize/uninitialize injection subsystem
NTSTATUS Inject_Init(VOID);
VOID Inject_Uninit(VOID);

VOID
NTAPI
Inject_InjectionApcNormalRoutine(
	_In_ PVOID NormalContext,
	_In_ PVOID SystemArgument1,
	_In_ PVOID SystemArgument2
);

VOID
NTAPI
Inject_ApcKernelRoutine(
	_In_ PKAPC Apc,
	_Inout_ PKNORMAL_ROUTINE* NormalRoutine,
	_Inout_ PVOID* NormalContext,
	_Inout_ PVOID* SystemArgument1,
	_Inout_ PVOID* SystemArgument2
);
// Queue check: compute hash of supplied image name and add process to pending list
// The Process parameter may be a referenced PEPROCESS (e.g. from PsLookupProcessByProcessId)
// or PsGetCurrentProcess(); the pending list will take its own reference when storing.
VOID Inject_CheckAndQueue(PUNICODE_STRING ImageName, PEPROCESS Process);

// (Pending list accessors removed — use Inject_CheckAndQueue and the
// atomic pop behavior in Inject_OnImageLoad.)

// Called from load-image notify to test for ntdll and perform injection
// Pass the PEPROCESS for the process that loaded the image (PsGetCurrentProcess())
// and the image information received by the load-image notify (PIMAGE_INFO).
VOID Inject_OnImageLoad(PUNICODE_STRING FullImageName, PEPROCESS Process, PIMAGE_INFO ImageInfo);

// Perform injection for process. Default implementation is a safe stub that
// only logs the intended action. The real, in-kernel injection implementation
// may be enabled by defining ENABLE_INJECT_IMPL at compile time. Returns an
// NTSTATUS indicating success or failure.
// Inject_Perform performs the actual injection for the supplied process. The
// ImageInfo parameter is the PIMAGE_INFO passed by the kernel load-image
// notify and may be NULL if unavailable. Returns NTSTATUS.
NTSTATUS Inject_Perform(PPENDING_INJECT InjectionInfo);
NTSTATUS Inject_PerformThunkLess(PPENDING_INJECT InjectionInfo);
BOOLEAN Inject_CanInject(PPENDING_INJECT injInfo); 
#endif
