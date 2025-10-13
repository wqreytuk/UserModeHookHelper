#ifndef INJECT_H
#define INJECT_H

#include "Common.h"


typedef VOID(*PKNORMAL_ROUTINE)(
	PVOID NormalContext,
	PVOID SystemArgument1,
	PVOID SystemArgument2
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


// Initialize/uninitialize injection subsystem
NTSTATUS Inject_Init(VOID);
VOID Inject_Uninit(VOID);

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
NTSTATUS Inject_Perform(PEPROCESS Process, PIMAGE_INFO ImageInfo);

#endif
