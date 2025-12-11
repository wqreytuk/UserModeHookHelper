#include "mini.h"
#include "SysCallback.h"
#include "FltCommPort.h"
#include "ListLib.h"
#include "Trace.h"
#include "HookList.h"
#include "PortCtx.h"
#include "DriverCtx.h"
#include "Inject.h"
#include <ntifs.h>
#include "StrLib.h"
NTSTATUS
MiniUnload(
	FLT_FILTER_UNLOAD_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(Flags);

	// free port context related resources (encapsulated in PortCtx module)
	// Uninitialize injection module before tearing down port contexts
	Inject_Uninit();
	PortCtx_Uninit();

	// free hook list entries (encapsulated in HookList module)
	HookList_Uninit();

	// Signal unloading to gate work items and broadcasts
	DriverCtx_SetUnloading(TRUE);
	// Wait briefly for outstanding work items to drain
	for (int i = 0; i < 50; ++i) {
		if (DriverCtx_GetOutstandingWorkItems() == 0) break;
		LARGE_INTEGER interval; interval.QuadPart = -100000LL; // 10ms
		KeDelayExecutionThread(KernelMode, FALSE, &interval);
	}
	// Unregister sys notify routine
	PsSetCreateProcessNotifyRoutine(ProcessCrNotify, TRUE);
	PsRemoveLoadImageNotifyRoutine(LoadImageNotify);

	PFLT_PORT sp = DriverCtx_GetServerPort();
	if (sp) {
		FltCloseCommunicationPort(sp);
		DriverCtx_ClearServerPort();
	}

	if (DriverCtx_GetFilter()) {
		FltUnregisterFilter(DriverCtx_GetFilter());
		DriverCtx_ClearFilter();
	}
	Log(L"successfully unloaded minifilter driver\n");
	return STATUS_SUCCESS;
}


// Dummy PreCreate callback
FLT_PREOP_CALLBACK_STATUS
MiniPreCreateCallback(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID* CompletionContext
)
{
	UNREFERENCED_PARAMETER(CompletionContext);
	if (!Data || !FltObjects) return FLT_PREOP_SUCCESS_NO_CALLBACK;
	// Only block for protected processes
	DWORD curPid = (DWORD)(ULONG_PTR)PsGetCurrentProcessId();
	if (!DriverCtx_IsProtectedPid(curPid)) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	// Resolve name and set per-handle context to avoid future name lookups
	PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
	NTSTATUS st = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &nameInfo);
	if (NT_SUCCESS(st) && nameInfo) {
		FltParseFileNameInformation(nameInfo);
		BOOLEAN shouldBlock = DriverCtx_IsBlockedDllName(nameInfo);
		if (shouldBlock) {
			Data->IoStatus.Status = STATUS_ACCESS_DENIED;
			Data->IoStatus.Information = 0;
			FltReleaseFileNameInformation(nameInfo);
			return FLT_PREOP_COMPLETE;
		}
		FltReleaseFileNameInformation(nameInfo);
	}
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// PreRead to block reads of blocked DLLs for the controller process
FLT_PREOP_CALLBACK_STATUS
MiniPreReadCallback(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Outptr_result_maybenull_ PVOID *CompletionContext
)
{
	UNREFERENCED_PARAMETER(CompletionContext);
	if (!Data || !FltObjects) return FLT_PREOP_SUCCESS_NO_CALLBACK;

	// Do NOT resolve filename; honor per-handle context set at create
	PUMHH_STREAMHANDLE_CTX ctx = NULL;
	NTSTATUS gc = FltGetFileContext(FltObjects->Instance,FltObjects->FileObject, (PFLT_CONTEXT*)&ctx);
	if (NT_SUCCESS(gc) && ctx) {
		BOOLEAN blocked = ctx->Blocked ? TRUE : FALSE;
		FltReleaseContext(ctx);
		if (blocked) {
			Data->IoStatus.Status = STATUS_ACCESS_DENIED;
			Data->IoStatus.Information = 0;
			return FLT_PREOP_COMPLETE;
		}
	}
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static SIZE_T _SpanPagesForRange(PVOID Address, SIZE_T Size) {
	PUCHAR base = (PUCHAR)((ULONG_PTR)Address & ~(PAGE_SIZE - 1));
	SIZE_T offset = (SIZE_T)((PUCHAR)Address - base);
	SIZE_T end = offset + Size;
	SIZE_T pages = (end + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
	return pages;
}

BOOLEAN Mini_WriteKernelMemory(PVOID Address, const VOID* Buffer, SIZE_T Size)
{
	if (!Address || !Buffer || Size == 0) return FALSE;
	PUCHAR base = (PUCHAR)((ULONG_PTR)Address & ~(PAGE_SIZE - 1));
	SIZE_T pageOffset = (SIZE_T)((PUCHAR)Address - base);
	SIZE_T span = _SpanPagesForRange(Address, Size);
	PMDL mdl = IoAllocateMdl(base, (ULONG)span, FALSE, FALSE, NULL);
	if (!mdl) return FALSE;
	BOOLEAN ok = FALSE;
	__try {
		MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);
		PVOID mapped = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
		if (mapped) {
			NTSTATUS ps = MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
			if (NT_SUCCESS(ps)) {
				RtlCopyMemory((PUCHAR)mapped + pageOffset, Buffer, Size);
				ok = TRUE;
			}
			MmUnmapLockedPages(mapped, mdl);
		}
		MmUnlockPages(mdl);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		ok = FALSE;
	}
	IoFreeMdl(mdl);
	return ok;
}

BOOLEAN Mini_ReadKernelMemory(PVOID Address, VOID* Buffer, SIZE_T Size)
{
	if (!Address || !Buffer || Size == 0) return FALSE;
	PUCHAR base = (PUCHAR)((ULONG_PTR)Address & ~(PAGE_SIZE - 1));
	SIZE_T pageOffset = (SIZE_T)((PUCHAR)Address - base);
	SIZE_T span = _SpanPagesForRange(Address, Size);
	PMDL mdl = IoAllocateMdl(base, (ULONG)span, FALSE, FALSE, NULL);
	if (!mdl) return FALSE;
	BOOLEAN ok = FALSE;
	__try {
		MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
		PVOID mapped = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
		if (mapped) {
			RtlCopyMemory(Buffer, (PUCHAR)mapped + pageOffset, Size);
			ok = TRUE;
			MmUnmapLockedPages(mapped, mdl);
		}
		MmUnlockPages(mdl);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		ok = FALSE;
	}
	IoFreeMdl(mdl);
	return ok;
}
