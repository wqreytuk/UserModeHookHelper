#include "mini.h"
#include "SysCallback.h" 
#include "ListLib.h"
#include "Trace.h"
#include "HookList.h" 
#include "DriverCtx.h"
#include "Inject.h"
#include <ntifs.h>
NTSTATUS
MiniUnload(
	FLT_FILTER_UNLOAD_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(Flags);

	// free port context related resources (encapsulated in PortCtx module)
	// Uninitialize injection module before tearing down port contexts
	Inject_Uninit();

	// free hook list entries (encapsulated in HookList module)
	HookList_Uninit();

	// Unregister sys notify routine
	PsSetCreateProcessNotifyRoutine(ProcessCrNotify, TRUE);
	PsRemoveLoadImageNotifyRoutine(LoadImageNotify);


	Log(L"successfully unloaded BootStart driver\n");
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
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	// Do nothing, just let the I/O continue
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

	BOOLEAN Mini_WriteKernelMemory(PVOID Address, const VOID* Buffer, SIZE_T Size)
	{
		if (!Address || !Buffer || Size == 0) return FALSE;

		PUCHAR base = (PUCHAR)((ULONG_PTR)Address & ~(PAGE_SIZE - 1));
		SIZE_T pageOffset = (SIZE_T)((PUCHAR)Address - base);
		SIZE_T total = pageOffset + Size;

		PMDL mdl = IoAllocateMdl(base, (ULONG)ALIGN_UP_BY(total, PAGE_SIZE), FALSE, FALSE, NULL);
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

				BOOLEAN Mini_ReadKernelMemory(PVOID Address, VOID* Buffer, SIZE_T Size)
				{
					if (!Address || !Buffer || Size == 0) return FALSE;

					PUCHAR base = (PUCHAR)((ULONG_PTR)Address & ~(PAGE_SIZE - 1));
					SIZE_T pageOffset = (SIZE_T)((PUCHAR)Address - base);
					SIZE_T total = pageOffset + Size;

					PMDL mdl = IoAllocateMdl(base, (ULONG)ALIGN_UP_BY(total, PAGE_SIZE), FALSE, FALSE, NULL);
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