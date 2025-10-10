#include "mini.h"
#include "SysCallback.h"
#include "FltCommPort.h"
#include "ListLib.h"
#include "Trace.h"
NTSTATUS
MiniUnload(
	FLT_FILTER_UNLOAD_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(Flags);

	// free port context related resources
	ExAcquireResourceExclusiveLite(&gVar.m_PortCtxListLock, TRUE);

	// Remove entries one-by-one from the list and free them.  This avoids
	// iterating over freed memory (use-after-free) which the previous
	// LIST_FOR_EACH_ENTRY + free caused.
	while (!IsListEmpty(&gVar.m_PortCtxList)) {
		PLIST_ENTRY entry = RemoveHeadList(&gVar.m_PortCtxList);
		PCOMM_CONTEXT ctx = CONTAINING_RECORD(entry, COMM_CONTEXT, m_entry);
		// RemoveHeadList already unlinks the entry from the list, so just free.
		ExFreePoolWithTag(ctx, tag_port);
	}

	// list is now empty
	InitializeListHead(&gVar.m_PortCtxList);
	ExReleaseResourceLite(&gVar.m_PortCtxListLock);

	// free ERESOURCE
	ExDeleteResourceLite(&gVar.m_PortCtxListLock);

	// free hook list entries
	ExAcquireResourceExclusiveLite(&gVar.m_HookListLock, TRUE);
	while (!IsListEmpty(&gVar.m_HookList)) {
		PLIST_ENTRY entry = RemoveHeadList(&gVar.m_HookList);
		PHOOK_ENTRY p = CONTAINING_RECORD(entry, HOOK_ENTRY, ListEntry);
		if (p->NtPath.Buffer) {
			ExFreePoolWithTag(p->NtPath.Buffer, tag_port);
		}
		ExFreePoolWithTag(p, tag_port);
	}
	InitializeListHead(&gVar.m_HookList);
	ExReleaseResourceLite(&gVar.m_HookListLock);
	ExDeleteResourceLite(&gVar.m_HookListLock);

	// Unregister sys notify routine
	PsSetCreateProcessNotifyRoutine(ProcessCrNotify, TRUE);
	PsRemoveLoadImageNotifyRoutine(LoadImageNotify);

	if (gVar.m_ServerPort) {
		FltCloseCommunicationPort(gVar.m_ServerPort);
		gVar.m_ServerPort = NULL;
	}

	if (gVar.m_Filter) { 
		FltUnregisterFilter(gVar.m_Filter);
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
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	// Do nothing, just let the I/O continue
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
