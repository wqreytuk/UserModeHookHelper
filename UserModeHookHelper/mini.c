#include "mini.h"
#include "SysCallback.h"
#include "FltCommPort.h"
#include "ListLib.h"
#include "Trace.h"
#include "HookList.h"
#include "PortCtx.h"
#include "DriverCtx.h"
NTSTATUS
MiniUnload(
	FLT_FILTER_UNLOAD_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(Flags);

	// free port context related resources (encapsulated in PortCtx module)
	PortCtx_Uninit();

	// free hook list entries (encapsulated in HookList module)
	HookList_Uninit();

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
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	// Do nothing, just let the I/O continue
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
