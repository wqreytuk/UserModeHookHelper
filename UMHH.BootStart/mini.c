#include "mini.h"
#include "SysCallback.h" 
#include "ListLib.h"
#include "Trace.h"
#include "HookList.h" 
#include "DriverCtx.h"
#include "Inject.h"
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