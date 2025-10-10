#include "Common.h"
#include "Trace.h"
#include "mini.h"
#include "SysCallback.h"
#include "HookList.h"
#include "PortCtx.h"
#include "DriverCtx.h"
 
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
	{ IRP_MJ_CREATE,
	  0,
	  MiniPreCreateCallback,
	  NULL },   // Post-operation = NULL
	{ IRP_MJ_OPERATION_END } // terminator
};

// Filter registration structure
const FLT_REGISTRATION FilterRegistration = {
	sizeof(FLT_REGISTRATION),        // Size
	FLT_REGISTRATION_VERSION,        // Version
	0,                               // Flags
	NULL,                            // Context registration
	Callbacks,                       // Operation callbacks
	MiniUnload,                      // FilterUnload
	NULL,                            // InstanceSetup
	NULL,                            // InstanceQueryTeardown
	NULL,                            // InstanceTeardownStart
	NULL,                            // InstanceTeardownComplete
	NULL,                            // GenerateFileName
	NULL,                            // GenerateDestinationFileName
	NULL,                            // NormalizeNameComponent
	NULL,                            // NormalizeNameComponentEx
	NULL                             // SectionNotificationCallback
};

// mainn
NTSTATUS
	DriverEntry(
		_In_ PDRIVER_OBJECT  DriverObject,
		_In_ PUNICODE_STRING RegistryPath
	)
{
	DbgBreakPoint();
	(RegistryPath); 
	Log(L"DriverEntry\n");

	// initialize modules
	HookList_Init();
	PortCtx_Init();

	// register minifilter
	PFLT_FILTER filter = NULL;
	NTSTATUS status = FltRegisterFilter(
		DriverObject,
		&FilterRegistration,
		&filter
	);
	// store filter in DriverCtx for controlled access
	if (NT_SUCCESS(status)) {
		DriverCtx_SetFilter(filter);
	}

	// we need to manually call miniunload until FltStartFiltering succeed
	if (NT_SUCCESS(status)) {
	status = FltStartFiltering(DriverCtx_GetFilter());
		if (!NT_SUCCESS(status)) {
			Log(L"failed to start filtering: 0x%x\n", status);
			MiniUnload(0);
			return status;
		} 
	}
	else {
		Log(L"failed to call FltRegisterFilter: 0x%x\n", status);
		MiniUnload(0);
		return status;
	}

	status = SetSysNotifiers();
	if (!NT_SUCCESS(status)) {
		Log(L"failed to set system notify routines\n");
		return status;
	}

	return status;
}