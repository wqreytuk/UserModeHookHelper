#include "Common.h"
#include "Trace.h"
#include "mini.h"
#include "SysCallback.h"
#include "HookList.h"
#include "PortCtx.h"
#include "DriverCtx.h"
#include "Inject.h"
#include "BootStartControl.h"
#include "PE.h"
#include "../../Shared/SharedMacroDef.h"
 
// Helper: read persisted settings from registry and initialize DriverCtx
static VOID LoadPersistedDriverSettings(VOID) {
	HANDLE hKey = NULL;
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING uKeyName;
	RtlInitUnicodeString(&uKeyName, REG_PERSIST_REGPATH);
	InitializeObjectAttributes(&oa, &uKeyName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
	NTSTATUS r = ZwOpenKey(&hKey, KEY_READ, &oa);
	if (!NT_SUCCESS(r)) return;

	// Read EnableGlobalHookMode (REG_DWORD)
	UNICODE_STRING valueName;
	RtlInitUnicodeString(&valueName, L"EnableGlobalHookMode");
	ULONG resultLength = 0;
	r = ZwQueryValueKey(hKey, &valueName, KeyValuePartialInformation, NULL, 0, &resultLength);
	if (r == STATUS_BUFFER_TOO_SMALL || r == STATUS_BUFFER_OVERFLOW) {
		PKEY_VALUE_PARTIAL_INFORMATION kv = ExAllocatePoolWithTag(NonPagedPool, resultLength, tag_ctx);
		if (kv) {
			r = ZwQueryValueKey(hKey, &valueName, KeyValuePartialInformation, kv, resultLength, &resultLength);
			if (NT_SUCCESS(r) && kv->Type == REG_DWORD && kv->DataLength >= sizeof(ULONG)) {
				ULONG val = 0;
				RtlCopyMemory(&val, kv->Data, sizeof(ULONG));
				DriverCtx_SetGlobalHookMode(val ? TRUE : FALSE);
				Log(L"Registry: EnableGlobalHookMode = %u\n", val);
			}
			ExFreePoolWithTag(kv, tag_ctx);
		}
	}

	// Read UserDir (REG_SZ/REG_EXPAND_SZ)
	UNICODE_STRING userDirValue;
	RtlInitUnicodeString(&userDirValue, L"UserDir");
	resultLength = 0;
	r = ZwQueryValueKey(hKey, &userDirValue, KeyValuePartialInformation, NULL, 0, &resultLength);
	if (r == STATUS_BUFFER_TOO_SMALL || r == STATUS_BUFFER_OVERFLOW) {
		PKEY_VALUE_PARTIAL_INFORMATION kv2 = ExAllocatePoolWithTag(NonPagedPool, resultLength, tag_ctx);
		if (kv2) {
			r = ZwQueryValueKey(hKey, &userDirValue, KeyValuePartialInformation, kv2, resultLength, &resultLength);
			if (NT_SUCCESS(r) && (kv2->Type == REG_SZ || kv2->Type == REG_EXPAND_SZ) && kv2->DataLength > 0) {
				ULONG dataBytes = kv2->DataLength;
				if (dataBytes % sizeof(WCHAR) != 0) dataBytes = dataBytes - (dataBytes % sizeof(WCHAR));
				PWCHAR buf = ExAllocatePoolWithTag(NonPagedPool, dataBytes + sizeof(WCHAR), tag_ctx);
				if (buf) {
					RtlZeroMemory(buf, dataBytes + sizeof(WCHAR));
					RtlCopyMemory(buf, kv2->Data, dataBytes);
					DriverCtx_SetUserDir(buf, dataBytes + sizeof(WCHAR));
					Log(L"Registry: UserDir loaded into DriverCtx\n");
					ExFreePoolWithTag(buf, tag_ctx);
				}
			}
			ExFreePoolWithTag(kv2, tag_ctx);
		}
	}

	ZwClose(hKey);
}

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
		{ IRP_MJ_CREATE,
			0,
			MiniPreCreateCallback,
			NULL },
		// { IRP_MJ_READ,
		// 	0,
		// 	MiniPreReadCallback,
		// 	NULL },
		{ IRP_MJ_OPERATION_END }
};

// Filter registration structure
// Context registrations
const FLT_CONTEXT_REGISTRATION Contexts[] = {
    { FLT_STREAMHANDLE_CONTEXT, 0, NULL, sizeof(UMHH_STREAMHANDLE_CTX), tag_stream_handle_ctx },
    { FLT_CONTEXT_END }
};

const FLT_REGISTRATION FilterRegistration = {
	sizeof(FLT_REGISTRATION),        // Size
	FLT_REGISTRATION_VERSION,        // Version
	0,                               // Flags
	Contexts,                        // Context registration
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
	// DbgBreakPoint();
	(RegistryPath);
	Log(L"DriverEntry\n");

	Inject_CheckWin7();
	 
	DriverCtx_SetSSDT((DWORD64)PE_GetSSDT());
	if(!DriverCtx_GetSSDT()) {
		Log(L"failed to get SSDT\n");
		return STATUS_UNSUCCESSFUL;
	}
	// stop umhh.bootstart driver
	// BS_SendSuspendInjectQueue(TRUE);
	// Log(L"Tell UMHH.BootStart driver to stop injection\n");


	// initialize modules
	HookList_Init();
	PortCtx_Init();
	Inject_Init();

	// Load persisted settings from registry (global hook mode, user dir, ...)
	LoadPersistedDriverSettings();

	// Ob callback registration moved to separate UMHH.ObCallback component.

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
			goto ABORTION;
		} 
	}
	else {
		Log(L"failed to call FltRegisterFilter: 0x%x\n", status);
		goto ABORTION;
	}

	status = Comm_CreatePort();
	if (!NT_SUCCESS(status)) {
		Log(L"failed to call Comm_CreatePort: 0x%x\n", status);
		goto ABORTION;
	}

	status = SetSysNotifiers();
	if (!NT_SUCCESS(status)) {
		Log(L"failed to set system notify routines\n");
		goto ABORTION;
	}


	return status;
ABORTION:
	MiniUnload(0);
	return status;
}