#include "Common.h"
#include "Trace.h"
#include "mini.h"
#include "SysCallback.h"
#include "HookList.h"
#include "DriverCtx.h"
#include "Inject.h"
 
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


VOID
DriverUnload(
	_In_ PDRIVER_OBJECT DriverObject
)
{
	UNREFERENCED_PARAMETER(DriverObject);
	// Reuse MiniUnload to cleanup resources
	MiniUnload(0);
	Log(L"DriverUnload invoked\n");
}
// mainn
NTSTATUS
	DriverEntry(
		_In_ PDRIVER_OBJECT  DriverObject,
		_In_ PUNICODE_STRING RegistryPath
	)
{
	DbgBreakPoint();
	(RegistryPath);
	(DriverObject);
	Log(L"DriverEntry\n");

	// Set unload routine so the driver can be unloaded safely
	DriverObject->DriverUnload = DriverUnload;

	// initialize modules
	HookList_Init();
	Inject_Init();

	// this driver is meaning to support global hook, so we don't care what registry value is, just set to global hook mode
	DriverCtx_SetGlobalHookMode(TRUE);


	NTSTATUS status = SetSysNotifiers();
	if (!NT_SUCCESS(status)) {
		Log(L"failed to set system notify routines\n");
		goto ABORTION;
	}
	return status;
ABORTION:
	MiniUnload(0);
	return status;
}