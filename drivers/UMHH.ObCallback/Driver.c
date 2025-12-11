
#pragma warning(push)
#pragma warning(disable:4141)
#include <fltkernel.h>
#pragma warning(pop)
#include <ntstrsafe.h>
#include "../../Shared/SharedMacroDef.h"
// Avoid LOG_PREFIX_OBC conflict; use ObCallback-specific prefix

#define LOG_PREFIX_OBC L"[UMHH.ObCallback]"
DWORD64 gHash;
typedef struct _HASH_NODE {
	LIST_ENTRY Link;
	ULONGLONG Hash;
} HASH_NODE, *PHASH_NODE;
LIST_ENTRY g_HashList; // list of whitelist hashes
KSPIN_LOCK g_HashLock; // protects g_HashList
BOOLEAN
NTAPI
SL_RtlSuffixUnicodeString(
	_In_ PUNICODE_STRING Suffix,
	_In_ PUNICODE_STRING String2,
	_In_ BOOLEAN CaseInSensitive
);
#include "../UserModeHookHelper/MacroDef.h"
// Cached blocked process suffix list
typedef struct _BLOCKED_NAME_NODE {
	LIST_ENTRY Link;
	UNICODE_STRING Name; // allocated buffer
} BLOCKED_NAME_NODE, *PBLOCKED_NAME_NODE;
static LIST_ENTRY g_BlockedProcList; // protected by g_BlockedProcLock
static KSPIN_LOCK g_BlockedProcLock;

static VOID FreeBlockedProcessList() {
	KIRQL irql; KeAcquireSpinLock(&g_BlockedProcLock, &irql);
	while (!IsListEmpty(&g_BlockedProcList)) {
		PLIST_ENTRY e = RemoveHeadList(&g_BlockedProcList);
		PBLOCKED_NAME_NODE n = CONTAINING_RECORD(e, BLOCKED_NAME_NODE, Link);
		if (n->Name.Buffer) ExFreePoolWithTag(n->Name.Buffer, 'bPNM');
		ExFreePoolWithTag(n, 'bPNM');
	}
	KeReleaseSpinLock(&g_BlockedProcLock, irql);
}

static VOID LoadBlockedProcessListFromRegistry() {
	FreeBlockedProcessList();
	OBJECT_ATTRIBUTES oa; UNICODE_STRING regPath; RtlInitUnicodeString(&regPath, REG_PERSIST_REGPATH L"\\");
	InitializeObjectAttributes(&oa, &regPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	HANDLE hKey = NULL; NTSTATUS st = ZwOpenKey(&hKey, KEY_READ, &oa);
	if (!NT_SUCCESS(st)) return;
	UNICODE_STRING valName; RtlInitUnicodeString(&valName, REG_BLOCKED_PROCESS_NAME);
	ULONG len = 0; st = ZwQueryValueKey(hKey, &valName, KeyValueFullInformation, NULL, 0, &len);
	if (st != STATUS_BUFFER_TOO_SMALL && st != STATUS_BUFFER_OVERFLOW) { ZwClose(hKey); return; }
	PKEY_VALUE_FULL_INFORMATION info = (PKEY_VALUE_FULL_INFORMATION)ExAllocatePoolWithTag(PagedPool, len, 'blRV');
	if (!info) { ZwClose(hKey); return; }
	st = ZwQueryValueKey(hKey, &valName, KeyValueFullInformation, info, len, &len);
	if (!NT_SUCCESS(st) || info->Type != REG_MULTI_SZ) { ExFreePoolWithTag(info, 'blRV'); ZwClose(hKey); return; }
	WCHAR* p = (WCHAR*)((PUCHAR)info + info->DataOffset);
	while (*p) {
		UNICODE_STRING entry; RtlInitUnicodeString(&entry, p);
		SIZE_T bytes = entry.Length + sizeof(WCHAR);
		PWCHAR buf = (PWCHAR)ExAllocatePoolWithTag(NonPagedPoolNx, bytes, 'bPNM');
		if (buf) {
			RtlCopyMemory(buf, entry.Buffer, entry.Length);
			buf[entry.Length / sizeof(WCHAR)] = L'\0';
			PBLOCKED_NAME_NODE node = (PBLOCKED_NAME_NODE)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(BLOCKED_NAME_NODE), 'bPNM');
			if (node) {
				node->Name.Buffer = buf; node->Name.Length = (USHORT)entry.Length; node->Name.MaximumLength = (USHORT)bytes;
				KIRQL irql; KeAcquireSpinLock(&g_BlockedProcLock, &irql);
				InsertTailList(&g_BlockedProcList, &node->Link);
				KeReleaseSpinLock(&g_BlockedProcLock, irql);
			}
			else {
				ExFreePoolWithTag(buf, 'bPNM');
			}
		}
		p += entry.Length / sizeof(WCHAR) + 1;
	}
	ExFreePoolWithTag(info, 'blRV'); ZwClose(hKey);
}

static BOOLEAN CheckBlockedProcessByName(PUNICODE_STRING imageNameSuffix) {
	BOOLEAN matched = FALSE;
	KIRQL irql; KeAcquireSpinLock(&g_BlockedProcLock, &irql);
	for (PLIST_ENTRY e = g_BlockedProcList.Flink; e != &g_BlockedProcList; e = e->Flink) {
		PBLOCKED_NAME_NODE n = CONTAINING_RECORD(e, BLOCKED_NAME_NODE, Link);
		if (SL_RtlSuffixUnicodeString(&n->Name, imageNameSuffix, TRUE)) { matched = TRUE; break; }
	}
	KeReleaseSpinLock(&g_BlockedProcLock, irql);
	return matched;
}
// Global SelfDefense toggle loaded from registry and runtime IOCTL
static BOOLEAN gSelfDefense = FALSE;
// Simple control device for runtime toggling
static PDEVICE_OBJECT gCtlDevice = NULL;
static UNICODE_STRING gCtlSymLink;
void Log(const WCHAR* format, ...);
PFLT_FILTER gFilter;
NTSYSAPI
NTSTATUS
NTAPI
RtlSystemTimeToLocalTime(
	_In_ PLARGE_INTEGER SystemTime,
	_Out_ PLARGE_INTEGER LocalTime
);

ULONGLONG SL_ComputeNtPathHash(_In_reads_bytes_opt_(ByteLen) const PUCHAR Bytes, _In_ SIZE_T ByteLen) {
	if (!Bytes || ByteLen == 0) return 0;

	// FNV-1a 64-bit constants
	const ULONGLONG FNV_offset = 14695981039346656037ULL;
	const ULONGLONG FNV_prime = 1099511628211ULL;
	ULONGLONG hash = FNV_offset;

	for (SIZE_T i = 0; i < ByteLen; ++i) {
		hash ^= (ULONGLONG)Bytes[i];
		hash *= FNV_prime;
	}
	return hash;
}

FLT_PREOP_CALLBACK_STATUS
PreCreateOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
) {
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	// Do nothing, just let the I/O continue
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

PVOID g_CallbackHandle;
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
	{ IRP_MJ_CREATE,
	  0,
	  PreCreateOperation,
	  NULL },

		  { IRP_MJ_OPERATION_END }
};

//
//  Context registraction construct defined in context.c
//

extern const FLT_CONTEXT_REGISTRATION ContextRegistration[];

//
//  This defines what we want to filter with FltMgr
//
NTSTATUS
MiniUnload(
	FLT_FILTER_UNLOAD_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(Flags);

	// Unregister OB callback if present
		// Free cached blocked process list
		FreeBlockedProcessList();
	if (g_CallbackHandle) {
		ObUnRegisterCallbacks(g_CallbackHandle);
		g_CallbackHandle = NULL;
	}

	// Unregister and clear the filter pointer
	if (gFilter) {
		FltUnregisterFilter(gFilter);
		gFilter = NULL;
	}

	// Free whitelist hash list
	KIRQL oldIrql; KeAcquireSpinLock(&g_HashLock, &oldIrql);
	while (!IsListEmpty(&g_HashList)) {
		PLIST_ENTRY e = RemoveHeadList(&g_HashList);
		PHASH_NODE n = CONTAINING_RECORD(e, HASH_NODE, Link);
		ExFreePoolWithTag(n, 'hLST');
	}
	KeReleaseSpinLock(&g_HashLock, oldIrql);

	// Cleanup control device
	if (gCtlDevice) {
		IoDeleteSymbolicLink(&gCtlSymLink);
		IoDeleteDevice(gCtlDevice);
		gCtlDevice = NULL;
	}

	Log(L"successfully unloaded UMHH.ObCallback driver\n");
	return STATUS_SUCCESS;
}
CONST FLT_REGISTRATION FilterRegistration = {

	sizeof(FLT_REGISTRATION),         //  Size
	FLT_REGISTRATION_VERSION,           //  Version
	0,                                  //  Flags

	NULL,                //  Context
	Callbacks,                          //  Operation callbacks

   MiniUnload,// / AvUnload,                           //  MiniFilterUnload

	NULL,          //  InstanceSetup
	NULL,          //  InstanceQueryTeardown
	NULL,          //  InstanceTeardownStart
	NULL,         //  InstanceTeardownComplete

	NULL,                               //  GenerateFileName
	NULL,                               //  NormalizeNameComponentCallback
	NULL,                               //  NormalizeContextCleanupCallback
	NULL,          //  TransactionNotificationCallback
	NULL,                               //  NormalizeNameComponentExCallback
	NULL            //  SectionNotificationCallback
};

BOOLEAN
NTAPI
SL_RtlSuffixUnicodeString(
	_In_ PUNICODE_STRING Suffix,
	_In_ PUNICODE_STRING String2,
	_In_ BOOLEAN CaseInSensitive
)
{
	//
	// RtlSuffixUnicodeString is not exported by ntoskrnl until Win10.
	//

	return String2->Length >= Suffix->Length &&
		RtlCompareUnicodeStrings(String2->Buffer + (String2->Length - Suffix->Length) / sizeof(WCHAR),
			Suffix->Length / sizeof(WCHAR),
			Suffix->Buffer,
			Suffix->Length / sizeof(WCHAR),
			CaseInSensitive) == 0;

}

// this callback function will make sure UMController.exe can always get the requested handle access
// this callback function will make sure UMController.exe can always get the requested handle access
NTSTATUS PreObjProcesCallback(
	_In_ PVOID RegistrationContext,
	_In_ POB_PRE_OPERATION_INFORMATION OperationInformation
) {
	UNREFERENCED_PARAMETER(RegistrationContext);
	if (!OperationInformation)
		return STATUS_SUCCESS;


	// and we need to deny termination access to our white list process
	if(gSelfDefense) // only delete termination access when self defense is on
	{
		PUNICODE_STRING imageName = NULL;
		NTSTATUS stImg = 0;
		if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
			goto https;
		}
		else {
			stImg = SeLocateProcessImageName((PEPROCESS)OperationInformation->Object, &imageName);
		}
		if (!NT_SUCCESS(stImg) || imageName == NULL || imageName->Length == 0) {
			if (imageName) { ExFreePool(imageName); imageName = NULL; }
			// Log(L"failed to located source process image path, Status=0x%x\n", stImg);
			goto https;
		}

		// compare hash
		DWORD64 hash = SL_ComputeNtPathHash((const PUCHAR)imageName->Buffer, imageName->Length);
		// Log(L"debug, opening process path=%wZ, Hash=0x%p\n", imageName, hash);
		ExFreePool(imageName); imageName = NULL;

		// Allow only if hash is present in whitelist list
		BOOLEAN matched = FALSE;
		KIRQL oldIrql;
		KeAcquireSpinLock(&g_HashLock, &oldIrql);
		for (PLIST_ENTRY e = g_HashList.Flink; e != &g_HashList; e = e->Flink) {
			PHASH_NODE n = CONTAINING_RECORD(e, HASH_NODE, Link);
			if (n->Hash == hash) { matched = TRUE; break; }
		}
		KeReleaseSpinLock(&g_HashLock, oldIrql);
		// we only delete terminate access when TARGET process matches our white list
		if (!matched) goto https;


		POB_PRE_CREATE_HANDLE_INFORMATION info = &OperationInformation->Parameters->CreateHandleInformation;
		// info->DesiredAccess &= ~0x1;

		// and we also need to deny process in blocked list to access process in whitelist
		stImg = SeLocateProcessImageName(PsGetCurrentProcess(), &imageName);
 
		if (!NT_SUCCESS(stImg) || imageName == NULL || imageName->Length == 0) {
			if (imageName) { ExFreePool(imageName); imageName = NULL; }
			// Log(L"failed to located source process image path, Status=0x%x\n", stImg);
			goto https;
		}
		// consult registry-based blocked process list
		if (CheckBlockedProcessByName(imageName)) {
				// only permit query limited process information
				info->DesiredAccess = 0x1000;
				ExFreePool(imageName); imageName = NULL;
				goto https;
		}
		ExFreePool(imageName); imageName = NULL;
	}

https://144.one
	{
		PUNICODE_STRING imageName = NULL;
		NTSTATUS stImg = 0;

		stImg = SeLocateProcessImageName(PsGetCurrentProcess(), &imageName);

		if (!NT_SUCCESS(stImg) || imageName == NULL || imageName->Length == 0) {
			if (imageName) { ExFreePool(imageName); imageName = NULL; }
			// Log(L"failed to located source process image path, Status=0x%x\n", stImg);
			goto http;
		}

		// compare hash
		DWORD64 hash = SL_ComputeNtPathHash((const PUCHAR)imageName->Buffer, imageName->Length);
		ExFreePool(imageName); imageName = NULL;

		// Allow only if hash is present in whitelist list
		BOOLEAN matched = FALSE;
		KIRQL oldIrql;
		KeAcquireSpinLock(&g_HashLock, &oldIrql);
		for (PLIST_ENTRY e = g_HashList.Flink; e != &g_HashList; e = e->Flink) {
			PHASH_NODE n = CONTAINING_RECORD(e, HASH_NODE, Link);
			if (n->Hash == hash) { matched = TRUE; break; }
		}
		KeReleaseSpinLock(&g_HashLock, oldIrql);
		if (!matched) goto http;

		if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
			POB_PRE_CREATE_HANDLE_INFORMATION info = &OperationInformation->Parameters->CreateHandleInformation;
			info->DesiredAccess = 0x1fffff;
		}
		if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
			POB_PRE_DUPLICATE_HANDLE_INFORMATION dupInfo = &OperationInformation->Parameters->DuplicateHandleInformation;
			dupInfo->DesiredAccess = 0x1fffff;
		}
	}

http://144.34.164.217
	return STATUS_SUCCESS;
}

// Thread object pre-operation callback: currently a pass-through (can be extended).
static NTSTATUS PreObjThreadCallback(
	_In_ PVOID RegistrationContext,
	_In_ POB_PRE_OPERATION_INFORMATION OperationInformation
) {
	UNREFERENCED_PARAMETER(RegistrationContext);
	if (!OperationInformation) return STATUS_SUCCESS;

	{
		PUNICODE_STRING imageName = NULL;
		NTSTATUS stImg = 0;

		stImg = SeLocateProcessImageName(PsGetCurrentProcess(), &imageName);

		if (!NT_SUCCESS(stImg) || imageName == NULL || imageName->Length == 0) {
			if (imageName) { ExFreePool(imageName); imageName = NULL; }
			// Log(L"failed to located source process image path, Status=0x%x\n", stImg);
			goto http;
		}

		// compare hash
		DWORD64 hash = SL_ComputeNtPathHash((const PUCHAR)imageName->Buffer, imageName->Length);
		ExFreePool(imageName); imageName = NULL;

		// Allow only if hash is present in whitelist list
		BOOLEAN allowed = FALSE;
		KIRQL oldIrql;
		KeAcquireSpinLock(&g_HashLock, &oldIrql);
		for (PLIST_ENTRY e = g_HashList.Flink; e != &g_HashList; e = e->Flink) {
			PHASH_NODE n = CONTAINING_RECORD(e, HASH_NODE, Link);
			if (n->Hash == hash) { allowed = TRUE; break; }
		}
		KeReleaseSpinLock(&g_HashLock, oldIrql);
		if (!allowed) goto http;

		if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
			POB_PRE_CREATE_HANDLE_INFORMATION info = &OperationInformation->Parameters->CreateHandleInformation;
			info->DesiredAccess = 0x1fffff;
		}
		if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
			POB_PRE_DUPLICATE_HANDLE_INFORMATION dupInfo = &OperationInformation->Parameters->DuplicateHandleInformation;
			dupInfo->DesiredAccess = 0x1fffff;
		}
	}

http://144.34.164.217
	return STATUS_SUCCESS;
}

// IOCTL codes for SelfDefense toggle
#ifndef UMHH_IOCTL_SET_SELFDEFENSE
#define UMHH_IOCTL_SET_SELFDEFENSE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif
#ifndef UMHH_IOCTL_GET_SELFDEFENSE
#define UMHH_IOCTL_GET_SELFDEFENSE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

static NTSTATUS UMHHObCtl_CreateClose(_In_ PDEVICE_OBJECT Dev, _Inout_ PIRP Irp) {
	UNREFERENCED_PARAMETER(Dev);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

static NTSTATUS UMHHObCtl_DeviceControl(_In_ PDEVICE_OBJECT Dev, _Inout_ PIRP Irp) {
	UNREFERENCED_PARAMETER(Dev);
	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
	ULONG code = irpSp->Parameters.DeviceIoControl.IoControlCode;
	NTSTATUS st = STATUS_INVALID_DEVICE_REQUEST;
	if (code == UMHH_IOCTL_SET_SELFDEFENSE) {
		if (irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(ULONG) && Irp->AssociatedIrp.SystemBuffer) {
			ULONG v = *(ULONG*)Irp->AssociatedIrp.SystemBuffer; gSelfDefense = (v != 0) ? TRUE : FALSE;
			st = STATUS_SUCCESS; Irp->IoStatus.Information = 0;
		}
		else { st = STATUS_BUFFER_TOO_SMALL; Irp->IoStatus.Information = 0; }
	}
	else if (code == UMHH_IOCTL_GET_SELFDEFENSE) {
		if (irpSp->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(ULONG) && Irp->AssociatedIrp.SystemBuffer) {
			*(ULONG*)Irp->AssociatedIrp.SystemBuffer = (gSelfDefense ? 1u : 0u);
			st = STATUS_SUCCESS; Irp->IoStatus.Information = sizeof(ULONG);
		}
		else { st = STATUS_BUFFER_TOO_SMALL; Irp->IoStatus.Information = 0; }
	}
	Irp->IoStatus.Status = st; IoCompleteRequest(Irp, IO_NO_INCREMENT); return st;
}
// regist object open / duplicate callback
NTSTATUS RegisterProcessCallback() {
	OB_OPERATION_REGISTRATION operations[1] = { 0 };
	RtlZeroMemory(operations, sizeof(operations));

	operations[0].ObjectType = PsProcessType;  // Monitor process objects (pointer)
	operations[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	operations[0].PreOperation = (POB_PRE_OPERATION_CALLBACK)PreObjProcesCallback;  // Callback for process deletion


	// operations[1].ObjectType = PsThreadType;
	// operations[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	// operations[1].PreOperation = (POB_PRE_OPERATION_CALLBACK)PreObjThreadCallback;


	OB_CALLBACK_REGISTRATION callbackRegistration = { 0 };
	callbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
	callbackRegistration.OperationRegistrationCount = ARRAYSIZE(operations);
	callbackRegistration.OperationRegistration = operations;
	callbackRegistration.RegistrationContext = NULL;

	NTSTATUS status = ObRegisterCallbacks(&callbackRegistration, &g_CallbackHandle);
	return status;
}
NTSTATUS
// mainn
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	  // DbgBreakPoint();

	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS  status = STATUS_SUCCESS;

// 	init blocked list
	
	// Initialize lists and load configuration from registry
	InitializeListHead(&g_HashList);
	KeInitializeSpinLock(&g_HashLock);
	InitializeListHead(&g_BlockedProcList);
	KeInitializeSpinLock(&g_BlockedProcLock);
	{
		UNICODE_STRING regPath;
		RtlInitUnicodeString(&regPath, REG_PERSIST_REGPATH);
		OBJECT_ATTRIBUTES oa;
		InitializeObjectAttributes(&oa, &regPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		HANDLE hKey = NULL;
		NTSTATUS st = ZwOpenKey(&hKey, KEY_READ, &oa);
		if (NT_SUCCESS(st)) {
			// Read SelfDefense toggle (REG_DWORD EnableSelfDefense)
			UNICODE_STRING sdName; RtlInitUnicodeString(&sdName, L"EnableSelfDefense");
			ULONG sdLen = 0;
			NTSTATUS stSd = ZwQueryValueKey(hKey, &sdName, KeyValuePartialInformation, NULL, 0, &sdLen);
			if (stSd == STATUS_BUFFER_TOO_SMALL || stSd == STATUS_BUFFER_OVERFLOW) {
				PKEY_VALUE_PARTIAL_INFORMATION kvpiSd = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPoolNx, sdLen, 'vSDC');
				if (kvpiSd) {
					stSd = ZwQueryValueKey(hKey, &sdName, KeyValuePartialInformation, kvpiSd, sdLen, &sdLen);
					if (NT_SUCCESS(stSd) && kvpiSd->Type == REG_DWORD && kvpiSd->DataLength >= sizeof(ULONG)) {
						ULONG v = *(ULONG*)kvpiSd->Data; gSelfDefense = (v != 0) ? TRUE : FALSE;
						Log(L"SelfDefense loaded: %d\n", (int)gSelfDefense);
					}
					ExFreePoolWithTag(kvpiSd, 'vSDC');
				}
			}
			// (no duplicate read)

			UNICODE_STRING valName;
			RtlInitUnicodeString(&valName, L"WhitelistHashes");
			// Query as REG_QWORD or REG_SZ numeric; allocate buffer for value info
			ULONG resultLen = 0;
			st = ZwQueryValueKey(hKey, &valName, KeyValuePartialInformation, NULL, 0, &resultLen);
			if (st == STATUS_BUFFER_TOO_SMALL || st == STATUS_BUFFER_OVERFLOW) {
				PKEY_VALUE_PARTIAL_INFORMATION kvpi = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPoolNx, resultLen, 'vHOC');
				if (kvpi) {
					st = ZwQueryValueKey(hKey, &valName, KeyValuePartialInformation, kvpi, resultLen, &resultLen);
					if (NT_SUCCESS(st)) {
						if (kvpi->Type == REG_MULTI_SZ && kvpi->DataLength >= sizeof(WCHAR)) {
							PWCH p = (PWCH)kvpi->Data;
							SIZE_T wc = kvpi->DataLength / sizeof(WCHAR);
							SIZE_T i = 0;
							while (i < wc) {
								if (p[i] == L'\0') { i++; continue; }
								PWCH start = &p[i]; SIZE_T len = 0;
								while (i + len < wc && p[i + len] != L'\0') len++;
								ULONGLONG hv = 0; ULONGLONG tmp = 0; swscanf_s(start, L"%llx", &tmp); hv = tmp;
								if (hv == 0) { tmp = 0; swscanf_s(start, L"%llu", &tmp); hv = tmp; }
								if (hv != 0) {
									PHASH_NODE node = (PHASH_NODE)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(HASH_NODE), 'hLST');
									if (node) { node->Hash = hv; KIRQL irql; KeAcquireSpinLock(&g_HashLock, &irql); InsertTailList(&g_HashList, &node->Link); KeReleaseSpinLock(&g_HashLock, irql); }
								}
								i += (len + 1);
							}
							Log(L"WhitelistHashes loaded (entries appended)\n");
						}
						else {
							Log(L"WhitelistHashes missing or wrong type=%u\n", kvpi->Type);
						}
					}
					ExFreePoolWithTag(kvpi, 'vHOC');
				}
			}
			ZwClose(hKey);
		}
		else {
			Log(L"Open registry failed for WhitelistHashes: 0x%x\n", st);
		}
	}

	// Load blocked process list once at driver start
	LoadBlockedProcessListFromRegistry();

	// Create control device for runtime toggling
	// Setup simple dispatch for CREATE/CLOSE/IOCTL
	DriverObject->MajorFunction[IRP_MJ_CREATE] = UMHHObCtl_CreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = UMHHObCtl_CreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = UMHHObCtl_DeviceControl;
	UNICODE_STRING devName; RtlInitUnicodeString(&devName, L"\\Device\\UMHHObCallbackCtl");
	RtlInitUnicodeString(&gCtlSymLink, L"\\DosDevices\\UMHHObCallbackCtl");
	PDEVICE_OBJECT dev = NULL;
	status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &dev);
	if (NT_SUCCESS(status)) {
		gCtlDevice = dev; (void)IoCreateSymbolicLink(&gCtlSymLink, &devName);
		Log(L"Control device created for UMHH.ObCallback\n");
	}



	// register ob callback
	status = RegisterProcessCallback();
	if (!NT_SUCCESS(status)) {
		Log(L"failed to register ObProcessType callback, Status=0x%x\n", status);
		goto ABORTION;
	}
	else
		Log(L"ObProcessType callback registered\n", status);
	status = FltRegisterFilter(DriverObject,
		&FilterRegistration,
		&gFilter);

	if (!NT_SUCCESS(status)) {

		Log(L"FltRegisterFilter FAILED. Status=0x%xx\n", status);
		goto ABORTION;
	}


	status = FltStartFiltering(gFilter);

	if (!NT_SUCCESS(status)) {
		Log(L"FltStartFiltering FAILED. Status=0x%x\n", status);
		goto ABORTION;
	}
	return status;
ABORTION:
	MiniUnload(0);
	return status;
}

void Log(const WCHAR* format, ...) {
	WCHAR buffer[2000] = { 0 };

	va_list args;
	va_start(args, format);
	RtlStringCchVPrintfW(buffer, ARRAYSIZE(buffer), format, args);
	va_end(args);

	// Build a timestamp prefix using local time
	LARGE_INTEGER systemTime = { 0 };
	LARGE_INTEGER localTime = { 0 };
	KeQuerySystemTime(&systemTime);
	if (!NT_SUCCESS(RtlSystemTimeToLocalTime(&systemTime, &localTime))) {
		localTime = systemTime;
	}
	TIME_FIELDS tf;
	RtlTimeToTimeFields(&localTime, &tf);
	WCHAR timebuf[64] = { 0 };
	RtlStringCchPrintfW(timebuf, ARRAYSIZE(timebuf), L"[%04hu-%02hu-%02hu %02hu:%02hu:%02hu.%03hu]",
		(tf.Year), (tf.Month), (tf.Day), (tf.Hour), (tf.Minute), (tf.Second), (tf.Milliseconds));

	// Print timestamp, compile-time prefix, and message
	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "%ws %ws %ws\n", timebuf, LOG_PREFIX_OBC, buffer);
}
