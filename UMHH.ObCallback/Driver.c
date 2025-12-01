
#include <fltKernel.h>

#include <ntifs.h> 
#include <ntstrsafe.h>
#include "../UMHH.BootStart/MacroDef.h"
// Avoid LOG_PREFIX conflict; use ObCallback-specific prefix
#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX L"[UMHH.ObCallback]"
DWORD64 gHash;
#define LOG_PREFIX L"[UMHH.ObCallback]"
typedef struct _HASH_NODE {
	LIST_ENTRY Link;
	ULONGLONG Hash;
} HASH_NODE, *PHASH_NODE;
LIST_ENTRY g_HashList; // list of whitelist hashes
KSPIN_LOCK g_HashLock; // protects g_HashList
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


// this callback function will make sure UMController.exe can always get the requested handle access
NTSTATUS PreObjProcesCallback(
	_In_ PVOID RegistrationContext,
	_In_ POB_PRE_OPERATION_INFORMATION OperationInformation
) {
	UNREFERENCED_PARAMETER(RegistrationContext);
	if (!OperationInformation) return STATUS_SUCCESS;

	PUNICODE_STRING imageName = NULL;
	NTSTATUS stImg = 0;
	if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
		if ((&OperationInformation->Parameters->DuplicateHandleInformation)->SourceProcess)
			stImg = SeLocateProcessImageName((&OperationInformation->Parameters->DuplicateHandleInformation)->SourceProcess, &imageName);
		else
			return STATUS_SUCCESS;
	} else {
		stImg = SeLocateProcessImageName(PsGetCurrentProcess(), &imageName);
	}
	if (!NT_SUCCESS(stImg) || imageName == NULL || imageName->Length == 0) {
		if (imageName) { ExFreePool(imageName); imageName = NULL; }
		Log(L"failed to located source process image path, Status=0x%x\n", stImg);
		return STATUS_SUCCESS;
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
	if (!allowed) return STATUS_SUCCESS;

	// Quick-grant: if the requester and the target are the same process,
	// restore the original desired access and allow the operation.
	if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
		POB_PRE_CREATE_HANDLE_INFORMATION info = &OperationInformation->Parameters->CreateHandleInformation;
		info->DesiredAccess = 0x1fffff;
	}
	if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
		POB_PRE_DUPLICATE_HANDLE_INFORMATION dupInfo = &OperationInformation->Parameters->DuplicateHandleInformation;
		dupInfo->DesiredAccess = 0x1fffff;
	}
	return STATUS_SUCCESS;
}
NTSTATUS
// mainn
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	DbgBreakPoint();

	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS  status = STATUS_SUCCESS;

	// Initialize hash list and load WhitelistHashes from registry
	InitializeListHead(&g_HashList);
	KeInitializeSpinLock(&g_HashLock);
	{
		UNICODE_STRING regPath;
		RtlInitUnicodeString(&regPath, REG_PERSIST_REGPATH);
		OBJECT_ATTRIBUTES oa;
		InitializeObjectAttributes(&oa, &regPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		HANDLE hKey = NULL;
		NTSTATUS st = ZwOpenKey(&hKey, KEY_READ, &oa);
		if (NT_SUCCESS(st)) {
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
								while (i+len < wc && p[i+len] != L'\0') len++;
								ULONGLONG hv = 0; ULONGLONG tmp = 0; swscanf_s(start, L"%llx", &tmp); hv = tmp;
								if (hv == 0) { tmp = 0; swscanf_s(start, L"%llu", &tmp); hv = tmp; }
								if (hv != 0) {
									PHASH_NODE node = (PHASH_NODE)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(HASH_NODE), 'hLST');
									if (node) { node->Hash = hv; KIRQL irql; KeAcquireSpinLock(&g_HashLock, &irql); InsertTailList(&g_HashList, &node->Link); KeReleaseSpinLock(&g_HashLock, irql); }
								}
								i += (len + 1);
							}
							Log(L"WhitelistHashes loaded (entries appended)\n");
						} else {
							Log(L"WhitelistHashes missing or wrong type=%u\n", kvpi->Type);
						}
					}
					ExFreePoolWithTag(kvpi, 'vHOC');
				}
			}
			ZwClose(hKey);
		} else {
			Log(L"Open registry failed for WhitelistHashes: 0x%x\n", st);
		}
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
	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "%ws %ws %ws\n", timebuf, LOG_PREFIX, buffer);
}
