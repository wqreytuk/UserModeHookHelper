
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
			stImg = SeLocateProcessImageName((&OperationInformation->Parameters->DuplicateHandleInformation)->SourceProcess,
				&imageName);
		else
			return STATUS_SUCCESS;
	}
	else {
		stImg = SeLocateProcessImageName(PsGetCurrentProcess(), &imageName);

	}
	if (!NT_SUCCESS(stImg) || imageName == NULL || imageName->Length == 0) {
		// imageName not available; ensure we don't hold a stale pointer
		if (imageName) {
			ExFreePool(imageName);
			imageName = NULL;
		}
		Log(L"failed to located source process image path, Status=0x%x\n", stImg);
		return STATUS_SUCCESS;
	}
	else {
		// compare hash
		DWORD64 hash = SL_ComputeNtPathHash((const PUCHAR)imageName->Buffer, imageName->Length);

		ExFreePool(imageName);
		imageName = NULL;

		if (hash != gHash)
			return STATUS_SUCCESS;
	}

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

// regist object open/duplicate callback
NTSTATUS RegisterProcessCallback() {
	OB_OPERATION_REGISTRATION operations[1] = { 0 };

	operations[0].ObjectType = PsProcessType;  // Monitor process objects (pointer)
	operations[0].Operations = 3;
	operations[0].PreOperation = (POB_PRE_OPERATION_CALLBACK)PreObjProcesCallback;  // Callback for process deletion

	OB_CALLBACK_REGISTRATION callbackRegistration = { 0 };
	callbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
	callbackRegistration.OperationRegistrationCount = 1;
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
	DbgBreakPoint();

	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS  status = STATUS_SUCCESS;

	// Read ControllerPathHash from persistent registry and assign to gHash
	// Path consistent with other modules: \Registry\Machine\SOFTWARE\GIAO\UserModeHookHelper
	{
		UNICODE_STRING regPath;
		RtlInitUnicodeString(&regPath, REG_PERSIST_REGPATH);
		OBJECT_ATTRIBUTES oa;
		InitializeObjectAttributes(&oa, &regPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		HANDLE hKey = NULL;
		NTSTATUS st = ZwOpenKey(&hKey, KEY_READ, &oa);
		if (NT_SUCCESS(st)) {
			UNICODE_STRING valName;
			RtlInitUnicodeString(&valName, L"ControllerPathHash");
			// Query as REG_QWORD or REG_SZ numeric; allocate buffer for value info
			ULONG resultLen = 0;
			st = ZwQueryValueKey(hKey, &valName, KeyValuePartialInformation, NULL, 0, &resultLen);
			if (st == STATUS_BUFFER_TOO_SMALL || st == STATUS_BUFFER_OVERFLOW) {
				PKEY_VALUE_PARTIAL_INFORMATION kvpi = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPoolNx, resultLen, 'vHOC');
				if (kvpi) {
					st = ZwQueryValueKey(hKey, &valName, KeyValuePartialInformation, kvpi, resultLen, &resultLen);
					if (NT_SUCCESS(st)) {
						if (kvpi->Type == REG_QWORD && kvpi->DataLength >= sizeof(ULONGLONG)) {
							gHash = *(const ULONGLONG*)kvpi->Data;
							Log(L"ControllerPathHash (REG_QWORD) loaded: 0x%llx\n", gHash);
						}
						else if (kvpi->Type == REG_SZ || kvpi->Type == REG_EXPAND_SZ) {
							// Parse hex or decimal string to ULONGLONG
							UNICODE_STRING s;
							s.Buffer = (PWCH)kvpi->Data;
							s.Length = (USHORT)(kvpi->DataLength - sizeof(WCHAR)); // exclude trailing null
							s.MaximumLength = (USHORT)(kvpi->DataLength);
							ULONGLONG v = 0;
							// Try hex first
							if (NT_SUCCESS(RtlUnicodeStringToInteger(&s, 16, (ULONG*)&v))) {
								// RtlUnicodeStringToInteger returns 32-bit; for 64-bit try manual parse
								// Fallback: scan with swscanf
								ULONGLONG vv = 0;
								swscanf_s(s.Buffer, L"%llx", &vv);
								if (vv != 0) v = vv;
							} else {
								ULONGLONG vv = 0; swscanf_s(s.Buffer, L"%llu", &vv); v = vv;
							}
							gHash = v;
							Log(L"ControllerPathHash (REG_SZ) loaded: 0x%llx\n", gHash);
						}
						else {
							Log(L"ControllerPathHash has unexpected type=%u\n", kvpi->Type);
						}
					}
					ExFreePoolWithTag(kvpi, 'vHOC');
				}
			}
			ZwClose(hKey);
		} else {
			Log(L"Open registry failed for ControllerPathHash: 0x%x\n", st);
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
