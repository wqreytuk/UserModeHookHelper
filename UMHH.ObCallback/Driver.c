
#include <fltKernel.h>

#include <ntifs.h> 
#include <ntstrsafe.h>
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


// 这个是我们的回调函数，我们将在这里进行一些检查来防止别人把我们关掉
NTSTATUS PreDeleteProcessCallback(
	_In_ PVOID RegistrationContext,
	_In_ POB_PRE_OPERATION_INFORMATION OperationInformation
) {
	if (!OperationInformation) return STATUS_SUCCESS;



	PUNICODE_STRING imageName = NULL;
	NTSTATUS stImg = 0;
	if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
		stImg = SeLocateProcessImageName((&OperationInformation->Parameters->DuplicateHandleInformation)->SourceProcess,
			&imageName);
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

		info->DesiredAccess = info->OriginalDesiredAccess;
		return STATUS_SUCCESS;

	}

	if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
		POB_PRE_DUPLICATE_HANDLE_INFORMATION dupInfo = &OperationInformation->Parameters->DuplicateHandleInformation;

		dupInfo->DesiredAccess = dupInfo->OriginalDesiredAccess;
		return STATUS_SUCCESS;

	}
}

// 该函数用于注册ObCallback
NTSTATUS RegisterProcessCallback() {
	OB_OPERATION_REGISTRATION operations[1] = { 0 };

	operations[0].ObjectType = *PsProcessType;  // Monitor process objects
	operations[0].Operations = 3;
	operations[0].PreOperation = PreDeleteProcessCallback;  // Callback for process deletion

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


	// DbgBreakPoint();


	NTSTATUS  status = STATUS_SUCCESS;
	PSECURITY_DESCRIPTOR sd = NULL;



	// 注册自保回调
	status = RegisterProcessCallback();
	if (!NT_SUCCESS(status)) {
		Log(L"failed to register ObProcessType callback, Status=0x%x\n", status);
		goto ABORTION;
	}
	else
		Log(L"ObProcessType callback registered\n", status);
	LARGE_INTEGER cookie;

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
