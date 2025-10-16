#include "FltCommPort.h"
#include "Trace.h"
#include "UKShared.h"
#include "HookList.h"
#include "PortCtx.h"
#include "DriverCtx.h"

// Hook list operations are implemented in HookList.c


// write a scalable code even though I only have one client
NTSTATUS
Comm_PortConnect(
	__in PFLT_PORT ClientPort,
	__in_opt PVOID ServerPortCookie,
	__in_bcount_opt(SizeOfContext) PVOID ConnectionContext,
	__in ULONG SizeOfContext,
	__deref_out_opt PVOID *ConnectionCookie
) {
	NTSTATUS status = STATUS_SUCCESS;
	(ServerPortCookie);
	(ConnectionContext);
	(SizeOfContext);

	PCOMM_CONTEXT pPortCtx = PortCtx_CreateAndInsert(PsGetCurrentProcessId(), ClientPort);
	if (!pPortCtx) {
		Log(L"failed to create port context\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	
	Log(L"process %d connected to port 0x%p with port context 0x%p",
		pPortCtx->m_UserProcessId,
		ClientPort,
		pPortCtx);

	*ConnectionCookie = pPortCtx;

	return status;
}	

NTSTATUS
Comm_CreatePort(
) {
	NTSTATUS status;


	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING uniString;
	PSECURITY_DESCRIPTOR sd;

	//  Create a communication port.
	WCHAR* pwchCommPort = UMHHLP_PORT_NAME;
	RtlInitUnicodeString(&uniString, pwchCommPort);

	Log(L"creating port...\n");

	status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);

	if (NT_SUCCESS(status))
	{
		InitializeObjectAttributes(&oa,
			&uniString,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			NULL,
			sd);
		PFLT_PORT serverPort = NULL;
		status = FltCreateCommunicationPort(DriverCtx_GetFilter(),
			&serverPort,
			&oa,
			NULL,
			Comm_PortConnect,
			Comm_PortDisconnect,
			Comm_MessageNotify,
			COMM_MAX_CONNECTION);
		if (NT_SUCCESS(status)) {
			DriverCtx_SetServerPort(serverPort);
		}

		Log(L"minifilter port created: %wZ\n", oa.ObjectName);
		FltFreeSecurityDescriptor(sd);
	}
	else {
		Log(L"failed to call FltBuildDefaultSecurityDescriptor: 0x%x\n", status);
		return status;
	}
	Log(L"port created successfully\n");
	return status;
}

VOID
Comm_PortDisconnect(
	__in PVOID ConnectionCookie
) {
	/* Use lookup+reference to avoid races where ConnectionCookie may be a
	 * dangling pointer. This atomically verifies the entry is still in the
	 * list and takes a ref.
	 */
	PCOMM_CONTEXT pPortCtx = PortCtx_FindAndReferenceByCookie(ConnectionCookie);
	if (!pPortCtx) return;

	Log(L"client process %d disconnected with port context 0x%p\n",
		pPortCtx->m_UserProcessId, pPortCtx);

	/* Unlink from module list and drop list ownership. This will call
	 * PortCtx_Dereference for the list's ref; we still hold our caller ref
	 * and must drop it below.
	 */
	PortCtx_Remove(pPortCtx);

	/* Drop our reference */
	PortCtx_Dereference(pPortCtx);
}



NTSTATUS
Comm_MessageNotify(
	__in PVOID ConnectionCookie,
	__in_bcount_opt(InputBufferSize) PVOID InputBuffer,
	__in ULONG InputBufferSize,
	__out_bcount_part_opt(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
	__in ULONG OutputBufferSize,
	__out PULONG ReturnOutputBufferLength
) {
	NTSTATUS status = STATUS_SUCCESS;
	/* Initialize caller-ref variables early so cleanup always sees defined
	 * values even when we jump to cleanup before the later assignment.
	 */
	PCOMM_CONTEXT pPortCtxCallerRef = NULL;
	// Validate input
	if (!InputBuffer || InputBufferSize < (ULONG)UMHH_MSG_HEADER_SIZE) {
		status = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	PUMHH_COMMAND_MESSAGE msg = (PUMHH_COMMAND_MESSAGE)InputBuffer;

	/* If a caller wants to use the connection cookie, take a reference at
	 * the top of this function to guard against concurrent disconnect/unload.
	 * PortCtx_Reference returns TRUE if we hold a ref.
	 */
	pPortCtxCallerRef = PortCtx_FindAndReferenceByCookie(ConnectionCookie);

	switch (msg->m_Cmd) {
	case CMD_SET_USER_DIR: {
		// Single global user-dir is expected (only UMController.exe will send this).
		SIZE_T payloadBytes = InputBufferSize - UMHH_MSG_HEADER_SIZE;
		if (payloadBytes < sizeof(WCHAR)) {
			if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
			status = STATUS_BUFFER_TOO_SMALL;
			goto cleanup;
		}
		PCWSTR w = (PCWSTR)msg->m_Data;
		SIZE_T wcharCount = payloadBytes / sizeof(WCHAR);
		BOOLEAN foundNull = FALSE;
		for (SIZE_T i = 0; i < wcharCount; ++i) {
			if (w[i] == L'\0') { foundNull = TRUE; break; }
		}
		if (!foundNull) {
			if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
			status = STATUS_INVALID_PARAMETER;
			goto cleanup;
		}
		NTSTATUS st = DriverCtx_SetUserDir(w, (SIZE_T)(wcharCount * sizeof(WCHAR)));
		if (OutputBuffer && OutputBufferSize >= sizeof(NTSTATUS)) {
			*(NTSTATUS*)OutputBuffer = st;
			if (ReturnOutputBufferLength) *ReturnOutputBufferLength = sizeof(NTSTATUS);
			status = STATUS_SUCCESS;
			goto cleanup;
		} else {
			if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
			status = STATUS_BUFFER_TOO_SMALL;
			goto cleanup;
		}
	}
	case CMD_ADD_HOOK: {
		// Expect at least an 8-byte hash. Remainder may contain a null-terminated
		// UTF-16LE NT path string (optional). Layout: [8-byte hash][WCHAR path...\0]
		if (InputBufferSize < ((ULONG)UMHH_MSG_HEADER_SIZE + (ULONG)sizeof(ULONGLONG))) {
			if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
			status = STATUS_BUFFER_TOO_SMALL;
			goto cleanup;
		}
		ULONGLONG hash = 0;
		RtlCopyMemory(&hash, msg->m_Data, sizeof(ULONGLONG));
		PCWSTR path = NULL;
		// Compute number of bytes available for the path after the 8-byte hash
		SIZE_T pathBytes = 0;
		// m_Data is a flexible payload array; the total payload bytes available after
		// the header is InputBufferSize - UMHH_MSG_HEADER_SIZE
		if (InputBufferSize > ((ULONG)UMHH_MSG_HEADER_SIZE + (ULONG)sizeof(ULONGLONG))) {
			pathBytes = InputBufferSize - UMHH_MSG_HEADER_SIZE - sizeof(ULONGLONG);
			if (pathBytes >= sizeof(WCHAR)) {
				path = (PCWSTR)(msg->m_Data + sizeof(ULONGLONG));
			}
		}
		NTSTATUS st = HookList_AddEntry(hash, path, pathBytes);
		if (OutputBuffer && OutputBufferSize >= sizeof(NTSTATUS)) {
			*(NTSTATUS*)OutputBuffer = st;
			if (ReturnOutputBufferLength) *ReturnOutputBufferLength = sizeof(NTSTATUS);
			status = STATUS_SUCCESS;
			goto cleanup;
		}
		else {
			if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
			status = STATUS_BUFFER_TOO_SMALL;
			goto cleanup;
		}
	}
	case CMD_REMOVE_HOOK: {
		if (InputBufferSize < (sizeof(UMHH_COMMAND_MESSAGE) + sizeof(ULONGLONG) - 1)) {
			if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
			status = STATUS_BUFFER_TOO_SMALL;
			goto cleanup;
		}
		ULONGLONG hash = 0;
		RtlCopyMemory(&hash, msg->m_Data, sizeof(ULONGLONG));
		BOOLEAN removed = HookList_RemoveEntry(hash);
		if (OutputBuffer && OutputBufferSize >= sizeof(BOOLEAN)) {
			*(BOOLEAN*)OutputBuffer = removed;
			if (ReturnOutputBufferLength) *ReturnOutputBufferLength = sizeof(BOOLEAN);
			status = STATUS_SUCCESS;
			goto cleanup;
		}
		else {
			if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
			status = STATUS_BUFFER_TOO_SMALL;
			goto cleanup;
		}
	}
	case CMD_CHECK_HOOK_LIST: {
		// Expect an 8-byte hash payload
		if (InputBufferSize < ((ULONG)UMHH_MSG_HEADER_SIZE + (ULONG)sizeof(ULONGLONG))) {
			// client didn't send full hash
			if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
			status = STATUS_BUFFER_TOO_SMALL;
			goto cleanup;
		}
		ULONGLONG hash = 0;
		// m_Data is declared as size 1; copy the following bytes
		RtlCopyMemory(&hash, msg->m_Data, sizeof(ULONGLONG));

		BOOLEAN found = FALSE;

		// Delegate to HookList module
		found = HookList_ContainsHash(hash);

		if (OutputBuffer && OutputBufferSize >= sizeof(BOOLEAN)) {
			*(BOOLEAN*)OutputBuffer = found;
			if (ReturnOutputBufferLength) *ReturnOutputBufferLength = sizeof(BOOLEAN);
			status = STATUS_SUCCESS;
			goto cleanup;
		}
		else {
			if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
			status = STATUS_BUFFER_TOO_SMALL;
			goto cleanup;
		}
	}
	case CMD_GET_IMAGE_PATH_BY_PID: {
		// Expect a 4-byte PID payload
		if (InputBufferSize < ((ULONG)UMHH_MSG_HEADER_SIZE + (ULONG)sizeof(DWORD))) {
			if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
			status = STATUS_BUFFER_TOO_SMALL;
			goto cleanup;
		}
		DWORD pid = 0;
		RtlCopyMemory(&pid, msg->m_Data, sizeof(DWORD));

		// Lookup process object
		PEPROCESS process = NULL;
		NTSTATUS st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
		if (!NT_SUCCESS(st) || process == NULL) {
			if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
			status = STATUS_NOT_FOUND;
			goto cleanup;
		}

		// Ask the kernel for the process image name (NT path). SeLocateProcessImageName
		// returns a pointer to a UNICODE_STRING allocated by the kernel which we must
		// free with ExFreePool when done.
		PUNICODE_STRING imageName = NULL;
		NTSTATUS res = SeLocateProcessImageName(process, &imageName);
		if (!NT_SUCCESS(res) || imageName == NULL || imageName->Length == 0) {
			ObDereferenceObject(process);
			if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
			status = STATUS_NOT_FOUND;
			goto cleanup;
		}

		// Copy imageName->Buffer (Unicode WCHARs) into OutputBuffer if large enough.
		ULONG bytesNeeded = imageName->Length + sizeof(WCHAR); // include space for null
		if (OutputBuffer && OutputBufferSize >= bytesNeeded) {
			RtlCopyMemory(OutputBuffer, imageName->Buffer, imageName->Length);
			// Null-terminate
			((WCHAR*)OutputBuffer)[imageName->Length / sizeof(WCHAR)] = L'\0';
			if (ReturnOutputBufferLength) *ReturnOutputBufferLength = bytesNeeded;
			status = STATUS_SUCCESS;
		}
		else {
			if (ReturnOutputBufferLength) *ReturnOutputBufferLength = bytesNeeded;
			status = STATUS_BUFFER_TOO_SMALL;
		}

		// Cleanup
		ExFreePool(imageName);
		ObDereferenceObject(process);
		goto cleanup;
		break;
	}
	default:
		break;
	}

cleanup:
	if (pPortCtxCallerRef) PortCtx_Dereference(pPortCtxCallerRef);
	return status;
}

NTSTATUS Comm_BroadcastProcessNotify(DWORD ProcessId, BOOLEAN Create, PULONG outNotifiedCount, PUNICODE_STRING imageName) {
	NTSTATUS status = STATUS_SUCCESS;
	PCOMM_CONTEXT* arr = NULL;
	ULONG count = 0;
	if (outNotifiedCount) *outNotifiedCount = 0;
	status = PortCtx_Snapshot(&arr, &count);
	if (!NT_SUCCESS(status)) return status;
	if (count == 0) return STATUS_SUCCESS;
	SIZE_T nameBytes = 0;
	if (imageName && imageName->Buffer && imageName->Length > 0) nameBytes = imageName->Length;

	// Build message: [DWORD pid][BOOLEAN create][optional WCHAR name...\0]
	ULONG payloadSize = (ULONG)(sizeof(DWORD) + sizeof(BOOLEAN) + nameBytes + (nameBytes ? sizeof(WCHAR) : 0));
	ULONG msgSize = UMHH_MSG_HEADER_SIZE + payloadSize;
	PUMHH_COMMAND_MESSAGE msg = ExAllocatePoolWithTag(NonPagedPool, msgSize, tag_port);
	if (!msg) {
		PortCtx_FreeSnapshot(arr, count);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlZeroMemory(msg, msgSize);
	msg->m_Cmd = CMD_PROCESS_NOTIFY;
	// copy pid and create flag
	RtlCopyMemory(msg->m_Data, &ProcessId, sizeof(DWORD));
	RtlCopyMemory(msg->m_Data + sizeof(DWORD), &Create, sizeof(BOOLEAN));
	// append optional image name (raw WCHARs), followed by NUL terminator
	if (nameBytes > 0 && imageName != NULL) {
		UCHAR* dest = (UCHAR*)msg->m_Data + sizeof(DWORD) + sizeof(BOOLEAN);
		RtlCopyMemory(dest, imageName->Buffer, nameBytes);
		// Null-terminate
		WCHAR* term = (WCHAR*)(dest + nameBytes);
		*term = L'\0';
		// NOTE: caller retains ownership of imageName and is responsible for
		// freeing it after this call.
	}

	ULONG notified = 0;
	for (ULONG i = 0; i < count; ++i) {
		PCOMM_CONTEXT ctx = arr[i];
		if (!ctx || ctx->m_ClientPort == NULL) continue;
		NTSTATUS st = FltSendMessage(DriverCtx_GetFilter(), &ctx->m_ClientPort, msg, msgSize, NULL, 0, NULL);
		if (NT_SUCCESS(st)) notified++;
		else {
			// Diagnostic log for failed sends to aid correlation during stress tests.
			Log(L"Comm_BroadcastProcessNotify: FltSendMessage failed for client pid %d port %p st=0x%x\n",
				ctx->m_UserProcessId, ctx->m_ClientPort, st);
		}
	}

	ExFreePool(msg);
	PortCtx_FreeSnapshot(arr, count);
	if (outNotifiedCount) *outNotifiedCount = notified;
	return STATUS_SUCCESS;
}

NTSTATUS Comm_BroadcastApcQueued(DWORD ProcessId, PULONG outNotifiedCount) {
	NTSTATUS status = STATUS_SUCCESS;
	PCOMM_CONTEXT* arr = NULL;
	ULONG count = 0;
	if (outNotifiedCount) *outNotifiedCount = 0;
	status = PortCtx_Snapshot(&arr, &count);
	if (!NT_SUCCESS(status)) return status;
	if (count == 0) return STATUS_SUCCESS;

	// Build message: [DWORD pid]
	ULONG payloadSize = (ULONG)sizeof(DWORD);
	ULONG msgSize = UMHH_MSG_HEADER_SIZE + payloadSize;
	PUMHH_COMMAND_MESSAGE msg = ExAllocatePoolWithTag(NonPagedPool, msgSize, tag_port);
	if (!msg) {
		PortCtx_FreeSnapshot(arr, count);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlZeroMemory(msg, msgSize);
	msg->m_Cmd = CMD_APC_QUEUED;
	RtlCopyMemory(msg->m_Data, &ProcessId, sizeof(DWORD));

	ULONG notified = 0;
	for (ULONG i = 0; i < count; ++i) {
		PCOMM_CONTEXT ctx = arr[i];
		if (!ctx || ctx->m_ClientPort == NULL) continue;
		NTSTATUS st = FltSendMessage(DriverCtx_GetFilter(), &ctx->m_ClientPort, msg, msgSize, NULL, 0, NULL);
		if (NT_SUCCESS(st)) notified++;
		else {
			Log(L"Comm_BroadcastApcQueued: FltSendMessage failed for client pid %d port %p st=0x%x\n",
				ctx->m_UserProcessId, ctx->m_ClientPort, st);
		}
	}

	ExFreePool(msg);
	PortCtx_FreeSnapshot(arr, count);
	if (outNotifiedCount) *outNotifiedCount = notified;
	return STATUS_SUCCESS;
}