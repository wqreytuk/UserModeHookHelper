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
	PCOMM_CONTEXT pPortCtx = (PCOMM_CONTEXT)ConnectionCookie;
	if (!pPortCtx) return;
	/* Try to take a reference; if the context is already removed/unloading
	 * PortCtx_Reference will return FALSE and we bail out. This avoids
	 * reading m_Removed directly and ensures we actually hold a ref.
	 */
	if (!PortCtx_Reference(pPortCtx)) {
		return;
	}

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
	(ConnectionCookie);
	(InputBuffer);
	(InputBufferSize);
	(OutputBuffer);
	(OutputBufferSize);
	(ReturnOutputBufferLength);
	/* Initialize caller-ref variables early so cleanup always sees defined
	 * values even when we jump to cleanup before the later assignment.
	 */
	PCOMM_CONTEXT pPortCtxCallerRef = NULL;
	BOOLEAN haveRef = FALSE;
	// Validate input
	if (!InputBuffer || InputBufferSize < sizeof(UMHH_COMMAND_MESSAGE)) {
		status = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	PUMHH_COMMAND_MESSAGE msg = (PUMHH_COMMAND_MESSAGE)InputBuffer;

	/* If a caller wants to use the connection cookie, take a reference at
	 * the top of this function to guard against concurrent disconnect/unload.
	 * PortCtx_Reference returns TRUE if we hold a ref.
	 */
	pPortCtxCallerRef = (PCOMM_CONTEXT)ConnectionCookie;
	haveRef = FALSE;
	if (pPortCtxCallerRef) {
		haveRef = PortCtx_Reference(pPortCtxCallerRef);
		if (!haveRef) pPortCtxCallerRef = NULL;
	}

	switch (msg->m_Cmd) {
	case CMD_ADD_HOOK: {
		// Expect at least an 8-byte hash. Remainder may contain a null-terminated
		// UTF-16LE NT path string (optional). Layout: [8-byte hash][WCHAR path...\0]
		if (InputBufferSize < (sizeof(UMHH_COMMAND_MESSAGE) + sizeof(ULONGLONG) - 1)) {
			if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
			status = STATUS_BUFFER_TOO_SMALL;
			goto cleanup;
		}
		ULONGLONG hash = 0;
		RtlCopyMemory(&hash, msg->m_Data, sizeof(ULONGLONG));
		PCWSTR path = NULL;
		// Compute number of bytes available for the path after the 8-byte hash
		SIZE_T pathBytes = 0;
		// m_Data is a 1-byte array at the end of UMHH_COMMAND_MESSAGE; the total payload
		// bytes available after the header is InputBufferSize - (sizeof(UMHH_COMMAND_MESSAGE) - 1)
		if (InputBufferSize > (sizeof(UMHH_COMMAND_MESSAGE) - 1 + sizeof(ULONGLONG))) {
			pathBytes = InputBufferSize - (sizeof(UMHH_COMMAND_MESSAGE) - 1) - sizeof(ULONGLONG);
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
		if (InputBufferSize < (sizeof(UMHH_COMMAND_MESSAGE) + sizeof(ULONGLONG) - 1)) {
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
		// existing behavior will be handled later; fall through to default for now
		break;
	}
	default:
		break;
	}
	
cleanup:
    if (pPortCtxCallerRef) PortCtx_Dereference(pPortCtxCallerRef);
    return status;
}