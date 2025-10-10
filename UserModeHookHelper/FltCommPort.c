#include "FltCommPort.h"
#include "Trace.h"
#include "UKShared.h"


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

	PCOMM_CONTEXT pPortCtx = ExAllocatePoolWithTag(NonPagedPool, sizeof(COMM_CONTEXT), tag_port);
	if (!pPortCtx) {
		Log(L"failed to call ExAllocatePoolWithTag\n");
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	pPortCtx->m_UserProcessId = PsGetCurrentProcessId();
	pPortCtx->m_ClientPort = ClientPort;
	pPortCtx->m_RefCount = 0; 
	InitializeListHead(&pPortCtx->m_entry);
	// insert into global list under lock
	ExAcquireResourceExclusiveLite(&gVar.m_PortCtxListLock, TRUE);
	InsertTailList(&gVar.m_PortCtxList, &pPortCtx->m_entry);
	ExReleaseResourceLite(&gVar.m_PortCtxListLock);
	
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
	 	status = FltCreateCommunicationPort(gVar.m_Filter,
	 		&gVar.m_ServerPort,
	 		&oa,
	 		NULL,
	 		Comm_PortConnect,
	 		Comm_PortDisconnect,
	 		Comm_MessageNotify,
	 		COMM_MAX_CONNECTION);
		if (NT_SUCCESS(status)) {
			Log(L"minifilter port created: %wZ\n", oa.ObjectName);
			FltFreeSecurityDescriptor(sd);
		}
		else {
			Log(L"failed to call FltCreateCommunicationPort: 0x%x\n", status);
			FltFreeSecurityDescriptor(sd);
			return status;
		}
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

	Log(L"client process %d disconnected with port context 0x%p\n",
		pPortCtx->m_UserProcessId, pPortCtx);

	// remove from ctx list (only if it's linked)
	ExAcquireResourceExclusiveLite(&gVar.m_PortCtxListLock, TRUE);
	// After InitializeListHead, an unlinked entry has Flink == &m_entry. So
	// check membership by comparing Flink to itself.
	if (pPortCtx->m_entry.Flink != &pPortCtx->m_entry) {
		RemoveEntryList(&pPortCtx->m_entry);
	}
	ExReleaseResourceLite(&gVar.m_PortCtxListLock);

	ExFreePoolWithTag(pPortCtx, tag_port);
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
	(ConnectionCookie);
	NTSTATUS status = STATUS_SUCCESS;
	PUMHH_COMMAND_MESSAGE pMsg = NULL;
	DWORD pid = 0;
	PEPROCESS pProcess = NULL;
	PUNICODE_STRING pImagePath = NULL;
	PWCHAR pOutputWide = NULL;
	ULONG requiredSize = 0;

	// Initialize return length
	if (ReturnOutputBufferLength) {
		*ReturnOutputBufferLength = 0;
	}

	// Validate input buffer size
	if (!InputBuffer || InputBufferSize < sizeof(UMHH_COMMAND_MESSAGE)) {
		Log(L"Comm_MessageNotify: Invalid input buffer size %lu\n", InputBufferSize);
		return STATUS_INVALID_PARAMETER;
	}

	pMsg = (PUMHH_COMMAND_MESSAGE)InputBuffer;

	switch (pMsg->m_Cmd) {
	case CMD_CHECK_HOOK_LIST: {
		// TODO: Implement hash-based hook list checking
		Log(L"Comm_MessageNotify: CMD_CHECK_HOOK_LIST not yet implemented\n");
		status = STATUS_NOT_IMPLEMENTED;
		break;
	}

	case CMD_GET_IMAGE_PATH_BY_PID: {
		// Validate payload size for PID
		// Compute the minimal required buffer size as: offset_of(m_Data) + payload_size
		// This avoids confusion from struct padding (sizeof may include padding).
		{
			ULONG minSize = (ULONG)((ULONG_PTR)&((UMHH_COMMAND_MESSAGE*)0)->m_Data) + sizeof(DWORD);
			if (InputBufferSize < minSize) {
				Log(L"Comm_MessageNotify: CMD_GET_IMAGE_PATH_BY_PID insufficient payload. Required: %lu, Provided: %lu\n", minSize, InputBufferSize);
				status = STATUS_INVALID_PARAMETER;
				break;
			}
		}

		// Extract PID from payload
		RtlCopyMemory(&pid, pMsg->m_Data, sizeof(DWORD));
		Log(L"Comm_MessageNotify: CMD_GET_IMAGE_PATH_BY_PID for PID %lu\n", pid);

		// Look up process by PID
		status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &pProcess);
		if (!NT_SUCCESS(status)) {
			Log(L"Comm_MessageNotify: PsLookupProcessByProcessId failed for PID %lu, status 0x%x\n", pid, status);
			break;
		}

		// Get the process image file name (NT path)
		status = SeLocateProcessImageName(pProcess, &pImagePath);
		if (!NT_SUCCESS(status)) {
			Log(L"Comm_MessageNotify: SeLocateProcessImageName failed for PID %lu, status 0x%x\n", pid, status);
			ObDereferenceObject(pProcess);
			break;
		}

		// Calculate required output size (wide string length + null terminator)
		requiredSize = pImagePath->Length + sizeof(WCHAR);

		if (!OutputBuffer || OutputBufferSize < requiredSize) {
			Log(L"Comm_MessageNotify: Output buffer too small. Required: %lu, Available: %lu\n", requiredSize, OutputBufferSize);
			status = STATUS_BUFFER_TOO_SMALL;
			if (ReturnOutputBufferLength) {
				*ReturnOutputBufferLength = requiredSize;
			}
		} else {
			// Copy the wide string to output buffer
			pOutputWide = (PWCHAR)OutputBuffer;
			RtlZeroMemory(pOutputWide, OutputBufferSize);
			RtlCopyMemory(pOutputWide, pImagePath->Buffer, pImagePath->Length);
			// Null-terminate
			pOutputWide[pImagePath->Length / sizeof(WCHAR)] = L'\0';
			
			if (ReturnOutputBufferLength) {
				*ReturnOutputBufferLength = requiredSize;
			}
			
			Log(L"Comm_MessageNotify: Returning path for PID %lu: %wZ\n", pid, pImagePath);
			status = STATUS_SUCCESS;
		}

		// Cleanup
		ExFreePool(pImagePath);
		ObDereferenceObject(pProcess);
		break;
	}

	default: {
		Log(L"Comm_MessageNotify: Unknown command %lu\n", pMsg->m_Cmd);
		status = STATUS_INVALID_PARAMETER;
		break;
	}
	}

	return status;
}