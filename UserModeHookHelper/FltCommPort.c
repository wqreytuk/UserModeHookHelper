#include "FltCommPort.h"
#include "Trace.h"
#include "UKShared.h"

// Add an entry to the hook list. The caller may provide an NT path
// (wide string) which will be copied into freshly allocated non-paged
// pool and attached to the entry. Returns STATUS_SUCCESS or an error code.
NTSTATUS HookList_AddEntry(ULONGLONG hash, PCWSTR NtPath) {
	PHOOK_ENTRY p = ExAllocatePoolWithTag(NonPagedPool, sizeof(HOOK_ENTRY), tag_port);
	if (!p) return STATUS_INSUFFICIENT_RESOURCES;
	RtlZeroMemory(p, sizeof(HOOK_ENTRY));
	p->Hash = hash;
	InitializeListHead(&p->ListEntry);
	p->NtPath.Buffer = NULL;
	p->NtPath.Length = 0;
	p->NtPath.MaximumLength = 0;

	if (NtPath) {
		size_t chars = wcslen(NtPath) + 1; // include null
		SIZE_T bytes = chars * sizeof(WCHAR);
		PWCHAR buf = ExAllocatePoolWithTag(NonPagedPool, bytes, tag_port);
		if (!buf) {
			ExFreePoolWithTag(p, tag_port);
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		RtlCopyMemory(buf, NtPath, bytes);
		p->NtPath.Buffer = buf;
		// Length excludes trailing null
		p->NtPath.Length = (USHORT)((chars - 1) * sizeof(WCHAR));
		p->NtPath.MaximumLength = (USHORT)(bytes);
	}

	ExAcquireResourceExclusiveLite(&gVar.m_HookListLock, TRUE);
	InsertTailList(&gVar.m_HookList, &p->ListEntry);
	ExReleaseResourceLite(&gVar.m_HookListLock);
	return STATUS_SUCCESS;
}

// Remove matching hash from hook list. Returns TRUE if removed.
BOOLEAN HookList_RemoveEntry(ULONGLONG hash) {
	BOOLEAN removed = FALSE;
	ExAcquireResourceExclusiveLite(&gVar.m_HookListLock, TRUE);
	PLIST_ENTRY entry = gVar.m_HookList.Flink;
	while (entry != &gVar.m_HookList) {
		PHOOK_ENTRY p = CONTAINING_RECORD(entry, HOOK_ENTRY, ListEntry);
		PLIST_ENTRY next = entry->Flink;
		if (p->Hash == hash) {
			RemoveEntryList(&p->ListEntry);
			if (p->NtPath.Buffer) {
				ExFreePoolWithTag(p->NtPath.Buffer, tag_port);
			}
			ExFreePoolWithTag(p, tag_port);
			removed = TRUE;
			break;
		}
		entry = next;
	}
	ExReleaseResourceLite(&gVar.m_HookListLock);
	return removed;
}


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

		DbgPrint("minifilter port created: %wZ\n", oa.ObjectName);
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
	NTSTATUS status = STATUS_SUCCESS;
	(ConnectionCookie);
	(InputBuffer);
	(InputBufferSize);
	(OutputBuffer);
	(OutputBufferSize);
	(ReturnOutputBufferLength);
	// Validate input
	if (!InputBuffer || InputBufferSize < sizeof(UMHH_COMMAND_MESSAGE)) {
		return STATUS_INVALID_PARAMETER;
	}

	PUMHH_COMMAND_MESSAGE msg = (PUMHH_COMMAND_MESSAGE)InputBuffer;
	switch (msg->m_Cmd) {
	case CMD_CHECK_HOOK_LIST: {
		// Expect an 8-byte hash payload
		if (InputBufferSize < (sizeof(UMHH_COMMAND_MESSAGE) + sizeof(ULONGLONG) - 1)) {
			// client didn't send full hash
			if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
			return STATUS_BUFFER_TOO_SMALL;
		}
		ULONGLONG hash = 0;
		// m_Data is declared as size 1; copy the following bytes
		RtlCopyMemory(&hash, msg->m_Data, sizeof(ULONGLONG));

		BOOLEAN found = FALSE;

		// Walk hook list under shared lock
		ExAcquireResourceSharedLite(&gVar.m_HookListLock, TRUE);
		PLIST_ENTRY entry = gVar.m_HookList.Flink;
		while (entry != &gVar.m_HookList) {
			PHOOK_ENTRY pHook = CONTAINING_RECORD(entry, HOOK_ENTRY, ListEntry);
			if (pHook && pHook->Hash == hash) {
				found = TRUE;
				break;
			}
			entry = entry->Flink;
		}
		ExReleaseResourceLite(&gVar.m_HookListLock);

		if (OutputBuffer && OutputBufferSize >= sizeof(BOOLEAN)) {
			*(BOOLEAN*)OutputBuffer = found;
			if (ReturnOutputBufferLength) *ReturnOutputBufferLength = sizeof(BOOLEAN);
			return STATUS_SUCCESS;
		}
		else {
			if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
			return STATUS_BUFFER_TOO_SMALL;
		}
	}
	case CMD_GET_IMAGE_PATH_BY_PID: {
		// existing behavior will be handled later; fall through to default for now
		break;
	}
	default:
		break;
	}

	return status;
}