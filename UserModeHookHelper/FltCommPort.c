#include "FltCommPort.h"
#include "Trace.h"


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
	return status;
}