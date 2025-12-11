#include "FltCommPort.h"
#include "Trace.h"
#include "UKShared.h"
#include "HookList.h"
#include "PortCtx.h"
#include "DriverCtx.h"
#include "Inject.h"
#include "PE.h"
#include "KernelOffsets.h"
#include "mini.h"
// Some WDK versions may not declare PsGetProcessWow64Process; forward-declare it here.
extern PVOID PsGetProcessWow64Process(IN PEPROCESS Process);
extern NTSTATUS NTAPI MmCopyVirtualMemory
(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
);
// Forward declarations for modular command handlers (defined below)
static NTSTATUS Handle_SetUserDir(PUMHH_COMMAND_MESSAGE msg, ULONG InputBufferSize, PVOID OutputBuffer, ULONG OutputBufferSize, PULONG ReturnOutputBufferLength);
static NTSTATUS Handle_AddHook(PUMHH_COMMAND_MESSAGE msg, ULONG InputBufferSize, PVOID OutputBuffer, ULONG OutputBufferSize, PULONG ReturnOutputBufferLength);
static NTSTATUS Handle_RemoveHook(PUMHH_COMMAND_MESSAGE msg, ULONG InputBufferSize, PVOID OutputBuffer, ULONG OutputBufferSize, PULONG ReturnOutputBufferLength);
static NTSTATUS Handle_CheckHookList(PUMHH_COMMAND_MESSAGE msg, ULONG InputBufferSize, PVOID OutputBuffer, ULONG OutputBufferSize, PULONG ReturnOutputBufferLength);
static NTSTATUS Handle_GetImagePathByPid(PUMHH_COMMAND_MESSAGE msg, ULONG InputBufferSize, PVOID OutputBuffer, ULONG OutputBufferSize, PULONG ReturnOutputBufferLength);
static NTSTATUS Handle_GetHookSection(PCOMM_CONTEXT CallerCtx, PUMHH_COMMAND_MESSAGE msg, ULONG InputBufferSize, PVOID OutputBuffer, ULONG OutputBufferSize, PULONG ReturnOutputBufferLength);
static NTSTATUS Handle_GetProcessHandle(PCOMM_CONTEXT CallerCtx, PUMHH_COMMAND_MESSAGE msg, ULONG InputBufferSize, PVOID OutputBuffer, ULONG OutputBufferSize, PULONG ReturnOutputBufferLength);
static NTSTATUS Handle_CreateRemoteThread(PCOMM_CONTEXT CallerCtx, PUMHH_COMMAND_MESSAGE msg, ULONG InputBufferSize, PVOID OutputBuffer, ULONG OutputBufferSize, PULONG ReturnOutputBufferLength);
static NTSTATUS Handle_GetSyscallAddr(PUMHH_COMMAND_MESSAGE msg, ULONG InputBufferSize, PVOID OutputBuffer, ULONG OutputBufferSize, PULONG ReturnOutputBufferLength);
static NTSTATUS Handle_WriteDllPathToTargetProcess(PCOMM_CONTEXT CallerCtx, PUMHH_COMMAND_MESSAGE msg, ULONG InputBufferSize, PVOID OutputBuffer, ULONG OutputBufferSize, PULONG ReturnOutputBufferLength);
static NTSTATUS Handle_UnprotectPpl(PUMHH_COMMAND_MESSAGE msg, ULONG InputBufferSize, PVOID OutputBuffer, ULONG OutputBufferSize, PULONG ReturnOutputBufferLength);
static NTSTATUS Handle_QueryPplProtection(PUMHH_COMMAND_MESSAGE msg, ULONG InputBufferSize, PVOID OutputBuffer, ULONG OutputBufferSize, PULONG ReturnOutputBufferLength);
static NTSTATUS Handle_RecoverPpl(PUMHH_COMMAND_MESSAGE msg, ULONG InputBufferSize, PVOID OutputBuffer, ULONG OutputBufferSize, PULONG ReturnOutputBufferLength);
static NTSTATUS Handle_WriteProcessMemory(PCOMM_CONTEXT CallerCtx, PUMHH_COMMAND_MESSAGE msg, ULONG InputBufferSize, PVOID OutputBuffer, ULONG OutputBufferSize, PULONG ReturnOutputBufferLength);


static NTSTATUS Handle_IsProcessWow64(PUMHH_COMMAND_MESSAGE msg, ULONG InputBufferSize, PVOID OutputBuffer, ULONG OutputBufferSize, PULONG ReturnOutputBufferLength);
static NTSTATUS Handle_IsProtectedProcess(PUMHH_COMMAND_MESSAGE msg, ULONG InputBufferSize, PVOID OutputBuffer, ULONG OutputBufferSize, PULONG ReturnOutputBufferLength);
static NTSTATUS Handle_SetGlobalHookMode(PUMHH_COMMAND_MESSAGE msg, ULONG InputBufferSize, PVOID OutputBuffer, ULONG OutputBufferSize, PULONG ReturnOutputBufferLength);
static NTSTATUS Handle_ForceInject(PUMHH_COMMAND_MESSAGE msg, ULONG InputBufferSize, PVOID OutputBuffer, ULONG OutputBufferSize, PULONG ReturnOutputBufferLength);
// NOTE: Do NOT declare or call user-mode-only path conversion helpers from
// kernel code here. NT-path resolution is performed in user-mode. The driver
// keeps a simple fallback when a path isn't supplied by user-mode.

// Hook list operations are implemented in HookList.c

// Work item used to defer broadcasts to a system thread when the caller's
// thread is terminating and cannot complete a synchronous FltSendMessage.
typedef struct _BROADCAST_WORK {
	WORK_QUEUE_ITEM WorkItem;
	PUMHH_COMMAND_MESSAGE Msg;
	ULONG MsgSize;
	PCOMM_CONTEXT* Array;
	ULONG Count;
	PFLT_FILTER FilterRef; // keep filter referenced during work
} BROADCAST_WORK, *PBROADCAST_WORK;

// Work item to defer EPROCESS field recovery (Protection / SectionSignatureLevel)
typedef struct _EPROCESS_RECOVERY_WORK {
	WORK_QUEUE_ITEM WorkItem;
	PEPROCESS Process; // referenced
	EPROCESS_OFFSETS Offsets; // offsets snapshot
	UCHAR OrigProtection;
	UCHAR OrigSectionSignatureLevel;
} EPROCESS_RECOVERY_WORK, *PEPROCESS_RECOVERY_WORK;

static VOID
EprocessRecoveryRoutine(
	PVOID Context
) {
	PEPROCESS_RECOVERY_WORK w = (PEPROCESS_RECOVERY_WORK)Context;
	if (!w) return;
	// Delay 2 seconds before recovery
	LARGE_INTEGER interval; interval.QuadPart = -20000000LL; // 2s in 100ns units
	KeDelayExecutionThread(KernelMode, FALSE, &interval);
	__try {
		if (w->Process) {
			// Restore original values (ignore current protection state changes)
			(void)Mini_WriteKernelMemory((PVOID)((PUCHAR)w->Process + w->Offsets.ProtectionOffset), &w->OrigProtection, sizeof(UCHAR));
			(void)Mini_WriteKernelMemory((PVOID)((PUCHAR)w->Process + w->Offsets.SectionSignatureLevelOffset), &w->OrigSectionSignatureLevel, sizeof(UCHAR));
			Log(L"Deferred recovery: restored Protection=%d SectionSignatureLevel=%d for PID=%u\n",
				w->OrigProtection, w->OrigSectionSignatureLevel, PsGetProcessId(w->Process));
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		Log(L"Deferred recovery: exception while restoring process fields\n");
	}
	if (w->Process) ObDereferenceObject(w->Process);
	ExFreePoolWithTag(w, tag_port);
}

// Worker routine that performs deferred broadcasts from a safe system
// context. It iterates the snapshot, sends messages, removes disconnected
// ports, and frees all transferred resources.
static VOID
BroadcastWorkRoutine(
	PVOID Context
) {
	PBROADCAST_WORK w = (PBROADCAST_WORK)Context;
	if (!w) return;
	// If driver is unloading or server port is gone, abort early.
	if (DriverCtx_IsUnloading() || DriverCtx_GetServerPort() == NULL) {
		PortCtx_FreeSnapshot(w->Array, w->Count);
		ExFreePoolWithTag(w->Msg, tag_port);
		ExFreePoolWithTag(w, tag_port);
		if (w->FilterRef) FltObjectDereference(w->FilterRef);
		DriverCtx_DecWorkItems();
		return;
	}

	for (ULONG j = 0; j < w->Count; ++j) {
		PCOMM_CONTEXT c = w->Array[j];
		if (!c || c->m_ClientPort == NULL) continue;
		LARGE_INTEGER timeout;
		timeout.QuadPart = -10000000LL; // 1 second timeout
		NTSTATUS r = FltSendMessage(DriverCtx_GetFilter(), &c->m_ClientPort, w->Msg, w->MsgSize, NULL, 0, &timeout);
		if (!NT_SUCCESS(r)) {
			Log(L"Deferred broadcast: FltSendMessage failed for client pid %d port %p st=0x%x\n",
				c->m_UserProcessId, c->m_ClientPort, r);
			if (r == STATUS_PORT_DISCONNECTED) {
				PortCtx_Remove(c);
			}
		}
	}

	// Free the snapshot references and buffers that were transferred to us.
	PortCtx_FreeSnapshot(w->Array, w->Count);
	ExFreePoolWithTag(w->Msg, tag_port);
	ExFreePoolWithTag(w, tag_port);
	if (w->FilterRef) FltObjectDereference(w->FilterRef);
	DriverCtx_DecWorkItems();
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




// Enumerate hook list NT paths into OutputBuffer as a sequence of
// null-terminated WCHAR strings concatenated one after another. The caller
// supplies OutputBuffer/OutputBufferSize and the handler returns the total
// bytes written (or required) in ReturnOutputBufferLength.
static NTSTATUS
Handle_EnumHooks(
	PUMHH_COMMAND_MESSAGE msg,
	ULONG InputBufferSize,
	PVOID OutputBuffer,
	ULONG OutputBufferSize,
	PULONG ReturnOutputBufferLength
) {
	UNREFERENCED_PARAMETER(InputBufferSize);
	UNREFERENCED_PARAMETER(msg);
	ULONG required = 0;
	NTSTATUS st = HookList_EnumeratePaths(OutputBuffer, OutputBufferSize, &required);
	if (ReturnOutputBufferLength) *ReturnOutputBufferLength = required;
	return st;
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
		if (pPortCtxCallerRef) PortCtx_Dereference(pPortCtxCallerRef);
		return status;
	}

	PUMHH_COMMAND_MESSAGE msg = (PUMHH_COMMAND_MESSAGE)InputBuffer;

	/* If a caller wants to use the connection cookie, take a reference at
	 * the top of this function to guard against concurrent disconnect/unload.
	 * PortCtx_Reference returns TRUE if we hold a ref.
	 */
	pPortCtxCallerRef = PortCtx_FindAndReferenceByCookie(ConnectionCookie);

	switch (msg->m_Cmd) {
	case CMD_SET_USER_DIR:
		status = Handle_SetUserDir(msg, InputBufferSize, OutputBuffer, OutputBufferSize, ReturnOutputBufferLength);
		break;
	case CMD_ADD_HOOK:
		status = Handle_AddHook(msg, InputBufferSize, OutputBuffer, OutputBufferSize, ReturnOutputBufferLength);
		break;
	case CMD_REMOVE_HOOK:
		status = Handle_RemoveHook(msg, InputBufferSize, OutputBuffer, OutputBufferSize, ReturnOutputBufferLength);
		break;
	case CMD_CHECK_HOOK_LIST:
		status = Handle_CheckHookList(msg, InputBufferSize, OutputBuffer, OutputBufferSize, ReturnOutputBufferLength);
		break;
	case CMD_GET_IMAGE_PATH_BY_PID:
		status = Handle_GetImagePathByPid(msg, InputBufferSize, OutputBuffer, OutputBufferSize, ReturnOutputBufferLength);
		break;
	case CMD_IS_PROCESS_WOW64:
		status = Handle_IsProcessWow64(msg, InputBufferSize, OutputBuffer, OutputBufferSize, ReturnOutputBufferLength);
		break;
	case CMD_IS_PROTECTED_PROCESS:
		status = Handle_IsProtectedProcess(msg, InputBufferSize, OutputBuffer, OutputBufferSize, ReturnOutputBufferLength);
		break;
	case CMD_ENUM_HOOKS:
		status = Handle_EnumHooks(msg, InputBufferSize, OutputBuffer, OutputBufferSize, ReturnOutputBufferLength);
		break;
	case CMD_GET_HOOK_SECTION:
		status = Handle_GetHookSection(pPortCtxCallerRef, msg, InputBufferSize, OutputBuffer, OutputBufferSize, ReturnOutputBufferLength);
		break;
	case CMD_GET_PROCESS_HANDLE:
		status = Handle_GetProcessHandle(pPortCtxCallerRef, msg, InputBufferSize, OutputBuffer, OutputBufferSize, ReturnOutputBufferLength);
		break;
	case CMD_GET_SYSCALL_ADDR:
		status = Handle_GetSyscallAddr(msg, InputBufferSize, OutputBuffer, OutputBufferSize, ReturnOutputBufferLength);
		break;
	case CMD_CREATE_REMOTE_THREAD:
		status = Handle_CreateRemoteThread(pPortCtxCallerRef, msg, InputBufferSize, OutputBuffer, OutputBufferSize, ReturnOutputBufferLength);
		break;
	case CMD_WRITE_DLL_PATH:
		status = Handle_WriteDllPathToTargetProcess(pPortCtxCallerRef, msg, InputBufferSize, OutputBuffer, OutputBufferSize, ReturnOutputBufferLength);
		break;
	case CMD_WRITE_PROCESS_MEMORY:
		status = Handle_WriteProcessMemory(pPortCtxCallerRef, msg, InputBufferSize, OutputBuffer, OutputBufferSize, ReturnOutputBufferLength);
		break;
	case CMD_UNPROTECT_PPL:
		status = Handle_UnprotectPpl(msg, InputBufferSize, OutputBuffer, OutputBufferSize, ReturnOutputBufferLength);
		break;
	case CMD_QUERY_PPL_PROTECTION:
		status = Handle_QueryPplProtection(msg, InputBufferSize, OutputBuffer, OutputBufferSize, ReturnOutputBufferLength);
		break;
	case CMD_RECOVER_PPL:
		status = Handle_RecoverPpl(msg, InputBufferSize, OutputBuffer, OutputBufferSize, ReturnOutputBufferLength);
		break;
		break;
	case CMD_SET_GLOBAL_HOOK_MODE:
		status = Handle_SetGlobalHookMode(msg, InputBufferSize, OutputBuffer, OutputBufferSize, ReturnOutputBufferLength);
		break; 
    
	default:
		break;
	}
	 
	if (pPortCtxCallerRef) PortCtx_Dereference(pPortCtxCallerRef);
	return status;
}
 
static NTSTATUS Handle_ForceInject(PUMHH_COMMAND_MESSAGE msg, ULONG InputBufferSize, PVOID OutputBuffer, ULONG OutputBufferSize, PULONG ReturnOutputBufferLength) {
	UNREFERENCED_PARAMETER(OutputBuffer);
	UNREFERENCED_PARAMETER(OutputBufferSize);

	if (InputBufferSize < ((ULONG)UMHH_MSG_HEADER_SIZE + (ULONG)sizeof(DWORD)) + (ULONG)sizeof(PVOID)) {
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
		return STATUS_BUFFER_TOO_SMALL;
	}
	DWORD pid = 0;
	RtlCopyMemory(&pid, msg->m_Data, sizeof(DWORD));
	PVOID nt_base = 0;
	RtlCopyMemory(&nt_base, msg->m_Data + sizeof(DWORD), sizeof(PVOID));
	if (!nt_base) {
		Log(L"user passed ntpath is NULL\n");
		return STATUS_UNSUCCESSFUL;
	}
	PEPROCESS process = NULL;
	PUNICODE_STRING imageName = NULL;
	NTSTATUS stLookup = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
	if (NT_SUCCESS(stLookup) && process != NULL) {
		NTSTATUS stImg = SeLocateProcessImageName(process, &imageName);
		if (!NT_SUCCESS(stImg) || imageName == NULL || imageName->Length == 0) {
			// imageName not available; ensure we don't hold a stale pointer
			if (imageName) {
				ExFreePool(imageName);
				imageName = NULL;
			}
		}
	}
	if (!process) {
		Log(L"FATAL, can not get EPROCESS by pid");
		return STATUS_UNSUCCESSFUL;
	}

	if (imageName) {
		// only queue injection when create process
		if (process) {
			Inject_CheckAndQueue(imageName, process,TRUE);
			
		}
		ExFreePool(imageName);
		imageName = NULL;
	}
	else {
		ObDereferenceObject(process);
		return STATUS_UNSUCCESSFUL;
	}

	PPENDING_INJECT injectionInfo = Inject_GetPendingInj(process);
	if (!injectionInfo) {
		Log(L"faild to get injection info with EPROCESS=0x%p from pending list", process);
		ObDereferenceObject(process);
		return STATUS_UNSUCCESSFUL;
	}
	injectionInfo->LdrLoadDllRoutineAddress = PE_GetExport(nt_base, LdrLoadDllRoutineName);
	if (!injectionInfo->LdrLoadDllRoutineAddress) {
		Log(L"can not get %s from ntbase=0x%p", LdrLoadDllRoutineName, nt_base);
		ObDereferenceObject(process);
		return STATUS_UNSUCCESSFUL;
	}
	if (injectionInfo) {
		if (injectionInfo->IsInjected) {
			Log(L"PID=%u already injected\n", pid);
			ObDereferenceObject(process);
			return STATUS_SUCCESS;
		}
		else {
			Log(L"Process %d WOW64: %s can be injected now\n", PsGetProcessId(process),
				!injectionInfo->x64 ? L"TRUE" : L"FALSE",
				PsGetProcessImageFileName(process));

			if (!NT_SUCCESS(Inject_QueueInjectionApc(KernelMode,
				&Inject_InjectionApcNormalRoutine,
				injectionInfo,
				NULL,
				NULL))) {
				Log(L"FATAL, failed to queue injection apc normal routine\n");
				ObDereferenceObject(process);
				return STATUS_UNSUCCESSFUL;
			}

			injectionInfo->IsInjected = TRUE;
		}
	}
	ObDereferenceObject(process);
	return STATUS_SUCCESS;
}
static NTSTATUS Handle_SetGlobalHookMode(PUMHH_COMMAND_MESSAGE msg, ULONG InputBufferSize, PVOID OutputBuffer, ULONG OutputBufferSize, PULONG ReturnOutputBufferLength) {
	UNREFERENCED_PARAMETER(OutputBuffer);
	UNREFERENCED_PARAMETER(OutputBufferSize);
	UNREFERENCED_PARAMETER(ReturnOutputBufferLength);
	if (InputBufferSize < (ULONG)(UMHH_MSG_HEADER_SIZE + sizeof(BOOLEAN))) return STATUS_INVALID_PARAMETER;
	BOOLEAN enabled = 0;
	RtlCopyMemory(&enabled, msg->m_Data, sizeof(BOOLEAN));
	DriverCtx_SetGlobalHookMode(enabled);
	Log(L"Driver: SetGlobalHookMode = %d\n", (int)enabled);
	return STATUS_SUCCESS;
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
		LARGE_INTEGER timeout;
		timeout.QuadPart = -10000000LL; // 1 second timeout
		NTSTATUS st = FltSendMessage(DriverCtx_GetFilter(), &ctx->m_ClientPort, msg, msgSize, NULL, 0, &timeout);
		if (NT_SUCCESS(st)) {
			notified++;
		}
		else {
			// If the port is disconnected, proactively remove the port context so
			// we don't keep attempting to send to a dead client.
			if (st == STATUS_PORT_DISCONNECTED) {
				Log(L"Comm_BroadcastProcessNotify: port appears disconnected, removing ctx for pid %d\n", ctx->m_UserProcessId);
				PortCtx_Remove(ctx);
			}
			else if (st == STATUS_THREAD_IS_TERMINATING) {
				// STATUS_THREAD_IS_TERMINATING observed: caller thread is terminating
				// and cannot complete the send. Defer the remaining broadcast to a
				// system worker thread so the message is delivered from a safe
				// context. We transfer ownership of 'msg' and 'arr' to the worker
				// and return success here.
				// Log(L"Comm_BroadcastProcessNotify: current thread is terminating, resend with delay work item\n");

				PBROADCAST_WORK work = ExAllocatePoolWithTag(NonPagedPool, sizeof(*work), tag_port);
				if (work) {
					RtlZeroMemory(work, sizeof(*work));
					work->Msg = msg; // transfer ownership
					work->MsgSize = msgSize;
					work->Array = arr; // transfer ownership
					work->Count = count;

					// Keep filter alive during work by referencing it
					work->FilterRef = DriverCtx_GetFilter();
					if (work->FilterRef) {
						FltObjectReference(work->FilterRef);
					}
					// Worker routine: iterate snapshot and call FltSendMessage from
					// system worker context.
					ExInitializeWorkItem(&work->WorkItem, BroadcastWorkRoutine, work);
					ExQueueWorkItem(&work->WorkItem, DelayedWorkQueue);

					// Prevent the current function from freeing resources below.
					msg = NULL;
					arr = NULL;
					status = STATUS_SUCCESS;
					if (outNotifiedCount) *outNotifiedCount = notified;
					return status;
				}
				else {
					// failed to allocate work item; fall through and return the
					// thread-terminating status to the caller.
					status = st;
				}
			}
			else {
				status = st;
			}
		}
	}

	ExFreePool(msg);
	PortCtx_FreeSnapshot(arr, count);
	if (outNotifiedCount) *outNotifiedCount = notified;
	return status;
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
		LARGE_INTEGER timeout;
		timeout.QuadPart = -10000000LL; // 1 second timeout
		NTSTATUS st = FltSendMessage(DriverCtx_GetFilter(), &ctx->m_ClientPort, msg, msgSize, NULL, 0, &timeout);
		if (NT_SUCCESS(st)) {
			notified++;
		}
		else {
			Log(L"Comm_BroadcastApcQueued: FltSendMessage failed for client pid %d port %p st=0x%x\n",
				ctx->m_UserProcessId, ctx->m_ClientPort, st);
			if (st == STATUS_PORT_DISCONNECTED) {
				Log(L"Comm_BroadcastApcQueued: port appears disconnected, removing ctx for pid %d\n", ctx->m_UserProcessId);
				PortCtx_Remove(ctx);
			}
			else if (st == (NTSTATUS)0xC000004B) {
				// Defer remaining sends to a system worker thread as above.
				PBROADCAST_WORK work = ExAllocatePoolWithTag(NonPagedPool, sizeof(*work), tag_port);
				if (work) {
					RtlZeroMemory(work, sizeof(*work));
					work->Msg = msg;
					work->MsgSize = msgSize;
					work->Array = arr;
					work->Count = count;

					DriverCtx_IncWorkItems();
					work->FilterRef = DriverCtx_GetFilter();
					if (work->FilterRef) {
						FltObjectReference(work->FilterRef);
					}
					ExInitializeWorkItem(&work->WorkItem, BroadcastWorkRoutine, work);
					ExQueueWorkItem(&work->WorkItem, DelayedWorkQueue);

					// Transfered ownership; prevent double-free below
					msg = NULL;
					arr = NULL;
					status = STATUS_SUCCESS;
					if (outNotifiedCount) *outNotifiedCount = notified;
					return status;
				}
				else {
					status = st;
				}
			}
			else {
				// other failures
			}
		}
	}

	ExFreePool(msg);
	PortCtx_FreeSnapshot(arr, count);
	if (outNotifiedCount) *outNotifiedCount = notified;
	return STATUS_SUCCESS;
}
 

static NTSTATUS
Handle_IsProcessWow64(
	PUMHH_COMMAND_MESSAGE msg,
	ULONG InputBufferSize,
	PVOID OutputBuffer,
	ULONG OutputBufferSize,
	PULONG ReturnOutputBufferLength
) {
	if (InputBufferSize < ((ULONG)UMHH_MSG_HEADER_SIZE + (ULONG)sizeof(DWORD))) {
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
		return STATUS_BUFFER_TOO_SMALL;
	}

	DWORD pid = 0;
	RtlCopyMemory(&pid, msg->m_Data, sizeof(DWORD));
	PEPROCESS process = NULL;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
	if (!NT_SUCCESS(status) || process == NULL) {
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
		if (OutputBuffer && OutputBufferSize >= sizeof(BOOLEAN)) RtlCopyMemory(OutputBuffer, &status, sizeof(status));
		return status;
	}

	BOOLEAN isWow64 = FALSE;

	PVOID wow = PsGetProcessWow64Process(process);
	isWow64 = (wow != NULL) ? TRUE : FALSE;


	ObDereferenceObject(process);

	if (OutputBuffer && OutputBufferSize >= sizeof(BOOLEAN)) {
		*(BOOLEAN*)OutputBuffer = isWow64;
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = sizeof(BOOLEAN);
		return STATUS_SUCCESS;
	} else {
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
		return STATUS_BUFFER_TOO_SMALL;
	}
}

static NTSTATUS
Handle_IsProtectedProcess(
	PUMHH_COMMAND_MESSAGE msg,
	ULONG InputBufferSize,
	PVOID OutputBuffer,
	ULONG OutputBufferSize,
	PULONG ReturnOutputBufferLength
) {
	if (InputBufferSize < ((ULONG)UMHH_MSG_HEADER_SIZE + (ULONG)sizeof(DWORD))) {
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
		return STATUS_BUFFER_TOO_SMALL;
	}

	DWORD pid = 0; RtlCopyMemory(&pid, msg->m_Data, sizeof(DWORD));
	PEPROCESS process = NULL;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
	if (!NT_SUCCESS(status) || process == NULL) {
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
		if (OutputBuffer && OutputBufferSize >= sizeof(NTSTATUS)) RtlCopyMemory(OutputBuffer, &status, sizeof(status));
		return status;
	}

	BOOLEAN isProtected = FALSE;
	__try {
		if (PsIsProtectedProcess(process)) {
			isProtected = TRUE;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		isProtected = FALSE;
	}
	ObDereferenceObject(process);

	if (OutputBuffer && OutputBufferSize >= sizeof(BOOLEAN)) {
		*(BOOLEAN*)OutputBuffer = isProtected;
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = sizeof(BOOLEAN);
		return STATUS_SUCCESS;
	} else {
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
		return STATUS_BUFFER_TOO_SMALL;
	}
}
 
// ---------- Command handlers (modularized) ----------

static NTSTATUS
Handle_SetUserDir(
	PUMHH_COMMAND_MESSAGE msg,
	ULONG InputBufferSize,
	PVOID OutputBuffer,
	ULONG OutputBufferSize,
	PULONG ReturnOutputBufferLength
) {
	SIZE_T payloadBytes = InputBufferSize - UMHH_MSG_HEADER_SIZE;
	if (payloadBytes < sizeof(WCHAR)) {
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
		return STATUS_BUFFER_TOO_SMALL;
	}
	PCWSTR w = (PCWSTR)msg->m_Data;
	SIZE_T wcharCount = payloadBytes / sizeof(WCHAR);
	BOOLEAN foundNull = FALSE;
	for (SIZE_T i = 0; i < wcharCount; ++i) { if (w[i] == L'\0') { foundNull = TRUE; break; } }
	if (!foundNull) { if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0; return STATUS_INVALID_PARAMETER; }
	NTSTATUS st = DriverCtx_SetUserDir(w, (SIZE_T)(wcharCount * sizeof(WCHAR)));
	if (OutputBuffer && OutputBufferSize >= sizeof(NTSTATUS)) {
		*(NTSTATUS*)OutputBuffer = st;
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = sizeof(NTSTATUS);
		return STATUS_SUCCESS;
	} else {
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
		return STATUS_BUFFER_TOO_SMALL;
	}
}

static NTSTATUS
Handle_AddHook(
	PUMHH_COMMAND_MESSAGE msg,
	ULONG InputBufferSize,
	PVOID OutputBuffer,
	ULONG OutputBufferSize,
	PULONG ReturnOutputBufferLength
) {
	if (InputBufferSize < ((ULONG)UMHH_MSG_HEADER_SIZE + (ULONG)sizeof(ULONGLONG))) {
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
		return STATUS_BUFFER_TOO_SMALL;
	}
	ULONGLONG hash = 0;
	RtlCopyMemory(&hash, msg->m_Data, sizeof(ULONGLONG));
	PCWSTR path = NULL;
	SIZE_T pathBytes = 0;
	if (InputBufferSize > ((ULONG)UMHH_MSG_HEADER_SIZE + (ULONG)sizeof(ULONGLONG))) {
		pathBytes = InputBufferSize - UMHH_MSG_HEADER_SIZE - sizeof(ULONGLONG);
		if (pathBytes >= sizeof(WCHAR)) path = (PCWSTR)(msg->m_Data + sizeof(ULONGLONG));
	}
	NTSTATUS st = HookList_AddEntry(hash, path, pathBytes);
	// If we successfully added an entry, update the anonymous section so
	// connected clients can MapViewOfFile and see the new snapshot.
	if (NT_SUCCESS(st)) {
		NTSTATUS st2 = HookList_CreateOrUpdateSection();
		if (!NT_SUCCESS(st2)) {
			Log(L"Handle_AddHook: HookList_CreateOrUpdateSection failed 0x%x\n", st2);
		} else {
			NTSTATUS st3 = HookList_SaveToRegistry();
			if (!NT_SUCCESS(st3)) {
				Log(L"Handle_AddHook: HookList_SaveToRegistry failed 0x%x\n", st3);
			}
		}
	}
	if (OutputBuffer && OutputBufferSize >= sizeof(NTSTATUS)) {
		*(NTSTATUS*)OutputBuffer = st;
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = sizeof(NTSTATUS);
		return STATUS_SUCCESS;
	} else {
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
		return STATUS_BUFFER_TOO_SMALL;
	}
}

static NTSTATUS
Handle_RemoveHook(
	PUMHH_COMMAND_MESSAGE msg,
	ULONG InputBufferSize,
	PVOID OutputBuffer,
	ULONG OutputBufferSize,
	PULONG ReturnOutputBufferLength
) {
	if (InputBufferSize < (sizeof(UMHH_COMMAND_MESSAGE) + sizeof(ULONGLONG) - 1)) {
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
		return STATUS_BUFFER_TOO_SMALL;
	}
	ULONGLONG hash = 0;
	RtlCopyMemory(&hash, msg->m_Data, sizeof(ULONGLONG));
	BOOLEAN removed = HookList_RemoveEntry(hash);
	// If we removed an entry, refresh the anonymous section so clients see
	// the updated snapshot.
	if (removed) {
		NTSTATUS st2 = HookList_CreateOrUpdateSection();
		if (!NT_SUCCESS(st2)) {
			Log(L"Handle_RemoveHook: HookList_CreateOrUpdateSection failed 0x%x\n", st2);
		} else {
			NTSTATUS st3 = HookList_SaveToRegistry();
			if (!NT_SUCCESS(st3)) {
				Log(L"Handle_RemoveHook: HookList_SaveToRegistry failed 0x%x\n", st3);
			}
		}
	}
	if (OutputBuffer && OutputBufferSize >= sizeof(BOOLEAN)) {
		*(BOOLEAN*)OutputBuffer = removed;
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = sizeof(BOOLEAN);
		return STATUS_SUCCESS;
	} else {
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
		return STATUS_BUFFER_TOO_SMALL;
	}
}

static NTSTATUS
Handle_CheckHookList(
	PUMHH_COMMAND_MESSAGE msg,
	ULONG InputBufferSize,
	PVOID OutputBuffer,
	ULONG OutputBufferSize,
	PULONG ReturnOutputBufferLength
) {
	if (InputBufferSize < ((ULONG)UMHH_MSG_HEADER_SIZE + (ULONG)sizeof(ULONGLONG))) {
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
		return STATUS_BUFFER_TOO_SMALL;
	}
	ULONGLONG hash = 0;
	RtlCopyMemory(&hash, msg->m_Data, sizeof(ULONGLONG));
	BOOLEAN found = HookList_ContainsHash(hash);
	if (OutputBuffer && OutputBufferSize >= sizeof(BOOLEAN)) {
		*(BOOLEAN*)OutputBuffer = found;
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = sizeof(BOOLEAN);
		return STATUS_SUCCESS;
	} else {
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
		return STATUS_BUFFER_TOO_SMALL;
	}
}

static NTSTATUS
Handle_GetImagePathByPid(
	PUMHH_COMMAND_MESSAGE msg,
	ULONG InputBufferSize,
	PVOID OutputBuffer,
	ULONG OutputBufferSize,
	PULONG ReturnOutputBufferLength
) {
	if (InputBufferSize < ((ULONG)UMHH_MSG_HEADER_SIZE + (ULONG)sizeof(DWORD))) {
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
		return STATUS_BUFFER_TOO_SMALL;
	}
	DWORD pid = 0;
	NTSTATUS status = STATUS_SUCCESS;
	RtlCopyMemory(&pid, msg->m_Data, sizeof(DWORD));
	PEPROCESS process = NULL;
	status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
	if (!NT_SUCCESS(status) || process == NULL) {
		if (ReturnOutputBufferLength)
			*ReturnOutputBufferLength = 0;
		// use OutputBuffer to get ntstatus, user mode code can get ntstatus if detect hResult != S_OK
		// I don't know how to convert ntstatus to hresult, microsoft provided HRESULT_FROM_NT is not
		// acurate for some unknown reason
		RtlCopyMemory(OutputBuffer, &status, sizeof(status));
		return status;
	}
	PUNICODE_STRING imageName = NULL;
	status = SeLocateProcessImageName(process, &imageName);
	if (!NT_SUCCESS(status) || imageName == NULL || imageName->Length == 0) {
		ObDereferenceObject(process);
		if (ReturnOutputBufferLength)
			*ReturnOutputBufferLength = 0;
		RtlCopyMemory(OutputBuffer, &status, sizeof(status));
		return status;
	}
	ULONG bytesNeeded = imageName->Length + sizeof(WCHAR);
	if (OutputBuffer && OutputBufferSize >= bytesNeeded) {
		RtlCopyMemory(OutputBuffer, imageName->Buffer, imageName->Length);
		((WCHAR*)OutputBuffer)[imageName->Length / sizeof(WCHAR)] = L'\0';
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = bytesNeeded;
		status = STATUS_SUCCESS;
	}
	else {
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = bytesNeeded;
		status = STATUS_BUFFER_TOO_SMALL;
		RtlCopyMemory(OutputBuffer, &status, sizeof(status));
	}
	ExFreePool(imageName);
	ObDereferenceObject(process);
	return status;
}

// Duplicate the kernel's hook-list section handle into the caller process
// and return the duplicated handle in the reply buffer (as a HANDLE).
static NTSTATUS
Handle_GetHookSection(
	PCOMM_CONTEXT CallerCtx,
	PUMHH_COMMAND_MESSAGE msg,
	ULONG InputBufferSize,
	PVOID OutputBuffer,
	ULONG OutputBufferSize,
	PULONG ReturnOutputBufferLength
) {
	UNREFERENCED_PARAMETER(msg);
	UNREFERENCED_PARAMETER(InputBufferSize);
	if (!OutputBuffer || OutputBufferSize < sizeof(HANDLE)) {
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
		return STATUS_BUFFER_TOO_SMALL;
	}

	if (!CallerCtx) return STATUS_INVALID_PARAMETER;

	// Lookup the target process and ask HookList to duplicate the section
	// handle into that process. HookList_DuplicateSectionHandle will return
	// a handle that is already valid in the target process.
	DWORD pid = (DWORD)(ULONG_PTR)CallerCtx->m_UserProcessId;
	PEPROCESS proc = NULL;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &proc);
	if (!NT_SUCCESS(status) || proc == NULL) return status;

	HANDLE dup = NULL;
	status = HookList_DuplicateSectionHandle(proc, &dup);
	if (NT_SUCCESS(status)) {
		if (OutputBuffer && OutputBufferSize >= sizeof(HANDLE)) {
			RtlCopyMemory(OutputBuffer, &dup, sizeof(HANDLE));
			if (ReturnOutputBufferLength) *ReturnOutputBufferLength = sizeof(HANDLE);
		}
	}
	ObDereferenceObject(proc);
	return status;
}

static NTSTATUS
Handle_GetProcessHandle(
	PCOMM_CONTEXT CallerCtx,
	PUMHH_COMMAND_MESSAGE msg,
	ULONG InputBufferSize,
	PVOID OutputBuffer,
	ULONG OutputBufferSize,
	PULONG ReturnOutputBufferLength
) {
	UNREFERENCED_PARAMETER(msg);
	UNREFERENCED_PARAMETER(InputBufferSize);
	// when requestor is x86, OutputBufferSize is sizeof(HANDLE)=4, it will be smaller than kernel code sizeof(HANDLE)
	// which will fail in this check, in fact, there is no need to use 8bytes to save a handle, 4 bytes is enough
	// it is only a user mode handle, so DWORD can store it
	// no, this is not a good way to solve this issue, we need force client to use a 8 bytes handle, otherwise
	// the memory will fucked up
	if (!OutputBuffer || OutputBufferSize < sizeof(HANDLE)) {
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
		return STATUS_BUFFER_TOO_SMALL;
	}

	if (!CallerCtx) return STATUS_INVALID_PARAMETER;

	// Caller target process is the client that sent the message
	DWORD callerPid = (DWORD)(ULONG_PTR)CallerCtx->m_UserProcessId;

	// Extract requested PID from message payload
	if (InputBufferSize < ((ULONG)UMHH_MSG_HEADER_SIZE + (ULONG)sizeof(DWORD))) {
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
		return STATUS_BUFFER_TOO_SMALL;
	}
	DWORD targetPid = 0;
	RtlCopyMemory(&targetPid, msg->m_Data, sizeof(DWORD));

	// Look up PEPROCESS for target
	PEPROCESS targetProc = NULL;
	NTSTATUS st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)targetPid, &targetProc);
	if (!NT_SUCCESS(st) || targetProc == NULL) {
		Log(L"can not located EPROCESS for target PID=%u", targetPid);
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
		return st;
	}

	// Open a handle to the target process in kernel (kernel handle in our process)
	HANDLE hTarget = NULL;
	st = ObOpenObjectByPointer(targetProc, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &hTarget);
	if (!NT_SUCCESS(st)) {
		ObDereferenceObject(targetProc);
		Log(L"can not reference target EPROCESS=0x%p object, Status=0x%x\n", targetProc, st);
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
		return st;
	}

	// Now open a handle to the caller process so we can duplicate into it
	PEPROCESS callerProc = NULL;
	st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)callerPid, &callerProc);
	if (!NT_SUCCESS(st) || callerProc == NULL) {
		ZwClose(hTarget);
		ObDereferenceObject(targetProc);
		Log(L"can not located EPROCESS for caller PID=%u", callerPid);
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
		return st;
	}

	HANDLE hCallerProc = NULL;
	st = ObOpenObjectByPointer(callerProc, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &hCallerProc);
	if (!NT_SUCCESS(st)) {
		ZwClose(hTarget);
		ObDereferenceObject(targetProc);
		ObDereferenceObject(callerProc);
		Log(L"can not reference caller EPROCESS=0x%p object, Status=0x%x\n", callerProc, st);
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
		return st;
	}

	// Duplicate the target process handle into the caller process with desired access.
	HANDLE dup = NULL;
	// Desired access: PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION
	// Use DUPLICATE_SAME_ACCESS to preserve current access of section handle; instead request specific rights by passing AccessMask.
	// PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION;
	// -> 0n1082
	// ACCESS_MASK DesiredAccess = 0x43A;
	HANDLE src_proc_handle = ZwCurrentProcess();

		// KAPC_STATE apc ;
		// KeStackAttachProcess(targetProc, &apc);
		 st = ZwDuplicateObject(src_proc_handle, hTarget, hCallerProc, &dup, PROCESS_ALL_ACCESS, 0, 0);
		// KeUnstackDetachProcess(&apc);
	
	// Cleanup kernel handles and object refs
	ZwClose(hTarget);
	ZwClose(hCallerProc);
	ObDereferenceObject(targetProc);
	ObDereferenceObject(callerProc);

	if (!NT_SUCCESS(st)) {
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
		return st;
	}

	// Return duplicated handle value to caller (handle is valid in caller process)
	RtlCopyMemory(OutputBuffer, &dup, sizeof(HANDLE));
	if (ReturnOutputBufferLength) *ReturnOutputBufferLength = sizeof(HANDLE);
	return STATUS_SUCCESS;
}

// Attempt to resolve the kernel address for a syscall by its service index.
// Payload: ULONG syscallNumber
// Reply: pointer-sized kernel address (if found).
static NTSTATUS
Handle_GetSyscallAddr(
	PUMHH_COMMAND_MESSAGE msg,
	ULONG InputBufferSize,
	PVOID OutputBuffer,
	ULONG OutputBufferSize,
	PULONG ReturnOutputBufferLength
) {
	UNREFERENCED_PARAMETER(msg);
	if (InputBufferSize < (UMHH_MSG_HEADER_SIZE + sizeof(ULONG))) {
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
		return STATUS_BUFFER_TOO_SMALL;
	}
	if (!OutputBuffer || OutputBufferSize < sizeof(PVOID)) {
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
		return STATUS_BUFFER_TOO_SMALL;
	}

	ULONG syscallNumber = 0;
	RtlCopyMemory(&syscallNumber, msg->m_Data, sizeof(ULONG));

	PVOID pKsdt = (PVOID)(ULONG_PTR)DriverCtx_GetSSDT();
	if (!pKsdt) {
		// Not available on this build - can't resolve
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
		return STATUS_NOT_SUPPORTED;
	}

	// KeServiceDescriptorTable layout: on x64, it's SERVICE_DESCRIPTOR with ServiceTableBase pointer
	// We treat pKsdt as pointer to a structure whose first field is the pointer to the service table.
	PULONG_PTR serviceTable = NULL;
	__try {
		serviceTable = *(PULONG_PTR*)pKsdt; // read first pointer-sized field
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
		return STATUS_UNSUCCESSFUL;
	}

	if (!serviceTable) {
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
		return STATUS_NOT_SUPPORTED;
	}

	// Bounds: we cannot easily know how large the table is. Do a sanity check on syscallNumber
	if (syscallNumber > 0x10000) {
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
		return STATUS_INVALID_PARAMETER;
	}
	// dd nt!KiServiceTable+(0x53*4) L1
	
	DWORD _ = *(DWORD*)(syscallNumber * 4 + (UCHAR*)serviceTable);
	
	// Read the entry. On many architectures the table contains direct function pointers.
	PVOID addr = (PVOID)((UCHAR*)serviceTable + (_ >> 4));
	 

	if (!addr) {
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
		return STATUS_NOT_FOUND;
	}

	RtlCopyMemory(OutputBuffer, &addr, sizeof(PVOID));
	if (ReturnOutputBufferLength) *ReturnOutputBufferLength = sizeof(PVOID);
	return STATUS_SUCCESS;
}

// Helper typedef for NtCreateThreadEx (undocumented) - driver uses Zw prefix
typedef NTSTATUS(NTAPI* PFN_ZWCREATETHREADEX)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

static NTSTATUS
Handle_CreateRemoteThread(
	PCOMM_CONTEXT CallerCtx,
	PUMHH_COMMAND_MESSAGE msg,
	ULONG InputBufferSize,
	PVOID OutputBuffer,
	ULONG OutputBufferSize,
	PULONG ReturnOutputBufferLength
) {
	(OutputBuffer);
	(OutputBufferSize);
	// Expect payload: DWORD pid; PVOID startRoutine; PVOID parameter; PVOID ntCreateThreadExAddr; PVOID extra
	ULONG need = (ULONG)(UMHH_MSG_HEADER_SIZE + sizeof(DWORD) + sizeof(PVOID) + sizeof(PVOID) + sizeof(PVOID) + sizeof(PVOID));
	if (InputBufferSize < need) {
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
		return STATUS_BUFFER_TOO_SMALL;
	}
	if (!CallerCtx) return STATUS_INVALID_PARAMETER;

	DWORD targetPid = 0;
	PVOID startRoutine = NULL;
	PVOID parameter = NULL;
	PVOID providedNtCreateAddr = NULL;
	PVOID extraValue = NULL;
	RtlCopyMemory(&targetPid, msg->m_Data, sizeof(DWORD));
	RtlCopyMemory(&startRoutine, msg->m_Data + sizeof(DWORD), sizeof(PVOID));
	RtlCopyMemory(&parameter, msg->m_Data + sizeof(DWORD) + sizeof(PVOID), sizeof(PVOID));
	// Required: ntCreateThreadExAddr and extra follow
	SIZE_T expectedBase = sizeof(DWORD) + sizeof(PVOID) + sizeof(PVOID);
	RtlCopyMemory(&providedNtCreateAddr, msg->m_Data + expectedBase, sizeof(PVOID));
	RtlCopyMemory(&extraValue, msg->m_Data + expectedBase + sizeof(PVOID), sizeof(PVOID));
	HANDLE proc_handle = NULL;
	RtlCopyMemory(&proc_handle, msg->m_Data + expectedBase + sizeof(PVOID) + sizeof(PVOID), sizeof(HANDLE));
 

	// Resolve NtCreateThreadEx: prefer caller-supplied kernel function pointer
	PFN_ZWCREATETHREADEX pfnNtCreateThreadEx = NULL;
	if (providedNtCreateAddr) {
		pfnNtCreateThreadEx = (PFN_ZWCREATETHREADEX)providedNtCreateAddr;
	}
	else {
		// cleanup 
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
		Log(L"user MUST provide NtCreateThreadEx kernel function address to make this work\n");
		return STATUS_NOT_IMPLEMENTED;
	}
	// before create thread, remove target process's protection
	PEPROCESS ep = NULL;
	PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)targetPid, &ep);
	if (!ep) {
		Log(L"failed to call PsLookupProcessByProcessId to get EPROCESS of target PID=%u\n", targetPid);
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
		return STATUS_UNSUCCESSFUL;
	}
	EPROCESS_ORI_VALUE ori_value = { 0 };
	if (PsIsProtectedProcess(ep)) {
		EPROCESS_OFFSETS off;
		if (KO_GetEprocessOffsets(&off)) {
			if (!Mini_ReadKernelMemory((PVOID)((PUCHAR)ep + off.SectionSignatureLevelOffset), &ori_value.SectionSignatureLevelValue, sizeof(UCHAR))) {
				Log(L"failed to call Mini_ReadKernelMemory to read out SectionSignatureLevel value, target PID=%u\n", targetPid);
				ObDereferenceObject(ep);
				return STATUS_UNSUCCESSFUL;
			}

			if (!Mini_ReadKernelMemory((PVOID)((PUCHAR)ep + off.ProtectionOffset), &ori_value.ProtectionValue, sizeof(UCHAR))) {
				Log(L"failed to call Mini_ReadKernelMemory to read out Protection value, target PID=%u\n", targetPid);
				ObDereferenceObject(ep);
				return STATUS_UNSUCCESSFUL;
			}
			// PPL process such as lsass.exe have arbitary code mitigation set, which will block our dll from loading
			// nt!MiArbitraryCodeBlocked will check this bit, if set, dll outside KnownDlls can not be loaded
			// we can search in kernel code to get the accurate offset and position
			// first locate export function nt!NtMapViewOfSection, the search asm code pattern to finally get nt!MiArbitraryCodeBlocked
			Log(L"get target PID=%u's original SectionSignatureLevel=%d, original Protection=%d\n",
				targetPid, ori_value.SectionSignatureLevelValue,ori_value.ProtectionValue);
			UCHAR _ = 0;
			// we should NOT modify target process's protection field, it may affect its feature
			// but we're allowed to modify its signature level so we can inject
			// it is time for us to refactor our client as a UI/Service seperated application
			// elevate Suicide to the same protection level as target process
			PEPROCESS suicide_ep = PsGetCurrentProcess();
			 if (!Mini_WriteKernelMemory((PVOID)((PUCHAR)suicide_ep + off.ProtectionOffset), &ori_value.ProtectionValue, sizeof(UCHAR))) {
				 Log(L"failed to call Mini_WriteKernelMemory to elevate Suicide to PPL process\n");
			 	ObDereferenceObject(ep);
			 	return STATUS_UNSUCCESSFUL;
			 }
			if (!Mini_WriteKernelMemory((PVOID)((PUCHAR)ep + off.SectionSignatureLevelOffset), &_, sizeof(UCHAR))) {
				Log(L"failed to call Mini_WriteKernelMemory to write in SectionSignatureLeve, target PID=%u\n", targetPid);
				ObDereferenceObject(ep);
				return STATUS_UNSUCCESSFUL;
			}
			Log(L"successfully zero out SectionSignatureLevel field of target process, PID=%u\n", targetPid);
		}
		else {
			ObDereferenceObject(ep);
			DRIVERCTX_OSVER ver = DriverCtx_GetOsVersion();
			Log(L"unsupported windows version, Major=%u Build=%u", ver.Major, ver.Build);
			return STATUS_UNSUCCESSFUL;
		}

		// after get original offset, we need save original value first, then we zero it our, then we call create thread
		// then we deference EP
	}
	EPROCESS_OFFSETS off;
	if (!KO_GetEprocessOffsets(&off)) {
		ObDereferenceObject(ep);
		DRIVERCTX_OSVER ver = DriverCtx_GetOsVersion();
		Log(L"unsupported windows version, Major=%u Build=%u", ver.Major, ver.Build);
		return STATUS_UNSUCCESSFUL;
	}
	{
		typedef struct _ACG_MitigationOffPos {
			ULONG mitigation_offset;
			UCHAR acg_pos;
			UCHAR acg_audit_pos;
		}ACG_MitigationOffPos;
		ACG_MitigationOffPos* acg =(ACG_MitigationOffPos*) &off.ACG_MitigationOffPos;
		if (acg->acg_audit_pos) {
			DWORD ori_acg_value = 0;
			if (!Mini_ReadKernelMemory((PVOID)((PUCHAR)ep + acg->mitigation_offset), &ori_acg_value, sizeof(DWORD))) {
				Log(L"failed to call Mini_ReadKernelMemory to read out original acg mitigation value, target PID=%u\n", targetPid);
				ObDereferenceObject(ep);
				return STATUS_UNSUCCESSFUL;
			}
			Log(L"get target PID=%u's original acg mitigation value=%d\n",
				targetPid, ori_acg_value);
			if (ori_acg_value & (1 << acg->acg_pos)) {
				Log(L"target process Pid=%u enabled ACG mitigation\n", targetPid);
				DWORD erased = ori_acg_value & (~(1 << acg->acg_pos));
				if (!Mini_WriteKernelMemory((PVOID)((PUCHAR)ep + acg->mitigation_offset), &erased, sizeof(DWORD))) {
					Log(L"failed to call Mini_WriteKernelMemory to delete acg mitigation flag\n");
					ObDereferenceObject(ep);
					return STATUS_UNSUCCESSFUL;
				}


				// normally, have acg enabled process may have SectionSignatureLevel non-zero
				{

					if (!Mini_ReadKernelMemory((PVOID)((PUCHAR)ep + off.SectionSignatureLevelOffset), &ori_value.SectionSignatureLevelValue, sizeof(UCHAR))) {
						Log(L"failed to call Mini_ReadKernelMemory to read out SectionSignatureLevel value, target PID=%u\n", targetPid);
						ObDereferenceObject(ep);
						return STATUS_UNSUCCESSFUL;
					}

					Log(L"get target PID=%u's original SectionSignatureLevel=%d\n",
						targetPid, ori_value.SectionSignatureLevelValue);
					if (ori_value.SectionSignatureLevelValue) {
						UCHAR _ = 0;

						if (!Mini_WriteKernelMemory((PVOID)((PUCHAR)ep + off.SectionSignatureLevelOffset), &_, sizeof(UCHAR))) {
							Log(L"failed to call Mini_WriteKernelMemory to write in SectionSignatureLeve, target PID=%u\n", targetPid);
							ObDereferenceObject(ep);
							return STATUS_UNSUCCESSFUL;
						}
						Log(L"successfully zero out SectionSignatureLevel field of target process, PID=%u\n", targetPid);
					}

				}
			}

			if (ori_acg_value & (1 << acg->acg_audit_pos)) {
				Log(L"target process Pid=%u enabled ACG_AUDIT mitigation\n", targetPid);
				DWORD erased = ori_acg_value & (~(1 << acg->acg_audit_pos));
				if (!Mini_WriteKernelMemory((PVOID)((PUCHAR)ep + acg->mitigation_offset), &erased, sizeof(DWORD))) {
					Log(L"failed to call Mini_WriteKernelMemory to delete acg mitigation flag\n");
					ObDereferenceObject(ep);
					return STATUS_UNSUCCESSFUL;
				}
			}
		}
	}
	// check if acg mitigation enabled

	NTSTATUS status = pfnNtCreateThreadEx(extraValue, THREAD_ALL_ACCESS, NULL, proc_handle, startRoutine, parameter, 0, 0, 0, 0, NULL);


	ObDereferenceObject(ep);
	// Note: keep hTargetProc and targetProc alive until after thread creation
	if (!NT_SUCCESS(status)) {
		Log(L"failed to call pfnNtCreateThreadEx, Status=0x%x\n", status);
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
		return status;
	}


	// Caller didn't request handle duplication; close created thread handle and return success
	ZwClose(*(PHANDLE)extraValue);
	 
	if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
	Log(L"successfully created thread in target process PID=%u\n", targetPid);
	return STATUS_SUCCESS;
}

// Handler stub: write a user-mode wide string (DLL path) into the target process.
// Payload: DWORD pid; PVOID userWideStringPtr
// Reply: PVOID (placeholder NULL). This function performs sanity checks and
// looks up the target process; the actual write-into-target logic should be
// implemented by the user and may replace the placeholder reply value.
static NTSTATUS
Handle_WriteDllPathToTargetProcess(
	PCOMM_CONTEXT CallerCtx,
	PUMHH_COMMAND_MESSAGE msg,
	ULONG InputBufferSize,
	PVOID OutputBuffer,
	ULONG OutputBufferSize,
	PULONG ReturnOutputBufferLength
) {
	UNREFERENCED_PARAMETER(CallerCtx);
	if (InputBufferSize < (UMHH_MSG_HEADER_SIZE + sizeof(DWORD) + sizeof(PVOID))) {
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
		return STATUS_BUFFER_TOO_SMALL;
	}

	DWORD pid = 0;
	PVOID userPtr = NULL;
	RtlCopyMemory(&pid, msg->m_Data, sizeof(DWORD));
	RtlCopyMemory(&userPtr, msg->m_Data + sizeof(DWORD), sizeof(PVOID));

	if (!userPtr) {
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
		return STATUS_INVALID_PARAMETER;
	}

	// Basic process lookup to validate PID
	PEPROCESS proc = NULL;
	NTSTATUS st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &proc);
	if (!NT_SUCCESS(st) || proc == NULL) {
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
		return st;
	}
	// MAP CODE BEGIN

	// resource tracking - initialize early so CLEAN_UP can safely release
	HANDLE SectionHandle = NULL;
	PVOID SectionMemoryAddress = NULL;
	PVOID local_SectionMemoryAddress = NULL;
	SIZE_T SectionSize = PAGE_SIZE;
	LARGE_INTEGER MaximumSize;
	MaximumSize.QuadPart = SectionSize;
	OBJECT_ATTRIBUTES   ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes,
		NULL,
		OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	 st = ZwCreateSection(&SectionHandle,
		GENERIC_READ | GENERIC_WRITE,
		&ObjectAttributes,
		&MaximumSize,
		PAGE_READWRITE,
		SEC_COMMIT,
		NULL);
	if (!NT_SUCCESS(st)) {
		Log(L"Handle_WriteDllPathToTargetProcess: failed to call ZwCreateSection: 0x%x Line=%d\n", st, __LINE__);
		goto CLEAN_UP;
	}
	st = ZwMapViewOfSection(SectionHandle,
		ZwCurrentProcess(),
		&local_SectionMemoryAddress,
		0,
		PAGE_SIZE,
		NULL,
		&SectionSize,
		ViewUnmap,
		0,
		PAGE_READWRITE);
	if (!NT_SUCCESS(st)) {
		Log(L"Handle_WriteDllPathToTargetProcessL: failed to call ZwMapViewOfSection for local map: 0x%x Line=%d\n", st, __LINE__);
		goto CLEAN_UP;
	}
	KAPC_STATE apc;

	// Attach to the target process
	KeStackAttachProcess(proc, &apc);
	st = ZwMapViewOfSection(SectionHandle,
	ZwCurrentProcess(),
		&SectionMemoryAddress,
		0,
		PAGE_SIZE,
		NULL,
		&SectionSize,
		ViewUnmap,
		0,
		PAGE_READWRITE);
	KeUnstackDetachProcess(&apc);
	if (!NT_SUCCESS(st)) {
		Log(L"Handle_WriteDllPathToTargetProcessL: failed to call ZwMapViewOfSection for remote map: 0x%x Line=%d\n", st,__LINE__);
		goto CLEAN_UP;
	}
	RtlCopyMemory(local_SectionMemoryAddress, userPtr, sizeof(WCHAR)*wcslen(userPtr));
	// MAP CODE END

	if (OutputBuffer && OutputBufferSize >= sizeof(PVOID)) {
		RtlCopyMemory(OutputBuffer, &SectionMemoryAddress, sizeof(PVOID));
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = sizeof(PVOID);
	} else {
		if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
		st = STATUS_BUFFER_TOO_SMALL;
	}
CLEAN_UP:
	if (local_SectionMemoryAddress) {
		NTSTATUS _ = ZwUnmapViewOfSection(
			ZwCurrentProcess(),
			local_SectionMemoryAddress);
		if (!NT_SUCCESS(_)) {
			Log(L"Handle_WriteDllPathToTargetProcessL: failed to call ZwUnmapViewOfSection for local map: 0x%x Line=%d\n", _, __LINE__);
		}
	}
	if (SectionHandle)
		ZwClose(SectionHandle);
	ObDereferenceObject(proc);
	return st;
}

// Elevate current process protection to match target PID's Protection value (PPL-like).

// Unprotect target process by zeroing SectionSignatureLevel (and optionally ACG bits if present).
static NTSTATUS Handle_UnprotectPpl(PUMHH_COMMAND_MESSAGE msg, ULONG InputBufferSize, PVOID OutputBuffer, ULONG OutputBufferSize, PULONG ReturnOutputBufferLength) {
	 
	UNREFERENCED_PARAMETER(OutputBufferSize);
	if (ReturnOutputBufferLength) *ReturnOutputBufferLength = sizeof(NTSTATUS);
	if (InputBufferSize < ((ULONG)UMHH_MSG_HEADER_SIZE + (ULONG)sizeof(DWORD))) {
		return STATUS_BUFFER_TOO_SMALL;
	}
	DWORD pid = 0; RtlCopyMemory(&pid, msg->m_Data, sizeof(DWORD));
	PEPROCESS ep = NULL;
	NTSTATUS st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &ep);
	if (!NT_SUCCESS(st) || ep == NULL) { 
		RtlCopyMemory(OutputBuffer, &st, sizeof(NTSTATUS));
		return st;
	}

	// Get offsets
	EPROCESS_OFFSETS off;
	if (!KO_GetEprocessOffsets(&off)) {
		DRIVERCTX_OSVER ver = DriverCtx_GetOsVersion();
		Log(L"Handle_UnprotectPpl: unsupported OS version Major=%u Build=%u\n", ver.Major, ver.Build);
		ObDereferenceObject(ep);
		st = STATUS_NOT_SUPPORTED;
		RtlCopyMemory(OutputBuffer, &st, sizeof(NTSTATUS));
		return st;
	}
	// Zero Protection to unprotect
	UCHAR zero = 0;
	if (!Mini_WriteKernelMemory((PVOID)((PUCHAR)ep + off.ProtectionOffset), &zero, sizeof(UCHAR))) {
		Log(L"Handle_UnprotectPpl: failed to clear Protection PID=%u\n", pid);
		ObDereferenceObject(ep);
		st = STATUS_UNSUCCESSFUL;
		RtlCopyMemory(OutputBuffer, &st, sizeof(NTSTATUS));
		return st;
	}

	Log(L"Handle_UnprotectPpl: cleared Protection PID=%u\n", pid);
	ObDereferenceObject(ep);

	st = STATUS_SUCCESS;
	RtlCopyMemory(OutputBuffer, &st, sizeof(NTSTATUS));
	return st;
}

// Query current EPROCESS->Protection value and return as DWORD.
static NTSTATUS Handle_QueryPplProtection(PUMHH_COMMAND_MESSAGE msg, ULONG InputBufferSize, PVOID OutputBuffer, ULONG OutputBufferSize, PULONG ReturnOutputBufferLength) {
	if (ReturnOutputBufferLength) *ReturnOutputBufferLength = sizeof(DWORD);
	if (InputBufferSize < ((ULONG)UMHH_MSG_HEADER_SIZE + (ULONG)sizeof(DWORD))) {
		return STATUS_BUFFER_TOO_SMALL;
	}
	DWORD pid = 0; 
	RtlCopyMemory(&pid, msg->m_Data, sizeof(DWORD));
	PEPROCESS ep = NULL; 
	NTSTATUS st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &ep);
	if (!NT_SUCCESS(st) || ep == NULL) { 
		return st; 
	}
	EPROCESS_OFFSETS off; 
	if (!KO_GetEprocessOffsets(&off)) { 
		ObDereferenceObject(ep); 
		return STATUS_NOT_SUPPORTED;
	}
	UCHAR prot = 0;
	if (!Mini_ReadKernelMemory((PVOID)((PUCHAR)ep + off.ProtectionOffset), &prot, sizeof(UCHAR))) { 
		ObDereferenceObject(ep); 
		return STATUS_UNSUCCESSFUL;
	}
	ObDereferenceObject(ep);
	DWORD out = (DWORD)prot;
	if (OutputBuffer && OutputBufferSize >= sizeof(DWORD)) {
		RtlCopyMemory(OutputBuffer, &out, sizeof(DWORD));
		return STATUS_SUCCESS; }
	return STATUS_BUFFER_TOO_SMALL;
}

// Recover PPL by setting Protection to provided byte in payload after PID.
static NTSTATUS Handle_RecoverPpl(PUMHH_COMMAND_MESSAGE msg, ULONG InputBufferSize, PVOID OutputBuffer, ULONG OutputBufferSize, PULONG ReturnOutputBufferLength) {
	(OutputBufferSize);
	if (ReturnOutputBufferLength) *ReturnOutputBufferLength = sizeof(NTSTATUS);
	ULONG need = (ULONG)(UMHH_MSG_HEADER_SIZE + sizeof(DWORD) + sizeof(DWORD));
	if (InputBufferSize < need) return STATUS_BUFFER_TOO_SMALL;
	DWORD pid = 0; DWORD prot = 0;
	RtlCopyMemory(&pid, msg->m_Data, sizeof(DWORD));
	RtlCopyMemory(&prot, msg->m_Data + sizeof(DWORD), sizeof(DWORD));
	PEPROCESS ep = NULL; NTSTATUS st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &ep);
	if (!NT_SUCCESS(st) || ep == NULL) { RtlCopyMemory(OutputBuffer, &st, sizeof(NTSTATUS)); return st; }
	EPROCESS_OFFSETS off; if (!KO_GetEprocessOffsets(&off)) { ObDereferenceObject(ep); st = STATUS_NOT_SUPPORTED; RtlCopyMemory(OutputBuffer, &st, sizeof(NTSTATUS)); return st; }
	UCHAR pv = (UCHAR)(prot & 0xFF);
	if (!Mini_WriteKernelMemory((PVOID)((PUCHAR)ep + off.ProtectionOffset), &pv, sizeof(UCHAR))) { ObDereferenceObject(ep); st = STATUS_UNSUCCESSFUL; RtlCopyMemory(OutputBuffer, &st, sizeof(NTSTATUS)); return st; }
	ObDereferenceObject(ep);
	st = STATUS_SUCCESS; RtlCopyMemory(OutputBuffer, &st, sizeof(NTSTATUS));
	return st;
}

// Write bytes into target process memory from user-mode buffer using MmCopyVirtualMemory.
static NTSTATUS Handle_WriteProcessMemory(
	PCOMM_CONTEXT CallerCtx,
	PUMHH_COMMAND_MESSAGE msg,
	ULONG InputBufferSize,
	PVOID OutputBuffer,
	ULONG OutputBufferSize,
	PULONG ReturnOutputBufferLength
) {
	if (ReturnOutputBufferLength) *ReturnOutputBufferLength = sizeof(NTSTATUS);
	if (InputBufferSize < (UMHH_MSG_HEADER_SIZE + sizeof(DWORD) + sizeof(PVOID) + sizeof(SIZE_T))) {
		NTSTATUS st = STATUS_BUFFER_TOO_SMALL;
		if (OutputBuffer && OutputBufferSize >= sizeof(NTSTATUS)) RtlCopyMemory(OutputBuffer, &st, sizeof(NTSTATUS));
		return st;
	}
	DWORD pid = 0; PVOID base = NULL; SIZE_T size = 0;
	RtlCopyMemory(&pid, msg->m_Data, sizeof(DWORD));
	RtlCopyMemory(&base, msg->m_Data + sizeof(DWORD), sizeof(PVOID));
	RtlCopyMemory(&size, msg->m_Data + sizeof(DWORD) + sizeof(PVOID), sizeof(SIZE_T));
	if (size == 0) {
		NTSTATUS st = STATUS_INVALID_PARAMETER;
		if (OutputBuffer && OutputBufferSize >= sizeof(NTSTATUS)) RtlCopyMemory(OutputBuffer, &st, sizeof(NTSTATUS));
		return st;
	}
	SIZE_T dataOffset = sizeof(DWORD) + sizeof(PVOID) + sizeof(SIZE_T);
	SIZE_T available = InputBufferSize - UMHH_MSG_HEADER_SIZE;
	if (available < dataOffset + size) {
		NTSTATUS st = STATUS_BUFFER_TOO_SMALL;
		if (OutputBuffer && OutputBufferSize >= sizeof(NTSTATUS)) RtlCopyMemory(OutputBuffer, &st, sizeof(NTSTATUS));
		return st;
	}
	// Lookup target process
	PEPROCESS targetProc = NULL;
	NTSTATUS st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &targetProc);
	if (!NT_SUCCESS(st) || targetProc == NULL) {
		if (OutputBuffer && OutputBufferSize >= sizeof(NTSTATUS)) RtlCopyMemory(OutputBuffer, &st, sizeof(NTSTATUS));
		return st;
	}
	// Source is from caller's user-mode buffer within this message; ensure we use the caller process context
	if (!CallerCtx) {
		ObDereferenceObject(targetProc);
		st = STATUS_INVALID_PARAMETER;
		if (OutputBuffer && OutputBufferSize >= sizeof(NTSTATUS)) RtlCopyMemory(OutputBuffer, &st, sizeof(NTSTATUS));
		return st;
	}
	DWORD callerPid = (DWORD)(ULONG_PTR)CallerCtx->m_UserProcessId;
	PEPROCESS callerProc = NULL;
	st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)callerPid, &callerProc);
	if (!NT_SUCCESS(st) || callerProc == NULL) {
		ObDereferenceObject(targetProc);
		if (OutputBuffer && OutputBufferSize >= sizeof(NTSTATUS)) RtlCopyMemory(OutputBuffer, &st, sizeof(NTSTATUS));
		return st;
	}
	SIZE_T copied = 0;
	// Build source pointer into caller process address space
	PUCHAR srcUser = (PUCHAR)msg->m_Data + dataOffset;
	st = MmCopyVirtualMemory(
		PsGetCurrentProcess(),
		srcUser,
		targetProc,
		base,
		size,
		KernelMode,
		&copied);
	ObDereferenceObject(targetProc);
	ObDereferenceObject(callerProc);
	if (!NT_SUCCESS(st) || copied != size) {
		if (OutputBuffer && OutputBufferSize >= sizeof(NTSTATUS)) RtlCopyMemory(OutputBuffer, &st, sizeof(NTSTATUS));
		return st;
	}
	NTSTATUS ok = STATUS_SUCCESS;
	if (OutputBuffer && OutputBufferSize >= sizeof(NTSTATUS)) RtlCopyMemory(OutputBuffer, &ok, sizeof(NTSTATUS));
	return STATUS_SUCCESS;
}
