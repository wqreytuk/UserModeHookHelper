#ifndef FLTCOMMPORT_H
#define FLTCOMMPORT_H
#include "Common.h"

typedef struct _COMM_CONTEXT {
	LIST_ENTRY		m_entry;
	HANDLE			m_UserProcessId;
	PFLT_PORT		m_ClientPort; 
	LONG			m_RefCount;
	BOOLEAN			m_Removed; /* TRUE when removed/unloading */
	// Optional null-terminated UTF-16LE directory supplied by user-mode client.
	// Allocated from NonPagedPool when set; freed during context cleanup.
	PWSTR               m_UserDir;
}COMM_CONTEXT, *PCOMM_CONTEXT;


NTSTATUS
Comm_CreatePort();

NTSTATUS
Comm_PortConnect(
	__in PFLT_PORT ClientPort,
	__in_opt PVOID ServerPortCookie,
	__in_bcount_opt(SizeOfContext) PVOID ConnectionContext,
	__in ULONG SizeOfContext,
	__deref_out_opt PVOID *ConnectionCookie
);
 
VOID
Comm_PortDisconnect(
	__in PVOID ConnectionCookie
);

/* Reference helpers used by PortCtx module; callers should use these when
 * accessing a PCOMM_CONTEXT across possible concurrent disconnect/unload.
 */
BOOLEAN PortCtx_Reference(PCOMM_CONTEXT ctx);
VOID PortCtx_Dereference(PCOMM_CONTEXT ctx);

 
NTSTATUS
Comm_MessageNotify(
	__in PVOID ConnectionCookie,
	__in_bcount_opt(InputBufferSize) PVOID InputBuffer,
	__in ULONG InputBufferSize,
	__out_bcount_part_opt(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
	__in ULONG OutputBufferSize,
	__out PULONG ReturnOutputBufferLength
);

// Broadcast a process create/exit notification to all connected clients.
// This is safe to call at APC level; it will iterate PortCtx list and send a
// small message to each client port. Returns number of clients successfully
// notified via outNotifiedCount (may be NULL).
NTSTATUS Comm_BroadcastProcessNotify(DWORD ProcessId, BOOLEAN Create, PULONG outNotifiedCount);
#endif