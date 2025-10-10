#ifndef FLTCOMMPORT_H
#define FLTCOMMPORT_H
#include "Common.h"

typedef struct _COMM_CONTEXT {
	LIST_ENTRY		m_entry;
	HANDLE			m_UserProcessId;
	PFLT_PORT		m_ClientPort; 
	LONG			m_RefCount;
}COMM_CONTEXT, *PCOMM_CONTEXT;

// Kernel-side hook list entry: stores a LIST_ENTRY plus the 64-bit hash
// and an optional NT path stored as a UNICODE_STRING. The NtPath.Buffer
// (if non-NULL) is separately allocated from non-paged pool and must be
// freed when the entry is removed.
typedef struct _HOOK_ENTRY {
	LIST_ENTRY ListEntry;
	ULONGLONG Hash;
	UNICODE_STRING NtPath;
} HOOK_ENTRY, *PHOOK_ENTRY;

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
 
NTSTATUS
Comm_MessageNotify(
	__in PVOID ConnectionCookie,
	__in_bcount_opt(InputBufferSize) PVOID InputBuffer,
	__in ULONG InputBufferSize,
	__out_bcount_part_opt(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
	__in ULONG OutputBufferSize,
	__out PULONG ReturnOutputBufferLength
);
#endif