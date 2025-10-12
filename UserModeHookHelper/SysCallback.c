#include "SysCallback.h"
#include "Trace.h"
#include "FltCommPort.h"
#include "HookList.h"
#include <ntstrsafe.h>

// Pending-inject list: holds PIDs we detected need DLL injection when ntdll.dll is loaded
typedef struct _PENDING_INJECT {
	LIST_ENTRY ListEntry;
	ULONG Pid;
} PENDING_INJECT, *PPENDING_INJECT;

static LIST_ENTRY s_PendingInjectList;
static KSPIN_LOCK s_PendingInjectLock;

// Simple FNV-1a 64-bit over UTF-16LE bytes
static ULONGLONG ComputeNtPathHash(PUNICODE_STRING Path)
{
	if (!Path || !Path->Buffer || Path->Length == 0) return 0;
	const ULONGLONG FNV_offset = 14695981039346656037ULL;
	const ULONGLONG FNV_prime = 1099511628211ULL;
	ULONGLONG hash = FNV_offset;
	// iterate over bytes of the UNICODE string (UTF-16LE)
	USHORT byteLen = Path->Length; // length in bytes
	PUCHAR bytes = (PUCHAR)Path->Buffer;
	for (USHORT i = 0; i < byteLen; ++i) {
		hash ^= (ULONGLONG)bytes[i];
		hash *= FNV_prime;
	}
	return hash;
}

static BOOLEAN PendingInject_Exists(ULONG pid)
{
	BOOLEAN found = FALSE;
	KIRQL oldIrql;
	KeAcquireSpinLock(&s_PendingInjectLock, &oldIrql);
	PLIST_ENTRY e = s_PendingInjectList.Flink;
	while (e != &s_PendingInjectList) {
		PPENDING_INJECT p = CONTAINING_RECORD(e, PENDING_INJECT, ListEntry);
		if (p->Pid == pid) { found = TRUE; break; }
		e = e->Flink;
	}
	KeReleaseSpinLock(&s_PendingInjectLock, oldIrql);
	return found;
}

static VOID PendingInject_Add(ULONG pid)
{
	if (PendingInject_Exists(pid)) return;
	PPENDING_INJECT p = ExAllocatePoolWithTag(NonPagedPool, sizeof(PENDING_INJECT), 'gInP');
	if (!p) return;
	RtlZeroMemory(p, sizeof(*p));
	p->Pid = pid;
	KIRQL oldIrql;
	KeAcquireSpinLock(&s_PendingInjectLock, &oldIrql);
	InsertTailList(&s_PendingInjectList, &p->ListEntry);
	KeReleaseSpinLock(&s_PendingInjectLock, oldIrql);
}

static VOID PendingInject_Remove(ULONG pid)
{
	KIRQL oldIrql;
	KeAcquireSpinLock(&s_PendingInjectLock, &oldIrql);
	PLIST_ENTRY e = s_PendingInjectList.Flink;
	while (e != &s_PendingInjectList) {
		PPENDING_INJECT p = CONTAINING_RECORD(e, PENDING_INJECT, ListEntry);
		e = e->Flink; // advance first since we may remove
		if (p->Pid == pid) {
			RemoveEntryList(&p->ListEntry);
			ExFreePoolWithTag(p, 'gInP');
			break;
		}
	}
	KeReleaseSpinLock(&s_PendingInjectLock, oldIrql);
}

// Simple case-insensitive check whether a UNICODE_STRING ends with "ntdll.dll"
static BOOLEAN ImageNameIsNtdll(PUNICODE_STRING ImageName)
{
	if (!ImageName || !ImageName->Buffer || ImageName->Length == 0) return FALSE;
	// find last backslash
	USHORT chars = ImageName->Length / sizeof(WCHAR);
	PWCHAR buf = ImageName->Buffer;
	PWCHAR last = buf + chars - 1;
	// walk backward to component start
	while (last >= buf && *last != L'\\' && *last != L'/') --last;
	PWCHAR comp = (last >= buf && (*last == L'\\' || *last == L'/')) ? (last + 1) : buf;
	// compare comp to L"ntdll.dll" case-insensitive
	static const WCHAR target[] = L"ntdll.dll";
	SIZE_T need = (wcslen(target)) * sizeof(WCHAR);
	USHORT compBytes = (USHORT)((buf + chars - comp) * sizeof(WCHAR));
	if (compBytes != need) {
		// lengths differ - but allow trailing path components with same length only
		if ((buf + chars - comp) * sizeof(WCHAR) < need) return FALSE;
	}
	UNICODE_STRING usComp;
	usComp.Buffer = comp;
	usComp.Length = (USHORT)((buf + chars - comp) * sizeof(WCHAR));
	usComp.MaximumLength = usComp.Length;
	UNICODE_STRING usTarget;
	RtlInitUnicodeString(&usTarget, target);
	// RtlCompareUnicodeString supports case-insensitive compare
	if (RtlCompareUnicodeString(&usComp, &usTarget, TRUE) == 0) return TRUE;
	return FALSE;
}

// Placeholder injection function to be implemented later
static VOID InjectDll(ULONG pid)
{
	UNREFERENCED_PARAMETER(pid);
	Log(L"InjectDll placeholder called for pid %u\n", pid);
}
NTSTATUS SetSysNotifiers() {
	NTSTATUS status;
	status = PsSetCreateProcessNotifyRoutine(ProcessCrNotify, FALSE);
	if (!NT_SUCCESS(status)) {
		Log(L"failed to call PsSetCreateProcessNotifyRoutin: 0x%x\n", status);
		return status;
	}
	status = PsSetLoadImageNotifyRoutine(LoadImageNotify);
	if (!NT_SUCCESS(status)) {
		Log(L"failed to call PsSetLoadImageNotifyRoutine: 0x%x\n", status);
		return status;
	}
	return status;
} 

VOID
ProcessCrNotify(
	IN HANDLE ParentId,
	IN HANDLE ProcessId,
	IN BOOLEAN Create
) {
	(ParentId);
	// Broadcast to any connected user-mode clients. ProcessId is a HANDLE-sized
	// value; we cast to DWORD to send the PID. If high bits exist on 64-bit
	// systems they are truncated, but PIDs fit in 32-bits on Windows.
	DWORD pid = (DWORD)(ULONG_PTR)ProcessId;
	ULONG notified = 0;
	NTSTATUS st = Comm_BroadcastProcessNotify(pid, Create, &notified);
	if (!NT_SUCCESS(st)) {
		Log(L"Comm_BroadcastProcessNotify failed: 0x%x\n", st);
	}

	// If this is a creation event, attempt to obtain the process NT image
	// path directly and compute the same FNV hash we use for HookList entries.
	// This avoids scanning every load-image event and restricts hook matching
	// to once per new process.
	if (Create) {
		PEPROCESS process = NULL;
		NTSTATUS r = PsLookupProcessByProcessId(ProcessId, &process);
		if (NT_SUCCESS(r) && process) {
			// SeLocateProcessImageName allocates a UNICODE_STRING buffer we must
			// free with ExFreePool when done (see FltCommPort.c usage).
			PUNICODE_STRING imageName;
			NTSTATUS stName = SeLocateProcessImageName(process, &imageName);
			if (NT_SUCCESS(stName) && imageName->Buffer && imageName->Length) {
				ULONGLONG hash = ComputeNtPathHash(imageName);
				if (hash != 0 && HookList_ContainsHash(hash)) {
					PendingInject_Add(pid);
					Log(L"Process create: queued pid %u for injection (matched image path)\n", pid);
				}
				// Free the buffer allocated by SeLocateProcessImageName
				ExFreePoolWithTag(imageName, 'gInP');
			}
			ObDereferenceObject(process);
		}
	}
}

VOID
LoadImageNotify(
	IN PUNICODE_STRING FullImageName,
	IN HANDLE ProcessId,
	IN PIMAGE_INFO ImageInfo
) {
	(ImageInfo);
	// Only act when we have a valid image name.
	if (!FullImageName || FullImageName->Length == 0) return;
	DWORD pid = (DWORD)(ULONG_PTR)ProcessId;

	// We no longer compute the full-image hash here because matching is
	// performed at process-create time in ProcessCrNotify (SeLocateProcessImageName).
	// Here we only look for ntdll.dll loads and perform injection for any
	// PIDs previously queued via PendingInject_Add.
	if (ImageNameIsNtdll(FullImageName)) {
		if (PendingInject_Exists(pid)) {
			Log(L"ntdll.dll loaded in pid %u: performing injection\n", pid);
			InjectDll(pid);
			PendingInject_Remove(pid);
		}
	}
}