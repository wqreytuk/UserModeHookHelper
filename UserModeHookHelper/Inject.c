#include "Inject.h"
#include "Trace.h"
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

static BOOLEAN PendingInject_Exists_Internal(ULONG pid)
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

static VOID PendingInject_Add_Internal(ULONG pid)
{
    if (PendingInject_Exists_Internal(pid)) return;
    PPENDING_INJECT p = ExAllocatePoolWithTag(NonPagedPool, sizeof(PENDING_INJECT), 'gInP');
    if (!p) return;
    RtlZeroMemory(p, sizeof(*p));
    p->Pid = pid;
    KIRQL oldIrql;
    KeAcquireSpinLock(&s_PendingInjectLock, &oldIrql);
    InsertTailList(&s_PendingInjectList, &p->ListEntry);
    KeReleaseSpinLock(&s_PendingInjectLock, oldIrql);
}

static VOID PendingInject_Remove_Internal(ULONG pid)
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
static BOOLEAN ImageNameIsNtdll_Internal(PUNICODE_STRING ImageName)
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
        if ((buf + chars - comp) * sizeof(WCHAR) < need) return FALSE;
    }
    UNICODE_STRING usComp;
    usComp.Buffer = comp;
    usComp.Length = (USHORT)((buf + chars - comp) * sizeof(WCHAR));
    usComp.MaximumLength = usComp.Length;
    UNICODE_STRING usTarget;
    RtlInitUnicodeString(&usTarget, target);
    if (RtlCompareUnicodeString(&usComp, &usTarget, TRUE) == 0) return TRUE;
    return FALSE;
}

// Placeholder injection function to be implemented later
VOID Inject_Perform(ULONG pid)
{
    UNREFERENCED_PARAMETER(pid);
    Log(L"Inject_Perform placeholder called for pid %u\n", pid);
}

NTSTATUS Inject_Init(VOID)
{
    InitializeListHead(&s_PendingInjectList);
    KeInitializeSpinLock(&s_PendingInjectLock);
    return STATUS_SUCCESS;
}

VOID Inject_Uninit(VOID)
{
    // Free any remaining entries
    KIRQL oldIrql;
    KeAcquireSpinLock(&s_PendingInjectLock, &oldIrql);
    PLIST_ENTRY e = s_PendingInjectList.Flink;
    while (e != &s_PendingInjectList) {
        PPENDING_INJECT p = CONTAINING_RECORD(e, PENDING_INJECT, ListEntry);
        e = e->Flink;
        RemoveEntryList(&p->ListEntry);
        ExFreePoolWithTag(p, 'gInP');
    }
    InitializeListHead(&s_PendingInjectList);
    KeReleaseSpinLock(&s_PendingInjectLock, oldIrql);
}

VOID Inject_CheckAndQueue(PUNICODE_STRING ImageName, DWORD pid)
{
    if (!ImageName || !ImageName->Buffer || ImageName->Length == 0) return;
    ULONGLONG hash = ComputeNtPathHash(ImageName);
    if (hash != 0 && HookList_ContainsHash(hash)) {
        PendingInject_Add_Internal(pid);
        Log(L"Process queued for injection (from broadcast) pid %u\n", pid);
    }
}

BOOLEAN Inject_PendingExists(ULONG pid)
{
    return PendingInject_Exists_Internal(pid);
}

VOID Inject_RemovePending(ULONG pid)
{
    PendingInject_Remove_Internal(pid);
}

VOID Inject_OnImageLoad(PUNICODE_STRING FullImageName, DWORD pid)
{
    if (!FullImageName || FullImageName->Length == 0) return;
    if (ImageNameIsNtdll_Internal(FullImageName)) {
        if (PendingInject_Exists_Internal(pid)) {
            Log(L"ntdll.dll loaded in pid %u: performing injection\n", pid);
            Inject_Perform(pid);
            PendingInject_Remove_Internal(pid);
        }
    }
}
