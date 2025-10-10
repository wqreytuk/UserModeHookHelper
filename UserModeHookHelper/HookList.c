#include "HookList.h"
#include "Tag.h"
#include "Trace.h"

// Internal hook list state (module-private)
static LIST_ENTRY s_HookList;
static ERESOURCE s_HookListLock;

// HOOK_ENTRY defined in FltCommPort.h (shared header)

NTSTATUS HookList_Init(VOID) {
    InitializeListHead(&s_HookList);
    ExInitializeResourceLite(&s_HookListLock);
    return STATUS_SUCCESS;
}

VOID HookList_Uninit(VOID) {
    ExAcquireResourceExclusiveLite(&s_HookListLock, TRUE);
    while (!IsListEmpty(&s_HookList)) {
        PLIST_ENTRY entry = RemoveHeadList(&s_HookList);
        PHOOK_ENTRY p = CONTAINING_RECORD(entry, HOOK_ENTRY, ListEntry);
        if (p->NtPath.Buffer) {
            ExFreePoolWithTag(p->NtPath.Buffer, tag_hlst);
        }
        ExFreePoolWithTag(p, tag_hlst);
    }
    InitializeListHead(&s_HookList);
    ExReleaseResourceLite(&s_HookListLock);
    ExDeleteResourceLite(&s_HookListLock);
}

NTSTATUS HookList_AddEntry(ULONGLONG hash, PCWSTR NtPath, SIZE_T PathBytes) {
    PHOOK_ENTRY p = ExAllocatePoolWithTag(NonPagedPool, sizeof(HOOK_ENTRY), tag_hlst);
    if (!p) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(p, sizeof(HOOK_ENTRY));
    p->Hash = hash;
    InitializeListHead(&p->ListEntry);
    p->NtPath.Buffer = NULL;
    p->NtPath.Length = 0;
    p->NtPath.MaximumLength = 0;

    if (NtPath && PathBytes > 0) {
        // Ensure PathBytes is even and at least includes a trailing null WCHAR
        SIZE_T bytes = PathBytes;
        if (bytes % sizeof(WCHAR) != 0) {
            // truncate to even number of bytes
            bytes = bytes - (bytes % sizeof(WCHAR));
        }
        if (bytes < sizeof(WCHAR)) {
            // nothing useful
            bytes = 0;
        }

        if (bytes > 0) {
            PWCHAR buf = ExAllocatePoolWithTag(NonPagedPool, bytes, tag_hlst);
            if (!buf) {
                ExFreePoolWithTag(p, tag_hlst);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            RtlCopyMemory(buf, NtPath, bytes);
            // Guarantee null-termination if caller didn't include it
            if (buf[(bytes / sizeof(WCHAR)) - 1] != L'\0') {
                // If there's room, append a null; otherwise ensure last WCHAR is null
                buf[(bytes / sizeof(WCHAR)) - 1] = L'\0';
            }
            p->NtPath.Buffer = buf;
            p->NtPath.Length = (USHORT)(bytes - sizeof(WCHAR));
            p->NtPath.MaximumLength = (USHORT)bytes;
        }
    }
    ExAcquireResourceExclusiveLite(&s_HookListLock, TRUE);
    InsertTailList(&s_HookList, &p->ListEntry);
    ExReleaseResourceLite(&s_HookListLock);
    return STATUS_SUCCESS;
}

BOOLEAN HookList_RemoveEntry(ULONGLONG hash) {
    BOOLEAN removed = FALSE;
    ExAcquireResourceExclusiveLite(&s_HookListLock, TRUE);
    PLIST_ENTRY entry = s_HookList.Flink;
    while (entry != &s_HookList) {
        PHOOK_ENTRY p = CONTAINING_RECORD(entry, HOOK_ENTRY, ListEntry);
        PLIST_ENTRY next = entry->Flink;
        if (p->Hash == hash) {
            RemoveEntryList(&p->ListEntry);
            if (p->NtPath.Buffer) {
                ExFreePoolWithTag(p->NtPath.Buffer, tag_hlst);
            }
            ExFreePoolWithTag(p, tag_hlst);
            removed = TRUE;
            break;
        }
        entry = next;
    }
    ExReleaseResourceLite(&s_HookListLock);
    return removed;
}

BOOLEAN HookList_ContainsHash(ULONGLONG hash) {
    BOOLEAN found = FALSE;
    ExAcquireResourceSharedLite(&s_HookListLock, TRUE);
    PLIST_ENTRY entry = s_HookList.Flink;
    while (entry != &s_HookList) {
        PHOOK_ENTRY p = CONTAINING_RECORD(entry, HOOK_ENTRY, ListEntry);
        if (p && p->Hash == hash) {
            found = TRUE;
            break;
        }
        entry = entry->Flink;
    }
    ExReleaseResourceLite(&s_HookListLock);
    return found;
}
