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
    // First, do a shared scan to quickly detect duplicates without allocating.
    ExAcquireResourceSharedLite(&s_HookListLock, TRUE);
    PLIST_ENTRY entry = s_HookList.Flink;
    while (entry != &s_HookList) {
        PHOOK_ENTRY e = CONTAINING_RECORD(entry, HOOK_ENTRY, ListEntry);
        if (e && e->Hash == hash) {
            ExReleaseResourceLite(&s_HookListLock);
            return STATUS_SUCCESS; // already present, idempotent
        }
        entry = entry->Flink;
    }
    ExReleaseResourceLite(&s_HookListLock);

    // Not found - allocate the new entry and optional path buffer.
    PHOOK_ENTRY p = ExAllocatePoolWithTag(NonPagedPool, sizeof(HOOK_ENTRY), tag_hlst);
    if (!p) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(p, sizeof(HOOK_ENTRY));
    p->Hash = hash;
    InitializeListHead(&p->ListEntry);
    p->NtPath.Buffer = NULL;
    p->NtPath.Length = 0;
    p->NtPath.MaximumLength = 0;

    PWCHAR buf = NULL;
    if (NtPath && PathBytes > 0) {
        SIZE_T bytes = PathBytes;
        if (bytes % sizeof(WCHAR) != 0) {
            bytes = bytes - (bytes % sizeof(WCHAR));
        }
        if (bytes >= sizeof(WCHAR)) {
            buf = ExAllocatePoolWithTag(NonPagedPool, bytes, tag_hlst);
            if (!buf) {
                ExFreePoolWithTag(p, tag_hlst);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            RtlCopyMemory(buf, NtPath, bytes);
            if (buf[(bytes / sizeof(WCHAR)) - 1] != L'\0') buf[(bytes / sizeof(WCHAR)) - 1] = L'\0';
            p->NtPath.Buffer = buf;
            p->NtPath.Length = (USHORT)(bytes - sizeof(WCHAR));
            p->NtPath.MaximumLength = (USHORT)bytes;
        }
    }

    // Acquire exclusive lock and re-check to handle races.
    ExAcquireResourceExclusiveLite(&s_HookListLock, TRUE);
    entry = s_HookList.Flink;
    while (entry != &s_HookList) {
        PHOOK_ENTRY e = CONTAINING_RECORD(entry, HOOK_ENTRY, ListEntry);
        if (e && e->Hash == hash) {
            // Another thread inserted it between our shared-scan and now.
            ExReleaseResourceLite(&s_HookListLock);
            if (p->NtPath.Buffer) ExFreePoolWithTag(p->NtPath.Buffer, tag_hlst);
            ExFreePoolWithTag(p, tag_hlst);
            return STATUS_SUCCESS;
        }
        entry = entry->Flink;
    }

    // Insert and release lock
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

NTSTATUS HookList_EnumeratePaths(PVOID OutputBuffer, ULONG OutputBufferSize, PULONG ReturnOutputBytes) {
    SIZE_T totalNeeded = 0;
    ExAcquireResourceSharedLite(&s_HookListLock, TRUE);
    PLIST_ENTRY entry = s_HookList.Flink;
    while (entry != &s_HookList) {
        PHOOK_ENTRY p = CONTAINING_RECORD(entry, HOOK_ENTRY, ListEntry);
        if (p && p->NtPath.Buffer && p->NtPath.Length > 0) {
            totalNeeded += p->NtPath.Length + sizeof(WCHAR); // include terminator
        } else {
            // still account for an empty placeholder
            totalNeeded += sizeof(WCHAR);
        }
        entry = entry->Flink;
    }
    ExReleaseResourceLite(&s_HookListLock);

    if (ReturnOutputBytes) *ReturnOutputBytes = (ULONG)totalNeeded;
    if (!OutputBuffer || OutputBufferSize < (ULONG)totalNeeded) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    // Fill buffer
    UCHAR* dest = (UCHAR*)OutputBuffer;
    SIZE_T remain = OutputBufferSize;
    ExAcquireResourceSharedLite(&s_HookListLock, TRUE);
    entry = s_HookList.Flink;
    while (entry != &s_HookList) {
        PHOOK_ENTRY p = CONTAINING_RECORD(entry, HOOK_ENTRY, ListEntry);
        if (p && p->NtPath.Buffer && p->NtPath.Length > 0) {
            SIZE_T bytes = p->NtPath.Length;
            if (bytes + sizeof(WCHAR) <= remain) {
                RtlCopyMemory(dest, p->NtPath.Buffer, bytes);
                // append terminator
                ((WCHAR*)dest)[bytes / sizeof(WCHAR)] = L'\0';
                dest += bytes + sizeof(WCHAR);
                remain -= (bytes + sizeof(WCHAR));
            } else {
                ExReleaseResourceLite(&s_HookListLock);
                return STATUS_BUFFER_TOO_SMALL;
            }
        } else {
            // write empty string
            if (sizeof(WCHAR) <= remain) {
                ((WCHAR*)dest)[0] = L'\0';
                dest += sizeof(WCHAR);
                remain -= sizeof(WCHAR);
            } else {
                ExReleaseResourceLite(&s_HookListLock);
                return STATUS_BUFFER_TOO_SMALL;
            }
        }
        entry = entry->Flink;
    }
    ExReleaseResourceLite(&s_HookListLock);

    return STATUS_SUCCESS;
}
