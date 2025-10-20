#include "HookList.h"
#include "Tag.h"
#include "Trace.h"

// Internal hook list state (module-private)
static LIST_ENTRY s_HookList;
static ERESOURCE s_HookListLock;
// Optional anonymous section that holds a snapshot of the hook hashes
static HANDLE s_SectionHandle = NULL;
static ERESOURCE s_SectionLock;

// HOOK_ENTRY defined in FltCommPort.h (shared header)

NTSTATUS HookList_Init(VOID) {
    InitializeListHead(&s_HookList);
    ExInitializeResourceLite(&s_HookListLock);
    ExInitializeResourceLite(&s_SectionLock);
    // Ensure an initial (possibly empty) section exists so clients can map
    // it immediately after connecting even if the hook list is empty.
    HookList_CreateOrUpdateSection();
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
    // Close section handle if present
    ExAcquireResourceExclusiveLite(&s_SectionLock, TRUE);
    if (s_SectionHandle) {
        ZwClose(s_SectionHandle);
        s_SectionHandle = NULL;
    }
    ExReleaseResourceLite(&s_SectionLock);
    ExDeleteResourceLite(&s_SectionLock);
}

// Internal helper: build an in-memory array of hashes. Caller must free the
// returned buffer via ExFreePoolWithTag(..., tag_hlst).
static NTSTATUS BuildHashSnapshot(PUCHAR* OutBuf, ULONG* OutSize) {
    if (!OutBuf || !OutSize) return STATUS_INVALID_PARAMETER;
    *OutBuf = NULL; *OutSize = 0;
    // Count entries
    ULONG count = 0;
    ExAcquireResourceSharedLite(&s_HookListLock, TRUE);
    PLIST_ENTRY entry = s_HookList.Flink;
    while (entry != &s_HookList) { count++; entry = entry->Flink; }
    ExReleaseResourceLite(&s_HookListLock);

    // Snapshot layout: DWORD version, DWORD count, DWORD reserved, followed by ULONGLONG[count]
    const ULONG header = sizeof(ULONG) * 3;
    SIZE_T bytes = header + (SIZE_T)count * sizeof(ULONGLONG);
    if (bytes == 0) return STATUS_UNSUCCESSFUL;
    PUCHAR buf = ExAllocatePoolWithTag(NonPagedPool, bytes, tag_hlst);
    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(buf, bytes);
    // version 1
    *(ULONG*)(buf) = 1;
    *(ULONG*)(buf + 4) = count;
    *(ULONG*)(buf + 8) = 0; // reserved

    // Fill hashes
    ULONG idx = 0;
    ExAcquireResourceSharedLite(&s_HookListLock, TRUE);
    entry = s_HookList.Flink;
    while (entry != &s_HookList) {
        PHOOK_ENTRY p = CONTAINING_RECORD(entry, HOOK_ENTRY, ListEntry);
        if (p) {
            ULONGLONG h = p->Hash;
            RtlCopyMemory(buf + header + idx * sizeof(ULONGLONG), &h, sizeof(ULONGLONG));
            idx++;
        }
        entry = entry->Flink;
    }
    ExReleaseResourceLite(&s_HookListLock);

    *OutBuf = buf;
    *OutSize = (ULONG)bytes;
    return STATUS_SUCCESS;
}

NTSTATUS HookList_CreateOrUpdateSection(VOID) {
    NTSTATUS status = STATUS_SUCCESS;
    PUCHAR snapshot = NULL; ULONG snapshotBytes = 0;
    status = BuildHashSnapshot(&snapshot, &snapshotBytes);
    if (!NT_SUCCESS(status)) return status;

    // Create a new section and populate it with the snapshot
    HANDLE newSection = NULL;
    LARGE_INTEGER maxSize;
    maxSize.QuadPart = snapshotBytes;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    // Request a section with read/write mapping so kernel can copy into it
    status = ZwCreateSection(&newSection, SECTION_ALL_ACCESS, &oa, &maxSize, PAGE_READWRITE, SEC_COMMIT, NULL);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(snapshot, tag_hlst);
        return status;
    }

    // Map into kernel and copy data
    PVOID viewBase = NULL;
    SIZE_T viewSize = 0;
    LARGE_INTEGER sectionOffset; sectionOffset.QuadPart = 0;
    status = ZwMapViewOfSection(newSection, ZwCurrentProcess(), &viewBase, 0, snapshotBytes, &sectionOffset, &viewSize, ViewUnmap, 0, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        ZwClose(newSection);
        ExFreePoolWithTag(snapshot, tag_hlst);
        return status;
    }

    RtlCopyMemory(viewBase, snapshot, snapshotBytes);

    // Unmap kernel view
    ZwUnmapViewOfSection(ZwCurrentProcess(), viewBase);

    ExFreePoolWithTag(snapshot, tag_hlst);

    // Swap in the new section handle under lock
    ExAcquireResourceExclusiveLite(&s_SectionLock, TRUE);
    if (s_SectionHandle) {
        ZwClose(s_SectionHandle);
    }
    s_SectionHandle = newSection;
    ExReleaseResourceLite(&s_SectionLock);

    return STATUS_SUCCESS;
}

NTSTATUS HookList_DuplicateSectionHandle(PEPROCESS TargetProcess, PHANDLE OutHandle) {
    if (!TargetProcess || !OutHandle) return STATUS_INVALID_PARAMETER;
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE sectionToDup = NULL;
    ExAcquireResourceSharedLite(&s_SectionLock, TRUE);
    sectionToDup = s_SectionHandle;
    if (!sectionToDup) {
        ExReleaseResourceLite(&s_SectionLock);
        return STATUS_NOT_FOUND;
    }
    // Take a reference to the section handle value for duplication
    // Open a handle to the target process with PROCESS_DUP_HANDLE
    HANDLE hTargetProc = NULL;
    status = ObOpenObjectByPointer(TargetProcess, OBJ_KERNEL_HANDLE, NULL, PROCESS_DUP_HANDLE, *PsProcessType, KernelMode, &hTargetProc);
    if (!NT_SUCCESS(status)) {
        ExReleaseResourceLite(&s_SectionLock);
        return status;
    }

    // Duplicate the section handle into target process
    HANDLE dupHandle = NULL;
    status = ZwDuplicateObject(ZwCurrentProcess(), sectionToDup, hTargetProc, &dupHandle, 0, 0, DUPLICATE_SAME_ACCESS);

    ZwClose(hTargetProc);
    ExReleaseResourceLite(&s_SectionLock);

    if (!NT_SUCCESS(status)) return status;

    // Return the duplicated handle (which is valid in the target process)
    *OutHandle = dupHandle;
    return STATUS_SUCCESS;
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
