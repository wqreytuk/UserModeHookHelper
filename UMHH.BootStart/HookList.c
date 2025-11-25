#include "HookList.h"
#include "Tag.h"
#include "Trace.h"
#include "StrLib.h"

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
	// Attempt to load persisted hook entries from registry. If this fails
	// we still continue with an empty hook-list but log the failure.
	NTSTATUS st = HookList_LoadFromRegistry();
	if (!NT_SUCCESS(st)) {
		Log(L"HookList_LoadFromRegistry failed: 0x%08x\n", st);
	}

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
		}
		else {
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
			}
			else {
				ExReleaseResourceLite(&s_HookListLock);
				return STATUS_BUFFER_TOO_SMALL;
			}
		}
		else {
			// write empty string
			if (sizeof(WCHAR) <= remain) {
				((WCHAR*)dest)[0] = L'\0';
				dest += sizeof(WCHAR);
				remain -= sizeof(WCHAR);
			}
			else {
				ExReleaseResourceLite(&s_HookListLock);
				return STATUS_BUFFER_TOO_SMALL;
			}
		}
		entry = entry->Flink;
	}
	ExReleaseResourceLite(&s_HookListLock);

	return STATUS_SUCCESS;
}

// Helper context for RtlQueryRegistryValues call
typedef struct _RL_CONTEXT {
	PUNICODE_STRING Buffer; // receives REG_MULTI_SZ block
} RL_CONTEXT, *PRL_CONTEXT;

// Callback used by RtlQueryRegistryValues to capture the REG_MULTI_SZ value
NTSTATUS NTAPI RegistryCallback(PRTL_QUERY_REGISTRY_TABLE QueryTable, PVOID Context) {
	UNREFERENCED_PARAMETER(QueryTable);
	UNREFERENCED_PARAMETER(Context);
	// Rtl layer will have placed the multi-sz in the provided buffer when
	// using RTL_QUERY_REGISTRY_DIRECT and a buffer was provided.
	return STATUS_SUCCESS;
}

NTSTATUS HookList_LoadFromRegistry(VOID) {
	NTSTATUS status = STATUS_SUCCESS;
	// Read HKLM\SOFTWARE\GIAO\UserModeHookHelper HookPaths REG_MULTI_SZ
	UNICODE_STRING keyPath;
	RtlInitUnicodeString(&keyPath, REG_PERSIST_REGPATH);

	// Query value directly using RtlQueryRegistryValues with RTL_QUERY_REGISTRY_DIRECT
	// Build a one-entry table for HookPaths
	RTL_QUERY_REGISTRY_TABLE localTable[2];
	RtlZeroMemory(localTable, sizeof(localTable));

	// Prepare a buffer for receiving the REG_MULTI_SZ; allocate modestly and let
	// callers reallocate if needed. We'll query with RTL_QUERY_REGISTRY_DIRECT
	// into a temp buffer via ZwQueryValueKey style is more verbose; instead use
	// RtlQueryRegistryValues with RTL_QUERY_REGISTRY_SUBKEY.

	// Use RtlQueryRegistryValues to query the subkey and directly extract the value
	localTable[0].Flags = RTL_QUERY_REGISTRY_SUBKEY | RTL_QUERY_REGISTRY_REQUIRED;
	localTable[0].Name = L"UserModeHookHelper"; // not used with SUBKEY? keep safe

	// Simpler approach: open the key and ZwQueryValueKey directly.
	HANDLE hKey = NULL;
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING uKeyName;
	RtlInitUnicodeString(&uKeyName, REG_PERSIST_REGPATH);
	InitializeObjectAttributes(&oa, &uKeyName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwOpenKey(&hKey, KEY_READ, &oa);
	if (!NT_SUCCESS(status)) {
		// Key may not exist, treat as empty list
		return STATUS_SUCCESS;
	}

	// Query value size first
	UNICODE_STRING valueName;
	RtlInitUnicodeString(&valueName, L"HookPaths");
	ULONG resultLength = 0;
	status = ZwQueryValueKey(hKey, &valueName, KeyValuePartialInformation, NULL, 0, &resultLength);
	if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW) {
		// either no value or other error
		ZwClose(hKey);
		if (status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND) return STATUS_SUCCESS;
		return STATUS_SUCCESS;
	}

	PKEY_VALUE_PARTIAL_INFORMATION kv = ExAllocatePoolWithTag(NonPagedPool, resultLength, tag_hlst);
	if (!kv) {
		ZwClose(hKey);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlZeroMemory(kv, resultLength);
	status = ZwQueryValueKey(hKey, &valueName, KeyValuePartialInformation, kv, resultLength, &resultLength);
	if (!NT_SUCCESS(status)) {
		ExFreePoolWithTag(kv, tag_hlst);
		ZwClose(hKey);
		return STATUS_SUCCESS; // treat as empty
	}

	if (kv->Type != REG_MULTI_SZ || kv->DataLength == 0) {
		ExFreePoolWithTag(kv, tag_hlst);
		ZwClose(hKey);
		return STATUS_SUCCESS;
	}

	PWCHAR buf = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, kv->DataLength + sizeof(WCHAR), tag_hlst);
	if (!buf) {
		ExFreePoolWithTag(kv, tag_hlst);
		ZwClose(hKey);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlZeroMemory(buf, kv->DataLength + sizeof(WCHAR));
	RtlCopyMemory(buf, kv->Data, kv->DataLength);

	// Walk multi-sz and call HookList_AddEntry for each non-empty string
	PWCHAR p = buf;
	while (*p) {
		SIZE_T len = (wcslen(p) + 1) * sizeof(WCHAR);
		// Compute hash using shared kernel helper
		ULONGLONG h = SL_ComputeNtPathHash((const PUCHAR)p, wcslen(p) * sizeof(WCHAR));
		// Add entry (idempotent)
		HookList_AddEntry(h, p, len);
		p = (PWCHAR)((PUCHAR)p + len);
	}

	ExFreePoolWithTag(buf, tag_hlst);
	ExFreePoolWithTag(kv, tag_hlst);
	ZwClose(hKey);
	return STATUS_SUCCESS;
}

NTSTATUS HookList_SaveToRegistry(VOID) {
	NTSTATUS status = STATUS_SUCCESS;
	ULONG totalBytes = 0;
	ExAcquireResourceSharedLite(&s_HookListLock, TRUE);
	PLIST_ENTRY entry = s_HookList.Flink;
	while (entry != &s_HookList) {
		PHOOK_ENTRY p = CONTAINING_RECORD(entry, HOOK_ENTRY, ListEntry);
		if (p && p->NtPath.Buffer && p->NtPath.Length > 0) {
			totalBytes += p->NtPath.Length + sizeof(WCHAR);
		} else {
			totalBytes += sizeof(WCHAR);
		}
		entry = entry->Flink;
	}
	ExReleaseResourceLite(&s_HookListLock);

	totalBytes += sizeof(WCHAR);
	PUCHAR buffer = ExAllocatePoolWithTag(NonPagedPool, totalBytes, tag_hlst);
	if (!buffer) return STATUS_INSUFFICIENT_RESOURCES;
	RtlZeroMemory(buffer, totalBytes);

	PUCHAR dest = buffer;
	ExAcquireResourceSharedLite(&s_HookListLock, TRUE);
	entry = s_HookList.Flink;
	while (entry != &s_HookList) {
		PHOOK_ENTRY p = CONTAINING_RECORD(entry, HOOK_ENTRY, ListEntry);
		if (p && p->NtPath.Buffer && p->NtPath.Length > 0) {
			SIZE_T bytes = p->NtPath.Length;
			RtlCopyMemory(dest, p->NtPath.Buffer, bytes);
			((WCHAR*)dest)[bytes / sizeof(WCHAR)] = L'\0';
			dest += bytes + sizeof(WCHAR);
		} else {
			((WCHAR*)dest)[0] = L'\0';
			dest += sizeof(WCHAR);
		}
		entry = entry->Flink;
	}
	ExReleaseResourceLite(&s_HookListLock);

	UNICODE_STRING uKeyName;
	OBJECT_ATTRIBUTES oa;
	RtlInitUnicodeString(&uKeyName, REG_PERSIST_REGPATH);
	InitializeObjectAttributes(&oa, &uKeyName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

	HANDLE hKey = NULL;
	status = ZwCreateKey(&hKey, KEY_WRITE, &oa, 0, NULL, 0, NULL);
	if (!NT_SUCCESS(status)) {
		ExFreePoolWithTag(buffer, tag_hlst);
		return status;
	}

	UNICODE_STRING valueName;
	RtlInitUnicodeString(&valueName, L"HookPaths");

	status = ZwSetValueKey(hKey, &valueName, 0, REG_MULTI_SZ, buffer, totalBytes - sizeof(WCHAR));
	ZwClose(hKey);
	ExFreePoolWithTag(buffer, tag_hlst);
	return status;
}