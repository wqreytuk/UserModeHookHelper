#ifndef HOOKLIST_H
#define HOOKLIST_H

#include "Common.h"

/*
 * HookList module
 *
 * Purpose:
 *   Maintain a kernel-side list of hook entries (64-bit hash + optional
 *   NT image path). This module encapsulates list state and locking.
 *
 * API contract:
 *   - HookList_Init/HookList_Uninit manage lifecycle; call Init from DriverEntry
 *     and Uninit from unload. Uninit frees all entries and their path buffers.
 *   - HookList_AddEntry(hash, NtPath, PathBytes)
 *       Adds an entry. NtPath may be NULL and PathBytes==0 to store only a hash.
 *       PathBytes is the byte length of the NtPath buffer (UTF-16LE). The
 *       module copies PathBytes (rounded to a WCHAR boundary) into non-paged
 *       pool and guarantees a terminating NUL in the stored buffer.
 *   - HookList_RemoveEntry(hash)
 *       Removes the first matching entry and frees its resources.
 *   - HookList_ContainsHash(hash)
 *       Read-only check whether any entry with the given hash exists.
 *
 * Thread-safety:
 *   All functions take internal locks. Callers must not access internal
 *   data structures directly. Add/Remove use exclusive locking; Contains uses
 *   shared locking.
 */


 // Kernel-side hook list entry: stores a LIST_ENTRY plus the 64-bit hash
 // and an optional NT path stored as a UNICODE_STRING. The NtPath.Buffer
 // (if non-NULL) is separately allocated from non-paged pool and must be
 // freed when the entry is removed.
typedef struct _HOOK_ENTRY {
	LIST_ENTRY ListEntry;
	ULONGLONG Hash;
	UNICODE_STRING NtPath;
	ULONGLONG ModuleBase; // New: module base address
	ULONGLONG Offset;     // New: offset from module base
} HOOK_ENTRY, *PHOOK_ENTRY;


NTSTATUS HookList_Init(VOID);
VOID HookList_Uninit(VOID);
// Create or refresh an anonymous section containing a compact snapshot of
// the hook-list hashes. The snapshot layout is:
//   DWORD Version;
//   DWORD Count;
//   DWORD Reserved; (padding)
//   ULONGLONG Hashes[Count];
// The function returns STATUS_SUCCESS on success.
NTSTATUS HookList_CreateOrUpdateSection(VOID);
// Duplicate the current anonymous section handle into the target process.
// On success returns STATUS_SUCCESS and sets *OutHandle to a kernel-handle
// that is already duplicated into the caller's process (caller-visible).
NTSTATUS HookList_DuplicateSectionHandle(PEPROCESS TargetProcess, PHANDLE OutHandle);
// Add entry with optional UTF-16LE path buffer. If PathBytes == 0, no path is stored.
NTSTATUS HookList_AddEntry(ULONGLONG hash, PCWSTR NtPath, SIZE_T PathBytes, ULONGLONG ModuleBase, ULONGLONG Offset);
BOOLEAN HookList_RemoveEntry(ULONGLONG hash);
BOOLEAN HookList_ContainsHash(ULONGLONG hash);

// Enumerate stored NT paths into the provided output buffer as a sequence
// of null-terminated WCHAR strings concatenated one after another.
// If OutputBuffer is NULL or OutputBufferSize is insufficient, the
// function returns STATUS_BUFFER_TOO_SMALL and sets *ReturnOutputBytes to
// the required number of bytes. On success returns STATUS_SUCCESS and
// sets *ReturnOutputBytes to the number of bytes written.
NTSTATUS HookList_EnumeratePaths(PVOID OutputBuffer, ULONG OutputBufferSize, PULONG ReturnOutputBytes);

// Load persisted hook NT paths from the registry. Reads
// HKLM\SOFTWARE\<vendor>\UserModeHookHelper\HookPaths (REG_MULTI_SZ) and adds
// each NT path into the in-kernel hook list via HookList_AddEntry. Returns
// STATUS_SUCCESS on success or an appropriate NTSTATUS on failure. This
// function is safe to call during driver initialization.
NTSTATUS HookList_LoadFromRegistry(VOID);
// Persist current hook NT paths into the registry as REG_MULTI_SZ at
// HKLM\SOFTWARE\<vendor>\UserModeHookHelper\HookPaths. The function
// gathers current NtPath strings under the list lock and writes them.
// Returns STATUS_SUCCESS on success.
NTSTATUS HookList_SaveToRegistry(VOID);

#endif
