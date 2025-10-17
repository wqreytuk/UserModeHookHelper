#pragma once
#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <Windows.h>

struct ProcessEntry {
    DWORD pid;
    std::wstring name;
    std::wstring path;
    std::wstring cmdline;
    bool bInHookList;
    bool is64;
    bool masterDllLoaded;
    FILETIME startTime = {0,0};
};

// Initialize internal structures (call once during startup)
void PM_Init();

// Clear all entries (used during initial load)
void PM_Clear();

// Add an entry (appends to internal list). Thread-safe.
void PM_AddEntry(const ProcessEntry& entry);

// Return number of stored entries
int PM_Size();

// Get a copy of the entry at index (thread-safe). Returns false if out of range.
bool PM_GetEntryCopyByIndex(int idx, ProcessEntry& out);

// Get index of PID, or -1 if not present. Thread-safe.
int PM_GetIndex(DWORD pid);

// Get a copy of entry by PID. If outIndex != nullptr will be filled with the mapped index.
bool PM_GetEntryCopyByPid(DWORD pid, ProcessEntry& out, int* outIndex = nullptr);

// Snapshot current PIDs (for resolver snapshots / scans)
std::vector<DWORD> PM_GetPidsSnapshot();

// Update fields for an existing PID (path, inHook, cmdline) if PID maps to an index.
void PM_UpdateEntryFields(DWORD pid, const std::wstring& path, bool inHook, const std::wstring& cmdline);

// Update module/architecture state (is64 and master DLL loaded) for an existing PID.
void PM_UpdateEntryModuleState(DWORD pid, bool is64, bool masterDllLoaded);

// Remove entry by PID (if exists). Thread-safe.
void PM_RemoveByPid(DWORD pid);

// Reserve an exit-waiter slot for pid. Returns true if slot reserved (caller should later release).
bool PM_TryReserveExitWaiter(DWORD pid);

// Release previously reserved exit-waiter slot for pid.
void PM_ReleaseExitWaiter(DWORD pid);

// Convenience: return a full copy of all entries (snapshot)
std::vector<ProcessEntry> PM_GetAll();

// Mark an existing entry as a new process instance (PID reused): clear name/path/cmdline,
// set bInHookList=false and update startTime.
void PM_MarkAsNewProcess(DWORD pid, const FILETIME& newStartTime);
