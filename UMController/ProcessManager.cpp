#include "pch.h"
#include "ProcessManager.h"
#include "Helper.h"
#include <mutex>
#include "RegistryStore.h"

namespace {
    std::vector<ProcessEntry> g_list;
    std::unordered_map<DWORD,int> g_index;
    std::unordered_set<DWORD> g_waiters;
    CRITICAL_SECTION g_lock;
    bool g_inited = false;
    // Hook hash cache
    std::unordered_set<unsigned long long> g_hookHashes;
    bool g_hookCacheInitialized = false;
}

void PM_SetHookHashSet(const std::unordered_set<unsigned long long>& s) {
    EnterCriticalSection(&g_lock);
    g_hookHashes = s;
    g_hookCacheInitialized = true;
    LeaveCriticalSection(&g_lock);
}

bool PM_IsHashInHookSet(unsigned long long h) {
    EnterCriticalSection(&g_lock);
    bool ok = g_hookCacheInitialized && (g_hookHashes.find(h) != g_hookHashes.end());
    LeaveCriticalSection(&g_lock);
    return ok;
}

bool PM_HasHookHashCache() {
    EnterCriticalSection(&g_lock);
    bool ok = g_hookCacheInitialized;
    LeaveCriticalSection(&g_lock);
    return ok;
}

void PM_ClearHookHashCache() {
    EnterCriticalSection(&g_lock);
    g_hookHashes.clear();
    g_hookCacheInitialized = false;
    LeaveCriticalSection(&g_lock);
}

void PM_Init() {
    if (g_inited) return;
    InitializeCriticalSection(&g_lock);
    g_inited = true;
}

void PM_Clear() {
    EnterCriticalSection(&g_lock);
    g_list.clear();
    g_index.clear();
    LeaveCriticalSection(&g_lock);
}

void PM_AddEntry(const ProcessEntry& entry) {
    EnterCriticalSection(&g_lock);
    int idx = (int)g_list.size();
    // Ensure new entries have default module flags set
    ProcessEntry e = entry;
    e.is64 = false;
    e.masterDllLoaded = false;
    e.pathHash = 0;
    g_list.push_back(e);
    g_index[entry.pid] = idx;
    LeaveCriticalSection(&g_lock);
}

int PM_Size() {
    EnterCriticalSection(&g_lock);
    int s = (int)g_list.size();
    LeaveCriticalSection(&g_lock);
    return s;
}

bool PM_GetEntryCopyByIndex(int idx, ProcessEntry& out) {
    EnterCriticalSection(&g_lock);
    if (idx < 0 || idx >= (int)g_list.size()) { LeaveCriticalSection(&g_lock); return false; }
    out = g_list[idx];
    LeaveCriticalSection(&g_lock);
    return true;
}

int PM_GetIndex(DWORD pid) {
    EnterCriticalSection(&g_lock);
    auto it = g_index.find(pid);
    int res = (it == g_index.end()) ? -1 : it->second;
    LeaveCriticalSection(&g_lock);
    return res;
}

bool PM_GetEntryCopyByPid(DWORD pid, ProcessEntry& out, int* outIndex) {
    EnterCriticalSection(&g_lock);
    auto it = g_index.find(pid);
    if (it == g_index.end()) { LeaveCriticalSection(&g_lock); return false; }
    int idx = it->second;
    if (idx < 0 || idx >= (int)g_list.size()) { LeaveCriticalSection(&g_lock); return false; }
    out = g_list[idx];
    if (outIndex) *outIndex = idx;
    LeaveCriticalSection(&g_lock);
    return true;
}

std::vector<DWORD> PM_GetPidsSnapshot() {
    EnterCriticalSection(&g_lock);
    std::vector<DWORD> res;
    res.reserve(g_list.size());
    for (const auto &e : g_list) res.push_back(e.pid);
    LeaveCriticalSection(&g_lock);
    return res;
}

void PM_UpdateEntryFields(DWORD pid, const std::wstring& path, bool inHook, const std::wstring& cmdline) {
    EnterCriticalSection(&g_lock);
    auto it = g_index.find(pid);
    if (it != g_index.end()) {
        int idx = it->second;
        if (idx >= 0 && idx < (int)g_list.size() && g_list[idx].pid == pid) {
            g_list[idx].path = path;
            // compute and store path hash when path is known
            if (!path.empty()) {
                const UCHAR* bytes = reinterpret_cast<const UCHAR*>(path.c_str());
                size_t bytesLen = path.size() * sizeof(wchar_t);
                g_list[idx].pathHash = Helper::GetNtPathHash(bytes, bytesLen);
				std::vector<std::wstring> marks;
				if (RegistryStore::ReadEarlyBreakMarks(marks)) {
					for (auto &m : marks) {
						std::wstring low = m;
						if (!_wcsicmp(m.c_str(), path.c_str()))
							g_list[idx].early_break = true;
						else
							g_list[idx].early_break = false;
					}
				}
            } else {
                g_list[idx].pathHash = 0;
            }
            g_list[idx].bInHookList = inHook;
            g_list[idx].cmdline = cmdline;
        }
    }
    LeaveCriticalSection(&g_lock);
}

std::vector<DWORD> PM_FindPidsByHash(unsigned long long hash) {
    EnterCriticalSection(&g_lock);
    std::vector<DWORD> res;
    if (hash == 0) { LeaveCriticalSection(&g_lock); return res; }
    for (const auto &e : g_list) {
        if (e.pathHash == hash) res.push_back(e.pid);
    }
    LeaveCriticalSection(&g_lock);
    return res;
}

void PM_UpdateEntryModuleState(DWORD pid, bool is64, bool masterDllLoaded) {
    EnterCriticalSection(&g_lock);
    auto it = g_index.find(pid);
    if (it != g_index.end()) {
        int idx = it->second;
        if (idx >= 0 && idx < (int)g_list.size() && g_list[idx].pid == pid) {
            g_list[idx].is64 = is64;
            g_list[idx].masterDllLoaded = masterDllLoaded;
        }
    }
    LeaveCriticalSection(&g_lock);
}

void PM_RemoveByPid(DWORD pid) {
    EnterCriticalSection(&g_lock);
    auto it = g_index.find(pid);
    if (it == g_index.end()) { LeaveCriticalSection(&g_lock); return; }
    int remIdx = it->second;
    if (remIdx >= 0 && remIdx < (int)g_list.size()) {
        g_list.erase(g_list.begin() + remIdx);
    }
    // Update indices incrementally
    g_index.erase(pid);
    for (int i = remIdx; i < (int)g_list.size(); ++i) {
        g_index[g_list[i].pid] = i;
    }
    LeaveCriticalSection(&g_lock);
}

bool PM_TryReserveExitWaiter(DWORD pid) {
    EnterCriticalSection(&g_lock);
    bool ok = (g_waiters.find(pid) == g_waiters.end());
    if (ok) g_waiters.insert(pid);
    LeaveCriticalSection(&g_lock);
    return ok;
}

void PM_ReleaseExitWaiter(DWORD pid) {
    EnterCriticalSection(&g_lock);
    g_waiters.erase(pid);
    LeaveCriticalSection(&g_lock);
}

std::vector<ProcessEntry> PM_GetAll() {
    EnterCriticalSection(&g_lock);
    auto copy = g_list;
    LeaveCriticalSection(&g_lock);
    return copy;
}
void PM_MarkAsNewProcess(DWORD pid, const FILETIME& newStartTime) {
	EnterCriticalSection(&g_lock);
	auto it = g_index.find(pid);
	if (it != g_index.end()) {
		int idx = it->second;
		if (idx >= 0 && idx < (int)g_list.size() && g_list[idx].pid == pid) {
			g_list[idx].name.clear();
			g_list[idx].path.clear();
			g_list[idx].cmdline.clear();
			g_list[idx].bInHookList = false;
			g_list[idx].startTime = newStartTime;
		}
	}
	LeaveCriticalSection(&g_lock);
}
