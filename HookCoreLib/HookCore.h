//#pragma once (already)
#pragma once
#include <string>
#include <vector>
#include "../Shared/HookServices.h" // shared interface (no windows.h here to avoid MFC ordering issue)

// Forward minimal Win32 types to avoid forcing <windows.h> in MFC public headers.
#ifndef _WINDEF_
typedef unsigned long DWORD;
#endif
#ifndef _BASETSD_H_
typedef unsigned long long ULONGLONG; // fallback if not already defined
#endif

// Placeholder core API for future hook logic implementation.
namespace HookCore {
    struct ModuleInfo { std::wstring name; std::wstring path; ULONGLONG base=0; ULONGLONG size=0; };
    // Enumerate modules for a process (snapshot-based). Returns false on failure.
    bool EnumerateModules(DWORD pid, std::vector<ModuleInfo>& out);
    // Validate an address lies within any loaded module; returns owning module name or empty.
    std::wstring FindOwningModule(DWORD pid, ULONGLONG address);
    // Placeholder for future hook application (returns false until implemented).
    // Apply a minimal validation hook. 'services' may be nullptr; if provided, core will emit
    // diagnostic messages via services->LogCore().
    bool ApplyHook(DWORD pid, ULONGLONG address, IHookServices* services);
}
