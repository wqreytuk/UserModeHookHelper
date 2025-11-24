#include "pch.h"
#include "UIHelpers.h"
#include "Helper.h"
#include "ProcFlags.h"

// Live formatting of the HookState column.
// If PF_IN_HOOK_LIST is set, we ignore any cached PF_MASTER_DLL_LOADED / PF_IS_64BIT
// bits and query the current process state on the fly for maximum accuracy.
// This ensures the column always reflects real-time DLL injection and architecture.
std::wstring FormatHookColumn(PROC_ITEMDATA packed) {
    DWORD flags = FLAGS_FROM_ITEMDATA(packed);
    DWORD pid   = PID_FROM_ITEMDATA(packed);
    if ((flags & PF_IN_HOOK_LIST) == 0)
        return std::wstring(L"No");

    // Dynamic queries: architecture then DLL presence (arch determines DLL name)
    bool is64 = false; Helper::IsProcess64(pid, is64);
    const wchar_t* dllName = is64 ? MASTER_X64_DLL_BASENAME : MASTER_X86_DLL_BASENAME;
    bool dllLoaded = false; Helper::IsModuleLoaded(pid, dllName, dllLoaded);

    wchar_t buf[128];
    swprintf_s(buf, _countof(buf), L"Yes (master=%s, %s)", dllLoaded ? L"Yes" : L"No", is64 ? L"x64" : L"x86");
    return std::wstring(buf);
}
