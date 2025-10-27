#include "pch.h"
#include "UIHelpers.h"

// Helper to format the HookState column text based on packed itemdata flags.
std::wstring FormatHookColumn(PROC_ITEMDATA packed, bool bInHookList) {
    if (!bInHookList) return std::wstring(L"No");
    DWORD flags = FLAGS_FROM_ITEMDATA(packed);
    bool master = (flags & PF_MASTER_DLL_LOADED) != 0;
    bool is64 = (flags & PF_IS_64BIT) != 0;
    wchar_t buf[128];
    // Format: Yes (master=Yes, x64)
    swprintf_s(buf, _countof(buf), L"Yes (master=%s, %s)", master ? L"Yes" : L"No", is64 ? L"x64" : L"x86");
    return std::wstring(buf);
}
