// Ensure consistent linkage with header export macro
#include "HookUIFactory.h"
#include "HookProcDlg.h"
#include "../Shared/LogMacros.h"

// Definition with HOOKUI_API to match header linkage spec
HOOKUI_API BOOL WINAPI ShowHookDialog(HWND hParent, DWORD pid, const wchar_t* processName, IHookServices* services) {
    // Ensure MFC uses this DLL's module state so dialog resources are found.
    AFX_MANAGE_STATE(AfxGetStaticModuleState());
    // Simple singleton behavior: destroy previous instance
    static HookProcDlg* gDlg = nullptr;
    if (gDlg && gDlg->GetSafeHwnd()) {
        gDlg->DestroyWindow();
        delete gDlg; gDlg = nullptr;
    }
    std::wstring name = processName ? processName : L"(unknown)";
    CWnd* parentWnd = CWnd::FromHandle(hParent);
    gDlg = new HookProcDlg(pid, name, services, parentWnd);
    if (!gDlg->CreateModeless(parentWnd)) {
        DWORD err = GetLastError();
        if (services) {
            wchar_t buf[256];
            _snwprintf_s(buf, _TRUNCATE, L"ShowHookDialog: CreateModeless failed (pid=%lu, name=%s, GetLastError=%lu)",
                static_cast<unsigned long>(pid), name.c_str(), static_cast<unsigned long>(err));
            // Use regular log channel; UI creation failure isn't core hook logic.
            services->Log(buf);
            // Additional hint if resource not found (ERROR_RESOURCE_NAME_NOT_FOUND == 1814)
            if (err == 1814) {
                LOG_UI(services, L"Resource load failure: confirm AFX_MANAGE_STATE present and HookUI.rc compiled into DLL.");
            }
        }
        delete gDlg; gDlg = nullptr;
        return FALSE;
    }
    gDlg->ShowWindow(SW_SHOW);
    return TRUE;
}
