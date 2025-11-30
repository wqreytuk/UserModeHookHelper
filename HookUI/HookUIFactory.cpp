// Ensure consistent linkage with header export macro
#include "HookUIFactory.h"
#include "HookProcDlg.h"
#include "../Shared/LogMacros.h"

// Definition with HOOKUI_API to match header linkage spec
HOOKUI_API BOOL WINAPI ShowHookDialog(HWND hParent, DWORD pid, const wchar_t* processName, IHookServices* services) {
    // Ensure MFC uses this DLL's module state so dialog resources are found.
    AFX_MANAGE_STATE(AfxGetStaticModuleState());
    std::wstring name = processName ? processName : L"(unknown)";
    CWnd* parentWnd = CWnd::FromHandle(hParent);
    HookProcDlg* dlg = new HookProcDlg(pid, name, services, parentWnd);
    if (!dlg->CreateModeless(parentWnd)) {
        DWORD err = GetLastError();
        if (services) {
            wchar_t buf[256];
            _snwprintf_s(buf, _TRUNCATE, L"ShowHookDialog: CreateModeless failed (pid=%lu, name=%s, GetLastError=%lu)",
                static_cast<unsigned long>(pid), name.c_str(), static_cast<unsigned long>(err));
            services->Log(buf);
            if (err == 1814) {
                LOG_UI(services, L"Resource load failure: confirm AFX_MANAGE_STATE present and HookUI.rc compiled into DLL.");
            }
        }
        delete dlg;
        return FALSE;
    }
    dlg->ShowWindow(SW_SHOW);
    return TRUE;
}
