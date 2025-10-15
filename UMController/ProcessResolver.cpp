#include "pch.h"
#include "ProcessResolver.h"
#include "Helper.h"
#include "FilterCommPort.h"
#include "ProcessManager.h"
// Need full dialog type for GetSafeHwnd() and message constants
#include "UMControllerDlg.h"
#include "UMControllerMsgs.h"

using namespace ProcessResolver;

void ProcessResolver::StartLoaderResolver(CUMControllerDlg* dlg, const std::vector<DWORD>& pids, Filter* filter) {
    std::vector<DWORD> loaderPids = pids;
    std::thread([dlg, loaderPids, filter]() {
        for (DWORD pid : loaderPids) {
            std::wstring ntPath;
            bool havePath = Helper::ResolveProcessNtImagePath(pid, *filter, ntPath);
            if (!havePath) {
                ::PostMessage(dlg->GetSafeHwnd(), WM_APP_UPDATE_PROCESS, (WPARAM)pid, 0);
                continue;
            }
            bool inHook = filter->FLTCOMM_CheckHookList(ntPath);
            std::wstring cmdline;
            Helper::GetProcessCommandLineByPID(pid, cmdline);
            PM_UpdateEntryFields(pid, ntPath, inHook, cmdline);
            ::PostMessage(dlg->GetSafeHwnd(), WM_APP_UPDATE_PROCESS, (WPARAM)pid, (LPARAM)UPDATE_SOURCE_LOAD);
        }
    }).detach();
}

void ProcessResolver::StartSingleResolver(CUMControllerDlg* dlg, DWORD pid, Filter* filter) {
    std::thread([dlg, pid, filter]() {
        std::wstring ntPath;
        if (!Helper::ResolveProcessNtImagePath(pid, *filter, ntPath)) {
            ::PostMessage(dlg->GetSafeHwnd(), WM_APP_UPDATE_PROCESS, (WPARAM)pid, 0);
            return;
        }
        bool inHook = filter->FLTCOMM_CheckHookList(ntPath);
        std::wstring cmdline;
        Helper::GetProcessCommandLineByPID(pid, cmdline);
        PM_UpdateEntryFields(pid, ntPath, inHook, cmdline);
        ::PostMessage(dlg->GetSafeHwnd(), WM_APP_UPDATE_PROCESS, (WPARAM)pid, (LPARAM)UPDATE_SOURCE_NOTIFY);
    }).detach();
}
