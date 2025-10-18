#include "pch.h"
#include "ProcessResolver.h"
#include "Helper.h"
#include "FilterCommPort.h"
#include "ProcessManager.h"
// Need full dialog type for GetSafeHwnd() and message constants
#include "UMControllerDlg.h"
#include "UMControllerMsgs.h"
#include "ProcFlags.h"

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
			// Compute module/arch state once in background
			bool is64 = false;
			bool dllLoaded = false;
			if (inHook) {
				Helper::IsProcess64(pid, is64);
				const wchar_t* dllName = is64 ? MASTER_X64_DLL_BASENAME : MASTER_X86_DLL_BASENAME;
				Helper::IsModuleLoaded(pid, dllName, dllLoaded);
			}
			PM_UpdateEntryModuleState(pid, is64, dllLoaded);
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
		// Compute module/arch state once in background
		bool is64 = false;
		bool dllLoaded = false;
		if (inHook) {
			Helper::IsProcess64(pid, is64);
			const wchar_t* dllName = is64 ? MASTER_X64_DLL_BASENAME : MASTER_X86_DLL_BASENAME;
			Helper::IsModuleLoaded(pid, dllName, dllLoaded);
		}
		PM_UpdateEntryModuleState(pid, is64, dllLoaded);
		PM_UpdateEntryFields(pid, ntPath, inHook, cmdline);
		::PostMessage(dlg->GetSafeHwnd(), WM_APP_UPDATE_PROCESS, (WPARAM)pid, (LPARAM)UPDATE_SOURCE_NOTIFY);
	}).detach();
}

void ProcessResolver::StartCreateChecker(HWND hwnd, DWORD pid) {
	std::thread([hwnd, pid]() {
		const int MAX_MS = 10000; // 10s
		const int INTERVAL_MS = 250;
		int waited = 0;
		bool dllLoaded = false;
        while (waited < MAX_MS) {
            bool is64 = false;
            Helper::IsProcess64(pid, is64);
            const wchar_t* targetName = is64 ? MASTER_X64_DLL_BASENAME : MASTER_X86_DLL_BASENAME;
            Helper::IsModuleLoaded(pid, targetName, dllLoaded);
			if (dllLoaded) break;
			std::this_thread::sleep_for(std::chrono::milliseconds(INTERVAL_MS));
			waited += INTERVAL_MS;
		}

		// If DLL loaded, try to resolve path and check hook list; otherwise
		// still update UI to clear any transient state.
        if (dllLoaded) {
            // Update cached module state so UI can use it without re-query
            PM_UpdateEntryModuleState(pid, dllLoaded ? true : false, dllLoaded);
            ::PostMessage(hwnd, WM_APP_UPDATE_PROCESS, (WPARAM)pid, (LPARAM)UPDATE_SOURCE_NOTIFY);
        } else {
            // Ensure module state is updated as not-loaded
            PM_UpdateEntryModuleState(pid, false, false);
            ::PostMessage(hwnd, WM_APP_UPDATE_PROCESS, (WPARAM)pid, (LPARAM)UPDATE_SOURCE_NOTIFY);
        }
		return;
	}).detach();
}
