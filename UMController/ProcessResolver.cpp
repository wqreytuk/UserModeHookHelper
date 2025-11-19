#include "pch.h"
#include "ProcessResolver.h"
#include "Helper.h"
#include "FilterCommPort.h"
#include "ProcessManager.h"
// Need full dialog type for GetSafeHwnd() and message constants
#include "UMControllerDlg.h"
#include "UMControllerMsgs.h"
#include "UMController.h"
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
			bool inHook = false;
			// If Global Hook Mode is enabled, consider all processes as 'inHook' for
			// purposes of checking master DLL presence. However, actual additions to
			// the persisted hook list remain controlled by HookPaths/user actions.
			bool globalMode = false;
			if (dlg) globalMode = dlg->IsGlobalHookModeEnabled();
			if (globalMode) {
				inHook = true;
			} else {
				// existing behavior: consult cache or filter IPC
				if (PM_HasHookHashCache()) {
					const UCHAR* bytes = reinterpret_cast<const UCHAR*>(ntPath.c_str());
					size_t bytesLen = ntPath.size() * sizeof(wchar_t);
					unsigned long long h = Helper::GetNtPathHash(bytes, bytesLen);
					inHook = PM_IsHashInHookSet(h);
				} else {
					inHook = filter->FLTCOMM_CheckHookList(ntPath);
				}
			}
			std::wstring cmdline;
			Helper::GetProcessCommandLineByPID(pid, cmdline);
			// On-demand arch & DLL presence only if process is in hook list.
			bool is64 = false;
			bool dllLoaded = false;
			if (inHook) {
				Helper::IsProcess64(pid, is64);
				const wchar_t* dllName = is64 ? MASTER_X64_DLL_BASENAME : MASTER_X86_DLL_BASENAME;
				Helper::IsModuleLoaded(pid, dllName, dllLoaded);
			}
			// Update cached module/arch state so UI and sorting can rely on it.
			PM_UpdateEntryModuleState(pid, is64, dllLoaded);
			// Update only fields; do not persist module state cache globally.
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
		// Single-resolution path: per-path IPC here is acceptable because
		// these are single lookups (notifications) and won't cause noticeable
		// latency. Use the existing per-path filter check.
		bool inHook = false;
		// If global hook mode is enabled, treat new incoming processes as 'inHook'
		// so we perform arch + master-DLL checks; persistence remains controlled
		// by HookPaths/user actions.
		if (dlg && dlg->IsGlobalHookModeEnabled()) {
			inHook = true;
		} else {
			inHook = filter->FLTCOMM_CheckHookList(ntPath);
		}
	// app.GetETW().Log(L"StartSingleResolver: pid=%u checked via IPC => %s\n", pid, inHook ? L"IN_HOOKLIST" : L"NOT_IN_HOOKLIST");
		std::wstring cmdline;
		Helper::GetProcessCommandLineByPID(pid, cmdline);
		bool is64 = false;
		bool dllLoaded = false;
		if (inHook) {
			Helper::IsProcess64(pid, is64);
			const wchar_t* dllName = is64 ? MASTER_X64_DLL_BASENAME : MASTER_X86_DLL_BASENAME;
			Helper::IsModuleLoaded(pid, dllName, dllLoaded);
		}
		// Update cached module/arch state so UI and sorting can rely on it.
		PM_UpdateEntryModuleState(pid, is64, dllLoaded);
		PM_UpdateEntryFields(pid, ntPath, inHook, cmdline);
		::PostMessage(dlg->GetSafeHwnd(), WM_APP_UPDATE_PROCESS, (WPARAM)pid, (LPARAM)UPDATE_SOURCE_NOTIFY);
	}).detach();
}

void ProcessResolver::StartCreateChecker(HWND hwnd, DWORD pid) {
	std::thread([hwnd, pid]() {
		const int MAX_MS = 10000; // 10s
		const int INTERVAL_MS = 1000;
		int waited = 0;
		bool dllLoaded = false;
		bool is64 = false;
		// Original simpler polling: just watch for master DLL load regardless of hook state.
		while (waited < MAX_MS) {
			Helper::IsProcess64(pid, is64);
			const wchar_t* targetName = is64 ? MASTER_X64_DLL_BASENAME : MASTER_X86_DLL_BASENAME;
			Helper::IsModuleLoaded(pid, targetName, dllLoaded);
			if (dllLoaded) break;
			std::this_thread::sleep_for(std::chrono::milliseconds(INTERVAL_MS));
			waited += INTERVAL_MS;
		}
		// Ensure cached module state updated before posting update so UI gets fresh flags
		PM_UpdateEntryModuleState(pid, is64, dllLoaded);
		::PostMessage(hwnd, WM_APP_UPDATE_PROCESS, (WPARAM)pid, (LPARAM)UPDATE_SOURCE_NOTIFY);
		return;
	}).detach();
}
