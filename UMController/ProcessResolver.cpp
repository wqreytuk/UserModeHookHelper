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
#include "RegistryStore.h"

using namespace ProcessResolver;

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
		}
		else {
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
			}
			else {
				inHook = filter->FLTCOMM_CheckHookList(ntPath);
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

void ProcessResolver::StartMasterDllScanner(CUMControllerDlg* dlg, const std::vector<DWORD>& pids, Filter* filter) {
	// refresh process filter, last 10s
	// std::thread([dlg, filter]() {
	// 	int cnt = 0;
	// 	const std::chrono::milliseconds interval(500);
	// 	while (cnt<10) {
	// 		dlg->FilterProcessList(L"");
	// 		std::this_thread::sleep_for(interval);
	// 		cnt++;
	// 	}
	// }).detach();
	std::thread([dlg, filter]() {
		const std::chrono::milliseconds interval(500);
		// Run as long as the process is alive. Do not exit when the dialog
		// window closes; threads will naturally terminate when the process
		// exits. Use app.GetHwnd() for posting updates when available.
		while (true) {
			// Snapshot current process entries from ProcessManager so we scan only
			// known processes and respect the existing ProcessManager state.
			std::vector<ProcessEntry> all = PM_GetAll();
			for (const auto &e : all) {
				DWORD pid = e.pid;
				// Resolve NT path and command line when available
				std::wstring ntPath = e.path;
				if (ntPath.empty() && filter) {
					std::wstring tmp;
					if (Helper::ResolveProcessNtImagePath(pid, *filter, tmp)) ntPath = tmp;
				}
				
				bool early_break = false;
				std::vector<std::wstring> marks;
				if (RegistryStore::ReadEarlyBreakMarks(marks)) {
					for (auto &m : marks) {
						std::wstring low = m;
						if (!_wcsicmp(m.c_str(), ntPath.c_str()))
							early_break = true;
						else
							early_break = false;
					}
				}

				std::wstring cmdline = e.cmdline;
				if (cmdline.empty()) Helper::GetProcessCommandLineByPID(pid, cmdline);

				bool is64 = false;
				bool dllLoaded = false;
				bool gh = false; RegistryStore::ReadGlobalHookMode(gh);
				// e.bInHookList is not reliable, because PM_GetAll is getting outdated data
				bool inHook = gh ? true : false;
				// If not in global mode, check whether this path is actually in the
				// hook list (via hash cache or filter IPC). If not in hook list,
				// skip the expensive module load check.
				if (!gh) {
					if (!inHook) {
						// determine via cached hook-hash set or filter IPC
						if (PM_HasHookHashCache()) {
							if (!ntPath.empty()) {
								const UCHAR* bytes = reinterpret_cast<const UCHAR*>(ntPath.c_str());
								size_t bytesLen = ntPath.size() * sizeof(wchar_t);
								unsigned long long h = Helper::GetNtPathHash(bytes, bytesLen);
								inHook = PM_IsHashInHookSet(h);
							}
						} else if (filter && !ntPath.empty()) {
							inHook = filter->FLTCOMM_CheckHookList(ntPath);
						}
					}
				}
				if (inHook || gh) {
					Helper::IsProcess64(pid, is64);
					// This scanner uses x64 basename unconditionally for detection
					const wchar_t* dllName = MASTER_X64_DLL_BASENAME;
					Helper::IsModuleLoaded(pid, dllName, dllLoaded);
				}

				// Update cached module/arch state and fields so UI can reflect changes
				// Fetch existing cached entry to detect changes and avoid
				// unnecessary UI updates which can cause flicker.
				ProcessEntry oldEntry; int oldIdx = -1;
				PM_GetEntryCopyByPid(pid, oldEntry, &oldIdx);
				bool old_is64 = oldEntry.is64;
				bool old_dll = oldEntry.masterDllLoaded;
				bool old_inHook = oldEntry.bInHookList;
				std::wstring old_path = oldEntry.path;
				std::wstring old_cmd = oldEntry.cmdline;

				if (is64 != old_is64 || dllLoaded != old_dll || inHook != old_inHook ||
					ntPath != old_path || cmdline != old_cmd ) {
					PM_UpdateEntryModuleState(pid, is64, dllLoaded);
					PM_UpdateEntryFields(pid, ntPath, inHook, cmdline);
					HWND hwnd = app.GetHwnd();
					if (hwnd) ::PostMessage(hwnd, WM_APP_UPDATE_PROCESS, (WPARAM)pid, (LPARAM)UPDATE_SOURCE_LOAD);
				}
			}
			std::this_thread::sleep_for(interval);
		}
	}).detach();
}

