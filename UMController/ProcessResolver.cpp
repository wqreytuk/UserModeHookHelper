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
			// Prefer the in-process hook-hash cache if available to avoid
			// expensive per-path IPC. Compute the NT-path hash and consult
			// ProcessManager's cache; otherwise fall back to Filter IPC.
			if (PM_HasHookHashCache()) {
				const UCHAR* bytes = reinterpret_cast<const UCHAR*>(ntPath.c_str());
				size_t bytesLen = ntPath.size() * sizeof(wchar_t);
				unsigned long long h = Helper::GetNtPathHash(bytes, bytesLen);
				inHook = PM_IsHashInHookSet(h);
				// app.GetETW().Log(L"StartLoaderResolver: pid=%u checked via CACHE => %s\n", pid, inHook ? L"IN_HOOKLIST" : L"NOT_IN_HOOKLIST");
			} else {
				inHook = filter->FLTCOMM_CheckHookList(ntPath);
				// app.GetETW().Log(L"StartLoaderResolver: pid=%u checked via IPC => %s\n", pid, inHook ? L"IN_HOOKLIST" : L"NOT_IN_HOOKLIST");
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
	bool inHook = filter->FLTCOMM_CheckHookList(ntPath);
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
		// Original simpler polling: just watch for master DLL load regardless of hook state.
		while (waited < MAX_MS) {
			bool is64 = false;
			Helper::IsProcess64(pid, is64);
			const wchar_t* targetName = is64 ? MASTER_X64_DLL_BASENAME : MASTER_X86_DLL_BASENAME;
			Helper::IsModuleLoaded(pid, targetName, dllLoaded);
			if (dllLoaded) break;
			std::this_thread::sleep_for(std::chrono::milliseconds(INTERVAL_MS));
			waited += INTERVAL_MS;
		}
		::PostMessage(hwnd, WM_APP_UPDATE_PROCESS, (WPARAM)pid, (LPARAM)UPDATE_SOURCE_NOTIFY);
		return;
	}).detach();
}
