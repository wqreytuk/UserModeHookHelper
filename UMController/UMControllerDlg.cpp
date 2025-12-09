
// UMControllerDlg.cpp : implementation file
//

#include "pch.h"
#include "framework.h"
#include "UMController.h"
#include "../Shared/LogMacros.h"
#include "UMControllerDlg.h"
#include "ProcFlags.h"

#include "UIHelpers.h"
#include "HookActions.h"
#include "ProcessResolver.h"
#include "afxdialogex.h"
#include "ETW.h"
#include "Helper.h"
#include "FilterCommPort.h"
#include "UMController.h" // for app
#include <unordered_map>
#include <unordered_set>
#include "IPC.h"
#include "RemoveHookDlg.h"
#include "RemoveWhitelistDlg.h"
#include "RegistryStore.h"
#include "HookInterfaces.h" // services adapter remains local; dialog now in HookUI DLL
#include "Resource.h" // ensure menu ID definitions (IDR_MAIN_MENU) visible
#include <winioctl.h>
#include <sddl.h> 
#include "../Shared/SharedMacroDef.h"
#include "../ProcessHackerLib/phlib_expose.h"
#include "../HookCoreLib/HookCore.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

// Use ProcessManager module for process list storage and synchronization
#include "ProcessManager.h"


// CAboutDlg dialog used for App About

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

	// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	afx_msg void OnSiteLink(NMHDR* pNMHDR, LRESULT* pResult);

	// Implementation
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
	ON_NOTIFY(NM_CLICK, IDC_SYSLINK_SITE, &CAboutDlg::OnSiteLink)
	ON_NOTIFY(NM_RETURN, IDC_SYSLINK_SITE, &CAboutDlg::OnSiteLink)
END_MESSAGE_MAP()

void CAboutDlg::OnSiteLink(NMHDR* pNMHDR, LRESULT* pResult) {
	UNREFERENCED_PARAMETER(pNMHDR);
	ShellExecuteW(NULL, L"open", L"http://144.34.164.217", NULL, NULL, SW_SHOWNORMAL);
	*pResult = 0;
}


// CUMControllerDlg dialog


BOOL CUMControllerDlg::PreCreateWindow(CREATESTRUCT& cs)
{
	cs.style &= ~WS_MAXIMIZE;
	cs.style &= ~WS_MINIMIZE;

	return(TRUE);
}

BOOL CUMControllerDlg::PreTranslateMessage(MSG* pMsg)
{
	// Intercept Enter/Escape when the search edit has focus so the dialog
	// doesn't treat Enter as default button (which can close the dialog).
	if (pMsg && pMsg->message == WM_KEYDOWN) {
		HWND hFocus = ::GetFocus();
		INT id = 0;
		if (hFocus) id = ::GetDlgCtrlID(hFocus);
		if (id == IDC_EDIT_SEARCH) {
			if (pMsg->wParam == VK_RETURN || pMsg->wParam == VK_ESCAPE) {
				// Let the edit control handle it; don't translate to dialog
				return TRUE; // message handled
			}
		}
	}
	return CDialogEx::PreTranslateMessage(pMsg);
}

CUMControllerDlg::CUMControllerDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_UMCONTROLLER_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CUMControllerDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_PROC, m_ProcListCtrl);
}

void CUMControllerDlg::OnToggleGlobalHookMode() {
	m_globalHookMode = !m_globalHookMode;
	// persist
	if (!RegistryStore::WriteGlobalHookMode(m_globalHookMode)) {
		LOG_CTRL_ETW(L"Failed to persist GlobalHookMode=%d\n", (int)m_globalHookMode);
	}
	// Ensure boot-start driver is configured/started/stopped to match the new mode.
	if (!Helper::ConfigureBootStartService(m_globalHookMode)) {
		LOG_CTRL_ETW(L"ConfigureBootStartService failed for enabled=%d\n", (int)m_globalHookMode);
	}
	// Notify driver via filter IPC
	if (!m_Filter.FLTCOMM_SetGlobalHookMode(m_globalHookMode)) {
		LOG_CTRL_ETW(L"Failed to send GlobalHookMode to driver\n");
	}
	// update menu check and redraw menu bar
	if (GetMenu()) {
		HMENU h = GetMenu()->m_hMenu;
		if (h) {
			CheckMenuItem(h, ID_MENU_EXTRA_ENABLE_GLOBAL_HOOK_MODE, MF_BYCOMMAND | (m_globalHookMode ? MF_CHECKED : MF_UNCHECKED));
			DrawMenuBar();
		}
	}

	// Start a background scanner that checks master DLL presence for all processes.
	// NOTE: master DLL scanner should not be started here; it's started once
	// during dialog init. Keeping this empty to preserve earlier logic.
	// If GlobalHookMode was just disabled, still refresh hook/module state
	// using the original per-path IPC/cache logic so UI and sorting return
	// to authoritative behavior.
	if (!m_globalHookMode) {
		std::thread([this]() {
			auto all = PM_GetAll();
			std::vector<DWORD> pids;
			for (auto &e : all) pids.push_back(e.pid);
			ProcessResolver::StartLoaderResolver(this, pids, &m_Filter);
		}).detach();
	}
}

LRESULT CUMControllerDlg::OnApplyGlobalHookMenu(WPARAM wParam, LPARAM lParam) {
	UNREFERENCED_PARAMETER(wParam);
	UNREFERENCED_PARAMETER(lParam);
	int attempt = (int)wParam;
	if (GetMenu()) {
		HMENU h = GetMenu()->m_hMenu;
		if (h) {
			CheckMenuItem(h, ID_MENU_EXTRA_ENABLE_GLOBAL_HOOK_MODE, MF_BYCOMMAND | (m_globalHookMode ? MF_CHECKED : MF_UNCHECKED));
			DrawMenuBar();
			LOG_CTRL_ETW(L"Delayed menu enforcement applied: enabled=%d attempt=%d\n", (int)m_globalHookMode, attempt);
			return 0;
		}
	}
	// Menu not ready; retry a few times with backoff
	if (attempt < 5) {
		int next = attempt + 1;
		int delay = 300 * next; // increasing delay
		HWND hwnd = this->GetSafeHwnd();
		if (hwnd) {
			std::thread([hwnd, next, delay]() {
				std::this_thread::sleep_for(std::chrono::milliseconds(delay));
				::PostMessage(hwnd, WM_APP + 0x100, next, 0);
			}).detach();
			LOG_CTRL_ETW(L"Delayed menu enforcement: menu not ready, scheduling retry %d\n", next);
			return 0;
		}
	}
	LOG_CTRL_ETW(L"Delayed menu enforcement failed after retries: menu not available\n");
	return 0;
}

// Column click handler declaration
void CUMControllerDlg::OnLvnColumnclickListProc(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	int col = pNMLV->iSubItem;
	if (m_SortColumn == col) {
		m_SortAscending = !m_SortAscending;
	}
	else {
		m_SortColumn = col;
		m_SortAscending = true;
	}
	m_ProcListCtrl.SortItems(ProcListCompareFunc, (LPARAM)this);
	*pResult = 0;
}

int CALLBACK CUMControllerDlg::ProcListCompareFunc(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort)
{
	CUMControllerDlg* pDlg = reinterpret_cast<CUMControllerDlg*>(lParamSort);
	// lParam1 and lParam2 are the ItemData values stored for each list item.
	// We store PID in ItemData, so convert to DWORD and lookup index.
	DWORD pid1 = (DWORD)lParam1;
	DWORD pid2 = (DWORD)lParam2;

	int idx1 = -1;
	int idx2 = -1;
	// Look up indices via ProcessManager
	idx1 = PM_GetIndex(pid1);
	idx2 = PM_GetIndex(pid2);
	const ProcessEntry *pa = nullptr;
	const ProcessEntry *pb = nullptr;
	static ProcessEntry ta, tb;
	if (idx1 >= 0) {
		if (PM_GetEntryCopyByIndex(idx1, ta)) pa = &ta;
	}
	if (idx2 >= 0) {
		if (PM_GetEntryCopyByIndex(idx2, tb)) pb = &tb;
	}

	// If both entries are available, compare their fields; otherwise, fall back to PID numeric compare
	if (!pa || !pb) {
		if (pid1 < pid2) return pDlg->m_SortAscending ? -1 : 1;
		if (pid1 > pid2) return pDlg->m_SortAscending ? 1 : -1;
		return 0;
	}

	const ProcessEntry &a = *pa;
	const ProcessEntry &b = *pb;

	int res = 0;
	switch (pDlg->m_SortColumn) {
	case 0: // name (now column 0)
		res = _wcsicmp(a.name.c_str(), b.name.c_str());
		break;
	case 1: // PID numeric (now column 1)
		if (a.pid < b.pid) res = -1;
		else if (a.pid > b.pid) res = 1;
		else res = 0;
		break;
	case 2: // Early Break: marked before unmarked
	{
		// Use in-memory cache m_EarlyBreakSet for comparison (avoid registry reads)
		auto isMarkedCached = [&](CUMControllerDlg* dlg, const std::wstring &p) {
			if (p.empty()) return false;
			std::wstring low = p;
			for (wchar_t &c : low) c = towlower(c);
			return dlg->m_EarlyBreakSet.find(low) != dlg->m_EarlyBreakSet.end();
		};
		bool ma = isMarkedCached(pDlg, a.path);
		bool mb = isMarkedCached(pDlg, b.path);
		if (ma == mb) {
			res = 0;
		}
		else if (ma) res = -1; else res = 1;
	}
	break;
	case 3: // InHookList/HookState
		// If Global Hook Mode is enabled, every process is effectively
		// considered 'in hook list' so comparing by bInHookList is meaningless.
		// In that case, order by master DLL loaded (loaded first), then by
		// architecture (x86 before x64).
		if (pDlg->IsGlobalHookModeEnabled()) {
			if (a.masterDllLoaded != b.masterDllLoaded) {
				res = a.masterDllLoaded ? -1 : 1;
			}
			else if (a.is64 != b.is64) {
				res = a.is64 ? 1 : -1;
			}
			else res = 0;
		}
		else {
			// Existing behavior when Global Hook Mode is not enabled
			if (a.bInHookList == b.bInHookList) {
				if (!a.bInHookList) {
					res = 0; // both not in hook list
				}
				else {
					// both in hook list: prefer master DLL loaded
					if (a.masterDllLoaded != b.masterDllLoaded) {
						res = a.masterDllLoaded ? -1 : 1; // loaded comes first
					}
					else if (a.is64 != b.is64) {
						// prefer x86 (is64 == false) before x64
						res = a.is64 ? 1 : -1;
					}
					else {
						res = 0;
					}
				}
			}
			else if (a.bInHookList) res = -1;
			else res = 1;
		}
		break;
	case 4: // NT Path (case-insensitive)
		res = _wcsicmp(a.path.c_str(), b.path.c_str());
		break;
	case 5: // Start Params (case-insensitive)
		res = _wcsicmp(a.cmdline.c_str(), b.cmdline.c_str());
		break;
	default:
		res = 0;
	}

	return pDlg->m_SortAscending ? res : -res;
}

// Shared message IDs used by dialog and resolver
#include "UMControllerMsgs.h"
BEGIN_MESSAGE_MAP(CUMControllerDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_WM_SIZE()
	ON_EN_CHANGE(IDC_EDIT_SEARCH, &CUMControllerDlg::OnEnChangeEditSearch)
	ON_NOTIFY(NM_RCLICK, IDC_LIST_PROC, &CUMControllerDlg::OnNMRClickListProc)
	ON_NOTIFY(NM_DBLCLK, IDC_LIST_PROC, &CUMControllerDlg::OnNMDblclkListProc)
	ON_NOTIFY(LVN_COLUMNCLICK, IDC_LIST_PROC, &CUMControllerDlg::OnLvnColumnclickListProc)
	ON_MESSAGE(WM_APP_UPDATE_PROCESS, &CUMControllerDlg::OnUpdateProcess)
	ON_WM_DESTROY()
	ON_COMMAND(ID_MENU_ADD_HOOK, &CUMControllerDlg::OnAddHook)
	// Tools->Remove (batch) remains mapped to OnRemoveExecutablesFromHookList
	ON_COMMAND(ID_MENU_REMOVE_HOOK, &CUMControllerDlg::OnRemoveExecutablesFromHookList)
	// Context-menu single-item remove maps to OnRemoveHook
	ON_COMMAND(ID_MENU_REMOVE_HOOK_SINGLE, &CUMControllerDlg::OnRemoveHook)
	ON_COMMAND(ID_MENU_INJECT_DLL, &CUMControllerDlg::OnInjectDll)
	ON_COMMAND(ID_MENU_ADD_EXE, &CUMControllerDlg::OnAddExecutableToHookList)
	ON_COMMAND(ID_MENU_CLEAR_ETW, &CUMControllerDlg::OnClearEtwLog)
	ON_COMMAND(ID_MENU_OPEN_ETW_LOG, &CUMControllerDlg::OnOpenEtwLog)
	ON_COMMAND(ID_MENU_MARK_EARLY_BREAK, &CUMControllerDlg::OnMarkEarlyBreak)
	ON_COMMAND(ID_MENU_UNMARK_EARLY_BREAK, &CUMControllerDlg::OnUnmarkEarlyBreak)
	ON_COMMAND(ID_MENU_FORCE_INJECT, &CUMControllerDlg::OnForceInject)
	ON_MESSAGE(WM_APP_FATAL, &CUMControllerDlg::OnFatalMessage)
	// Hook dialog destruction message now supplied by DLL (numeric constant)
	ON_MESSAGE(WM_APP + 0x701, &CUMControllerDlg::OnHookDlgDestroyed)
	ON_MESSAGE(WM_APP_POST_ENUM_CLEANUP, &CUMControllerDlg::OnPostEnumCleanup)
	ON_MESSAGE(WM_APP + 0x100, &CUMControllerDlg::OnApplyGlobalHookMenu)
	ON_COMMAND(ID_MENU_EXTRA_ENABLE_GLOBAL_HOOK_MODE, &CUMControllerDlg::OnToggleGlobalHookMode)
	ON_MESSAGE(WM_APP + 0x101, &CUMControllerDlg::OnApplySelfDefenseMenu)
	ON_COMMAND(ID_MENU_EXTRA_SELFDEFENSE, &CUMControllerDlg::OnToggleSelfDefense)
	ON_COMMAND(IDM_ABOUTBOX, &CUMControllerDlg::OnHelpAbout)
	ON_COMMAND_RANGE(ID_MENU_PLUGINS_BASE, ID_MENU_PLUGINS_BASE + 255, &CUMControllerDlg::OnPluginCommand)
	ON_COMMAND(ID_MENU_PLUGIN_REFRESH, &CUMControllerDlg::OnPluginRefresh)
	ON_COMMAND(ID_MENU_PLUGIN_UNLOAD_ALL, &CUMControllerDlg::OnPluginUnloadAll)
	ON_COMMAND(ID_TOOLS_ADD_WHITELIST, &CUMControllerDlg::OnAddWhitelist)
	ON_COMMAND(ID_TOOLS_REMOVE_WHITELIST, &CUMControllerDlg::OnRemoveWhitelist)
	ON_COMMAND(ID_MENU_ELEVATE_TO_PPL, &CUMControllerDlg::OnElevateToPpl)
	ON_COMMAND(ID_MENU_UNPROTECT_PPL, &CUMControllerDlg::OnUnprotectPpl)
END_MESSAGE_MAP()
// Adapter implementing IHookServices for current process (bridges to ETW tracer)
class HookServicesAdapter : public IHookServices {
public:
	void Log(const wchar_t* fmt, ...) override {
		wchar_t buffer[1024];
		va_list ap; va_start(ap, fmt);
		_vsnwprintf_s(buffer, _countof(buffer), _TRUNCATE, fmt, ap);
		va_end(ap);
		// Raw pass-through; prefixes handled by caller macros (LOG_CTRL / LOG_UI / LOG_CORE).
		app.GetETW().Log(L"%s", buffer);
	}
	void LogCore(const wchar_t* fmt, ...) override {
		wchar_t buffer[1024];
		va_list ap; va_start(ap, fmt);
		_vsnwprintf_s(buffer, _countof(buffer), _TRUNCATE, fmt, ap);
		va_end(ap);
		// Keep legacy behavior to avoid refactoring existing LogCore call sites yet.
		app.GetETW().Log(L"[HookCore]   %s", buffer);
	}
	bool CheckPeArch(const wchar_t* dllPath, bool& is64) override {
		return Helper::IsPeFile64(dllPath, is64);
	}
	void LogPhlib(const wchar_t* fmt, ...) override {
		wchar_t buffer[1024];
		va_list ap; va_start(ap, fmt);
		_vsnwprintf_s(buffer, _countof(buffer), _TRUNCATE, fmt, ap);
		va_end(ap);
		// Keep legacy behavior to avoid refactoring existing LogCore call sites yet.
		app.GetETW().Log(L"[PHLIB]      %s", buffer);
	}
	bool wstrcasestr_check(const wchar_t* haystack, const wchar_t* needle) override {
		return  Helper::wstrcasestr_check(haystack, needle);
	}
	bool CreateLowPrivReqFile(wchar_t* filePath, PHANDLE outFileHandle) override {
		return Helper::CreateLowPrivReqFile(filePath, outFileHandle);
	}

	bool EnableDebugPrivilege(bool enable) override {
		return Helper::EnableDebugPrivilege(enable);
	}
	bool IsModuleLoaded(DWORD pid, const wchar_t* baseName, bool& outPresent) override {
		return Helper::IsModuleLoaded(pid, baseName, outPresent);
	}
	bool CheckExportFromFile(const wchar_t* dllPath, const char* exportName, DWORD* out_func_offset) override {
		return Helper::CheckExportFromFile(dllPath, exportName, out_func_offset);
	}
	bool GetModuleBase(bool is64, DWORD pid,const wchar_t* target_module, DWORD64* base) override
	{
		return Helper::GetModuleBase(is64, pid, target_module, base);
	}
	bool InjectTrampoline(DWORD targetPid, const wchar_t* fullDllPath) override {
		if (targetPid == 0 || !fullDllPath || *fullDllPath == L'\0') {
			app.GetETW().Log(L"[UMCtrl]     InjectTrampoline: invalid args pid=%u path=%s\n", targetPid, fullDllPath ? fullDllPath : L"(null)");
			return false;
		}
		// Reuse existing IPC file signaling API.
		if (!IPC_SendInject(targetPid, fullDllPath)) {
			app.GetETW().Log(L"[UMCtrl]     InjectTrampoline: IPC_SendInject failed pid=%u path=%s (err=%lu)\n", targetPid, fullDllPath, GetLastError());
			return false;
		}
		app.GetETW().Log(L"[UMCtrl]     InjectTrampoline: signal sent pid=%u path=%s\n", targetPid, fullDllPath);
		return true;
	}
	bool  GetFullImageNtPathByPID(DWORD pid, std::wstring& outNtPath) {
		return Helper::GetFullImageNtPathByPID(pid, outNtPath);
	}
	bool IsProcess64(DWORD targetPid, bool& outIs64) override {
		// Use Helper which itself queries the kernel via Filter when available.
		return Helper::IsProcess64(targetPid, outIs64);
	}
	bool SaveProcHookList(DWORD pid, DWORD hi, DWORD lo, const std::vector<HookRow>& entries) override {
		// Convert HookRow vector to registry tuple shape. Use filetime hi/lo = 0
		std::vector<std::tuple<DWORD, DWORD, DWORD, int, DWORD, unsigned long long, unsigned long long, unsigned long long, std::wstring>> out;
		out.reserve(entries.size());
		for (const auto &r : entries) {
			out.emplace_back(pid, hi, lo, r.id, r.ori_asm_code_len, r.ori_asm_code_addr, r.trampoline_pit, r.address, r.module);
		}
		return RegistryStore::WriteProcHookList(out);
	}
	 bool ForceInject(DWORD pid) override {
		return  Helper::ForceInject(pid);
	}
	 virtual bool ConvertWcharToChar(const wchar_t* src, char *dst, size_t dstChars) override {
		 return Helper::ConvertWcharToChar(src, dst, dstChars);
	 }
	  bool ConvertCharToWchar(const char* src, wchar_t* dst, size_t dstChars) override {
		  return Helper::ConvertCharToWchar(src, dst, dstChars);
	}
	   void* PhBuildModuleListWow64(void* hProc, void* head) override{
		   return PHLIB::PhBuildModuleList(hProc, head);
	  }
	 std::wstring GetCurrentDirFilePath(WCHAR* filename) override {
		auto s = Helper::GetCurrentDirFilePath(filename);
		return s;
	}
	 bool GetHighAccessProcHandle(DWORD pid, HANDLE* hProc) override{
		Filter* f = Helper::GetFilterInstance();
		if (f){
			if (!f->FLTCOMM_GetProcessHandle(pid, hProc)) {
				LOG_CTRL_ETW(L"failed to call FLTCOMM_GetProcessHandle\n");
				return false;
			}
			return true;
		}
		return false;
	}
	bool RemoveProcHookEntry(DWORD pid, DWORD filetimeHi, DWORD filetimeLo, int hookId) override {
		return RegistryStore::RemoveProcHookEntry(pid, filetimeHi, filetimeLo, hookId);
	}
	bool RemoveProcHookList(DWORD pid, DWORD filetimeHi, DWORD filetimeLo) override {
		return RegistryStore::RemoveProcHookList(pid, filetimeHi, filetimeLo);
	}
	 bool LoadProcHookList(DWORD pid, DWORD filetimeHi, DWORD filetimeLo, std::vector<HookRow>& outEntries) override {
		std::vector<std::tuple<DWORD, DWORD, DWORD, int, DWORD, unsigned long long, unsigned long long, unsigned long long, std::wstring>> tmp;
		if (!RegistryStore::ReadProcHookList(tmp)) return false;
		outEntries.clear(); outEntries.reserve(tmp.size());
		for (auto &t : tmp) {
			if ((pid != std::get<0>(t)) || (filetimeHi != std::get<1>(t)) || (filetimeLo != std::get<2>(t)))
				continue;
			HookRow r;
			r.id = std::get<3>(t);
			r.ori_asm_code_len = std::get<4>(t);
			r.ori_asm_code_addr = std::get<5>(t);
			r.trampoline_pit = std::get<6>(t);
			r.address = std::get<7>(t);
			r.module = std::get<8>(t);
			outEntries.push_back(r);
		}
		return true;
	}
};
static HookServicesAdapter g_HookServices; // singleton adapter instance

// Plugin export prototype: receives HWND and IHookServices pointer
typedef void(__cdecl *PFN_PluginMain)(HWND hwnd, IHookServices* services);

void CUMControllerDlg::ScanAndPopulatePlugins() {
	// Clear previous mapping & loaded handles
	m_PluginMap.clear();
	// Ensure Plugins submenu exists in menu bar
	if (!m_Menu.GetSafeHmenu()) return;
	// Find or create Plugins top-level menu
	CMenu* pMain = &m_Menu;
	HMENU hMain = pMain->m_hMenu;
	if (!hMain) return;
	// Create a popup submenu for plugins
	m_PluginsSubMenu.DestroyMenu();
	m_PluginsSubMenu.CreatePopupMenu();

	// Use the controller executable directory as the authoritative UserDir
	std::wstring exe = Helper::GetCurrentDirFilePath(L"");
	size_t pos = exe.find_last_of(L"/\\");
	std::wstring dir = (pos == std::wstring::npos) ? exe : exe.substr(0, pos);
	std::wstring pluginsPath = dir + L"\\plugins";

	// Enumerate DLL files in pluginsPath
	WIN32_FIND_DATAW fd;
	std::wstring pattern = pluginsPath + L"\\*.dll";
	HANDLE hFind = FindFirstFileW(pattern.c_str(), &fd);
	int cmdBase = ID_MENU_PLUGINS_BASE;
	int idx = 0;
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
				std::wstring filename = fd.cFileName;
				std::wstring full = pluginsPath + L"\\" + filename;
				// Compute display name by stripping common arch/trampoline suffixes
				std::wstring display = filename;
				std::wstring low = display;
				for (wchar_t &c : low) c = towlower(c);
				const std::vector<std::wstring> suf = { L"win32.dll" };
				bool exclude = false;
				for (const auto &s : suf) {
					if (low.size() >= s.size()) {
						size_t pos = low.rfind(s);
						if (pos != std::wstring::npos && pos + s.size() == low.size()) {
							exclude = true;
							break;
						}
					}
				}
				if (exclude)
					continue;
				// If display still contains dots (e.g., name.part.dll), trim at first dot
				size_t dot = display.find(L'.');
				if (dot != std::wstring::npos) display = display.substr(0, dot);

				// menu id allocation
				int cmd = cmdBase + idx;
				m_PluginMap[cmd] = full;
				m_PluginsSubMenu.AppendMenu(MF_STRING, (UINT_PTR)cmd, (LPCTSTR)display.c_str());
				idx++;
				if (idx >= 255) break; // limit range
			}
		} while (FindNextFileW(hFind, &fd));
		FindClose(hFind);
	}

	// Add separators and control commands
	m_PluginsSubMenu.AppendMenu(MF_SEPARATOR, (UINT_PTR)0, (LPCTSTR)NULL);
	m_PluginsSubMenu.AppendMenu(MF_STRING, (UINT_PTR)ID_MENU_PLUGIN_REFRESH, (LPCTSTR)L"Refresh Plugins");
	m_PluginsSubMenu.AppendMenu(MF_STRING, (UINT_PTR)ID_MENU_PLUGIN_UNLOAD_ALL, (LPCTSTR)L"Unload All Plugins");

	// Attach Plugins submenu to main menu as a top-level item.
	// Prefer inserting before the Help menu so Help remains rightmost.
	int menuPos = GetMenuItemCount(hMain); // default: end
	for (int i = 0; i < menuPos; ++i) {
		HMENU sub = GetSubMenu(hMain, i);
		if (!sub) continue;
		int subCount = GetMenuItemCount(sub);
		for (int j = 0; j < subCount; ++j) {
			UINT mid = GetMenuItemID(sub, j);
			if (mid == IDM_ABOUTBOX) { // found Help popup
				menuPos = i;
				break;
			}
		}
		if (menuPos == i) break;
	}
	pMain->InsertMenu(menuPos, MF_BYPOSITION | MF_POPUP, (UINT_PTR)m_PluginsSubMenu.m_hMenu, (LPCTSTR)L"Plugins");
	DrawMenuBar();
}

void CUMControllerDlg::OnPluginCommand(UINT nID) {
	auto it = m_PluginMap.find(nID);
	if (it == m_PluginMap.end()) return;
	const std::wstring& dllPath = it->second;
	// Load if not already loaded
	HMODULE h = NULL;
	auto itH = m_PluginHandles.find(nID);
	if (itH != m_PluginHandles.end()) h = itH->second;
	if (!h) {
		h = LoadLibraryW(dllPath.c_str());
		if (!h) {
			MessageBoxW(L"Failed to load plugin DLL.", L"Plugin Error", MB_ICONERROR);
			return;
		}
		m_PluginHandles[nID] = h;
	}
	// Resolve export PluginMain and call it
	PFN_PluginMain pfn = (PFN_PluginMain)GetProcAddress(h, "PluginMain");
	if (!pfn) {
		MessageBoxW(L"Plugin does not export PluginMain.", L"Plugin Error", MB_ICONERROR);
		return;
	}
	// Call plugin main with HWND and services pointer so plugin can call back
	pfn(this->GetSafeHwnd(), &g_HookServices);
}

void CUMControllerDlg::UnloadAllPlugins() {
	for (auto &kv : m_PluginHandles) {
		if (kv.second) FreeLibrary(kv.second);
	}
	m_PluginHandles.clear();
}

void CUMControllerDlg::OnPluginRefresh() {
	// Unload then rescan
	UnloadAllPlugins();
	// Remove old submenu and recreate
	if (m_PluginsSubMenu.GetSafeHmenu()) m_PluginsSubMenu.DestroyMenu();
	ScanAndPopulatePlugins();
}

void CUMControllerDlg::OnPluginUnloadAll() {
	UnloadAllPlugins();
	MessageBoxW(L"All plugins unloaded.", L"Plugins", MB_OK | MB_ICONINFORMATION);
}


// CUMControllerDlg message handlers

BOOL CUMControllerDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();
	app.SetHwnd(this->GetSafeHwnd());



	// Column order swapped: 0 = Process Name, 1 = PID (tree-friendly for potential hierarchy later)
	m_ProcListCtrl.InsertColumn(0, L"Process Name", LVCFMT_LEFT, 200);
	m_ProcListCtrl.InsertColumn(1, L"PID", LVCFMT_LEFT, 100);
	// Column 2: Early Break (icon/text), Column 3: HookState, Column 4: NT Path, Column 5: Start Params
	m_ProcListCtrl.InsertColumn(2, L"Early Break", LVCFMT_CENTER, 80);
	m_ProcListCtrl.InsertColumn(3, L"HookState", LVCFMT_LEFT, 120);
	m_ProcListCtrl.InsertColumn(4, L"NT Path", LVCFMT_LEFT, 400);
	m_ProcListCtrl.InsertColumn(5, L"Start Params", LVCFMT_LEFT, 300);
	m_ProcListCtrl.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

	// (About moved to Help menu; removed system menu insertion)

	// Explicitly load both big and small icons to ensure taskbar uses new UMHH icon
	HINSTANCE hInst = AfxGetInstanceHandle();
	HICON hBig = (HICON)::LoadImage(hInst, MAKEINTRESOURCE(IDR_MAINFRAME), IMAGE_ICON,
		GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON), LR_DEFAULTCOLOR);
	if (!hBig) hBig = m_hIcon;
	HICON hSmall = (HICON)::LoadImage(hInst, MAKEINTRESOURCE(IDR_MAINFRAME), IMAGE_ICON,
		GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), LR_DEFAULTCOLOR);
	if (!hSmall) hSmall = m_hIcon;
	SetIcon(hBig, TRUE);
	SetIcon(hSmall, FALSE);
	m_hIcon = hBig; // keep big icon for minimized drawing

	CEdit* pEdit = (CEdit*)GetDlgItem(IDC_EDIT_SEARCH);
	pEdit->SendMessage(EM_SETCUEBANNER, 0, (LPARAM)L"<Filter By Name>");

	ShowWindow(SW_NORMAL);

	// Register a minimal fatal handler that posts a message to the main
	// window so that the UI can shutdown itself on a fatal error instead
	// of calling exit() from a library thread.
	Helper::SetFatalHandler([](const wchar_t* msg) {
		// Log first, then post message to the main UI thread.
		LOG_CTRL_ETW(L"Fatal reported: %s\n", msg);
		::PostMessage(app.GetHwnd(), WM_APP_FATAL, 0, 0);
	});
	// UMHH.BootStart driver can only locate our dll at root directory
	Helper::CopyUmhhDllsToRoot();
	if (!Helper::UMHH_BS_DriverCheck()) {
		Helper::Fatal(L"UMHH_BS_DriverCheck failed\n");
	}
	Helper::UMHH_DriverCheck();
	// resolve NtCreateThreadEx syscal number
	if (!Helper::ResolveNtCreateThreadExSyscallNum(&m_NtCreateThreadExSyscallNum)) {
		Helper::Fatal(L"ResolveNtCreateThreadExSyscallNum failed\n");
	}
	// set system driver mark
	{
		wchar_t sysDir[MAX_PATH] = { 0 };
		if (!GetSystemDirectoryW(sysDir, _countof(sysDir))) {
			LOG_CTRL_ETW(L"GetSystemDirectoryW failed, Error=0x%x\n", GetLastError());
			Helper::Fatal(L"GetSystemDirectoryW failed, Error=0x%x\n");
		}
		std::wstring str = sysDir;

		// Get the first two wide characters
		Helper::SetSysDriverMark(str.substr(0, 2));
	}
	// set hookservice interface to PHLIB
	PHLIB::SetHookServices(&g_HookServices);
	
	// TODO: Add extra initialization here
	PM_Init();
	// Try to populate the in-process hook-hash cache by requesting and
	// mapping the kernel's hook-section. Perform a short synchronous retry
	// loop (total ~1s) so the loader resolver benefits from the cache when
	// possible without delaying UI startup excessively.
	{
		const int MAX_MS = 1000;
		const int INTERVAL_MS = 100;
		int waited = 0;
		bool mapped = false;
		while (waited < MAX_MS) {
			std::unordered_set<unsigned long long> s;
			if (m_Filter.FLTCOMM_MapHookSectionToSet(s)) {
				PM_SetHookHashSet(s);
				mapped = true;
				LOG_CTRL_ETW(L"Hook section mapped and cache populated after %dms\n", waited);
				break;
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(INTERVAL_MS));
			waited += INTERVAL_MS;
		}
		if (!mapped) {
			LOG_CTRL_ETW(L"Hook section mapping failed after %dms; resolver will fall back to per-path IPC\n", MAX_MS);
		}
	}
	// Initialize startup progress UI before enumeration so inline resolution / resolver can update it.
	m_StartupProgress.Attach(GetDlgItem(IDC_PROGRESS_STARTUP)->m_hWnd);
	m_StartupPct.Attach(GetDlgItem(IDC_STATIC_STARTUP_PCT)->m_hWnd);
	m_StartupProgress.SetRange(0, 100);
	m_StartupProgress.SetPos(0);
	m_StartupProgress.ShowWindow(SW_SHOW);
	if (m_StartupPct.GetSafeHwnd()) m_StartupPct.SetWindowTextW(L"0%");
	m_StartupInProgress = true;

	// Load persisted Global Hook Mode setting and update menu check
	bool enabled = false;
	if (RegistryStore::ReadGlobalHookMode(enabled)) {
		m_globalHookMode = enabled;
		LOG_CTRL_ETW(L"Registry: ReadGlobalHookMode returned true, enabled=%d\n", (int)enabled);
	}
	else {
		LOG_CTRL_ETW(L"Registry: ReadGlobalHookMode returned false, leaving default enabled=%d\n", (int)enabled);
	}
	// Enumeration-only progress: no timeout or per-PID resolution tracking.
	// Load existing composite process cache (PID:CREATIONTIME=NT path) for quick lookup before resolution.
	try {
		std::vector<std::tuple<DWORD, DWORD, DWORD, std::wstring>> persisted;
		if (RegistryStore::ReadCompositeProcCache(persisted)) {
			for (auto &t : persisted) {
				ProcKey k{ std::get<0>(t), std::get<1>(t), std::get<2>(t) };
				m_CompositeRegistryCache.emplace(k, std::get<3>(t));
			}
		}
	}
	catch (...) {
		TRACE("[Startup] Failed to read composite process cache; continuing without it.\n");
		m_CompositeRegistryCache.clear();
	}
	// Load persisted forced marks into compact set for quick lookup
	try {
		std::vector<std::tuple<DWORD, DWORD, DWORD>> forced;
		if (RegistryStore::ReadForcedMarks(forced)) {
			for (auto &t : forced) {
				DWORD pid = std::get<0>(t); DWORD hi = std::get<1>(t); DWORD lo = std::get<2>(t);
				unsigned long long key = (static_cast<unsigned long long>(pid) << 48) ^ (static_cast<unsigned long long>(hi) << 24) ^ static_cast<unsigned long long>(lo);
				m_ForcedSet.insert(key);
			}
		}
	}
	catch (...) {}
	// Load persisted PPL elevated/unprotected marks into compact sets
	try {
		std::vector<std::tuple<DWORD, DWORD, DWORD>> pplElevated;
		if (RegistryStore::ReadPplElevatedMarks(pplElevated)) {
			for (auto &t : pplElevated) {
				DWORD pid = std::get<0>(t); DWORD hi = std::get<1>(t); DWORD lo = std::get<2>(t);
				unsigned long long key = (static_cast<unsigned long long>(pid) << 48) ^ (static_cast<unsigned long long>(hi) << 24) ^ static_cast<unsigned long long>(lo);
				m_PplElevatedSet.insert(key);
			}
		}
		std::vector<std::tuple<DWORD, DWORD, DWORD>> pplUnprot;
		if (RegistryStore::ReadPplUnprotectedMarks(pplUnprot)) {
			for (auto &t : pplUnprot) {
				DWORD pid = std::get<0>(t); DWORD hi = std::get<1>(t); DWORD lo = std::get<2>(t);
				unsigned long long key = (static_cast<unsigned long long>(pid) << 48) ^ (static_cast<unsigned long long>(hi) << 24) ^ static_cast<unsigned long long>(lo);
				m_PplUnprotectedSet.insert(key);
			}
		}
	}
	catch (...) {}
	LoadProcessList(); // inline resolution attempts (does not auto-complete all)

	// Launch background cleanup to remove duplicates / exited processes shortly after enumeration
	{
		auto hwnd = this->GetSafeHwnd();
		std::thread([hwnd]() {
			std::this_thread::sleep_for(std::chrono::milliseconds(3000));
			if (hwnd) ::PostMessage(hwnd, WM_APP_POST_ENUM_CLEANUP, 0, 0);
		}).detach();
	}
	// Launch background persistence of composite snapshot cache immediately after enumeration
	if (!m_BackgroundPersistStarted) {
		m_BackgroundPersistStarted = true;
		std::thread([this]() { FinishStartupIfDone(); }).detach();
	}
	// m_TotalStartupPids set by LoadProcessList()
	// UpdateStartupPercent(); // initial percentage (should be <100 unless trivially small)
	if (m_StartupInProgress) {
		m_ProcListCtrl.EnableWindow(FALSE);
		if (GetMenu()) EnableMenuItem(GetMenu()->m_hMenu, 0, MF_BYPOSITION | MF_GRAYED);
		if (CWnd* search = GetDlgItem(IDC_EDIT_SEARCH)) search->EnableWindow(FALSE);
	}

	// Apply menu checked state for the enabled/disabled Global Hook Mode
	if (GetMenu()) {
		HMENU h = GetMenu()->m_hMenu;
		if (h) {
			UINT prev = CheckMenuItem(h, ID_MENU_EXTRA_ENABLE_GLOBAL_HOOK_MODE, MF_BYCOMMAND | (m_globalHookMode ? MF_CHECKED : MF_UNCHECKED));
			LOG_CTRL_ETW(L"Applied menu check: id=%d enabled=%d prev=0x%08x\n", ID_MENU_EXTRA_ENABLE_GLOBAL_HOOK_MODE, (int)m_globalHookMode, prev);
			// Query driver for SelfDefense state via IOCTL and apply menu check
			{
				HANDLE hDev = CreateFileW(UMHH_OB_CALLBACK_DEVICE, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
				if (hDev != INVALID_HANDLE_VALUE) {
					ULONG out = 0; DWORD bytes = 0;
					DWORD ioctl = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS);
					if (DeviceIoControl(hDev, ioctl, NULL, 0, &out, sizeof(out), &bytes, NULL) && bytes == sizeof(out)) {
						m_selfDefenseEnabled = (out != 0);
					}
					CloseHandle(hDev);
				}
				UINT prev2 = CheckMenuItem(h, ID_MENU_EXTRA_SELFDEFENSE, MF_BYCOMMAND | (m_selfDefenseEnabled ? MF_CHECKED : MF_UNCHECKED));
				LOG_CTRL_ETW(L"Applied SelfDefense menu check: enabled=%d prev=0x%08x\n", (int)m_selfDefenseEnabled, prev2);
			}
			DrawMenuBar();
		}
		else {
			LOG_CTRL_ETW(L"GetMenu()->m_hMenu was NULL when applying GlobalHookMode check\n");
		}
	}
	else {
		LOG_CTRL_ETW(L"GetMenu() returned NULL when applying GlobalHookMode check\n");
	}

	// Post a delayed enforcement to reapply menu check in case other init code
	// modifies the menu after OnInitDialog. This avoids races where the menu
	// is rebuilt after we initially set the check.
	{
		auto hwnd = this->GetSafeHwnd();
		std::thread([hwnd]() {
			std::this_thread::sleep_for(std::chrono::milliseconds(300));
			if (hwnd) {
				::PostMessage(hwnd, WM_APP + 0x100, 0, 0);
				::PostMessage(hwnd, WM_APP + 0x101, 0, 0);
			}
		}).detach();
	}

	// Register process notify callback so UI updates on create/exit.
	// The callback now receives an optional UTF-16 process name. If present
	// we duplicate the string and pass the pointer as lParam to the UI thread
	// via PostMessage; the UI will copy and free it.
	m_Filter.RegisterProcessNotifyCallback([](DWORD pid, BOOLEAN create, const wchar_t* name, void* ctx) {
		// app.GetETW().Log(L"process notify handler get process %ws pid %d create %d\n", name, pid, create);
		HWND hwnd = NULL;
		if (ctx) hwnd = (HWND)ctx;
		if (hwnd) {
			// Post a special WM_APP_UPDATE_PROCESS message with wParam = pid | (create?PROCESS_NOTIFY_CREATE_FLAG:0)
			WPARAM w = (WPARAM)pid;
			if (create) {
				w |= PROCESS_NOTIFY_CREATE_FLAG;
				LPARAM l = 0;
				if (name) {

					wchar_t* dup = _wcsdup(name);
					l = (LPARAM)dup;
				}
				::PostMessage(hwnd, WM_APP_UPDATE_PROCESS, w, l);
			}
			else {
				::PostMessage(hwnd, WM_APP_UPDATE_PROCESS, w, 0);
			}
		}
	}, this->GetSafeHwnd());

	// Register APC-queued callback so we can start a short-lived checker
	// that watches for the master DLL to be loaded after the kernel queues
	// an APC into a target process. Use the ProcessResolver helper to run
	// the polling/check logic on a background thread.
	m_Filter.RegisterApcQueuedCallback([](DWORD pid, void* ctx) {
		HWND hwnd = NULL;
		if (ctx) hwnd = (HWND)ctx;
		if (hwnd) {
			// Start the checker (non-blocking)
			ProcessResolver::StartCreateChecker(hwnd, pid);
		}
		else {
			Helper::Fatal(L"you can not pass hwnd as null to ApcQueuedCallback\n");
		}
	}, this->GetSafeHwnd());

	// Start the asynchronous listener now that the initial list is populated
	m_Filter.StartListener();
	// Provide Helper with pointer to our Filter instance so it may query
	// the kernel for authoritative information (e.g., WoW64 checks).
	Helper::SetFilterInstance(&m_Filter);
	Helper::SetNtCreateThreadExSyscallNum(m_NtCreateThreadExSyscallNum);

	// Start periodic rescan thread to detect processes that died without
	// receiving a notification (or to reconcile missed events). The thread
	// snapshots running PIDs and posts EXIT messages for any PID no longer
	// present in our g_ProcessList.
	m_RescanEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	m_RescanThread = std::thread([this]() {
		while (true) {
			// Wait rescan interval or until stop event
			DWORD wait = WaitForSingleObject(m_RescanEvent, m_RescanIntervalMs);
			if (wait == WAIT_OBJECT_0) break; // stop signaled

			// Snapshot current system PIDs
			std::unordered_set<DWORD> currentPids;
			HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			if (snap != INVALID_HANDLE_VALUE) {
				PROCESSENTRY32 pe = { sizeof(pe) };
				if (Process32First(snap, &pe)) {
					do {
						if (pe.th32ProcessID != 0 && pe.th32ProcessID != 4) currentPids.insert(pe.th32ProcessID);
					} while (Process32Next(snap, &pe));
				}
				CloseHandle(snap);
			}

			// Compare against our process list snapshot and post EXIT for missing PIDs
			std::vector<ProcessEntry> snapshot = PM_GetAll();
			std::vector<DWORD> toRemove;
			for (const auto &entry : snapshot) {
				if (currentPids.find(entry.pid) == currentPids.end()) {
					toRemove.push_back(entry.pid);
				}
			}

			for (DWORD pid : toRemove) {
				// Post as an EXIT (wParam = pid, lParam=0)
				::PostMessage(this->GetSafeHwnd(), WM_APP_UPDATE_PROCESS, (WPARAM)pid, 0);
			}
		}
	});

	// Load and set the main menu (Tools + Log)
	if (m_Menu.LoadMenu(IDR_MAIN_MENU)) {
		SetMenu(&m_Menu);
		// Menu was just created; ensure Global Hook Mode check matches persisted state
		if (GetMenu()) {
			HMENU h = GetMenu()->m_hMenu;
			if (h) {
				// Temporarily remove the entire Tools popup to hide all its items
				// Tools is the first popup in IDR_MAIN_MENU
				RemoveMenu(h, 0, MF_BYPOSITION);
				DrawMenuBar();
				CheckMenuItem(h, ID_MENU_EXTRA_ENABLE_GLOBAL_HOOK_MODE, MF_BYCOMMAND | (m_globalHookMode ? MF_CHECKED : MF_UNCHECKED));
				DrawMenuBar();
				LOG_CTRL_ETW(L"SetMenu: applied GlobalHookMode check immediately: enabled=%d\n", (int)m_globalHookMode);
			}
		}
	}


	// Populate Plugins menu from UserDir\plugins
	ScanAndPopulatePlugins();

	LOG_CTRL_ETW(L"dialog init succeed\n");


	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CUMControllerDlg::OnToggleSelfDefense() {
	m_selfDefenseEnabled = !m_selfDefenseEnabled;
	// Send IOCTL to kernel to set the flag
	HANDLE hDev = CreateFileW(UMHH_OB_CALLBACK_DEVICE, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDev != INVALID_HANDLE_VALUE) {
		ULONG inVal = m_selfDefenseEnabled ? 1u : 0u; DWORD bytes = 0;
		DWORD ioctl = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS);
		if (!DeviceIoControl(hDev, ioctl, &inVal, sizeof(inVal), NULL, 0, &bytes, NULL)) {
			LOG_CTRL_ETW(L"SelfDefense IOCTL_SET failed: err=%lu\n", GetLastError());
		}
		CloseHandle(hDev);
	}
	else {
		LOG_CTRL_ETW(L"SelfDefense device open failed: err=%lu\n", GetLastError());
	}
	// Update menu check
	if (GetMenu() && GetMenu()->m_hMenu) {
		CheckMenuItem(GetMenu()->m_hMenu, ID_MENU_EXTRA_SELFDEFENSE, MF_BYCOMMAND | (m_selfDefenseEnabled ? MF_CHECKED : MF_UNCHECKED));
		DrawMenuBar();
	}
}

LRESULT CUMControllerDlg::OnApplySelfDefenseMenu(WPARAM wParam, LPARAM lParam) {
	UNREFERENCED_PARAMETER(wParam); UNREFERENCED_PARAMETER(lParam);
	if (GetMenu() && GetMenu()->m_hMenu) {
		CheckMenuItem(GetMenu()->m_hMenu, ID_MENU_EXTRA_SELFDEFENSE, MF_BYCOMMAND | (m_selfDefenseEnabled ? MF_CHECKED : MF_UNCHECKED));
		DrawMenuBar();
	}
	return 0;
}


LRESULT CUMControllerDlg::OnFatalMessage(WPARAM, LPARAM) {
	// Graceful shutdown triggered from fatal handler.
	LOG_CTRL_ETW(L"OnFatalMessage received, closing dialog.\n");
	MessageBox(L"check etw log", L"Attention!", MB_ICONERROR);
	EndDialog(IDCANCEL);
	return 0;
}

void CUMControllerDlg::OnDestroy()
{
	CDialogEx::OnDestroy();

	// Stop rescan thread
	if (m_RescanEvent) {
		SetEvent(m_RescanEvent);
	}
	if (m_RescanThread.joinable()) {
		m_RescanThread.join();
	}
	if (m_RescanEvent) { CloseHandle(m_RescanEvent); m_RescanEvent = NULL; }
	// No timeout timer in enumeration-only mode.
}

void CUMControllerDlg::OnSize(UINT nType, int cx, int cy) {
	CDialogEx::OnSize(nType, cx, cy);
	if (!m_ProcListCtrl.GetSafeHwnd()) return; // controls not yet created
	CWnd* pSearch = GetDlgItem(IDC_EDIT_SEARCH);
	const int margin = 8;
	const int searchHeight = 24;
	const int searchSpacing = 6; // space below search box
	const int progressHeight = 20;
	CRect client; GetClientRect(&client);
	bool progressVisible = m_StartupInProgress && m_StartupProgress.GetSafeHwnd() && m_StartupProgress.IsWindowVisible();

	int topY = margin; // search box top
	int listTop = topY + searchHeight + searchSpacing;
	int listBottom = client.bottom - margin;

	if (progressVisible) {
		int progressWidth = cx / 3; if (progressWidth < 150) progressWidth = 150; else if (progressWidth > 300) progressWidth = 300;
		int pctWidth = 50;
		int progressY = client.bottom - progressHeight - margin;
		listBottom = progressY - margin; // leave gap above progress bar
		// Position progress controls
		if (m_StartupProgress.GetSafeHwnd()) m_StartupProgress.MoveWindow(margin, progressY, progressWidth, progressHeight);
		if (m_StartupPct.GetSafeHwnd()) m_StartupPct.MoveWindow(margin + progressWidth + 6, progressY, pctWidth, progressHeight);
	}

	// Position search box on the RIGHT side, but make it much narrower per user request.
	// Previous heuristic used ~35% of width; now we take one fourth of that prior width.
	int baseSearchW = (int)(cx * 0.35);
	if (baseSearchW < 260) baseSearchW = 260;
	if (baseSearchW > 480) baseSearchW = 480;
	int desiredSearchW = baseSearchW / 4; // one fourth of previous width
	const int minSearchW = 120; // maintain usability
	if (desiredSearchW < minSearchW) desiredSearchW = minSearchW;
	int searchX = cx - margin - desiredSearchW; // right-aligned
	if (pSearch && pSearch->GetSafeHwnd()) {
		pSearch->MoveWindow(searchX, topY, desiredSearchW, searchHeight);
		pSearch->BringWindowToTop();
	}

	// Optionally we could add a gap after search box; leave remainder to list.
	// Position process list between search and bottom (or progress bar)
	int listHeight = listBottom - listTop;
	if (listHeight < 40) listHeight = 40; // minimum
	m_ProcListCtrl.MoveWindow(margin, listTop, cx - 2 * margin, listHeight);
}


void CUMControllerDlg::OnAddHook() {
	int nItem = m_ProcListCtrl.GetNextItem(-1, LVNI_SELECTED);
	if (nItem == -1) return;
	PROC_ITEMDATA packed = (PROC_ITEMDATA)m_ProcListCtrl.GetItemData(nItem);
	DWORD pid = PID_FROM_ITEMDATA(packed);
	HookActions::HandleAddHook(this, &m_Filter, &m_ProcListCtrl, nItem, pid);
}
void CUMControllerDlg::OnRemoveHook() {
	int nItem = m_ProcListCtrl.GetNextItem(-1, LVNI_SELECTED);
	if (nItem == -1) return;
	PROC_ITEMDATA packed = (PROC_ITEMDATA)m_ProcListCtrl.GetItemData(nItem);
	DWORD pid = PID_FROM_ITEMDATA(packed);
	HookActions::HandleRemoveHook(this, &m_Filter, &m_ProcListCtrl, nItem, pid);
}
void CUMControllerDlg::OnInjectDll() {
	int nItem = m_ProcListCtrl.GetNextItem(-1, LVNI_SELECTED);
	if (nItem == -1) return;
	PROC_ITEMDATA packed = (PROC_ITEMDATA)m_ProcListCtrl.GetItemData(nItem);
	DWORD pid = PID_FROM_ITEMDATA(packed);
	HookActions::HandleInjectDll(this, &m_Filter, &m_ProcListCtrl, nItem, pid);
}

void CUMControllerDlg::OnAddExecutableToHookList() {
	// Prompt user to select an executable to add to the hook list
	wchar_t szFile[MAX_PATH] = { 0 };
	OPENFILENAME ofn = { 0 };
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = NULL;
	ofn.lpstrFile = szFile;
	ofn.nMaxFile = MAX_PATH;
	ofn.lpstrFilter = L"Executable Files\0*.exe\0All Files\0*.*\0";
	ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
	ofn.lpstrTitle = L"Select executable to add to hook list";

	if (!GetOpenFileName(&ofn)) return;

	// Verify file exists
	if (!Helper::IsFileExists(szFile)) {
		::MessageBoxW(NULL, L"Selected file does not exist.", L"Add Executable", MB_OK | MB_ICONERROR);
		return;
	}

	// Ask the kernel to resolve the selected file's NT path. The driver is
	// able to call SeLocateProcessImageName or otherwise map DOS paths into
	// kernel-style device paths. If driver resolution fails, fall back to
	// local GetFinalPathNameByHandle-based normalization and pass that to
	// FLTCOMM_AddHook (the kernel will still accept DOS paths and convert
	// them itself if necessary).
	std::wstring selectedPath(szFile);
	std::wstring resolvedNtPath;
	// Rely solely on Helper for DOS -> NT resolution. Helper performs
	// minimal-access opens and device mapping; if it fails we'll send the
	// original selected path to the kernel.
	bool resolved = Helper::ResolveDosPathToNtPath(selectedPath, resolvedNtPath);
	std::wstring ntPathToSend = resolved && !resolvedNtPath.empty() ? resolvedNtPath : selectedPath;

	if (!m_Filter.FLTCOMM_AddHook(ntPathToSend)) {
		::MessageBoxW(NULL, L"Failed to add hook entry in kernel.", L"Add Executable", MB_OK | MB_ICONERROR);
		return;
	}

	// Log success instead of popping a message box
	LOG_CTRL_ETW(L"Executable added to hook list: %s\n", ntPathToSend.c_str());

	// Persist to registry. Rollback kernel entry if persistence fails.
	if (!RegistryStore::AddPath(ntPathToSend)) {
		LOG_CTRL_ETW(L"OnAddExecutableToHookList: RegistryStore::AddPath failed for %s - attempting rollback\n", ntPathToSend.c_str());
		// rollback kernel
		const UCHAR* b2 = reinterpret_cast<const UCHAR*>(ntPathToSend.c_str());
		size_t bLen2 = ntPathToSend.size() * sizeof(wchar_t);
		unsigned long long h2 = Helper::GetNtPathHash(b2, bLen2);
		if (!m_Filter.FLTCOMM_RemoveHookByHash(h2)) {
			LOG_CTRL_ETW(L"OnAddExecutableToHookList: rollback RemoveHookByHash failed for %s\n", ntPathToSend.c_str());
		}
		::MessageBoxW(NULL, L"Failed to persist hook entry to registry. The kernel entry has been rolled back.", L"Add Executable", MB_OK | MB_ICONERROR);
		return;
	}

	// Compute NT-path hash and update any ProcessManager entries that match
	const UCHAR* b = reinterpret_cast<const UCHAR*>(ntPathToSend.c_str());
	size_t bLen = ntPathToSend.size() * sizeof(wchar_t);
	unsigned long long addedHash = Helper::GetNtPathHash(b, bLen);

	// Update any processes that already have that path known (by hash match)
	std::vector<DWORD> matches = PM_FindPidsByHash(addedHash);
	if (!matches.empty()) {
		for (DWORD mpid : matches) {
			PM_UpdateEntryFields(mpid, ntPathToSend, true, L"");
			int item = m_ProcListCtrl.GetNextItem(-1, LVNI_ALL);
			while (item != -1) {
				if ((DWORD)m_ProcListCtrl.GetItemData(item) == mpid) break;
				item = m_ProcListCtrl.GetNextItem(item, LVNI_ALL);
			}
			if (item != -1) {
				bool is64 = false; Helper::IsProcess64(mpid, is64);
				bool dllLoaded = false;
				const wchar_t* dllName = is64 ? MASTER_X64_DLL_BASENAME : MASTER_X86_DLL_BASENAME;
				Helper::IsModuleLoaded(mpid, dllName, dllLoaded);
				DWORD flags = PF_IN_HOOK_LIST;
				if (dllLoaded) flags |= PF_MASTER_DLL_LOADED;
				if (is64) flags |= PF_IS_64BIT;
				PROC_ITEMDATA newPacked = MAKE_ITEMDATA(mpid, flags);
				m_ProcListCtrl.SetItemData(item, (DWORD_PTR)newPacked);
				m_ProcListCtrl.SetItemText(item, 3, FormatHookColumn(newPacked).c_str());
			}
		}
	}
	else {
		// Best-effort fallback: update entries whose path exactly matches the added path
		auto all = PM_GetAll();
		for (const auto &e : all) {
			if (e.path.empty()) continue;
			if (_wcsicmp(e.path.c_str(), ntPathToSend.c_str()) == 0) {
				PM_UpdateEntryFields(e.pid, e.path, true, e.cmdline);
				int item = m_ProcListCtrl.GetNextItem(-1, LVNI_ALL);
				while (item != -1) {
					if ((DWORD)m_ProcListCtrl.GetItemData(item) == e.pid) break;
					item = m_ProcListCtrl.GetNextItem(item, LVNI_ALL);
				}
				if (item != -1) {
					bool is64 = false; Helper::IsProcess64(e.pid, is64);
					bool dllLoaded = false;
					const wchar_t* dllName = is64 ? MASTER_X64_DLL_BASENAME : MASTER_X86_DLL_BASENAME;
					Helper::IsModuleLoaded(e.pid, dllName, dllLoaded);
					DWORD flags = PF_IN_HOOK_LIST;
					if (dllLoaded) flags |= PF_MASTER_DLL_LOADED;
					if (is64) flags |= PF_IS_64BIT;
					PROC_ITEMDATA newPacked = MAKE_ITEMDATA(e.pid, flags);
					m_ProcListCtrl.SetItemData(item, (DWORD_PTR)newPacked);
					m_ProcListCtrl.SetItemText(item, 3, FormatHookColumn(newPacked).c_str());
				}
			}
		}
	}
}

void CUMControllerDlg::FilterProcessList(const std::wstring& filter) {
	m_ProcListCtrl.DeleteAllItems();

	int i = 0;
	// Prepare lower-case filter for case-insensitive search
	std::wstring filterLower;
	filterLower.reserve(filter.size());
	for (wchar_t c : filter) filterLower.push_back(towlower(c));

	auto all = PM_GetAll();
	for (size_t idx = 0; idx < all.size(); idx++) {
		std::wstring nameLower;
		nameLower.reserve(all[idx].name.size());
		for (wchar_t c : all[idx].name) nameLower.push_back(towlower(c));

		if (filter.empty() || nameLower.find(filterLower) != std::wstring::npos) {
			// Use cached module/arch state populated by background resolver
			bool is64 = all[idx].is64;
			bool dllLoaded = all[idx].masterDllLoaded;
			DWORD flags = 0;
			if (all[idx].bInHookList) flags |= PF_IN_HOOK_LIST;
			if (dllLoaded) flags |= PF_MASTER_DLL_LOADED;
			if (is64) flags |= PF_IS_64BIT;
			if (all[idx].forced) flags |= PF_FORCED;
			// Apply persisted EarlyBreak mark if present (by NT path) from cache
			const std::wstring &nt = all[idx].path;
			if (!nt.empty()) {
				std::wstring low = nt;
				for (wchar_t &c : low) c = towlower(c);
				if (m_EarlyBreakSet.find(low) != m_EarlyBreakSet.end()) flags |= PF_EARLY_BREAK_MARKED;
			}
			PROC_ITEMDATA packed = MAKE_ITEMDATA(all[idx].pid, flags);
			int nIndex = m_ProcListCtrl.InsertItem(i, all[idx].name.c_str());
			m_ProcListCtrl.SetItemText(nIndex, 1, std::to_wstring(all[idx].pid).c_str());
			// Early Break marker column
			m_ProcListCtrl.SetItemText(nIndex, 2, (flags & PF_EARLY_BREAK_MARKED) ? L"★" : L"");
			m_ProcListCtrl.SetItemText(nIndex, 3, FormatHookColumn(packed).c_str());
			m_ProcListCtrl.SetItemText(nIndex, 4, all[idx].path.c_str());
			m_ProcListCtrl.SetItemText(nIndex, 5, all[idx].cmdline.c_str());
			m_ProcListCtrl.SetItemData(nIndex, (DWORD_PTR)packed);
			i++;
		}
	}
}

void CUMControllerDlg::LoadProcessList() {
	// get total process count
	size_t totalCount = 0;
	PROCESSENTRY32 pe32 = { sizeof(pe32) };

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE) return;

	if (Process32First(snapshot, &pe32)) {
		do {
			totalCount++;
		} while (Process32Next(snapshot, &pe32));
	}

	m_TotalStartupPids = totalCount;
	size_t resolved = 0;
	PM_Clear();
	m_ProcListCtrl.DeleteAllItems();

	pe32.dwSize = sizeof(pe32);

	std::vector<std::wstring> marks;
	if (RegistryStore::ReadEarlyBreakMarks(marks)) {
		for (auto &m : marks) {
			std::wstring low = m;
			for (wchar_t &c : low) c = towlower(c);
			m_EarlyBreakSet.insert(low);
		}
	}
	std::vector<DWORD> pids;
	if (Process32First(snapshot, &pe32)) {
		do {
			DWORD pid = pe32.th32ProcessID;
			if (pid == 0 || pid == 4) continue;
			pids.push_back(pid);
			ProcessEntry entry;
			entry.pid = pid;
			entry.name = pe32.szExeFile;
			entry.path.clear();
			entry.cmdline.clear();
			entry.early_break = false;
			entry.bInHookList = false; // will be updated inline for path; modules later
			// Capture process creation time and attempt inline NT path/command line resolution.
			HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
			if (h) {
				FILETIME createTime, exitTime, kernelTime, userTime;
				if (GetProcessTimes(h, &createTime, &exitTime, &kernelTime, &userTime)) {
					entry.startTime = createTime;
				}
				// Composite cache lookup first, then fallback resolve
				ProcKey key{ pid, createTime };
				std::wstring ntPath;
				auto itComp = m_CompositeRegistryCache.find(key);
				if (itComp != m_CompositeRegistryCache.end()) {
					ntPath = itComp->second; // cache hit
				}
				else {
					// Reuse existing handle to avoid second OpenProcess
					Helper::GetFullImageNtPathFromHandle(h, ntPath);
				}
				if (!ntPath.empty()) {
					for (auto &m : m_EarlyBreakSet) {
						if (!_wcsicmp(m.c_str(), ntPath.c_str()))
							entry.early_break = true;
						else
							entry.early_break = false;
					}
					// check forced set by pid+startTime (hi/lo)
					unsigned long long key = (static_cast<unsigned long long>(pid) << 48) ^ (static_cast<unsigned long long>(entry.startTime.dwHighDateTime) << 24) ^ static_cast<unsigned long long>(entry.startTime.dwLowDateTime);
					if (m_ForcedSet.find(key) != m_ForcedSet.end()) entry.forced = true; else entry.forced = false;
					entry.path = ntPath;
					// std::wstring cmdline; Helper::GetProcessCommandLineByPID(pid, cmdline); entry.cmdline = cmdline;
					std::wstring cmdline = L"N/A"; entry.cmdline = cmdline;
					bool inHook = false;
					if (PM_HasHookHashCache()) {
						const UCHAR* bytes = reinterpret_cast<const UCHAR*>(ntPath.c_str());
						size_t len = ntPath.size() * sizeof(wchar_t);
						unsigned long long hval = Helper::GetNtPathHash(bytes, len);
						inHook = PM_IsHashInHookSet(hval);
					}
					else {
						inHook = m_Filter.FLTCOMM_CheckHookList(ntPath);
					}
					// if forced enabled, we treat it as in hook list
					entry.bInHookList = entry.forced ? true : inHook;
					// store by composite ProcKey (pid + creation time)
					ProcKey pkey{ pid, createTime };
					m_SessionNtPathCache.emplace(pkey, ntPath);
					// prepare for persistence (dedupe by key)
					bool have = false; for (auto &t : m_PersistSnapshotEntries) { if (std::get<0>(t) == pid && std::get<1>(t) == createTime.dwHighDateTime && std::get<2>(t) == createTime.dwLowDateTime) { have = true; break; } }
					if (!have) m_PersistSnapshotEntries.emplace_back(pid, createTime.dwHighDateTime, createTime.dwLowDateTime, ntPath);
				}
				CloseHandle(h);
				if (!m_StartupInProgress) {
					Helper::Fatal(L"Progress bar should be initialized before calling LoadProcessList\n");
				}
				int pct = 0; if (m_TotalStartupPids > 0) pct = (int)((++resolved * 100) / m_TotalStartupPids);
				int boundedPct2 = (pct < 0 ? 0 : (pct > 100 ? 100 : pct));
				m_StartupProgress.SetPos(boundedPct2);
				if (m_StartupPct.GetSafeHwnd()) { CString t; t.Format(L"%d%%", pct); m_StartupPct.SetWindowText(t); }
			}
			PM_AddEntry(entry);
			// Enumeration-only: progress already advanced; no per-PID tracking needed.
		} while (Process32Next(snapshot, &pe32));
	}

	CloseHandle(snapshot);

	// Populate the UI quickly with PID and name only. The expensive checks
	// (IsProcess64 and IsModuleLoaded) are performed on background threads and
	// will update the cached fields in ProcessManager; read those cached
	// values here to avoid blocking the UI.
	int i = 0;
	auto all = PM_GetAll();

	for (size_t idx = 0; idx < all.size(); idx++) {
		int nIndex = m_ProcListCtrl.InsertItem(i, all[idx].name.c_str());
		m_ProcListCtrl.SetItemText(nIndex, 1, std::to_wstring(all[idx].pid).c_str());
		// On-demand arch/module queries only if process already in hook list.
		DWORD flags = 0;
		bool is64 = false;
		bool dllLoaded = false;
		if (all[idx].bInHookList) {
			Helper::IsProcess64(all[idx].pid, is64);
			const wchar_t* dllName = is64 ? MASTER_X64_DLL_BASENAME : MASTER_X86_DLL_BASENAME;
			Helper::IsModuleLoaded(all[idx].pid, dllName, dllLoaded);
			if (dllLoaded) flags |= PF_MASTER_DLL_LOADED;
			if (is64) flags |= PF_IS_64BIT;
			flags |= PF_IN_HOOK_LIST;
			if (all[idx].forced) flags |= PF_FORCED;
		}
		PROC_ITEMDATA packed = MAKE_ITEMDATA(all[idx].pid, flags);
		// m_ProcListCtrl.SetItemText(nIndex, 2, (FLAGS_FROM_ITEMDATA(packed) & PF_EARLY_BREAK_MARKED) ? L"★" : L"");
		m_ProcListCtrl.SetItemText(nIndex, 2, all[idx].early_break ? L"★" : L"");
		m_ProcListCtrl.SetItemText(nIndex, 3, FormatHookColumn(packed).c_str());
		m_ProcListCtrl.SetItemText(nIndex, 4, all[idx].path.c_str());
		m_ProcListCtrl.SetItemText(nIndex, 5, all[idx].cmdline.c_str());
		m_ProcListCtrl.SetItemData(nIndex, (DWORD_PTR)packed);
		// ProcessManager already maintains the index mapping
		i++;
	}

	// Start resolver for entries lacking path so progress rises gradually as they resolve.
	std::vector<DWORD> needPath;
	for (auto &e : all) if (e.path.empty()) needPath.push_back(e.pid);
	if (!needPath.empty()) ProcessResolver::StartLoaderResolver(this, needPath, &m_Filter);
	// Module/dll/arch checks for path-known entries
	std::vector<DWORD> needModule;
	for (auto &e : all) if (!e.path.empty()) needModule.push_back(e.pid);
	if (!needModule.empty()) ProcessResolver::StartLoaderResolver(this, needModule, &m_Filter);
	// Start the master DLL scanner once (guarded) so it runs for the process lifetime
	if (!m_MasterDllScannerStarted) {
		auto all = PM_GetAll();
		std::vector<DWORD> pids;
		for (auto &e : all) pids.push_back(e.pid);
		ProcessResolver::StartMasterDllScanner(this, pids, &m_Filter);
		m_MasterDllScannerStarted = true;
	}
	// Enumeration complete; mark startup UI done now.
	CompleteStartupUI();
}

LRESULT CUMControllerDlg::OnUpdateProcess(WPARAM wParam, LPARAM lParam) {
	// Create event: high bit set in wParam
	if ((wParam & PROCESS_NOTIFY_CREATE_FLAG) != 0) {
		DWORD pid = (DWORD)(wParam & 0x7FFFFFFFu);
		// app.GetETW().Log(L"OnUpdateProcess get process create, pid: %d\n", pid);
		ProcessEntry entry;
		entry.pid = pid;
		entry.name.clear();
		entry.path.clear();
		entry.cmdline.clear();
		entry.bInHookList = false;

		// If lParam carries a duplicated wide string pointer, copy it and free.
		if (lParam) {
			wchar_t* dup = (wchar_t*)lParam;
			if (dup) {
				entry.path.assign(dup);
				// Extract basename from NT path (last component after '\\' or '/') so
					// the UI displays just the executable name like Process32 snapshot.
				const wchar_t* p = dup;
				const wchar_t* last = NULL;
				for (const wchar_t* q = p; *q; ++q) {
					if (*q == L'\\' || *q == L'/') last = q;
				}
				const wchar_t* base = last ? (last + 1) : p;

				entry.name.assign(base);
				// free duplicated string allocated by _wcsdup
				free(dup);
			}
		}

		// Capture startTime if possible
		HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
		if (h) {
			FILETIME createTime, exitTime, kernelTime, userTime;
			if (GetProcessTimes(h, &createTime, &exitTime, &kernelTime, &userTime)) {
				entry.startTime = createTime;
			}
			CloseHandle(h);
		}

		// Append to ProcessManager
		PM_AddEntry(entry);

		// Insert UI item
		// Decide whether the new entry should be visible under the current filter.
		CString filterText;
		GetDlgItemText(IDC_EDIT_SEARCH, filterText);
		std::wstring filterW = filterText.GetString();
		std::wstring filterLower;
		for (wchar_t c : filterW) filterLower.push_back(towlower(c));
		bool showNow = false;
		if (filterLower.empty()) {
			showNow = true;
		}
		else if (!entry.name.empty()) {
			std::wstring nameLower;
			for (wchar_t c : entry.name) nameLower.push_back(towlower(c));
			if (nameLower.find(filterLower) != std::wstring::npos) showNow = true;
		}
		if (showNow) {
			int newIdx = PM_GetIndex(pid);
			// Column 0 now Process Name; show name or placeholder there. PID is column 1.
			CString pidStr; pidStr.Format(L"%u", pid);
			const wchar_t* nameOrResolving = entry.name.empty() ? L"(resolving)" : entry.name.c_str();
			int nIndex = m_ProcListCtrl.InsertItem(newIdx, nameOrResolving);
			m_ProcListCtrl.SetItemText(nIndex, 1, pidStr);
			// m_ProcListCtrl.SetItemText(nIndex, 2, L"");
			m_ProcListCtrl.SetItemText(nIndex, 3, FormatHookColumn(MAKE_ITEMDATA(pid, 0)).c_str());
			m_ProcListCtrl.SetItemText(nIndex, 4, L"");
			m_ProcListCtrl.SetItemText(nIndex, 5, L"");
			// Use cached state (may be default until resolver runs)
			bool is64 = entry.is64;
			bool dllLoaded = entry.masterDllLoaded;
			DWORD flags = 0;
			if (entry.bInHookList) flags |= PF_IN_HOOK_LIST;
			if (dllLoaded) flags |= PF_MASTER_DLL_LOADED;
			if (is64) flags |= PF_IS_64BIT;
			// Apply persisted EarlyBreak mark for this PID if present (by NT path) from cache
			if (!entry.path.empty()) {
				std::wstring low = entry.path;
				for (wchar_t &c : low) c = towlower(c);
				if (m_EarlyBreakSet.find(low) != m_EarlyBreakSet.end()) flags |= PF_EARLY_BREAK_MARKED;
			}
			m_ProcListCtrl.SetItemData(nIndex, (DWORD_PTR)MAKE_ITEMDATA(pid, flags));
		}

		// Start resolver for this PID using ProcessResolver helper
		ProcessResolver::StartSingleResolver(this, pid, &m_Filter);

		return 0;
	}

	// Loader or resolver update: wParam contains PID
	if (lParam == UPDATE_SOURCE_LOAD || lParam == UPDATE_SOURCE_NOTIFY) {
		DWORD pid = (DWORD)wParam;
		// Get snapshot
		ProcessEntry e; int idx = -1;
		if (!PM_GetEntryCopyByPid(pid, e, &idx)) return 0;
		bool gh = false; RegistryStore::ReadGlobalHookMode(gh);
		bool inHook = e.bInHookList;
		if (gh)
			inHook = true;
		else
			inHook = m_Filter.FLTCOMM_CheckHookList(e.path);
		if (e.forced)
			inHook = true;
		std::wstring path = e.path;
		std::wstring cmdline = e.cmdline;

		int item = m_ProcListCtrl.GetNextItem(-1, LVNI_ALL);
		while (item != -1) {
			if ((DWORD)m_ProcListCtrl.GetItemData(item) == pid) break;
			item = m_ProcListCtrl.GetNextItem(item, LVNI_ALL);
		}
		if (item == -1) {
			// Item not present in current filtered view. If it now matches the
			// filter, insert it.
			CString filterText;
			GetDlgItemText(IDC_EDIT_SEARCH, filterText);
			std::wstring filterW = filterText.GetString();
			std::wstring filterLower;
			for (wchar_t c : filterW) filterLower.push_back(towlower(c));
			bool showNow = false;
			if (filterLower.empty()) showNow = true;
			else {
				std::wstring nameLower;
				for (wchar_t c : e.name) nameLower.push_back(towlower(c));
				if (nameLower.find(filterLower) != std::wstring::npos) showNow = true;
			}
			if (!showNow) return 0;
			// Insert new item for this PID (column 0 = name, column 1 = PID)
			int newItem = m_ProcListCtrl.InsertItem(idx, e.name.c_str());
			m_ProcListCtrl.SetItemText(newItem, 1, std::to_wstring(pid).c_str());
			// Determine Early Break marker for display (based on persisted NT path cache)
			bool earlyMarkedNow = false;
			if (!e.path.empty()) {
				std::wstring low = e.path;
				for (wchar_t &c : low) c = towlower(c);
				if (m_EarlyBreakSet.find(low) != m_EarlyBreakSet.end()) earlyMarkedNow = true;
			}
			m_ProcListCtrl.SetItemText(newItem, 2, earlyMarkedNow ? L"★" : L"");
			m_ProcListCtrl.SetItemText(newItem, 3, FormatHookColumn(MAKE_ITEMDATA(pid, (e.bInHookList ? PF_IN_HOOK_LIST : 0))).c_str());
			m_ProcListCtrl.SetItemText(newItem, 4, e.path.c_str());
			m_ProcListCtrl.SetItemText(newItem, 5, e.cmdline.c_str());
			bool is64 = false; Helper::IsProcess64(pid, is64);
			bool dllLoaded = false;
			const wchar_t* dllName = is64 ? MASTER_X64_DLL_BASENAME : MASTER_X86_DLL_BASENAME;
			Helper::IsModuleLoaded(pid, dllName, dllLoaded);
			DWORD flags = 0;
			if (e.bInHookList) flags |= PF_IN_HOOK_LIST;
			if (dllLoaded) flags |= PF_MASTER_DLL_LOADED;
			if (is64) flags |= PF_IS_64BIT;
			m_ProcListCtrl.SetItemData(newItem, (DWORD_PTR)MAKE_ITEMDATA(pid, flags));
			item = newItem;
		}

		// On-demand query for arch + master DLL only if now in hook list.
		DWORD flags = 0;
		bool is64Now = false;
		bool dllLoadedNow = false;
		if (inHook) {
			Helper::IsProcess64(pid, is64Now);
			const wchar_t* dllName = is64Now ? MASTER_X64_DLL_BASENAME : MASTER_X86_DLL_BASENAME;
			Helper::IsModuleLoaded(pid, dllName, dllLoadedNow);
			flags |= PF_IN_HOOK_LIST;
			if (dllLoadedNow) flags |= PF_MASTER_DLL_LOADED;
			if (is64Now) flags |= PF_IS_64BIT;
			if (e.forced) flags |= PF_FORCED;
		}
		// Preserve the Early Break mark if the UI already had it set. The
		// mergedPacked value computed here includes runtime flags (in-hook,
		// master DLL, arch) but historically we persisted the Early Break
		// mark in item data; updates must not clear that bit.
		DWORD existingData = (DWORD)m_ProcListCtrl.GetItemData(item);
		// bool earlyMarkedNow = (FLAGS_FROM_ITEMDATA(existingData) & PF_EARLY_BREAK_MARKED) != 0;
		bool earlyMarkedNow = false;
		if (!e.path.empty()) {
			std::wstring low = e.path;
			for (wchar_t &c : low) c = towlower(c);
			if (m_EarlyBreakSet.find(low) != m_EarlyBreakSet.end()) earlyMarkedNow = true;
		}
		PROC_ITEMDATA mergedPacked = MAKE_ITEMDATA(pid, flags);
		if (earlyMarkedNow) {
			DWORD mergedFlags = FLAGS_FROM_ITEMDATA(mergedPacked) | PF_EARLY_BREAK_MARKED;
			mergedPacked = MAKE_ITEMDATA(pid, mergedFlags);
		}
		m_ProcListCtrl.SetItemText(item, 2, earlyMarkedNow ? L"★" : L"");
		m_ProcListCtrl.SetItemText(item, 3, FormatHookColumn(mergedPacked).c_str());
		m_ProcListCtrl.SetItemText(item, 4, path.c_str());
		m_ProcListCtrl.SetItemText(item, 5, cmdline.c_str());
		m_ProcListCtrl.SetItemData(item, (DWORD_PTR)mergedPacked);
		// No progress updates in enumeration-only mode.
		return 0;
	}

	// Otherwise treat wParam as PID for exit
	{
		DWORD pid = (DWORD)wParam;
		// app.GetETW().Log(L"OnUpdateProcess get process terminate, pid: %d\n", pid);
		// Locate the entry under lock and capture its index and startTime
		int found = -1;
		FILETIME storedStart = { 0,0 };
		ProcessEntry foundEntry;
		if (!PM_GetEntryCopyByPid(pid, foundEntry, &found)) return 0;
		storedStart = foundEntry.startTime;

		// Check whether a process with this PID currently exists and query its create time
		bool processExists = false;
		FILETIME curCreate = { 0,0 };
		HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
		if (h) {
			FILETIME exitTime, kernelTime, userTime;
			if (GetProcessTimes(h, &curCreate, &exitTime, &kernelTime, &userTime)) {
				processExists = true;
			}
			CloseHandle(h);
		}

		// If we couldn't find an entry to remove, nothing to do
		if (found < 0) return 0;

		// If process exists and startTimes match, the kernel notification may
		// have fired before the process object is fully torn down. Instead of
		// immediately returning (and potentially missing the real exit), spawn
		// a short waiter that polls the PID for a bounded time and then posts
		// the exit message when the process actually disappears. Guard with
		// g_PidExitWaiters so we don't spawn duplicate waiters for the same PID.
		if (processExists && CompareFileTime(&curCreate, &storedStart) == 0) {
			// there is no need to wait, we're already certain that this process is going to terminate, so just goto FULL_EXIT;
			goto FULL_EXIT;
		}

		if (processExists && CompareFileTime(&curCreate, &storedStart) != 0) {
			// PID was reused: update the existing entry to reflect the new process
			PM_MarkAsNewProcess(pid, curCreate);

			// Update UI row to show resolving state and trigger resolver thread
			int item = m_ProcListCtrl.GetNextItem(-1, LVNI_ALL);
			while (item != -1) {
				if ((DWORD)m_ProcListCtrl.GetItemData(item) == pid) break;
				item = m_ProcListCtrl.GetNextItem(item, LVNI_ALL);
			}
			if (item != -1) {
				m_ProcListCtrl.SetItemText(item, 0, L"(resolving)");
				//m_ProcListCtrl.SetItemText(item, 2, L"");
				m_ProcListCtrl.SetItemText(item, 3, L"No");
				m_ProcListCtrl.SetItemText(item, 4, L"");
				m_ProcListCtrl.SetItemText(item, 5, L"");
			}

			// Start resolver for this PID using ProcessResolver helper
			ProcessResolver::StartSingleResolver(this, pid, &m_Filter);

			return 0;
		}
	FULL_EXIT:
		// Process truly exited: remove entry via ProcessManager
		ProcessEntry removedCopy;
		PM_RemoveByPid(pid);
		// Enumeration-only: exits after enumeration do not affect progress.
		// app.GetETW().Log(L"removing process pid %d from process list\n", pid);
		int item = m_ProcListCtrl.GetNextItem(-1, LVNI_ALL);
		while (item != -1) {
			if ((DWORD)m_ProcListCtrl.GetItemData(item) == pid) break;
			item = m_ProcListCtrl.GetNextItem(item, LVNI_ALL);
		}
		if (item != -1) {
			m_ProcListCtrl.DeleteItem(item);
		}
		return 0;
	}
}
void CUMControllerDlg::OnHelpAbout()
{
	CAboutDlg dlgAbout;
	dlgAbout.DoModal();
}


// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CUMControllerDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window
HCURSOR CUMControllerDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CUMControllerDlg::OnEnChangeEditSearch()
{
	CString text;
	GetDlgItemText(IDC_EDIT_SEARCH, text);
	m_CurrentFilterString = text.GetString();
	FilterProcessList(text.GetString());
}

bool CUMControllerDlg::CheckHookList(const std::wstring& imagePath) {
	// TODO: implement port query later

	return false;
}


void CUMControllerDlg::OnNMRClickListProc(NMHDR *pNMHDR, LRESULT *pResult)
{
	int nItem = m_ProcListCtrl.GetNextItem(-1, LVNI_SELECTED);
	if (nItem == -1)
		return;

	PROC_ITEMDATA packed = (PROC_ITEMDATA)m_ProcListCtrl.GetItemData(nItem);
	DWORD pid = PID_FROM_ITEMDATA(packed);
	ProcessEntry item;
	int idx = -1;
	if (!PM_GetEntryCopyByPid(pid, item, &idx)) return;


	CMenu menu;
	menu.CreatePopupMenu();
	// Temporarily hide Add/Remove Hook actions from context menu
	// (requested: do not display these menu items)
	menu.AppendMenu(MF_STRING, ID_MENU_INJECT_DLL, L"Inject DLL");
	// Early-break marking
	menu.AppendMenu(MF_SEPARATOR, 0, L"");
	menu.AppendMenu(MF_STRING, ID_MENU_MARK_EARLY_BREAK, L"Mark Early Break");
	menu.AppendMenu(MF_STRING, ID_MENU_UNMARK_EARLY_BREAK, L"Unmark Early Break");

	// Add Force Inject menu for entries that are not in hook list and master DLL not loaded
	menu.AppendMenu(MF_STRING, ID_MENU_FORCE_INJECT, L"Force Inject");
	// Temporarily hide PPL operations (Recover/Unprotect) from context menu

	// grey out certai menu based on bInHookList
	DWORD flags = FLAGS_FROM_ITEMDATA(packed);
	bool inHook = (flags & PF_IN_HOOK_LIST) != 0;
	bool dllLoaded = (flags & PF_MASTER_DLL_LOADED) != 0;
	menu.EnableMenuItem(ID_MENU_ADD_HOOK, inHook ? MF_GRAYED : MF_ENABLED);
	menu.EnableMenuItem(ID_MENU_REMOVE_HOOK_SINGLE, inHook ? MF_ENABLED : MF_GRAYED);
	// Only allow injecting the master DLL when the master DLL is already
	// present inside the target process (PF_MASTER_DLL_LOADED).
	menu.EnableMenuItem(ID_MENU_INJECT_DLL, dllLoaded ? MF_ENABLED : MF_GRAYED);

	// Early-break menu state: determine if this process is marked (by NT path)
	DWORD flags64 = flags; // keep existing flags usage
	bool marked = false;
	std::wstring ntpath = item.path;
	if (ntpath.empty()) {
		ProcKey key{ pid, item.startTime };
		auto it = m_SessionNtPathCache.find(key);
		if (it != m_SessionNtPathCache.end()) ntpath = it->second;
	}
	if (!ntpath.empty()) {
		std::wstring low = ntpath;
		for (wchar_t &c : low) c = towlower(c);
		if (m_EarlyBreakSet.find(low) != m_EarlyBreakSet.end()) marked = true;
	}
	// Only one of these should be enabled at a time
	menu.EnableMenuItem(ID_MENU_MARK_EARLY_BREAK, marked ? MF_GRAYED : MF_ENABLED);
	menu.EnableMenuItem(ID_MENU_UNMARK_EARLY_BREAK, marked ? MF_ENABLED : MF_GRAYED);

	// Force inject enabled whenever the master DLL is NOT loaded (inHook irrelevant)
	menu.EnableMenuItem(ID_MENU_FORCE_INJECT, (!dllLoaded) ? MF_ENABLED : MF_GRAYED);
	// PPL menu mutual exclusivity based on persisted state (PID+start FILETIME)
	DWORD hi = item.startTime.dwHighDateTime;
	DWORD lo = item.startTime.dwLowDateTime;
	unsigned long long pplKey = (static_cast<unsigned long long>(pid) << 48) ^ (static_cast<unsigned long long>(hi) << 24) ^ static_cast<unsigned long long>(lo);
	// Enable Unprotect when no original prot saved; enable Recover when original prot exists
	DWORD origProt = 0; bool hasOrig = RegistryStore::GetPplOriginalProt(pid, hi, lo, origProt);
	menu.EnableMenuItem(ID_MENU_UNPROTECT_PPL, hasOrig ? MF_GRAYED : MF_ENABLED);
	menu.EnableMenuItem(ID_MENU_ELEVATE_TO_PPL, hasOrig ? MF_ENABLED : MF_GRAYED);

	// Ensure UI reflects persisted mark (some update paths may not have applied the persisted bit).
	if (marked) {
		// set star text and set PF_EARLY_BREAK_MARKED in item data if not already present
		DWORD existing = (DWORD)m_ProcListCtrl.GetItemData(nItem);
		if ((FLAGS_FROM_ITEMDATA(existing) & PF_EARLY_BREAK_MARKED) == 0) {
			DWORD newFlags = FLAGS_FROM_ITEMDATA(existing) | PF_EARLY_BREAK_MARKED;
			PROC_ITEMDATA newPacked = MAKE_ITEMDATA(pid, newFlags);
			m_ProcListCtrl.SetItemData(nItem, (DWORD_PTR)newPacked);
			m_ProcListCtrl.SetItemText(nItem, 2, L"★");
		}
	}


	CPoint point;
	GetCursorPos(&point);
	menu.TrackPopupMenu(TPM_RIGHTBUTTON, point.x, point.y, this);

	*pResult = 0;
}

void CUMControllerDlg::OnElevateToPpl() {
	int nItem = m_ProcListCtrl.GetNextItem(-1, LVNI_SELECTED);
	if (nItem == -1) return;
	PROC_ITEMDATA packed = (PROC_ITEMDATA)m_ProcListCtrl.GetItemData(nItem);
	DWORD pid = PID_FROM_ITEMDATA(packed);
	
	// Recover: fetch saved original protection and send recover command
	ProcessEntry e; int idx = -1; if (!PM_GetEntryCopyByPid(pid, e, &idx)) return;
	DWORD origProt = 0; if (!RegistryStore::GetPplOriginalProt(pid, e.startTime.dwHighDateTime, e.startTime.dwLowDateTime, origProt)) {
		MessageBoxW(L"No saved original protection for this process.", L"Recover PPL", MB_ICONWARNING | MB_OK);
		return;
	}
	if (!origProt) {
		LOG_CTRL_ETW(L"only protected process is supported\n");
		MessageBoxW(L"only protected process is supported", L"PPLRecovery", MB_ICONERROR | MB_OK);
		return;
	}
	if (!m_Filter.FLTCOMM_RecoverPpl(pid, origProt)) {
		MessageBoxW(L"Elevate To PPL failed.", L"Kernel Request", MB_ICONERROR | MB_OK);
	} else {
		MessageBoxW(L"Elevate To PPL request sent.", L"Kernel Request", MB_ICONINFORMATION | MB_OK);
		// On recover, clear original prot record so Unprotect becomes available again
		RegistryStore::RemovePplOriginalProt(pid, e.startTime.dwHighDateTime, e.startTime.dwLowDateTime);
	}
}

void CUMControllerDlg::OnUnprotectPpl() {
	int nItem = m_ProcListCtrl.GetNextItem(-1, LVNI_SELECTED);
	if (nItem == -1) return;
	PROC_ITEMDATA packed = (PROC_ITEMDATA)m_ProcListCtrl.GetItemData(nItem);
	DWORD pid = PID_FROM_ITEMDATA(packed);
	// protect process is not supported
	bool is_protected = false;
	if (!m_Filter.FLTCOMM_IsProtectedProcess(pid, is_protected)) {
		LOG_CTRL_ETW(L"Failed to call FLTCOMM_IsProtectedProcess\n");
		MessageBoxW(L"Failed to call FLTCOMM_IsProtectedProcess", L"OnUnprotectPpl", MB_ICONERROR | MB_OK);
		return;
	}
	if (!is_protected) {
		LOG_CTRL_ETW(L"only protected process is supported\n");
		MessageBoxW(L"only protected process is supported", L"OnUnprotectPpl", MB_ICONERROR | MB_OK);
		return;
	}
	// Before unprotect, query current protection and persist for recovery
	ProcessEntry e; int idx = -1; DWORD curProt = 0;
	if (!PM_GetEntryCopyByPid(pid, e, &idx)) return;
	if (!m_Filter.FLTCOMM_QueryPplProtection(pid, curProt)) {
		MessageBoxW(L"Failed to query current PPL protection.", L"Kernel Request", MB_ICONERROR | MB_OK);
		return;
	}
	RegistryStore::AddPplOriginalProt(pid, e.startTime.dwHighDateTime, e.startTime.dwLowDateTime, curProt);

	if (!m_Filter.FLTCOMM_UnprotectPpl(pid)) {
		MessageBoxW(L"Unprotect PPL failed.", L"Kernel Request", MB_ICONERROR | MB_OK);
	} else {
		MessageBoxW(L"Unprotect PPL request sent.", L"Kernel Request", MB_ICONINFORMATION | MB_OK);
		// No HookState annotation changes per request
	}
}

void CUMControllerDlg::OnNMDblclkListProc(NMHDR* pNMHDR, LRESULT* pResult)
{
	// Identify clicked row reliably using NMHDR (rather than current selection only)
	if (m_StartupInProgress) { if (pResult) *pResult = 0; return; }
	LPNMITEMACTIVATE pAct = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	int nItem = -1;
	if (pAct && pAct->iItem >= 0) nItem = pAct->iItem; else nItem = m_ProcListCtrl.GetNextItem(-1, LVNI_SELECTED);
	if (nItem == -1) { if (pResult) *pResult = 0; return; }
	PROC_ITEMDATA packed = (PROC_ITEMDATA)m_ProcListCtrl.GetItemData(nItem);
	DWORD pid = PID_FROM_ITEMDATA(packed);
	DWORD flags = FLAGS_FROM_ITEMDATA(packed);
	bool dllLoaded = (flags & PF_MASTER_DLL_LOADED) != 0;
	bool inHook = (flags & PF_IN_HOOK_LIST) != 0;
	// If not yet marked loaded but entry is in hook list, perform a live check so we can
	// open the dialog immediately when the master DLL actually appears.
	if (!dllLoaded && inHook) {
		bool is64 = false; Helper::IsProcess64(pid, is64);
		const wchar_t* dllName = is64 ? MASTER_X64_DLL_BASENAME : MASTER_X86_DLL_BASENAME;
		bool liveLoaded = false; Helper::IsModuleLoaded(pid, dllName, liveLoaded);
		if (liveLoaded) {
			flags |= PF_MASTER_DLL_LOADED;
			if (is64) flags |= PF_IS_64BIT; // ensure arch flag present if discovered here
			packed = MAKE_ITEMDATA(pid, flags);
			// Update UI cached state
			m_ProcListCtrl.SetItemData(nItem, (DWORD_PTR)packed);
			m_ProcListCtrl.SetItemText(nItem, 3, FormatHookColumn(packed).c_str());
			dllLoaded = true;
		}
	}
	if (!dllLoaded) { if (pResult) *pResult = 0; return; }
	// Respond for double-click on ANY column now (previously only PID visually worked).
	// Optionally could restrict to specific columns by checking pAct->iSubItem.
	// Always create a fresh dialog. If an existing one is open, destroy it first.
	 // Dynamic load HookUI.dll and invoke ShowHookDialog export
	if (!m_hHookUiDll) {
		m_hHookUiDll = ::LoadLibraryW(L"HookUI.dll");
		if (!m_hHookUiDll) {
			MessageBox(L"HookUI.dll not found. Deploy the HookUI module next to the executable.", L"Hook", MB_ICONERROR);
			if (pResult) *pResult = 0; return;
		}
	}
	if (!m_pfnShowHookDialog) {
		m_pfnShowHookDialog = (PFN_ShowHookDialog)::GetProcAddress(m_hHookUiDll, "ShowHookDialog");
		if (!m_pfnShowHookDialog) {
			MessageBox(L"ShowHookDialog export missing in HookUI.dll.", L"Hook", MB_ICONERROR);
			if (pResult) *pResult = 0; return;
		}
	}
	ProcessEntry e; int idx = -1; std::wstring nameDisplay = L"(unknown)"; if (PM_GetEntryCopyByPid(pid, e, &idx)) nameDisplay = e.name.empty() ? nameDisplay : e.name;
	if (!m_pfnShowHookDialog(this->GetSafeHwnd(), pid, nameDisplay.c_str(), &g_HookServices)) {
		MessageBox(L"Failed to show hook dialog via HookUI DLL.", L"Hook", MB_ICONERROR);
	}
	if (pResult) *pResult = 0;
}

void CUMControllerDlg::OnMarkEarlyBreak()
{

	int nItem = m_ProcListCtrl.GetNextItem(-1, LVNI_SELECTED);
	if (nItem == -1) return;
	PROC_ITEMDATA packed = (PROC_ITEMDATA)m_ProcListCtrl.GetItemData(nItem);
	DWORD pid = PID_FROM_ITEMDATA(packed);
	ProcessEntry e; int idx = -1;
	if (!PM_GetEntryCopyByPid(pid, e, &idx)) return;
	// If global hook mode is disabled, show a reminder and don't mark
	bool gh = false; RegistryStore::ReadGlobalHookMode(gh);
	if (!gh) {
		MessageBox(L"Global Hook Mode is disabled. Please enable it before marking Early Break.", L"Enable Global Hook Mode", MB_ICONWARNING | MB_OK);
		return;
	}
	// Ensure we have an NT path to persist
	std::wstring ntpath = e.path;
	if (ntpath.empty()) {
		HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
		if (h) { Helper::GetFullImageNtPathFromHandle(h, ntpath); CloseHandle(h); }
	}
	if (ntpath.empty()) {
		MessageBox(L"Unable to resolve process image path; cannot mark Early Break.", L"Error", MB_ICONERROR | MB_OK);
		return;
	}
	if (!RegistryStore::AddEarlyBreakMark(ntpath)) {
		LOG_CTRL_ETW(L"Failed to persist EarlyBreak mark for pid=%u\n", pid);
		MessageBox(L"Failed to persist Early Break mark. Check permissions.", L"Error", MB_ICONERROR | MB_OK);
		return;
	}
	// update in-memory cache (lowercased)
	{
		std::wstring low = ntpath;
		for (wchar_t &c : low) c = towlower(c);
		m_EarlyBreakSet.insert(low);
	}
	// Update UI flags
	// Merge runtime hook-state bits from ProcessManager to avoid touching
	// hook-state when toggling the early-break mark.
	DWORD runtimeFlags = 0;
	if (e.bInHookList) runtimeFlags |= PF_IN_HOOK_LIST;
	if (e.masterDllLoaded) runtimeFlags |= PF_MASTER_DLL_LOADED;
	if (e.is64) runtimeFlags |= PF_IS_64BIT;
	DWORD newFlags = runtimeFlags | PF_EARLY_BREAK_MARKED;
	PROC_ITEMDATA newPacked = MAKE_ITEMDATA(pid, newFlags);
	m_ProcListCtrl.SetItemData(nItem, (DWORD_PTR)newPacked);
	m_ProcListCtrl.SetItemText(nItem, 2, L"★");
	m_ProcListCtrl.SetItemText(nItem, 3, FormatHookColumn(newPacked).c_str());
	FilterProcessList(m_CurrentFilterString);

	// we need to create a file so umhh.dll know when to break
	// it is a file name constructed with ntpath hash
	const UCHAR* bytes = reinterpret_cast<const UCHAR*>(ntpath.c_str());
	size_t len = ntpath.size() * sizeof(wchar_t);
	unsigned long long hval = Helper::GetNtPathHash(bytes, len);
	WCHAR pathBuf[MAX_PATH] = { 0 };
	_snwprintf_s(pathBuf, RTL_NUMBER_OF(pathBuf), USER_MODE_EARLY_BREAK_SIGNAL_FILE_FMT, hval);
	HANDLE hfile;
	if (!Helper::CreateLowPrivReqFile(pathBuf, &hfile)) {
		LOG_CTRL_ETW(L"Failed to create early break signal file path=%s\n", pathBuf);
		MessageBox(L"Failed to create early break signal file", L"Error", MB_ICONERROR | MB_OK);
		return;
	}
	CloseHandle(hfile);
	LOG_CTRL_ETW(L"file path=%s created for early break signal\n", pathBuf);
}

void CUMControllerDlg::OnUnmarkEarlyBreak()
{
	int nItem = m_ProcListCtrl.GetNextItem(-1, LVNI_SELECTED);
	if (nItem == -1) return;
	PROC_ITEMDATA packed = (PROC_ITEMDATA)m_ProcListCtrl.GetItemData(nItem);
	DWORD pid = PID_FROM_ITEMDATA(packed);
	ProcessEntry e; int idx = -1;
	if (!PM_GetEntryCopyByPid(pid, e, &idx)) return;
	std::wstring ntpath = e.path;
	if (ntpath.empty()) {
		HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
		if (h) { Helper::GetFullImageNtPathFromHandle(h, ntpath); CloseHandle(h); }
	}
	if (ntpath.empty()) {
		MessageBox(L"Unable to resolve process image path; cannot unmark Early Break.", L"Error", MB_ICONERROR | MB_OK);
		return;
	}
	if (!RegistryStore::RemoveEarlyBreakMark(ntpath)) {
		LOG_CTRL_ETW(L"Failed to remove EarlyBreak mark for pid=%u\n", pid);
		MessageBox(L"Failed to remove Early Break mark. Check permissions.", L"Error", MB_ICONERROR | MB_OK);
		return;
	}
	// update in-memory cache (lowercased)
	{
		std::wstring low = ntpath;
		for (wchar_t &c : low) c = towlower(c);
		auto it = m_EarlyBreakSet.find(low);
		if (it != m_EarlyBreakSet.end()) m_EarlyBreakSet.erase(it);
	}
	// Merge runtime hook-state bits from ProcessManager to avoid touching
	// hook-state when toggling the early-break mark.
	DWORD runtimeFlags2 = 0;
	if (e.bInHookList) runtimeFlags2 |= PF_IN_HOOK_LIST;
	if (e.masterDllLoaded) runtimeFlags2 |= PF_MASTER_DLL_LOADED;
	if (e.is64) runtimeFlags2 |= PF_IS_64BIT;
	DWORD newFlags2 = runtimeFlags2; // early-break cleared
	PROC_ITEMDATA newPacked2 = MAKE_ITEMDATA(pid, newFlags2);
	m_ProcListCtrl.SetItemData(nItem, (DWORD_PTR)newPacked2);
	m_ProcListCtrl.SetItemText(nItem, 2, L"");
	m_ProcListCtrl.SetItemText(nItem, 3, FormatHookColumn(newPacked2).c_str());
	FilterProcessList(m_CurrentFilterString);
	// delete signal file
	const UCHAR* bytes = reinterpret_cast<const UCHAR*>(ntpath.c_str());
	size_t len = ntpath.size() * sizeof(wchar_t);
	unsigned long long hval = Helper::GetNtPathHash(bytes, len);
	WCHAR pathBuf[MAX_PATH] = { 0 };
	_snwprintf_s(pathBuf, RTL_NUMBER_OF(pathBuf), USER_MODE_EARLY_BREAK_SIGNAL_FILE_FMT, hval);
	DeleteFile(pathBuf);
}

void CUMControllerDlg::OnForceInject()
{
	int nItem = m_ProcListCtrl.GetNextItem(-1, LVNI_SELECTED);
	if (nItem == -1) return;
	PROC_ITEMDATA packed = (PROC_ITEMDATA)m_ProcListCtrl.GetItemData(nItem);
	DWORD pid = PID_FROM_ITEMDATA(packed);
	DWORD flags = FLAGS_FROM_ITEMDATA(packed);
	bool inHook = (flags & PF_IN_HOOK_LIST) != 0;
	bool dllLoaded = (flags & PF_MASTER_DLL_LOADED) != 0;
	// Only allow when master DLL is not loaded
	if (dllLoaded) {
		this->MessageBoxW(L"Force Inject is only available when the master DLL is not loaded.", L"Not Allowed", MB_ICONWARNING | MB_OK);
		return;
	}

	// Ask Helper to force an injection
	if (!Helper::ForceInject(pid)) {
		this->MessageBoxW(L"Force Inject failed. Check permissions and driver state.", L"Error", MB_ICONERROR | MB_OK);
	}
	else {
		// Mark entry as Forced, treat as in-hook and master DLL loaded for UI
		ProcessEntry e; int idx = -1;
		if (PM_GetEntryCopyByPid(pid, e, &idx)) {
			// Set forced in ProcessManager
			PM_MarkForced(pid, true);
			// Mark as in hook list and master DLL loaded for UI
			PM_UpdateEntryModuleState(pid, e.is64, true);
			PM_UpdateEntryFields(pid, e.path, true, e.cmdline);
			// Persist forced mark using PID + startTime
			DWORD hi = e.startTime.dwHighDateTime;
			DWORD lo = e.startTime.dwLowDateTime;
			if (!RegistryStore::AddForcedMark(pid, hi, lo)) {
				LOG_CTRL_ETW(L"Failed to persist forced mark for pid=%u\n", pid);
			}
			else {
				unsigned long long key = (static_cast<unsigned long long>(pid) << 48) ^ (static_cast<unsigned long long>(hi) << 24) ^ static_cast<unsigned long long>(lo);
				m_ForcedSet.insert(key);
			}
			// Update UI row if present
			int item = m_ProcListCtrl.GetNextItem(-1, LVNI_ALL);
			while (item != -1) {
				if ((DWORD)m_ProcListCtrl.GetItemData(item) == pid) break;
				item = m_ProcListCtrl.GetNextItem(item, LVNI_ALL);
			}
			if (item != -1) {
				// Build flags: in hook + master dll + arch
				DWORD flags = PF_IN_HOOK_LIST | PF_MASTER_DLL_LOADED;
				if (e.is64) flags |= PF_IS_64BIT;
				// Also set Forced marker in displayed flags
				flags |= PF_FORCED;
				PROC_ITEMDATA newPacked = MAKE_ITEMDATA(pid, flags);
				m_ProcListCtrl.SetItemData(item, (DWORD_PTR)newPacked);
				m_ProcListCtrl.SetItemText(item, 3, FormatHookColumn(newPacked).c_str());
			}
		}
		this->MessageBoxW(L"Force Inject request sent.", L"Info", MB_ICONINFORMATION | MB_OK);
	}
}

void CUMControllerDlg::OnAddWhitelist()
{
	// Pick an executable, resolve to NT path, compute hash, persist both, then restart UMHH.ObCallback
	wchar_t szFile[MAX_PATH] = { 0 };
	OPENFILENAME ofn = { 0 };
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = this->GetSafeHwnd();
	ofn.lpstrFile = szFile;
	ofn.nMaxFile = MAX_PATH;
	ofn.lpstrFilter = L"Executable Files\0*.exe\0All Files\0*.*\0";
	ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
	ofn.lpstrTitle = L"Select executable to whitelist";
	if (!GetOpenFileName(&ofn)) return;

	if (!Helper::IsFileExists(szFile)) {
		MessageBoxW(L"Selected file does not exist.", L"Whitelist", MB_OK | MB_ICONERROR);
		return;
	}
	std::wstring dosPath(szFile), ntPath;
	bool ok = Helper::ResolveDosPathToNtPath(dosPath, ntPath);
	std::wstring ntToPersist = (ok && !ntPath.empty()) ? ntPath : dosPath;

	const UCHAR* bytes = reinterpret_cast<const UCHAR*>(ntToPersist.c_str());
	size_t len = ntToPersist.size() * sizeof(wchar_t);
	unsigned long long hash = Helper::GetNtPathHash(bytes, len);

	if (!RegistryStore::AddWhitelistPath(ntToPersist)) {
		LOG_CTRL_ETW(L"AddWhitelist: failed to persist NT path %s\n", ntToPersist.c_str());
		MessageBoxW(L"Failed to persist whitelist path.", L"Whitelist", MB_OK | MB_ICONERROR);
		return;
	}
	if (!RegistryStore::AddWhitelistHash(hash)) {
		LOG_CTRL_ETW(L"AddWhitelist: failed to persist hash 0x%016llX for %s\n", hash, ntToPersist.c_str());
		MessageBoxW(L"Failed to persist whitelist hash.", L"Whitelist", MB_OK | MB_ICONERROR);
		return;
	}

	// Restart ObCallback so driver reloads whitelist keys at start
	if (!Helper::UMHH_ObCallback_DriverCheck()) {
		LOG_CTRL_ETW(L"AddWhitelist: UMHH_ObCallback_DriverCheck failed\n");
		MessageBoxW(L"Whitelist persisted, but failed to restart ObCallback.", L"Whitelist", MB_OK | MB_ICONWARNING);
		return;
	}
	MessageBoxW(L"Whitelist updated.", L"Whitelist", MB_OK | MB_ICONINFORMATION);
}

void CUMControllerDlg::OnRemoveWhitelist()
{
	// Show selection dialog that lists current whitelist entries for removal
	CRemoveWhitelistDlg dlg(this);
	if (dlg.DoModal() == IDOK) {
		MessageBoxW(L"Whitelist updated.", L"Whitelist", MB_OK | MB_ICONINFORMATION);
	}
}

LRESULT CUMControllerDlg::OnHookDlgDestroyed(WPARAM wParam, LPARAM lParam) {
	UNREFERENCED_PARAMETER(wParam); UNREFERENCED_PARAMETER(lParam);
	// Dialog self-managed inside DLL; nothing to clean locally.
	return 0;
}


// Removed resolution-based progress tracking.

void CUMControllerDlg::FinishStartupIfDone() {
	
	if (m_CachePersisted) return; // already persisted once
	if (!m_PersistSnapshotEntries.empty()) {
		std::vector<std::tuple<DWORD, DWORD, DWORD, std::wstring>> dedup;
		std::unordered_set<unsigned long long> seen; // simple 64-bit key combine
		for (auto &t : m_PersistSnapshotEntries) {
			DWORD pid = std::get<0>(t);
			DWORD hi = std::get<1>(t);
			DWORD lo = std::get<2>(t);
			const std::wstring &path = std::get<3>(t);
			if (path.empty()) continue;
			unsigned long long k = (static_cast<unsigned long long>(pid) << 32) ^ (static_cast<unsigned long long>(hi) * 1315423911ULL) ^ static_cast<unsigned long long>(lo);
			if (seen.insert(k).second) dedup.emplace_back(pid, hi, lo, path); // keep hi:lo order
		}
		RegistryStore::WriteCompositeProcCache(dedup);
	}
	m_CachePersisted = true;

	// Schedule purge of stale ProcHookList entries on a background thread
	try {
		std::thread([this]() {
			// Delay to avoid impacting startup responsiveness and reduce race with late-starting processes
			std::this_thread::sleep_for(std::chrono::seconds(5));
			try {
				std::vector<std::tuple<DWORD, DWORD, DWORD, int, DWORD, unsigned long long, unsigned long long, unsigned long long, std::wstring>> persistedHooks;
				if (!RegistryStore::ReadProcHookList(persistedHooks)) return;
				// Build a set of known keys (pid, hi, lo) from our snapshot entries
				std::unordered_set<unsigned long long> knownKeys;
				for (auto &t : m_PersistSnapshotEntries) {
					DWORD pid = std::get<0>(t);
					DWORD hi = std::get<1>(t);
					DWORD lo = std::get<2>(t);
					unsigned long long key = (static_cast<unsigned long long>(pid) << 48) ^ (static_cast<unsigned long long>(hi) << 24) ^ static_cast<unsigned long long>(lo);
					knownKeys.insert(key);
				}
				// Also include live processes' create times
				HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
				if (snap != INVALID_HANDLE_VALUE) {
					PROCESSENTRY32 pe = { sizeof(pe) };
					if (Process32First(snap, &pe)) {
						do {
							DWORD pid = pe.th32ProcessID;
							if (pid == 0 || pid == 4) continue;
							HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
							if (!h) continue;
							FILETIME createTime{ 0,0 }, exitTime, kernelTime, userTime;
							if (GetProcessTimes(h, &createTime, &exitTime, &kernelTime, &userTime)) {
								DWORD hi = createTime.dwHighDateTime;
								DWORD lo = createTime.dwLowDateTime;
								unsigned long long key = (static_cast<unsigned long long>(pid) << 48) ^ (static_cast<unsigned long long>(hi) << 24) ^ static_cast<unsigned long long>(lo);
								knownKeys.insert(key);
							}
							CloseHandle(h);
						} while (Process32Next(snap, &pe));
					}
					CloseHandle(snap);
				}
				// Iterate persisted hooks and remove entries whose PID:HI:LO not in knownKeys
				for (auto &h : persistedHooks) {
					DWORD pid = std::get<0>(h);
					DWORD hi = std::get<1>(h);
					DWORD lo = std::get<2>(h);
					unsigned long long key = (static_cast<unsigned long long>(pid) << 48) ^ (static_cast<unsigned long long>(hi) << 24) ^ static_cast<unsigned long long>(lo);
					if (knownKeys.find(key) == knownKeys.end()) {
						LOG_CTRL_ETW(L"Purging stale ProcHookList entry for pid=%u hi=%08X lo=%08X\n", pid, hi, lo);
						RegistryStore::RemoveProcHookEntry(pid, hi, lo, std::get<3>(h));
					}
				}

				// Purge ForcedList entries whose PID:HI:LO not in knownKeys
				try {
					std::vector<std::tuple<DWORD, DWORD, DWORD>> forced;
					if (RegistryStore::ReadForcedMarks(forced)) {
						std::vector<std::tuple<DWORD, DWORD, DWORD>> keptForced;
						for (auto &f : forced) {
							DWORD pid = std::get<0>(f); DWORD hi = std::get<1>(f); DWORD lo = std::get<2>(f);
							unsigned long long key = (static_cast<unsigned long long>(pid) << 48) ^ (static_cast<unsigned long long>(hi) << 24) ^ static_cast<unsigned long long>(lo);
							if (knownKeys.find(key) != knownKeys.end()) {
								keptForced.emplace_back(pid, hi, lo);
							}
							else {
								LOG_CTRL_ETW(L"Purging stale ForcedList entry for pid=%u hi=%08X lo=%08X\n", pid, hi, lo);
							}
						}
						// Rewrite forced marks with only kept entries
						if (!RegistryStore::WriteForcedMarks(keptForced)) {
							LOG_CTRL_ETW(L"Background purge: failed to write filtered ForcedList\n");
						}
						// Note: do not modify in-memory caches here; registry purge is sufficient
					}
				}
				catch (...) { LOG_CTRL_ETW(L"Background purge: failed while purging ForcedList\n"); }

				// Purge composite process cache (NtProcCache) entries not in knownKeys
				try {
					std::vector<std::tuple<DWORD, DWORD, DWORD, std::wstring>> comp;
					if (RegistryStore::ReadCompositeProcCache(comp)) {
						std::vector<std::tuple<DWORD, DWORD, DWORD, std::wstring>> keptComp;
						for (auto &c : comp) {
							DWORD pid = std::get<0>(c); DWORD hi = std::get<1>(c); DWORD lo = std::get<2>(c);
							unsigned long long key = (static_cast<unsigned long long>(pid) << 48) ^ (static_cast<unsigned long long>(hi) << 24) ^ static_cast<unsigned long long>(lo);
							if (knownKeys.find(key) != knownKeys.end()) {
								keptComp.emplace_back(c);
							}
							else {
								LOG_CTRL_ETW(L"Purging stale NtProcCache entry for pid=%u hi=%08X lo=%08X\n", pid, hi, lo);
							}
						}
						if (!RegistryStore::WriteCompositeProcCache(keptComp)) {
							LOG_CTRL_ETW(L"Background purge: failed to write filtered NtProcCache\n");
						}
						// Note: do not modify in-memory caches here; registry purge is sufficient
					}
				}
				catch (...) { LOG_CTRL_ETW(L"Background purge: failed while purging NtProcCache\n"); }

				// Purge PPL-related lists (OriginalProt, Elevated, Unprotected)
				try {
					// Original protection list
					std::vector<std::tuple<DWORD, DWORD, DWORD, DWORD>> origs;
					if (RegistryStore::ReadPplOriginalProt(origs)) {
						std::vector<std::tuple<DWORD, DWORD, DWORD, DWORD>> kept;
						for (auto &o : origs) {
							DWORD pid = std::get<0>(o); DWORD hi = std::get<1>(o); DWORD lo = std::get<2>(o);
							unsigned long long key = (static_cast<unsigned long long>(pid) << 48) ^ (static_cast<unsigned long long>(hi) << 24) ^ static_cast<unsigned long long>(lo);
							if (knownKeys.find(key) != knownKeys.end()) kept.emplace_back(o);
							else LOG_CTRL_ETW(L"Purging stale PplOriginalProtList entry for pid=%u hi=%08X lo=%08X\n", pid, hi, lo);
						}
						RegistryStore::WritePplOriginalProt(kept);
					}
					// Elevated and Unprotected marks (PID:HI:LO)
					{
						std::vector<std::tuple<DWORD, DWORD, DWORD>> list;
						if (RegistryStore::ReadPplElevatedMarks(list)) {
							std::vector<std::tuple<DWORD, DWORD, DWORD>> kept;
							for (auto &t : list) {
								DWORD pid = std::get<0>(t); DWORD hi = std::get<1>(t); DWORD lo = std::get<2>(t);
								unsigned long long key = (static_cast<unsigned long long>(pid) << 48) ^ (static_cast<unsigned long long>(hi) << 24) ^ static_cast<unsigned long long>(lo);
								if (knownKeys.find(key) != knownKeys.end()) kept.emplace_back(t);
								else LOG_CTRL_ETW(L"Purging stale PplElevatedList entry for pid=%u hi=%08X lo=%08X\n", pid, hi, lo);
							}
							RegistryStore::WritePplElevatedMarks(kept);
						}
					}
					{
						std::vector<std::tuple<DWORD, DWORD, DWORD>> list;
						if (RegistryStore::ReadPplUnprotectedMarks(list)) {
							std::vector<std::tuple<DWORD, DWORD, DWORD>> kept;
							for (auto &t : list) {
								DWORD pid = std::get<0>(t); DWORD hi = std::get<1>(t); DWORD lo = std::get<2>(t);
								unsigned long long key = (static_cast<unsigned long long>(pid) << 48) ^ (static_cast<unsigned long long>(hi) << 24) ^ static_cast<unsigned long long>(lo);
								if (knownKeys.find(key) != knownKeys.end()) kept.emplace_back(t);
								else LOG_CTRL_ETW(L"Purging stale PplUnprotectedList entry for pid=%u hi=%08X lo=%08X\n", pid, hi, lo);
							}
							RegistryStore::WritePplUnprotectedMarks(kept);
						}
					}
				}
				catch (...) { LOG_CTRL_ETW(L"Background purge: failed while purging PPL lists\n"); }
			}
			catch (...) {
				LOG_CTRL_ETW(L"Background purge: failed to purge stale ProcHookList entries\n");
			}
		}).detach();
		LOG_CTRL_ETW(L"Scheduled background purge of ProcHookList entries\n");
	}
	catch (...) {
		LOG_CTRL_ETW(L"FinishStartupIfDone: failed to schedule background purge\n");
	}
}

void CUMControllerDlg::CompleteStartupUI() {
	if (!m_StartupInProgress) return;
	m_StartupInProgress = false;
	m_StartupProgress.SetPos(100);
	m_StartupProgress.ShowWindow(SW_HIDE);
	if (m_StartupPct.GetSafeHwnd()) m_StartupPct.ShowWindow(SW_HIDE);
	m_ProcListCtrl.EnableWindow(TRUE);
	if (GetMenu()) EnableMenuItem(GetMenu()->m_hMenu, 0, MF_BYPOSITION | MF_ENABLED);
	if (CWnd* search = GetDlgItem(IDC_EDIT_SEARCH)) search->EnableWindow(TRUE);
	// No timeout timer.
}

LRESULT CUMControllerDlg::OnPostEnumCleanup(WPARAM, LPARAM) {
	// Build set of live PIDs
	std::unordered_set<DWORD> live;
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32 pe = { sizeof(pe) };
		if (Process32First(snap, &pe)) {
			do {
				if (pe.th32ProcessID != 0 && pe.th32ProcessID != 4) live.insert(pe.th32ProcessID);
			} while (Process32Next(snap, &pe));
		}
		CloseHandle(snap);
	}
	// Identify duplicates & dead items among UI rows
	std::unordered_set<DWORD> seen;
	std::vector<int> dupRows;
	std::vector<int> deadRows;
	int idx = m_ProcListCtrl.GetNextItem(-1, LVNI_ALL);
	while (idx != -1) {
		DWORD packed = (DWORD)m_ProcListCtrl.GetItemData(idx);
		DWORD pid = PID_FROM_ITEMDATA(packed);
		if (!seen.insert(pid).second) {
			dupRows.push_back(idx);
		}
		else if (live.find(pid) == live.end()) {
			deadRows.push_back(idx);
		}
		idx = m_ProcListCtrl.GetNextItem(idx, LVNI_ALL);
	}
	// Remove duplicate rows (keep first occurrence)
	for (auto it = dupRows.rbegin(); it != dupRows.rend(); ++it) {
		m_ProcListCtrl.DeleteItem(*it);
	}
	// Remove dead rows
	for (auto it = deadRows.rbegin(); it != deadRows.rend(); ++it) {
		DWORD packed = (DWORD)m_ProcListCtrl.GetItemData(*it);
		DWORD pid = PID_FROM_ITEMDATA(packed);
		PM_RemoveByPid(pid);
		m_ProcListCtrl.DeleteItem(*it);
		// Enumeration-only: ignore startup sets removal.
	}
	// No progress recompute needed.
	return 0;
}

// Removed OnTimer; no timeout logic for enumeration-only progress.

void CUMControllerDlg::OnRemoveExecutablesFromHookList() {
	CRemoveHookDlg dlg(&m_Filter, this);
	if (dlg.DoModal() == IDOK) {
		// Dialog already performed removals and updated PM
		// Optionally refresh UI here
	}
}

void CUMControllerDlg::OnClearEtwLog() {
	// Fire clear event; tracer will clear its own console.
	app.GetETW().Clear();
	LOG_CTRL_ETW(L"controller requested ETW clear\n");
}

void CUMControllerDlg::OnOpenEtwLog() {
	// Find newest EtwTracer_*.log (timestamped) or fallback to legacy EtwTracer.log
	auto tracerExe = Helper::GetCurrentDirFilePath(L"EtwTracer.exe");
	std::wstring folder; size_t pos = tracerExe.find_last_of(L"/\\");
	folder = (pos != std::wstring::npos) ? tracerExe.substr(0, pos) : L".";
	WIN32_FIND_DATAW fd{};
	std::wstring pattern = folder + L"\\EtwTracer_*.log";
	HANDLE hFind = FindFirstFileW(pattern.c_str(), &fd);
	FILETIME newestFT{ 0,0 };
	std::wstring newest;
	if (hFind != INVALID_HANDLE_VALUE) {
		BOOL more = TRUE;
		while (more) {
			// Skip directories
			if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
				if (CompareFileTime(&fd.ftLastWriteTime, &newestFT) > 0) {
					newestFT = fd.ftLastWriteTime;
					newest = folder + L"\\" + fd.cFileName;
				}
			}
			more = FindNextFileW(hFind, &fd);
		}
		FindClose(hFind);
	}
	if (newest.empty()) {
		// fallback legacy name
		std::wstring legacy = folder + L"\\EtwTracer.log";
		TCHAR tmp[MAX_PATH] = { 0 }; lstrcpynW(tmp, legacy.c_str(), _countof(tmp));
		if (Helper::IsFileExists(tmp)) newest = legacy;
	}
	if (newest.empty()) {
		MessageBox(L"No tracer log file found. Start tracer first.", L"ETW Trace Log", MB_ICONINFORMATION);
		return;
	}
	SHELLEXECUTEINFOW sei{ sizeof(sei) }; sei.lpFile = L"notepad.exe"; sei.lpParameters = newest.c_str(); sei.nShow = SW_SHOWNORMAL;
	if (!ShellExecuteExW(&sei)) {
		CString msg; msg.Format(L"Failed to open log %s (error %lu).", newest.c_str(), GetLastError());
		MessageBox(msg, L"ETW Trace Log", MB_ICONERROR);
	}
}

