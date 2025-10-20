
// UMControllerDlg.cpp : implementation file
//

#include "pch.h"
#include "framework.h"
#include "UMController.h"
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
END_MESSAGE_MAP()


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

// Column click handler declaration
void CUMControllerDlg::OnLvnColumnclickListProc(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	int col = pNMLV->iSubItem;
	if (m_SortColumn == col) {
		m_SortAscending = !m_SortAscending;
	} else {
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
	case 0: // PID numeric
		if (a.pid < b.pid) res = -1;
		else if (a.pid > b.pid) res = 1;
		else res = 0;
		break;
	case 1: // name
		res = _wcsicmp(a.name.c_str(), b.name.c_str());
		break;
	case 2: // InHookList: Yes before No when ascending
		if (a.bInHookList == b.bInHookList) res = 0;
		else if (a.bInHookList) res = -1;
		else res = 1;
		break;
	case 3: // NT Path (case-insensitive)
		res = _wcsicmp(a.path.c_str(), b.path.c_str());
		break;
	case 4: // Start Params (case-insensitive)
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
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_EN_CHANGE(IDC_EDIT_SEARCH, &CUMControllerDlg::OnEnChangeEditSearch)
	ON_NOTIFY(NM_RCLICK, IDC_LIST_PROC, &CUMControllerDlg::OnNMRClickListProc)
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
	ON_MESSAGE(WM_APP_FATAL, &CUMControllerDlg::OnFatalMessage)
END_MESSAGE_MAP()


// CUMControllerDlg message handlers

BOOL CUMControllerDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();
	app.SetHwnd(this->GetSafeHwnd());



	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	m_ProcListCtrl.InsertColumn(0, L"PID", LVCFMT_LEFT, 100);
	m_ProcListCtrl.InsertColumn(1, L"Process Name", LVCFMT_LEFT, 200);
	// Column 2: HookState (Yes/No/master/x86|x64), Column 3: NT Path, Column 4: Start Params
	m_ProcListCtrl.InsertColumn(2, L"HookState", LVCFMT_LEFT, 120);
	m_ProcListCtrl.InsertColumn(3, L"NT Path", LVCFMT_LEFT, 400);
	m_ProcListCtrl.InsertColumn(4, L"Start Params", LVCFMT_LEFT, 300);
	m_ProcListCtrl.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	CEdit* pEdit = (CEdit*)GetDlgItem(IDC_EDIT_SEARCH);
	pEdit->SendMessage(EM_SETCUEBANNER, 0, (LPARAM)L"<Filter By Name>");

	ShowWindow(SW_NORMAL);

	// Register a minimal fatal handler that posts a message to the main
	// window so that the UI can shutdown itself on a fatal error instead
	// of calling exit() from a library thread.
	Helper::SetFatalHandler([](const wchar_t* msg) {
		// Log first, then post message to the main UI thread.
		app.GetETW().Log(L"Fatal reported: %s\n", msg);
		::PostMessage(app.GetHwnd(), WM_APP_FATAL, 0, 0);
	});

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
				app.GetETW().Log(L"Hook section mapped and cache populated after %dms\n", waited);
				break;
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(INTERVAL_MS));
			waited += INTERVAL_MS;
		}
		if (!mapped) {
			app.GetETW().Log(L"Hook section mapping failed after %dms; resolver will fall back to per-path IPC\n", MAX_MS);
		}
	}
	LoadProcessList();
	FilterProcessList(L"");

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
					// Extract basename from NT path (last component after '\\' or '/') so
					// the UI displays just the executable name like Process32 snapshot.
					const wchar_t* p = name;
					const wchar_t* last = NULL;
					for (const wchar_t* q = p; *q; ++q) {
						if (*q == L'\\' || *q == L'/') last = q;
					}
					const wchar_t* base = last ? (last + 1) : p;
					// Duplicate the base name for the UI thread to own
					wchar_t* dup = _wcsdup(base);
					l = (LPARAM)dup;
				}
				::PostMessage(hwnd, WM_APP_UPDATE_PROCESS, w, l);
			} else {
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

	// Load and set the Tools menu for the dialog
	if (m_Menu.LoadMenu(IDR_TOOLS_MENU)) {
		SetMenu(&m_Menu);
	}

	app.GetETW().Log(L"dialog init succeed\n");


	return TRUE;  // return TRUE  unless you set the focus to a control
}

LRESULT CUMControllerDlg::OnFatalMessage(WPARAM, LPARAM) {
	// Graceful shutdown triggered from fatal handler.
	app.GetETW().Log(L"OnFatalMessage received, closing dialog.\n");
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
	wchar_t szFile[MAX_PATH] = {0};
	OPENFILENAME ofn = {0};
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
	app.GetETW().Log(L"Executable added to hook list: %s\n", ntPathToSend.c_str());

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
				bool dllLoaded = false; Helper::IsModuleLoaded(mpid, is64 ? MASTER_X64_DLL_BASENAME : MASTER_X86_DLL_BASENAME, dllLoaded);
				DWORD flags = PF_IN_HOOK_LIST;
				if (dllLoaded) flags |= PF_MASTER_DLL_LOADED;
				if (is64) flags |= PF_IS_64BIT;
				PROC_ITEMDATA newPacked = MAKE_ITEMDATA(mpid, flags);
				m_ProcListCtrl.SetItemData(item, (DWORD_PTR)newPacked);
				m_ProcListCtrl.SetItemText(item, 2, FormatHookColumn(newPacked, true).c_str());
			}
		}
	} else {
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
					bool dllLoaded = false; Helper::IsModuleLoaded(e.pid, is64 ? MASTER_X64_DLL_BASENAME : MASTER_X86_DLL_BASENAME, dllLoaded);
					DWORD flags = PF_IN_HOOK_LIST;
					if (dllLoaded) flags |= PF_MASTER_DLL_LOADED;
					if (is64) flags |= PF_IS_64BIT;
					PROC_ITEMDATA newPacked = MAKE_ITEMDATA(e.pid, flags);
					m_ProcListCtrl.SetItemData(item, (DWORD_PTR)newPacked);
					m_ProcListCtrl.SetItemText(item, 2, FormatHookColumn(newPacked, true).c_str());
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
				PROC_ITEMDATA packed = MAKE_ITEMDATA(all[idx].pid, flags);
				int nIndex = m_ProcListCtrl.InsertItem(i, std::to_wstring(all[idx].pid).c_str());
				m_ProcListCtrl.SetItemText(nIndex, 1, all[idx].name.c_str());
				m_ProcListCtrl.SetItemText(nIndex, 2, FormatHookColumn(packed, all[idx].bInHookList).c_str());
				m_ProcListCtrl.SetItemText(nIndex, 3, all[idx].path.c_str());
				m_ProcListCtrl.SetItemText(nIndex, 4, all[idx].cmdline.c_str());
				m_ProcListCtrl.SetItemData(nIndex, (DWORD_PTR)packed);
			i++;
		}
	}
}

void CUMControllerDlg::LoadProcessList() {
	PM_Clear();
	m_ProcListCtrl.DeleteAllItems();

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE) return;

	PROCESSENTRY32 pe32 = { sizeof(pe32) };
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
			entry.bInHookList = false; // will be updated in background
			// Capture process creation time (startTime) if possible to help
			// detect PID reuse. Attempt to open the process briefly.
			HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
			if (h) {
				FILETIME createTime, exitTime, kernelTime, userTime;
				if (GetProcessTimes(h, &createTime, &exitTime, &kernelTime, &userTime)) {
					entry.startTime = createTime;
				}
				CloseHandle(h);
			}
			PM_AddEntry(entry);
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
		int nIndex = m_ProcListCtrl.InsertItem(i, std::to_wstring(all[idx].pid).c_str());
		m_ProcListCtrl.SetItemText(nIndex, 1, all[idx].name.c_str());
		// compute flags and packed itemdata before formatting the hook column
		bool is64 = all[idx].is64;
		bool dllLoaded = all[idx].masterDllLoaded;
		DWORD flags = 0;
		if (all[idx].bInHookList) flags |= PF_IN_HOOK_LIST;
		if (dllLoaded) flags |= PF_MASTER_DLL_LOADED;
		if (is64) flags |= PF_IS_64BIT;
		PROC_ITEMDATA packed = MAKE_ITEMDATA(all[idx].pid, flags);
		m_ProcListCtrl.SetItemText(nIndex, 2, FormatHookColumn(packed, all[idx].bInHookList).c_str());
		m_ProcListCtrl.SetItemText(nIndex, 3, all[idx].path.c_str());
		m_ProcListCtrl.SetItemText(nIndex, 4, all[idx].cmdline.c_str());
		m_ProcListCtrl.SetItemData(nIndex, (DWORD_PTR)packed);
		// ProcessManager already maintains the index mapping
		i++;
	}

	// Start background resolver using ProcessResolver helper
	ProcessResolver::StartLoaderResolver(this, pids, &m_Filter);
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
				entry.name.assign(dup);
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
		} else if (!entry.name.empty()) {
			std::wstring nameLower;
			for (wchar_t c : entry.name) nameLower.push_back(towlower(c));
			if (nameLower.find(filterLower) != std::wstring::npos) showNow = true;
		}
			if (showNow) {
			int newIdx = PM_GetIndex(pid);
			int nIndex = m_ProcListCtrl.InsertItem(newIdx, std::to_wstring(pid).c_str());
			// If the kernel provided a process name in lParam, show it immediately;
			// otherwise display a resolving placeholder while the resolver runs.
			if (!entry.name.empty()) {
				m_ProcListCtrl.SetItemText(nIndex, 1, entry.name.c_str());
			} else {
				m_ProcListCtrl.SetItemText(nIndex, 1, L"(resolving)");
			}
			m_ProcListCtrl.SetItemText(nIndex, 2, FormatHookColumn(MAKE_ITEMDATA(pid, 0), false).c_str());
			m_ProcListCtrl.SetItemText(nIndex, 3, L"");
			m_ProcListCtrl.SetItemText(nIndex, 4, L"");
				// Use cached state (may be default until resolver runs)
				bool is64 = entry.is64;
				bool dllLoaded = entry.masterDllLoaded;
				DWORD flags = 0;
				if (entry.bInHookList) flags |= PF_IN_HOOK_LIST;
				if (dllLoaded) flags |= PF_MASTER_DLL_LOADED;
				if (is64) flags |= PF_IS_64BIT;
				m_ProcListCtrl.SetItemData(nIndex, (DWORD_PTR)MAKE_ITEMDATA(pid, flags));
		}

			// Start resolver for this PID using ProcessResolver helper
			ProcessResolver::StartSingleResolver(this, pid, &m_Filter);

		return 0;
	}

	// Loader or resolver update: wParam contains PID
	if (lParam == UPDATE_SOURCE_LOAD || lParam == UPDATE_SOURCE_NOTIFY) {
		DWORD pid = (DWORD)wParam;
	ProcessEntry e;
	int idx = -1;
	if (!PM_GetEntryCopyByPid((DWORD)wParam, e, &idx)) return 0;
	bool inHook = e.bInHookList;
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
			// Insert new item for this PID
			int newItem = m_ProcListCtrl.InsertItem(idx, std::to_wstring(pid).c_str());
			m_ProcListCtrl.SetItemText(newItem, 1, e.name.c_str());
			m_ProcListCtrl.SetItemText(newItem, 2, FormatHookColumn(MAKE_ITEMDATA(pid, (e.bInHookList?PF_IN_HOOK_LIST:0)), e.bInHookList).c_str());
			m_ProcListCtrl.SetItemText(newItem, 3, e.path.c_str());
			m_ProcListCtrl.SetItemText(newItem, 4, e.cmdline.c_str());
			bool is64=false; Helper::IsProcess64(pid, is64);
			bool dllLoaded=false; Helper::IsModuleLoaded(pid, is64 ? MASTER_X64_DLL_BASENAME : MASTER_X86_DLL_BASENAME, dllLoaded);
			DWORD flags = 0;
			if (e.bInHookList) flags |= PF_IN_HOOK_LIST;
			if (dllLoaded) flags |= PF_MASTER_DLL_LOADED;
			if (is64) flags |= PF_IS_64BIT;
			m_ProcListCtrl.SetItemData(newItem, (DWORD_PTR)MAKE_ITEMDATA(pid, flags));
			item = newItem;
		}

	// compute flags from cached ProcessEntry (is64/master dll) before formatting the column text
		ProcessEntry snapshot;
		int dummyIdx = -1;
		if (!PM_GetEntryCopyByPid(pid, snapshot, &dummyIdx)) return 0;
		bool is64 = snapshot.is64;
		bool dllLoaded = snapshot.masterDllLoaded;
		DWORD flags = 0;
		if (inHook) flags |= PF_IN_HOOK_LIST;
		if (dllLoaded) flags |= PF_MASTER_DLL_LOADED;
		if (is64) flags |= PF_IS_64BIT;
		m_ProcListCtrl.SetItemText(item, 2, FormatHookColumn(MAKE_ITEMDATA(pid, flags), inHook).c_str());
	m_ProcListCtrl.SetItemText(item, 3, path.c_str());
	m_ProcListCtrl.SetItemText(item, 4, cmdline.c_str());
	m_ProcListCtrl.SetItemData(item, (DWORD_PTR)MAKE_ITEMDATA(pid, flags));
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
				m_ProcListCtrl.SetItemText(item, 1, L"(resolving)");
				m_ProcListCtrl.SetItemText(item, 2, L"No");
				m_ProcListCtrl.SetItemText(item, 3, L"");
				m_ProcListCtrl.SetItemText(item, 4, L"");
			}

			// Start resolver for this PID using ProcessResolver helper
			ProcessResolver::StartSingleResolver(this, pid, &m_Filter);

			return 0;
		}
FULL_EXIT:
		// Process truly exited: remove entry via ProcessManager
		ProcessEntry removedCopy;
		PM_RemoveByPid(pid);
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
void CUMControllerDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
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
	menu.AppendMenu(MF_STRING, ID_MENU_ADD_HOOK, L"Add to Hook List");
	// Use single-item remove ID for context menu so Tools->Remove remains the batch dialog
	menu.AppendMenu(MF_STRING, ID_MENU_REMOVE_HOOK_SINGLE, L"Remove from Hook List");
	menu.AppendMenu(MF_STRING, ID_MENU_INJECT_DLL, L"Inject DLL");

	// grey out certai menu based on bInHookList
	DWORD flags = FLAGS_FROM_ITEMDATA(packed);
	bool inHook = (flags & PF_IN_HOOK_LIST) != 0;
	bool dllLoaded = (flags & PF_MASTER_DLL_LOADED) != 0;
	menu.EnableMenuItem(ID_MENU_ADD_HOOK, inHook ? MF_GRAYED : MF_ENABLED);
	menu.EnableMenuItem(ID_MENU_REMOVE_HOOK_SINGLE, inHook ? MF_ENABLED : MF_GRAYED);
	// Only allow injecting the master DLL when the master DLL is already
	// present inside the target process (PF_MASTER_DLL_LOADED).
	menu.EnableMenuItem(ID_MENU_INJECT_DLL, dllLoaded ? MF_ENABLED : MF_GRAYED);


	CPoint point;
	GetCursorPos(&point);
	menu.TrackPopupMenu(TPM_RIGHTBUTTON, point.x, point.y, this);

	*pResult = 0;
}

void CUMControllerDlg::OnRemoveExecutablesFromHookList() {
	CRemoveHookDlg dlg(&m_Filter, this);
	if (dlg.DoModal() == IDOK) {
		// Dialog already performed removals and updated PM
		// Optionally refresh UI here
	}
}
