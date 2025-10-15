
// UMControllerDlg.cpp : implementation file
//

#include "pch.h"
#include "framework.h"
#include "UMController.h"
#include "UMControllerDlg.h"
#include "ProcFlags.h"
#include "afxdialogex.h"
#include "ETW.h"
#include "Helper.h"
#include "FilterCommPort.h"
#include "UMController.h" // for app
#include <unordered_map>
#include <unordered_set>
#include "IPC.h"

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

// Custom message used to signal a fatal error from any thread.
#define WM_APP_FATAL (WM_APP + 0x100)
// Message to update a single process row from background thread.
#define WM_APP_UPDATE_PROCESS (WM_APP + 0x101)
// lParam values for WM_APP_UPDATE_PROCESS to identify the source
#define UPDATE_SOURCE_LOAD 1
#define UPDATE_SOURCE_NOTIFY 2
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
	ON_COMMAND(ID_MENU_REMOVE_HOOK, &CUMControllerDlg::OnRemoveHook)
	ON_COMMAND(ID_MENU_INJECT_DLL, &CUMControllerDlg::OnInjectDll)
	ON_MESSAGE(WM_APP_FATAL, &CUMControllerDlg::OnFatalMessage)
END_MESSAGE_MAP()


// CUMControllerDlg message handlers

BOOL CUMControllerDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();




	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	m_ProcListCtrl.InsertColumn(0, L"PID", LVCFMT_LEFT, 100);
	m_ProcListCtrl.InsertColumn(1, L"Process Name", LVCFMT_LEFT, 200);
	// Column 2: InHookList (Yes/No), Column 3: NT Path, Column 4: Start Params
	m_ProcListCtrl.InsertColumn(2, L"InHookList", LVCFMT_LEFT, 80);
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
		CWnd* pMain = AfxGetMainWnd();
		if (pMain && pMain->GetSafeHwnd()) {
			::PostMessage(pMain->GetSafeHwnd(), WM_APP_FATAL, 0, 0);
		}
	});

	// TODO: Add extra initialization here
	PM_Init();
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

	app.GetETW().Log(L"dialog init succeed\n");


	return TRUE;  // return TRUE  unless you set the focus to a control
}

LRESULT CUMControllerDlg::OnFatalMessage(WPARAM, LPARAM) {
	// Graceful shutdown triggered from fatal handler.
	app.GetETW().Log(L"OnFatalMessage received, closing dialog.\n");
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

}
void CUMControllerDlg::OnRemoveHook() {

}
void CUMControllerDlg::OnInjectDll() {

	// Get selected item PID
	int nItem = m_ProcListCtrl.GetNextItem(-1, LVNI_SELECTED);
	if (nItem == -1) {
		MessageBox(L"Please select a target process first.", L"Inject DLL", MB_OK | MB_ICONINFORMATION);
		return;
	}

	DWORD pid = (DWORD)m_ProcListCtrl.GetItemData(nItem);

	// Show file open dialog for DLL selection
	wchar_t szFile[MAX_PATH] = {0};
	OPENFILENAME ofn = {0};
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = this->GetSafeHwnd();
	ofn.lpstrFile = szFile;
	ofn.nMaxFile = MAX_PATH;
	ofn.lpstrFilter = L"DLL Files\0*.dll\0All Files\0*.*\0";
	ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
	ofn.lpstrTitle = L"Select DLL to inject";

	if (!GetOpenFileName(&ofn)) return;

	// Call IPC_SendInject (UMController/IPC.cpp)
	BOOL ok = IPC_SendInject(pid, szFile);
	if (ok) {
		app.GetETW().Log(L"IPC_SendInject succeeded for pid %u dll %s\n", pid, szFile);
		MessageBox(L"Injection request sent.", L"Inject DLL", MB_OK | MB_ICONINFORMATION);
	} else {
		app.GetETW().Log(L"IPC_SendInject failed for pid %u dll %s\n", pid, szFile);
		MessageBox(L"Failed to send injection request.", L"Inject DLL", MB_OK | MB_ICONERROR);
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
				bool is64=false; Helper::IsProcess64(all[idx].pid, is64);
				bool dllLoaded=false; Helper::IsModuleLoaded(all[idx].pid, is64? MASTER_X64_DLL_BASENAME: MASTER_X86_DLL_BASENAME, dllLoaded);
				DWORD flags = 0;
				if (all[idx].bInHookList) flags |= PF_IN_HOOK_LIST;
				if (dllLoaded) flags |= PF_MASTER_DLL_LOADED;
				if (is64) flags |= PF_IS_64BIT;
				PROC_ITEMDATA packed = MAKE_ITEMDATA(all[idx].pid, flags);
				int nIndex = m_ProcListCtrl.InsertItem(i, std::to_wstring(all[idx].pid).c_str());
				m_ProcListCtrl.SetItemText(nIndex, 1, all[idx].name.c_str());
				m_ProcListCtrl.SetItemText(nIndex, 2, all[idx].bInHookList ? L"Yes" : L"No");
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

	// Populate the UI quickly with PID and name only
	int i = 0;
	auto all = PM_GetAll();
	for (size_t idx = 0; idx < all.size(); idx++) {
		int nIndex = m_ProcListCtrl.InsertItem(i, std::to_wstring(all[idx].pid).c_str());
		m_ProcListCtrl.SetItemText(nIndex, 1, all[idx].name.c_str());
		m_ProcListCtrl.SetItemText(nIndex, 2, all[idx].bInHookList ? L"Yes" : L"No");
		m_ProcListCtrl.SetItemText(nIndex, 3, all[idx].path.c_str());
		m_ProcListCtrl.SetItemText(nIndex, 4, all[idx].cmdline.c_str());
		bool is64=false; Helper::IsProcess64(all[idx].pid, is64);
		bool dllLoaded=false; Helper::IsModuleLoaded(all[idx].pid, is64 ? MASTER_X64_DLL_BASENAME : MASTER_X86_DLL_BASENAME, dllLoaded);
		DWORD flags = 0;
		if (all[idx].bInHookList) flags |= PF_IN_HOOK_LIST;
		if (dllLoaded) flags |= PF_MASTER_DLL_LOADED;
		if (is64) flags |= PF_IS_64BIT;
		PROC_ITEMDATA packed = MAKE_ITEMDATA(all[idx].pid, flags);
		m_ProcListCtrl.SetItemData(nIndex, (DWORD_PTR)packed);
		// ProcessManager already maintains the index mapping
		i++;
	}

	// Start background thread to resolve details (NT path, hook membership, cmdline)
	// Use a stable snapshot of PIDs so the resolver won't race with list mutations.
	std::vector<DWORD> loaderPids = pids; // copy snapshot captured earlier
	std::thread([this, loaderPids]() {
		for (DWORD pid : loaderPids) {
			std::wstring ntPath;
			// Call ResolveProcessNtImagePath exactly once. If it returns false,
			// assume the target process exited while resolving and post an exit
			// message so the existing exit handling will remove the entry.
			bool havePath = Helper::ResolveProcessNtImagePath(pid, m_Filter, ntPath);
			if (!havePath) {
				// app.GetETW().Log(L"process %d terminated during we resolving its ntpath\n", pid);
				// Post an exit to trigger removal of any transient entry
				::PostMessage(this->GetSafeHwnd(), WM_APP_UPDATE_PROCESS, (WPARAM)pid, 0);
				continue;
			}

			bool inHook = m_Filter.FLTCOMM_CheckHookList(ntPath);
			std::wstring cmdline;
			Helper::GetProcessCommandLineByPID(pid, cmdline);

			// Update shared data via ProcessManager
			PM_UpdateEntryFields(pid, ntPath, inHook, cmdline);

			// Post update to UI thread for this PID (from initial loader)
			::PostMessage(this->GetSafeHwnd(), WM_APP_UPDATE_PROCESS, (WPARAM)pid, (LPARAM)UPDATE_SOURCE_LOAD);
		}
	}).detach();
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
			m_ProcListCtrl.SetItemText(nIndex, 2, L"No");
			m_ProcListCtrl.SetItemText(nIndex, 3, L"");
			m_ProcListCtrl.SetItemText(nIndex, 4, L"");
			bool is64=false; Helper::IsProcess64(pid, is64);
			bool dllLoaded=false; Helper::IsModuleLoaded(pid, is64 ? MASTER_X64_DLL_BASENAME : MASTER_X86_DLL_BASENAME, dllLoaded);
			DWORD flags = 0;
			if (entry.bInHookList) flags |= PF_IN_HOOK_LIST;
			if (dllLoaded) flags |= PF_MASTER_DLL_LOADED;
			if (is64) flags |= PF_IS_64BIT;
			m_ProcListCtrl.SetItemData(nIndex, (DWORD_PTR)MAKE_ITEMDATA(pid, flags));
		}

			// Resolver thread: single-call resolver
		std::thread([this, pid]() {
			std::wstring ntPath;
			// Single attempt: if resolve fails, assume process exited while resolving
			if (!Helper::ResolveProcessNtImagePath(pid, m_Filter, ntPath)) { 
				// app.GetETW().Log(L"process %d terminated during we resolving its ntpath\n", pid);
				::PostMessage(this->GetSafeHwnd(), WM_APP_UPDATE_PROCESS, (WPARAM)pid, 0);
				return;
			}
			bool inHook = m_Filter.FLTCOMM_CheckHookList(ntPath);
			std::wstring cmdline;
			Helper::GetProcessCommandLineByPID(pid, cmdline);

			PM_UpdateEntryFields(pid, ntPath, inHook, cmdline);

			::PostMessage(this->GetSafeHwnd(), WM_APP_UPDATE_PROCESS, (WPARAM)pid, (LPARAM)UPDATE_SOURCE_NOTIFY);
		}).detach();

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
			m_ProcListCtrl.SetItemText(newItem, 2, e.bInHookList ? L"Yes" : L"No");
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

		m_ProcListCtrl.SetItemText(item, 2, inHook ? L"Yes" : L"No");
		m_ProcListCtrl.SetItemText(item, 3, path.c_str());
		m_ProcListCtrl.SetItemText(item, 4, cmdline.c_str());
		// refresh flags
		bool is64=false; Helper::IsProcess64(pid, is64);
		bool dllLoaded=false; Helper::IsModuleLoaded(pid, is64 ? MASTER_X64_DLL_BASENAME : MASTER_X86_DLL_BASENAME, dllLoaded);
		DWORD flags = 0;
		if (inHook) flags |= PF_IN_HOOK_LIST;
		if (dllLoaded) flags |= PF_MASTER_DLL_LOADED;
		if (is64) flags |= PF_IS_64BIT;
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
			// app.GetETW().Log(L"OnUpdateProcess detected early terminate notification, spawning waiter for pid: %d\n", pid);
			if (PM_TryReserveExitWaiter(pid)) {
				std::thread([this, pid]() {
					const int MAX_WAIT_MS = 2000; // 2s max
					const int SLEEP_MS = 50;
					int waited = 0;
					while (waited < MAX_WAIT_MS) {
						HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
						if (!h) break; // process gone
						CloseHandle(h);
						std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_MS));
						waited += SLEEP_MS;
					}
					PM_ReleaseExitWaiter(pid);
					// Post exit to trigger removal path
					// ::PostMessage(this->GetSafeHwnd(), WM_APP_UPDATE_PROCESS, (WPARAM)pid, 0);
				}).detach();
				goto FULL_EXIT;
			}
			return 0;
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

			// Start resolver thread for this PID (same as create handler)
			std::thread([this, pid]() {
				std::wstring ntPath;
				if (!Helper::ResolveProcessNtImagePath(pid, m_Filter, ntPath)) {
					// app.GetETW().Log(L"process %d terminated during we resolving its ntpath\n", pid);
					::PostMessage(this->GetSafeHwnd(), WM_APP_UPDATE_PROCESS, (WPARAM)pid, 0);
					return;
				}
				bool inHook = m_Filter.FLTCOMM_CheckHookList(ntPath);
				std::wstring cmdline;
				Helper::GetProcessCommandLineByPID(pid, cmdline);

				// Update shared structures via ProcessManager
				PM_UpdateEntryFields(pid, ntPath, inHook, cmdline);

				::PostMessage(this->GetSafeHwnd(), WM_APP_UPDATE_PROCESS, (WPARAM)pid, (LPARAM)UPDATE_SOURCE_NOTIFY);
			}).detach();

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
//  the minimized window.
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
	menu.AppendMenu(MF_STRING, ID_MENU_REMOVE_HOOK, L"Remove from Hook List");
	menu.AppendMenu(MF_STRING, ID_MENU_INJECT_DLL, L"Inject DLL");

	// grey out certai menu based on bInHookList
	DWORD flags = FLAGS_FROM_ITEMDATA(packed);
	bool inHook = (flags & PF_IN_HOOK_LIST) != 0;
	bool dllLoaded = (flags & PF_MASTER_DLL_LOADED) != 0;
	menu.EnableMenuItem(ID_MENU_ADD_HOOK, inHook ? MF_GRAYED : MF_ENABLED);
	menu.EnableMenuItem(ID_MENU_REMOVE_HOOK, inHook ? MF_ENABLED : MF_GRAYED);
	menu.EnableMenuItem(ID_MENU_INJECT_DLL, inHook ? MF_ENABLED : MF_GRAYED);


	CPoint point;
	GetCursorPos(&point);
	menu.TrackPopupMenu(TPM_RIGHTBUTTON, point.x, point.y, this);

	*pResult = 0;
}
