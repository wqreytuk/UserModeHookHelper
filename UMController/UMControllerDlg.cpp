
// UMControllerDlg.cpp : implementation file
//

#include "pch.h"
#include "framework.h"
#include "UMController.h"
#include "UMControllerDlg.h"
#include "afxdialogex.h"
#include "ETW.h"
#include "Helper.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

std::vector<ProcessEntry> g_ProcessList;

#include "UMController.h" // for app

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
	int idx1 = (int)lParam1;
	int idx2 = (int)lParam2;

	// Validate indices
	if (idx1 < 0 || idx1 >= (int)g_ProcessList.size() || idx2 < 0 || idx2 >= (int)g_ProcessList.size())
		return 0;

	const ProcessEntry &a = g_ProcessList[idx1];
	const ProcessEntry &b = g_ProcessList[idx2];

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
BEGIN_MESSAGE_MAP(CUMControllerDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_EN_CHANGE(IDC_EDIT_SEARCH, &CUMControllerDlg::OnEnChangeEditSearch)
	ON_NOTIFY(NM_RCLICK, IDC_LIST_PROC, &CUMControllerDlg::OnNMRClickListProc)
	ON_NOTIFY(LVN_COLUMNCLICK, IDC_LIST_PROC, &CUMControllerDlg::OnLvnColumnclickListProc)
	ON_MESSAGE(WM_APP_UPDATE_PROCESS, &CUMControllerDlg::OnUpdateProcess)
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
	LoadProcessList();
	FilterProcessList(L"");

	app.GetETW().Log(L"dialog init succeed\n");


	return TRUE;  // return TRUE  unless you set the focus to a control
}

LRESULT CUMControllerDlg::OnFatalMessage(WPARAM, LPARAM) {
	// Graceful shutdown triggered from fatal handler.
	app.GetETW().Log(L"OnFatalMessage received, closing dialog.\n");
	EndDialog(IDCANCEL);
	return 0;
}


void CUMControllerDlg::OnAddHook() {

}
void CUMControllerDlg::OnRemoveHook() {

}
void CUMControllerDlg::OnInjectDll() {


}

void CUMControllerDlg::FilterProcessList(const std::wstring& filter) {
	m_ProcListCtrl.DeleteAllItems();

	int i = 0;
	// Prepare lower-case filter for case-insensitive search
	std::wstring filterLower;
	filterLower.reserve(filter.size());
	for (wchar_t c : filter) filterLower.push_back(towlower(c));

	for (size_t idx = 0; idx < g_ProcessList.size(); idx++) {
		std::wstring nameLower;
		nameLower.reserve(g_ProcessList[idx].name.size());
		for (wchar_t c : g_ProcessList[idx].name) nameLower.push_back(towlower(c));

		if (filter.empty() || nameLower.find(filterLower) != std::wstring::npos) {
				// Insert PID in column 0, process name in column 1, InHookList in column 2,
				// NT Path in column 3 and Start Params in column 4
				int nIndex = m_ProcListCtrl.InsertItem(i, std::to_wstring(g_ProcessList[idx].pid).c_str());
				m_ProcListCtrl.SetItemText(nIndex, 1, g_ProcessList[idx].name.c_str());
				m_ProcListCtrl.SetItemText(nIndex, 2, g_ProcessList[idx].bInHookList ? L"Yes" : L"No");
				m_ProcListCtrl.SetItemText(nIndex, 3, g_ProcessList[idx].path.c_str());
				m_ProcListCtrl.SetItemText(nIndex, 4, g_ProcessList[idx].cmdline.c_str());

			// save idx of g_ProcessList vector, so we know if this entry is in hook list
			// in right click menu handler
			m_ProcListCtrl.SetItemData(nIndex, (DWORD_PTR)idx);
			i++;
		}
	}
}

void CUMControllerDlg::LoadProcessList() {
	g_ProcessList.clear();
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
			g_ProcessList.push_back(entry);
		} while (Process32Next(snapshot, &pe32));
	}

	CloseHandle(snapshot);

	// Populate the UI quickly with PID and name only
	int i = 0;
	for (size_t idx = 0; idx < g_ProcessList.size(); idx++) {
		int nIndex = m_ProcListCtrl.InsertItem(i, std::to_wstring(g_ProcessList[idx].pid).c_str());
		m_ProcListCtrl.SetItemText(nIndex, 1, g_ProcessList[idx].name.c_str());
		m_ProcListCtrl.SetItemText(nIndex, 2, g_ProcessList[idx].bInHookList ? L"Yes" : L"No");
		m_ProcListCtrl.SetItemText(nIndex, 3, g_ProcessList[idx].path.c_str());
		m_ProcListCtrl.SetItemText(nIndex, 4, g_ProcessList[idx].cmdline.c_str());
		m_ProcListCtrl.SetItemData(nIndex, (DWORD_PTR)idx);
		i++;
	}

	// Start background thread to resolve details (NT path, hook membership, cmdline)
	std::thread([this]() {
		for (size_t idx = 0; idx < g_ProcessList.size(); idx++) {
			ProcessEntry& entry = g_ProcessList[idx];
			std::wstring ntPath;
			if (Helper::ResolveProcessNtImagePath(entry.pid, m_Filter, ntPath)) {
				entry.path = ntPath;
				entry.bInHookList = m_Filter.FLTCOMM_CheckHookList(ntPath);
			} else {
				entry.path.clear();
				entry.bInHookList = false;
			}

			std::wstring cmdline;
			if (Helper::GetProcessCommandLineByPID(entry.pid, cmdline)) {
				entry.cmdline = cmdline;
			} else {
				entry.cmdline.clear();
			}

			// Post update to UI thread for this entry index
			::PostMessage(this->GetSafeHwnd(), WM_APP_UPDATE_PROCESS, (WPARAM)idx, 0);
		}
	}).detach();
}

LRESULT CUMControllerDlg::OnUpdateProcess(WPARAM wParam, LPARAM lParam) {
	int idx = (int)wParam;
	if (idx < 0 || idx >= (int)g_ProcessList.size()) return 0;
	// Find the list item with ItemData == idx
	int item = m_ProcListCtrl.GetNextItem(-1, LVNI_ALL);
	while (item != -1) {
		if ((int)m_ProcListCtrl.GetItemData(item) == idx) break;
		item = m_ProcListCtrl.GetNextItem(item, LVNI_ALL);
	}
	if (item == -1) return 0;

	m_ProcListCtrl.SetItemText(item, 2, g_ProcessList[idx].bInHookList ? L"Yes" : L"No");
	m_ProcListCtrl.SetItemText(item, 3, g_ProcessList[idx].path.c_str());
	m_ProcListCtrl.SetItemText(item, 4, g_ProcessList[idx].cmdline.c_str());
	return 0;
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

	int idx = (int)m_ProcListCtrl.GetItemData(nItem);
	auto& item = g_ProcessList[idx];


	CMenu menu;
	menu.CreatePopupMenu();
	menu.AppendMenu(MF_STRING, ID_MENU_ADD_HOOK, L"Add to Hook List");
	menu.AppendMenu(MF_STRING, ID_MENU_REMOVE_HOOK, L"Remove from Hook List");
	menu.AppendMenu(MF_STRING, ID_MENU_INJECT_DLL, L"Inject DLL");

	// grey out certai menu based on bInHookList
	menu.EnableMenuItem(ID_MENU_ADD_HOOK, item.bInHookList ? MF_GRAYED : MF_ENABLED);
	menu.EnableMenuItem(ID_MENU_REMOVE_HOOK, item.bInHookList ? MF_ENABLED : MF_GRAYED);
	menu.EnableMenuItem(ID_MENU_INJECT_DLL, item.bInHookList ? MF_ENABLED : MF_GRAYED);


	CPoint point;
	GetCursorPos(&point);
	menu.TrackPopupMenu(TPM_RIGHTBUTTON, point.x, point.y, this);

	*pResult = 0;
}
