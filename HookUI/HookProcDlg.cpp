// Clean, corrected implementation with multi-column sorting support

#include "HookProcDlg.h"
#include "../Shared/LogMacros.h"
#include "../Shared/HookRow.h"
#include <tlhelp32.h>
#include <cwchar>
#include <cwctype>
#include <CommCtrl.h> // for EM_SETCUEBANNER
#include <afxdlgs.h> // CFileDialog
#include "../HookCoreLib/HookCore.h"
#include "../UMController/Helper.h"
#include "../UMController/RegistryStore.h"
#include "../Shared/HookRow.h"
#include "../Shared/SharedMacroDef.h"
static std::wstring Hex64(ULONGLONG v) {
    wchar_t buf[32];
    _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"%llX", v);
    return buf;
}

static void CopyTextToClipboard(const CString& text, HWND owner) {
    if (text.IsEmpty()) return;
    if (::OpenClipboard(owner)) {
        EmptyClipboard();
        size_t len = (text.GetLength() + 1) * sizeof(wchar_t);
        HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, len);
        if (h) {
            void* p = GlobalLock(h);
            if (p) {
                memcpy(p, (LPCWSTR)text.GetString(), len);
                GlobalUnlock(h);
                SetClipboardData(CF_UNICODETEXT, h);
            }
            else {
                GlobalFree(h);
            }
        }
        ::CloseClipboard();
    }
}

const UINT HookProcDlg::kMsgHookDlgDestroyed = WM_APP + 0x701;

BEGIN_MESSAGE_MAP(HookProcDlg, CDialogEx)
    ON_BN_CLICKED(IDC_HOOKUI_BTN_APPLY, &HookProcDlg::OnBnClickedApplyHook)
    ON_WM_SIZE()
    ON_WM_CONTEXTMENU()
    ON_WM_LBUTTONDOWN()
    ON_WM_LBUTTONUP()
    ON_WM_MOUSEMOVE()
    ON_WM_GETMINMAXINFO()
    ON_NOTIFY(LVN_COLUMNCLICK, IDC_HOOKUI_LIST_MODULES, &HookProcDlg::OnColumnClickModules)
    ON_NOTIFY(LVN_ITEMCHANGED, IDC_HOOKUI_LIST_MODULES, &HookProcDlg::OnModuleItemChanged)
    ON_EN_SETFOCUS(IDC_HOOKUI_EDIT_OFFSET, &HookProcDlg::OnEnSetFocusOffset)
    ON_EN_SETFOCUS(IDC_HOOKUI_EDIT_DIRECT, &HookProcDlg::OnEnSetFocusDirect)
    ON_NOTIFY(NM_CUSTOMDRAW, IDC_HOOKUI_LIST_MODULES, &HookProcDlg::OnCustomDrawModules)
END_MESSAGE_MAP()

HookProcDlg::HookProcDlg(DWORD pid, const std::wstring& name, IHookServices* services, CWnd* parent)
    : CDialogEx(IDD_HOOKUI_PROC_DLG, parent), m_pid(pid), m_name(name), m_services(services) {}

BOOL HookProcDlg::CreateModeless(CWnd* parent) { return Create(IDD_HOOKUI_PROC_DLG, parent); }

BOOL HookProcDlg::OnInitDialog() {
    CDialogEx::OnInitDialog();
    CString title; title.Format(L"Hook Process PID %lu - %s", m_pid, m_name.c_str());
    SetWindowText(title);
    m_ModuleList.Attach(GetDlgItem(IDC_HOOKUI_LIST_MODULES)->m_hWnd);
    m_ModuleList.InsertColumn(0, L"Base", LVCFMT_LEFT, 80);
    m_ModuleList.InsertColumn(1, L"Size", LVCFMT_LEFT, 70);
    m_ModuleList.InsertColumn(2, L"Name", LVCFMT_LEFT, 140);
    m_ModuleList.InsertColumn(3, L"Path", LVCFMT_LEFT, 300);
    m_ModuleList.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
    LONG lvStyle = ::GetWindowLong(m_ModuleList.GetSafeHwnd(), GWL_STYLE);
    lvStyle |= LVS_SHOWSELALWAYS; ::SetWindowLong(m_ModuleList.GetSafeHwnd(), GWL_STYLE, lvStyle);
    ::SetWindowPos(m_ModuleList.GetSafeHwnd(), nullptr, 0,0,0,0, SWP_NOMOVE|SWP_NOSIZE|SWP_NOZORDER|SWP_FRAMECHANGED);
    PopulateModuleList();
    // Hook list initialization
    m_HookList.Attach(GetDlgItem(IDC_HOOKUI_LIST_HOOKS)->m_hWnd);
    m_HookList.InsertColumn(0, L"Hook ID", LVCFMT_LEFT, 80);
    m_HookList.InsertColumn(1, L"Address", LVCFMT_LEFT, 100);
    m_HookList.InsertColumn(2, L"Module", LVCFMT_LEFT, 180);
    m_HookList.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    PopulateHookList();
    // Load persisted hook rows for this PID (use PID + startTime key stored by controller)
    // Attempt to obtain process creation FILETIME to form the key components
    FILETIME createTime{0,0};
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, m_pid);
    if (h) {
        FILETIME exitTime, kernelTime, userTime;
        if (GetProcessTimes(h, &createTime, &exitTime, &kernelTime, &userTime)) {
            // success
        }
        CloseHandle(h);
    }
    // If createTime is zero, we still attempt load with hi/lo = 0
    DWORD hi = createTime.dwHighDateTime;
    DWORD lo = createTime.dwLowDateTime;
    std::vector<HookRow> persisted;
    if (m_services && m_services->LoadProcHookList(m_pid, hi, lo, persisted)) {
        for (auto &pr : persisted) {
            // controller returns HookRow populated; we still need to verify PID+FILETIME
            // For backward-compatibility the controller should only return rows for this PID+FILETIME.
            // We'll accept any returned HookRow and add those matching m_pid.
            // Note: If the controller uses a combined key, it may choose to return only matching rows.
            // restore row preserving hook id
            if (pr.id == -1) continue; // skip invalid
            HookRow* hr = new HookRow(pr);
            // If caller didn't populate ori_asm_code_addr, it will be zero.
            CString idC; idC.Format(L"%d", hr->id);
            CString addrC; addrC.Format(L"0x%llX", hr->address);
            int idx = m_HookList.GetItemCount();
            int i = m_HookList.InsertItem(idx, idC);
            m_HookList.SetItemText(i, 1, addrC);
            m_HookList.SetItemText(i, 2, hr->module.c_str());
            m_HookList.SetItemData(i, (DWORD_PTR)hr);
            if (hr->id >= m_nextHookId) m_nextHookId = hr->id + 1;
        }
    }
    // apply initial splitter
    CRect rc; GetClientRect(&rc); UpdateLayoutForSplitter(rc.Width(), rc.Height());
    // preview banner removed for cleaner UI
    return TRUE;
}

void HookProcDlg::OnDestroy() {
    FreeModuleRows();
    FreeHookRows();
    m_ModuleList.DeleteAllItems();
    m_HookList.DeleteAllItems();
    m_ModuleList.Detach();
    CDialogEx::OnDestroy();
    if (CWnd* parent = GetParent()) {
        ::PostMessage(parent->GetSafeHwnd(), HookProcDlg::kMsgHookDlgDestroyed, (WPARAM)this, 0);
    }
}

void HookProcDlg::UpdateLayoutForSplitter(int cx, int cy) {
    const int margin = 7;
    int leftWidth = m_splitPos; if (leftWidth < 120) leftWidth = 120; if (leftWidth > cx - 160) leftWidth = cx - 160;
    int listTop = margin + 11;
    int listHeight = cy - listTop - 20; if (listHeight < 80) listHeight = 80;
    m_ModuleList.MoveWindow(margin, listTop, leftWidth, listHeight);
    int panelX = margin + leftWidth + margin;
    auto moveCtrl = [&](int id, int x, int y, int w, int h) { CWnd* c = GetDlgItem(id); if (c) c->MoveWindow(x, y, w, h); };
    moveCtrl(IDC_HOOKUI_STATIC_OFFSET, panelX, 18, 70, 14);
    moveCtrl(IDC_HOOKUI_EDIT_OFFSET, panelX, 30, 140, 18);
    moveCtrl(IDC_HOOKUI_STATIC_DIRECT, panelX, 55, 140, 14);
    moveCtrl(IDC_HOOKUI_EDIT_DIRECT, panelX, 67, 140, 18);
    int applyY = 100; int btnW = 65; moveCtrl(IDC_HOOKUI_BTN_APPLY, panelX, applyY, btnW, 22); moveCtrl(IDCANCEL, panelX + btnW + 5, applyY, btnW, 22);
    int hooksY = applyY + 24;
    int hooksW = cx - panelX - margin; int hooksH = listTop + listHeight - hooksY; if (hooksH < 40) hooksH = 40;
    moveCtrl(IDC_HOOKUI_LIST_HOOKS, panelX, hooksY, hooksW, hooksH);
}

void HookProcDlg::OnLButtonDown(UINT nFlags, CPoint point) {
    CRect rc; GetClientRect(&rc);
    int rightPanelLeft = m_splitPos + 14; CRect splRect(rightPanelLeft - m_splitterWidth, 0, rightPanelLeft + m_splitterWidth, rc.Height());
    if (splRect.PtInRect(point)) { m_draggingSplitter = true; SetCapture(); }
    CDialogEx::OnLButtonDown(nFlags, point);
}

void HookProcDlg::OnLButtonUp(UINT nFlags, CPoint point) {
    if (m_draggingSplitter) { m_draggingSplitter = false; ReleaseCapture(); }
    CDialogEx::OnLButtonUp(nFlags, point);
}

void HookProcDlg::OnMouseMove(UINT nFlags, CPoint point) {
    if (m_draggingSplitter) {
        int newLeft = point.x - 7; m_splitPos = newLeft; CRect rc; GetClientRect(&rc); UpdateLayoutForSplitter(rc.Width(), rc.Height());
    } else {
        int rightPanelLeft = m_splitPos + 14; CRect splRect(rightPanelLeft - m_splitterWidth, 0, rightPanelLeft + m_splitterWidth, 10000);
        if (splRect.PtInRect(point)) SetCursor(::LoadCursor(NULL, IDC_SIZEWE));
    }
    CDialogEx::OnMouseMove(nFlags, point);
}

void HookProcDlg::PopulateHookList() {
    m_HookList.DeleteAllItems();
    // TODO: read persisted hooks for this pid or wire live update.
}

int HookProcDlg::AddHookEntry(const HookRow& row) {
    int idx = m_HookList.GetItemCount();
    int useId = row.id;
    if (useId == -1) useId = m_nextHookId++;
    CString idC; idC.Format(L"%d", useId);
    CString addrC; addrC.Format(L"0x%llX", row.address);
    CString useIdC; useIdC.Format(L"%d", useId);
    int i = m_HookList.InsertItem(idx, useIdC);
    m_HookList.SetItemText(i, 1, addrC);
    m_HookList.SetItemText(i, 2, row.module.c_str());
    // Allocate a HookRow copy and attach to the list item so we can later locate by address
    HookRow* hr = new HookRow(row);
    hr->id = useId;
    m_HookList.SetItemData(i, (DWORD_PTR)hr);
    // Persist updated list for this PID using RegistryStore
    // Build entries vector and write
    FILETIME createTime{0,0}; HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, m_pid);
    if (h) { FILETIME et,k,u; if (GetProcessTimes(h, &createTime, &et, &k, &u)) { } CloseHandle(h); }
    DWORD hi = createTime.dwHighDateTime; DWORD lo = createTime.dwLowDateTime;
    std::vector<HookRow*> rows;
    int count = m_HookList.GetItemCount();
    for (int j = 0; j < count; ++j) {
        HookRow* r = reinterpret_cast<HookRow*>(m_HookList.GetItemData(j));
        if (!r) continue;
        rows.push_back(r);
        if (r->id >= m_nextHookId) m_nextHookId = r->id + 1;
    }
    if (m_services) {
        // Convert vector<HookRow*> to vector<HookRow> for service
        std::vector<HookRow> outRows; outRows.reserve(rows.size());
        for (auto pr : rows) if (pr) outRows.push_back(*pr);
        m_services->SaveProcHookList(m_pid,hi,lo,outRows);
    }
    return i;
}

void HookProcDlg::PopulateModuleList() {
    FreeModuleRows();
    m_ModuleList.DeleteAllItems();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, m_pid);
    if (snap == INVALID_HANDLE_VALUE) return;
    MODULEENTRY32 me = { sizeof(me) };
    int i = 0;
    if (Module32First(snap, &me)) {
        do {
            int idx = m_ModuleList.InsertItem(i, (std::wstring(L"0x") + Hex64((ULONGLONG)me.modBaseAddr)).c_str());
            m_ModuleList.SetItemText(idx, 1, (std::wstring(L"0x") + Hex64((ULONGLONG)me.modBaseSize)).c_str());
            m_ModuleList.SetItemText(idx, 2, me.szModule);
            m_ModuleList.SetItemText(idx, 3, me.szExePath);
            ModuleRow* row = new ModuleRow{ (ULONGLONG)me.modBaseAddr,(ULONGLONG)me.modBaseSize, me.szModule, me.szExePath };
            m_ModuleList.SetItemData(idx, (DWORD_PTR)row);
            i++;
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
}

bool HookProcDlg::GetSelectedModule(std::wstring& name, ULONGLONG& base) const {
    int sel = m_ModuleList.GetNextItem(-1, LVNI_SELECTED);
    if (sel == -1) return false;
    ModuleRow* row = reinterpret_cast<ModuleRow*>(m_ModuleList.GetItemData(sel));
    if(!row) return false;
    name = row->name;
    base = row->base;
    return true;
}

int CALLBACK HookProcDlg::ModuleCompare(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort){
    HookProcDlg* self=reinterpret_cast<HookProcDlg*>(lParamSort); if(!self) return 0;
    ModuleRow* r1=reinterpret_cast<ModuleRow*>(lParam1); ModuleRow* r2=reinterpret_cast<ModuleRow*>(lParam2);
    if(!r1||!r2) return 0;
    int r=0;
    switch(self->m_sortColumn){
    case 0: r = (r1->base<r2->base)?-1:(r1->base>r2->base?1:0); break; // Base
    case 1: r = (r1->size<r2->size)?-1:(r1->size>r2->size?1:0); break; // Size
    case 2: r = _wcsicmp(r1->name.c_str(), r2->name.c_str()); break; // Name
    case 3: r = _wcsicmp(r1->path.c_str(), r2->path.c_str()); break; // Path
    default: r=0; break;
    }
    if(!self->m_sortAscending) r = -r;
    return r;
}

void HookProcDlg::OnColumnClickModules(NMHDR* pNMHDR, LRESULT* pResult) {
    LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
    int col = pNMLV->iSubItem;
    if (m_sortColumn == col) m_sortAscending = !m_sortAscending; else { m_sortColumn = col; m_sortAscending = true; }
    m_ModuleList.SortItems(ModuleCompare, (LPARAM)this);
    if (pResult) *pResult = 0;
}

void HookProcDlg::FreeModuleRows(){
    int count = m_ModuleList.GetItemCount();
    for(int i=0;i<count;i++){
        ModuleRow* row=reinterpret_cast<ModuleRow*>(m_ModuleList.GetItemData(i));
        if(row){ delete row; }
        m_ModuleList.SetItemData(i,0);
    }
}

void HookProcDlg::FreeHookRows() {
    int count = m_HookList.GetItemCount();
    for (int i = 0; i < count; ++i) {
        HookRow* hr = reinterpret_cast<HookRow*>(m_HookList.GetItemData(i));
        if (hr) delete hr;
        m_HookList.SetItemData(i, 0);
    }
}

void HookProcDlg::OnContextMenu(CWnd* pWnd, CPoint point) {
    // Translate screen point to client and hit-test the hook list
    if (!m_HookList.GetSafeHwnd()) return;
    CPoint clientPoint = point;
    m_HookList.ScreenToClient(&clientPoint);
    LVHITTESTINFO ht = {0}; ht.pt = clientPoint;
    int item = m_HookList.HitTest(&ht);
    if (item == -1) return; // click not on an item

    CMenu menu; menu.CreatePopupMenu();
    const UINT CMD_DISABLE = 0x8001;
    const UINT CMD_ENABLE = 0x8002;
    const UINT CMD_REMOVE = 0x8003;
    const UINT CMD_COPY_ADDR = 0x8004;
    menu.AppendMenuW(MF_STRING, CMD_DISABLE, L"Disable");
    menu.AppendMenuW(MF_STRING, CMD_ENABLE, L"Enable");
    menu.AppendMenuW(MF_STRING, CMD_REMOVE, L"Remove");
    menu.AppendMenuW(MF_SEPARATOR, 0, (LPCTSTR)NULL);
    menu.AppendMenuW(MF_STRING, CMD_COPY_ADDR, L"Copy Address");

    // Determine whether the row is currently disabled (we mark it by prefixing module with "[DISABLED] ")
    bool isDisabled = false;
    HookRow* testHr = reinterpret_cast<HookRow*>(m_HookList.GetItemData(item));
    if (testHr) {
        if (testHr->module.rfind(L"[DISABLED] ", 0) == 0) isDisabled = true;
    }

    CString addrText = m_HookList.GetItemText(item, 1);

    // Only enable the relevant action: if disabled -> Enable is active; else Disable is active.
    menu.EnableMenuItem(CMD_DISABLE, MF_BYCOMMAND | (isDisabled ? MF_GRAYED : MF_ENABLED));
    menu.EnableMenuItem(CMD_ENABLE, MF_BYCOMMAND | (isDisabled ? MF_ENABLED : MF_GRAYED));
    menu.EnableMenuItem(CMD_COPY_ADDR, MF_BYCOMMAND | (!addrText.IsEmpty() ? MF_ENABLED : MF_GRAYED));

    // Store selected item index in window userdata so handlers can find it
    SetWindowLongPtr(m_hWnd, GWLP_USERDATA, (LONG_PTR)item);

    // Display the menu and dispatch command to our handlers
    int cmd = menu.TrackPopupMenu(TPM_LEFTALIGN | TPM_RETURNCMD | TPM_RIGHTBUTTON, point.x, point.y, this);
    if (cmd == 0) return;

    switch (cmd) {
    case 0x8001: OnHookMenuDisable(); break;
    case 0x8002: OnHookMenuEnable(); break;
    case 0x8003: OnHookMenuRemove(); break;
    case 0x8004:
        CopyTextToClipboard(addrText, this->GetSafeHwnd());
        break;
    }
}


// Handlers: left as stubs for user implementation
void HookProcDlg::OnHookMenuDisable() {
    int item = (int)GetWindowLongPtr(m_hWnd, GWLP_USERDATA);
    if (item < 0 || item >= m_HookList.GetItemCount()) return;
    HookRow* hr = reinterpret_cast<HookRow*>(m_HookList.GetItemData(item));
    if (!hr) return;
    // UI-only: mark disabled (prepend [DISABLED] to module text)
    std::wstring mod = hr->module;
    if (mod.find(L"[DISABLED]") == std::wstring::npos) {
        mod = std::wstring(L"[DISABLED] ") + mod;
        hr->module = mod;
        m_HookList.SetItemText(item, 2, mod.c_str());
    }
	
   
	if (!HookCore::DisableHook(m_pid, hr->address, m_services, (PVOID)hr->ori_asm_code_addr, hr->ori_asm_code_len)) {
		LOG_UI(m_services, L"failed to call HookCore::DisableHook\n");
		MessageBoxW(L"failed to call HookCore::DisableHook\n", L"Hook", MB_OK | MB_ICONERROR);
		return;
	}

	// Persist change
	FILETIME createTime{ 0,0 }; HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, m_pid);
	if (h) { FILETIME et, k, u; if (GetProcessTimes(h, &createTime, &et, &k, &u)) {} CloseHandle(h); }
	DWORD hi = createTime.dwHighDateTime; DWORD lo = createTime.dwLowDateTime;
	std::vector<HookRow*> rows;
	int count = m_HookList.GetItemCount();
	for (int j = 0; j < count; ++j) {
		HookRow* r = reinterpret_cast<HookRow*>(m_HookList.GetItemData(j));
		if (!r) continue;
		rows.push_back(r);
		if (r->id >= m_nextHookId) m_nextHookId = r->id + 1;
	}
	if (m_services) {
		// Convert vector<HookRow*> to vector<HookRow> for service
		std::vector<HookRow> outRows; outRows.reserve(rows.size());
		for (auto pr : rows) if (pr) outRows.push_back(*pr);
		m_services->SaveProcHookList(m_pid,hi,lo,outRows);
	}
}

void HookProcDlg::OnHookMenuEnable() {
    int item = (int)GetWindowLongPtr(m_hWnd, GWLP_USERDATA);
    if (item < 0 || item >= m_HookList.GetItemCount()) return;
    HookRow* hr = reinterpret_cast<HookRow*>(m_HookList.GetItemData(item));
    if (!hr) return;
    // UI-only: remove [DISABLED] marker if present
    std::wstring mod = hr->module;
    size_t pos = mod.find(L"[DISABLED] ");
    if (pos != std::wstring::npos) {
        mod = mod.substr(pos + wcslen(L"[DISABLED] "));
        hr->module = mod;
        m_HookList.SetItemText(item, 2, mod.c_str());
    }

	HookCore::EnableHook(m_pid, hr->address, m_services, (PVOID)hr->trampoline_pit);

	// Persist change
	FILETIME createTime{ 0,0 }; HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, m_pid);
	if (h) { FILETIME et, k, u; if (GetProcessTimes(h, &createTime, &et, &k, &u)) {} CloseHandle(h); }
	DWORD hi = createTime.dwHighDateTime; DWORD lo = createTime.dwLowDateTime;
	std::vector<HookRow*> rows;
	int count = m_HookList.GetItemCount();
	for (int j = 0; j < count; ++j) {
		HookRow* r = reinterpret_cast<HookRow*>(m_HookList.GetItemData(j));
		if (!r) continue;
		rows.push_back(r);
		if (r->id >= m_nextHookId) m_nextHookId = r->id + 1;
	}
	if (m_services) {
		// Convert vector<HookRow*> to vector<HookRow> for service
		std::vector<HookRow> outRows; outRows.reserve(rows.size());
		for (auto pr : rows) if (pr) outRows.push_back(*pr);
		m_services->SaveProcHookList(m_pid,hi,lo,outRows);
	}
}

void HookProcDlg::OnHookMenuRemove() {
	m_nextHookId--;
    int item = (int)GetWindowLongPtr(m_hWnd, GWLP_USERDATA);
    if (item < 0 || item >= m_HookList.GetItemCount()) return;
    HookRow* hr = reinterpret_cast<HookRow*>(m_HookList.GetItemData(item));
    if (!hr) return;
	if (!HookCore::RemoveHook(m_pid, hr->address, m_services, hr->id, hr->ori_asm_code_len, (PVOID)hr->trampoline_pit)) {
		if (m_services)
			LOG_UI(m_services, L"failed to call HookCore::RemoveHook\n");
		MessageBoxW(L"failed to call HookCore::RemoveHook\n", L"Hook", MB_OK | MB_ICONERROR);
		return;
	}

	// UI-only: remove the item and free memory
	m_HookList.DeleteItem(item);
	delete hr;

    // Persist change
    FILETIME createTime{0,0}; HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, m_pid);
    if (h) { FILETIME et,k,u; if (GetProcessTimes(h, &createTime, &et, &k, &u)) {} CloseHandle(h); }
    DWORD hi = createTime.dwHighDateTime; DWORD lo = createTime.dwLowDateTime;
    std::vector<HookRow*> rows;
    for (int i = 0; i < m_HookList.GetItemCount(); ++i) rows.push_back(reinterpret_cast<HookRow*>(m_HookList.GetItemData(i)));
    if (m_services) {
        std::vector<HookRow> out; out.reserve(rows.size());
        for (auto r : rows) if (r) out.push_back(*r);
		m_services->SaveProcHookList(m_pid, hi, lo, out);
    }
}

void HookProcDlg::OnModuleItemChanged(NMHDR* pNMHDR, LRESULT* pResult){ if(pResult) *pResult=0; }
void HookProcDlg::OnEnSetFocusOffset(){ }
void HookProcDlg::OnEnSetFocusDirect(){ }
void HookProcDlg::OnGetMinMaxInfo(MINMAXINFO* lpMMI) { CDialogEx::OnGetMinMaxInfo(lpMMI); lpMMI->ptMinTrackSize.x=480; lpMMI->ptMinTrackSize.y=260; }

void HookProcDlg::OnCustomDrawModules(NMHDR* pNMHDR, LRESULT* pResult){
    NMLVCUSTOMDRAW* pCD = reinterpret_cast<NMLVCUSTOMDRAW*>(pNMHDR);
    if (!pCD || !pResult) return;
    switch (pCD->nmcd.dwDrawStage) {
    case CDDS_PREPAINT:
        *pResult = CDRF_NOTIFYITEMDRAW; return;
    case CDDS_ITEMPREPAINT:
        {
            UINT itemIndex = (UINT)pCD->nmcd.dwItemSpec;
            BOOL isSelected = (m_ModuleList.GetItemState(itemIndex, LVIS_SELECTED) & LVIS_SELECTED) != 0;
            if (isSelected) {
                pCD->clrTextBk = GetSysColor(COLOR_HIGHLIGHT);
                pCD->clrText   = GetSysColor(COLOR_HIGHLIGHTTEXT);
            }
            *pResult = CDRF_DODEFAULT; return;
        }
    }
    *pResult = CDRF_DODEFAULT;
}

ULONGLONG HookProcDlg::ParseAddressText(const std::wstring& input, bool& ok) const {
    ok = false; if (input.empty()) return 0ULL; std::wstring t = input; for (auto &c : t) c = towlower(c);
    // allow optional 0x prefix
    if (t.rfind(L"0x",0)==0) t = t.substr(2);
    // allow backtick separators for readability (e.g. 7ff8`e8320088) - strip them
    std::wstring stripped; stripped.reserve(t.size());
    for (wchar_t c : t) {
        if (c == L'`') continue;
        stripped.push_back(c);
    }
    // validate remaining characters are hex digits
    for (wchar_t c: stripped) {
        if (!(iswdigit(c) || (c >= L'a' && c <= L'f'))) return 0ULL;
    }
    wchar_t* end=nullptr; ULONGLONG v = wcstoull(stripped.c_str(), &end, 16); if(end && *end==0){ ok=true; return v;} return 0ULL;
}

void HookProcDlg::OnBnClickedApplyHook() {
    // If the target process no longer exists, close this modeless dialog to avoid acting on a dead PID.
    bool procFound = false;
	bool rehook = false;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe = { sizeof(pe) };
        if (Process32First(hSnap, &pe)) {
            do {
                if ((DWORD)pe.th32ProcessID == m_pid) { procFound = true; break; }
            } while (Process32Next(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    if (!procFound) {
        MessageBox(L"Target process does not appear to be running. Closing dialog.", L"Hook", MB_ICONWARNING);
        // Destroy the dialog window; parent will be notified in OnDestroy and will delete this object.
        DestroyWindow();
        return;
    }


	CString directStr; GetDlgItemText(IDC_HOOKUI_EDIT_DIRECT, directStr);
	CString offsetStr; GetDlgItemText(IDC_HOOKUI_EDIT_OFFSET, offsetStr);
	std::wstring direct = directStr.GetString();
	std::wstring offset = offsetStr.GetString();
	if (!m_services) {
		MessageBox(L"Fatal error! m_services not initialized!", L"Hook", MB_OK | MB_ICONERROR);
		return;
	}
    // Trim simple whitespace
    auto trimWS = [](std::wstring& s){ while(!s.empty() && iswspace(s.back())) s.pop_back(); size_t i=0; while(i<s.size() && iswspace(s[i])) i++; if(i) s = s.substr(i); };
    trimWS(direct); trimWS(offset);

    ULONGLONG addr = 0ULL; bool ok=false;
    if(!direct.empty()) {
            addr = ParseAddressText(direct, ok);
            if(!ok){ MessageBox(L"Invalid direct address. Use hex (e.g. 0x7FF612341000).", L"Hook", MB_ICONERROR); return; }
    } else {
        // Module base + optional offset mode
        std::wstring modName; ULONGLONG base=0ULL; if(!GetSelectedModule(modName, base)) {
            MessageBox(L"Select a module (Base column) or provide a direct address.", L"Hook", MB_ICONWARNING); return; }
        ULONGLONG offVal=0ULL; bool offOk=true; // empty offset means 0
        if(!offset.empty()) { offVal = ParseAddressText(offset, offOk); }
        if(!offOk){ MessageBox(L"Invalid offset. Use hex like 0x200 or leave empty.", L"Hook", MB_ICONERROR); return; }
        addr = base + offVal; ok = true;
            if(m_services) LOG_UI(m_services, L"Using module '%s' base 0x%llX + offset 0x%llX => 0x%llX", modName.c_str(), base, offVal, addr);
    }

    if (m_services) LOG_UI(m_services, L"Attempting hook at 0x%llX for pid %u (%s)\n", addr, m_pid, m_name.c_str());



    // Ask user to select a DLL to be loaded inside the target process (file explorer)
    CString filter = L"DLL Files (*.dll)|*.dll|All Files (*.*)|*.*||";
    CFileDialog fd(TRUE, L"dll", NULL, OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST, filter, this);
    if (fd.DoModal() != IDOK) {
        // User cancelled selection; abort apply
        if (m_services) LOG_UI(m_services, L"ApplyHook cancelled by user (no DLL selected)\n");
        return;
    }
    CString selectedPath = fd.GetPathName();
	CString hook_code_dll_name = selectedPath.Mid(selectedPath.ReverseFind('\\') + 1);
	// we can not use LoadLibrary to check if required export function exist
	// because we can only load x64 hookcode.dll, if user is trying to hook SysWOW64 process
	// I can do shit about it
	// we need to mannuly check it from file
	bool is64 = false;
	m_services->IsProcess64(m_pid, is64);
	DWORD hook_code_offset = 0;
	if (!m_services->CheckExportFromFile(selectedPath.GetString(), is64 ? HOOK_CODE_EXPORT_X64 : HOOK_CODE_EXPORT_X86, &hook_code_offset)) {
		; LOG_UI(m_services, L"failed to call CheckExportFromFile, PE_Path=%s, CPU=%s\n", selectedPath.GetString(), is64 ? L"x64" : L"x86");
		MessageBox(L"failed to call CheckExportFromFile", L"Hook", MB_OK | MB_ICONERROR); 
		return;
	}
	if (!hook_code_offset) {
		LOG_UI(m_services, L"failed to get required export function: %s\n", is64 ? HOOK_CODE_EXPORT_X64 : HOOK_CODE_EXPORT_X86);
		MessageBox(L"failed to get required export function from HookCode dll", L"Hook", MB_OK | MB_ICONERROR);
		return;
	}
    // Copy the selected DLL to a local temp folder beside this module so the
    // master DLL can reliably open it. Use a timestamped filename to avoid
    // collisions. If the copy fails, fall back to the original selected path.
    std::wstring pathToInject = selectedPath.GetString();
	wchar_t* temp_hook_code_dll_name = 0;
    {
        wchar_t modPathBuf[MAX_PATH];
        DWORD modLen = GetModuleFileNameW(AfxGetInstanceHandle(), modPathBuf, _countof(modPathBuf));
        std::wstring folder;
        if (modLen == 0) {
            folder = L".\\" HOOK_CODE_TEMP_DIR_NAME;
        } else {
            std::wstring modPath(modPathBuf);
            size_t p = modPath.find_last_of(L"\\/");
			if (p == std::wstring::npos) folder = L".\\" HOOK_CODE_TEMP_DIR_NAME;
            else folder = modPath.substr(0, p) + L"\\" HOOK_CODE_TEMP_DIR_NAME;
        }
        // Ensure directory exists (CreateDirectoryW is fine if already exists)
        if (!CreateDirectoryW(folder.c_str(), NULL)) {
            DWORD err = GetLastError();
            if (err != ERROR_ALREADY_EXISTS) {
                LOG_UI(m_services, L"CreateDirectoryW failed for %s err=%u\n", folder.c_str(), err);
            }
        }
        // Build timestamped filename
        SYSTEMTIME st; GetLocalTime(&st);
        wchar_t ts[64];
        swprintf(ts, _countof(ts), L"%04d%02d%02d_%02d%02d%02d_%03d",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
		std::wstring new_dll_name = L"";
		new_dll_name = new_dll_name + ts + L"_" + std::wstring(hook_code_dll_name.GetString());
		temp_hook_code_dll_name = (wchar_t*)malloc(2 * (new_dll_name.length() + 1));
		ZeroMemory(temp_hook_code_dll_name, 2 * (new_dll_name.length() + 1));
		memcpy(temp_hook_code_dll_name, new_dll_name.c_str(), 2 * new_dll_name.length());
        std::wstring dest = folder + L"\\" + ts + L"_" + std::wstring(hook_code_dll_name.GetString());
        if (CopyFileW(selectedPath.GetString(), dest.c_str(), FALSE)) {
            pathToInject = dest; // use copied file
            LOG_UI(m_services, L"Copied hook DLL to %s\n", dest.c_str());
        } else {
            DWORD err = GetLastError();
            LOG_UI(m_services, L"CopyFileW failed src=%s dst=%s err=%u - falling back to original\n", selectedPath.GetString(), dest.c_str(), err);
            // keep pathToInject as original selectedPath
        }
    }
	DWORD64 hook_code_dll_base = 0;
    // Signal master DLL (via IHookServices) to load the selected DLL inside target process
    if (m_services) {
        if (!m_services->InjectTrampoline(m_pid, pathToInject.c_str())) {
            LOG_UI(m_services, L"InjectTrampoline failed for pid=%u path=%s\n", m_pid, pathToInject.c_str());
            MessageBox(L"Failed to request master DLL to load selected DLL. Check logs.", L"Hook", MB_OK | MB_ICONERROR);
            return;
        }
        LOG_UI(m_services, L"InjectTrampoline signaled pid=%u path=%s\n", m_pid, pathToInject.c_str());
        // check if HookCode injected

			// Poll up to 5 seconds (50 * 100ms) for trampoline module presence.
		const int maxIterations = 50;
		bool loaded = false;
		for (int iter = 0; iter < maxIterations && !loaded; ++iter) {
			std::vector<HookCore::ModuleInfo> mods; HookCore::EnumerateModules(m_pid, mods);
			for (auto &m : mods) {
				if (_wcsicmp(m.name.c_str(), temp_hook_code_dll_name) == 0) {
					hook_code_dll_base = m.base;
					loaded = true;
					break;
				}
			}
			if (!loaded) Sleep(100);
		}
		if (!loaded) {
			LOG_UI(m_services, L"faile to load hookcode dll: %s\n",selectedPath.GetString());
			MessageBox(L"faile to load hookcode dll", L"Hook", MB_OK | MB_ICONERROR);
			return;
		}
	}

	// check if user is rehook before apply hook
	for (int i = 0; i < m_HookList.GetItemCount(); ++i) {
		HookRow* hr = reinterpret_cast<HookRow*>(m_HookList.GetItemData(i));
		if (!hr) {
			LOG_UI(m_services, L"weird, hr can not be NULL during iteration\n");
			continue;
		}
		if (hr->address == addr) {
			rehook = true;
			LOG_UI(m_services, L"trying hook address that has already been hooked, recover to original code first\n");
			if (!HookCore::RemoveHook(m_pid, addr, m_services, hr->id, hr->ori_asm_code_len, (PVOID)hr->trampoline_pit)){
				LOG_UI(m_services, L"failed to remove hook first before rehooking the same address\n");
				MessageBox(L"Failed to remove hook first before rehooking the same address", L"Hook", MB_OK | MB_ICONERROR);
				return;
			}
		}
	}

    // Proceed with the existing hook attempt (ApplyHook) after requesting trampoline load
    DWORD ori_asm_code_len = 0;
	PVOID trampoline_pit = 0;
	PVOID ori_asm_code_addr = 0;
    int assignedHookId = m_nextHookId; // reserve id that will be used for this new hook
    bool success = HookCore::ApplyHook(m_pid, addr, m_services, hook_code_dll_base+hook_code_offset, assignedHookId, &ori_asm_code_len,
		&trampoline_pit,&ori_asm_code_addr);
	if (success) {
		if (m_services) LOG_UI(m_services, L"HookCore::ApplyHook succeeded at 0x%llX\n", addr);
		MessageBox(L"Hook succeed", L"Hook", MB_OK | MB_ICONINFORMATION);
		// Add entry to hook list UI: resolve owning module and show module+offset as hook id
		std::wstring moduleName = L"(unknown)";
		ULONGLONG moduleBase = 0;
		std::vector<HookCore::ModuleInfo> mods; HookCore::EnumerateModules(m_pid, mods);
		for (auto &m : mods) {
			if (addr >= m.base && addr < m.base + m.size) { moduleName = m.name; moduleBase = m.base; break; }
		}
        // Add numeric hook entry (auto-incrementing ID), only new hook addr will be added
        if (!rehook) {
            HookRow r; r.id = assignedHookId; r.address = addr; r.module = moduleName; 
			r.ori_asm_code_len = ori_asm_code_len; r.trampoline_pit = (unsigned long long)trampoline_pit;
			r.ori_asm_code_addr =(DWORD64) ori_asm_code_addr;
            AddHookEntry(r);
        }
	}
	else {
		if (m_services) LOG_UI(m_services, L"HookCore::ApplyHook failed at 0x%llX\n", addr);
		MessageBox(L"Hook failed", L"Hook", MB_OK | MB_ICONERROR);
	}
}

void HookProcDlg::OnSize(UINT nType, int cx, int cy) {
    CDialogEx::OnSize(nType,cx,cy);
    if(!m_ModuleList.GetSafeHwnd()) return;
    const int margin=7;
    const int rightPanelMinW = 210;
    const int interY = 12;
    const int labelH = 14;
    const int editH = 18;
    const int btnH = 22;
    int rightPanelW = 250;
    int availW = cx - (margin*2) - rightPanelW;
    if (availW < 160) availW = 160;
    if (cx < (margin*2 + rightPanelW + 160)) {
        rightPanelW = cx - (margin*2) - 160;
        if (rightPanelW < rightPanelMinW) rightPanelW = rightPanelMinW;
    }
    int listW = cx - (margin*2) - rightPanelW;
    int topYModulesLabel = 7;
    int listTop = topYModulesLabel + 11;
    int listH = cy - listTop - 60; if(listH < 80) listH = 80;
    HDWP hdwp = BeginDeferWindowPos(10);
    if (!hdwp) { m_ModuleList.MoveWindow(margin, listTop, listW, listH); }
    int panelX = margin + listW + margin;
    int y = listTop;
    CWnd* wOffsetLabel = GetDlgItem(IDC_HOOKUI_STATIC_OFFSET);
    CWnd* wOffsetEdit  = GetDlgItem(IDC_HOOKUI_EDIT_OFFSET);
    if (wOffsetLabel && wOffsetEdit) {
        if (hdwp) {
            hdwp = DeferWindowPos(hdwp, wOffsetLabel->GetSafeHwnd(), nullptr, panelX, y, rightPanelW - margin, labelH, SWP_NOZORDER|SWP_NOACTIVATE);
            hdwp = DeferWindowPos(hdwp, wOffsetEdit->GetSafeHwnd(),  nullptr, panelX, y + labelH + 2, rightPanelW - margin, editH, SWP_NOZORDER|SWP_NOACTIVATE);
        } else {
            wOffsetLabel->MoveWindow(panelX, y, rightPanelW - margin, labelH);
            wOffsetEdit->MoveWindow(panelX, y + labelH + 2, rightPanelW - margin, editH);
        }
        y += labelH + 2 + editH + interY;
    }
    CWnd* wDirectLabel = GetDlgItem(IDC_HOOKUI_STATIC_DIRECT);
    CWnd* wDirectEdit  = GetDlgItem(IDC_HOOKUI_EDIT_DIRECT);
    if (wDirectLabel && wDirectEdit) {
        if (hdwp) {
            hdwp = DeferWindowPos(hdwp, wDirectLabel->GetSafeHwnd(), nullptr, panelX, y, rightPanelW - margin, labelH, SWP_NOZORDER|SWP_NOACTIVATE);
            hdwp = DeferWindowPos(hdwp, wDirectEdit->GetSafeHwnd(),  nullptr, panelX, y + labelH + 2, rightPanelW - margin, editH, SWP_NOZORDER|SWP_NOACTIVATE);
        } else {
            wDirectLabel->MoveWindow(panelX, y, rightPanelW - margin, labelH);
            wDirectEdit->MoveWindow(panelX, y + labelH + 2, rightPanelW - margin, editH);
        }
        y += labelH + 2 + editH + interY;
    }
    CWnd* wApply = GetDlgItem(IDC_HOOKUI_BTN_APPLY);
    CWnd* wClose = GetDlgItem(IDCANCEL);
    int btnW = (rightPanelW - margin - 5) / 2; if (btnW < 60) btnW = 60;
    if (wApply && wClose) {
        if (hdwp) {
            hdwp = DeferWindowPos(hdwp, wApply->GetSafeHwnd(), nullptr, panelX, y, btnW, btnH, SWP_NOZORDER|SWP_NOACTIVATE);
            hdwp = DeferWindowPos(hdwp, wClose->GetSafeHwnd(), nullptr, panelX + btnW + 5, y, btnW, btnH, SWP_NOZORDER|SWP_NOACTIVATE);
        } else {
            wApply->MoveWindow(panelX, y, btnW, btnH);
            wClose->MoveWindow(panelX + btnW + 5, y, btnW, btnH);
        }
        y += btnH + interY;
    }
    // Position hook list on right side below buttons and stretch to bottom
    CWnd* wHookList = GetDlgItem(IDC_HOOKUI_LIST_HOOKS);
    if (wHookList && wHookList->GetSafeHwnd()) {
        int hooksX = panelX;
        int hooksY = y;
        int hooksW = rightPanelW - margin;
        int hooksH = cy - hooksY - margin;
        if (hooksH < 40) hooksH = 40;
        if (hdwp) hdwp = DeferWindowPos(hdwp, wHookList->GetSafeHwnd(), nullptr, hooksX, hooksY, hooksW, hooksH, SWP_NOZORDER|SWP_NOACTIVATE);
        else wHookList->MoveWindow(hooksX, hooksY, hooksW, hooksH);
        y += hooksH + interY;
    }
    CWnd* wHint = GetDlgItem(IDC_HOOKUI_STATIC_HINT);
    if (wHint) {
        int hintY = listTop + listH + 5; if (hintY + 16 > cy) hintY = cy - 20;
        if (hdwp) { hdwp = DeferWindowPos(hdwp, wHint->GetSafeHwnd(), nullptr, margin, hintY, listW - margin, 16, SWP_NOZORDER|SWP_NOACTIVATE); }
        else { wHint->MoveWindow(margin, hintY, listW - margin, 16); }
    }
    if (hdwp) { hdwp = DeferWindowPos(hdwp, m_ModuleList.GetSafeHwnd(), nullptr, margin, listTop, listW, listH, SWP_NOZORDER|SWP_NOACTIVATE); EndDeferWindowPos(hdwp); }
    RedrawWindow(nullptr, nullptr, RDW_INVALIDATE|RDW_ALLCHILDREN|RDW_UPDATENOW);
}
