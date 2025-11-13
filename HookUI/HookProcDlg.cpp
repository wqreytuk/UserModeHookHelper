// Clean, corrected implementation with multi-column sorting support

#include "HookProcDlg.h"
#include "../Shared/LogMacros.h"
#include <tlhelp32.h>
#include <cwchar>
#include <cwctype>
#include <CommCtrl.h> // for EM_SETCUEBANNER
#include "../HookCoreLib/HookCore.h"

static std::wstring Hex64(ULONGLONG v) {
    wchar_t buf[32];
    _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"%llX", v);
    return buf;
}

const UINT HookProcDlg::kMsgHookDlgDestroyed = WM_APP + 0x701;

BEGIN_MESSAGE_MAP(HookProcDlg, CDialogEx)
    ON_BN_CLICKED(IDC_HOOKUI_BTN_APPLY, &HookProcDlg::OnBnClickedApplyHook)
    ON_WM_SIZE()
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
    if (CWnd* wDirectEdit = GetDlgItem(IDC_HOOKUI_EDIT_DIRECT)) {
        ::SendMessage(wDirectEdit->GetSafeHwnd(), EM_SETCUEBANNER, 0, (LPARAM)L"(Preview DLL version)");
    }
    return TRUE;
}

void HookProcDlg::OnDestroy() {
    FreeModuleRows();
    m_ModuleList.DeleteAllItems();
    m_ModuleList.Detach();
    CDialogEx::OnDestroy();
    if (CWnd* parent = GetParent()) {
        ::PostMessage(parent->GetSafeHwnd(), HookProcDlg::kMsgHookDlgDestroyed, (WPARAM)this, 0);
    }
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
    if (t.rfind(L"0x",0)==0) t = t.substr(2); for (wchar_t c: t){ if(!(iswdigit(c)||(c>='a'&&c<='f'))) return 0ULL; }
    wchar_t* end=nullptr; ULONGLONG v = wcstoull(t.c_str(), &end, 16); if(end && *end==0){ ok=true; return v;} return 0ULL;
}

void HookProcDlg::OnBnClickedApplyHook() {
    CString directStr; GetDlgItemText(IDC_HOOKUI_EDIT_DIRECT, directStr);
    CString offsetStr; GetDlgItemText(IDC_HOOKUI_EDIT_OFFSET, offsetStr);
    std::wstring direct = directStr.GetString();
    std::wstring offset = offsetStr.GetString();

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
    bool success = HookCore::ApplyHook(m_pid, addr, m_services);
    if (success) {
        if (m_services) LOG_UI(m_services, L"HookCore::ApplyHook succeeded at 0x%llX\n", addr);
        MessageBox(L"Hook applied (basic validation + R/W test).", L"Hook", MB_OK | MB_ICONINFORMATION);
    } else {
        if (m_services) LOG_UI(m_services, L"HookCore::ApplyHook failed at 0x%llX\n", addr);
        MessageBox(L"Hook failed (address invalid or memory inaccessible).", L"Hook", MB_OK | MB_ICONERROR);
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
    CWnd* wHint = GetDlgItem(IDC_HOOKUI_STATIC_HINT);
    if (wHint) {
        int hintY = listTop + listH + 5; if (hintY + 16 > cy) hintY = cy - 20;
        if (hdwp) { hdwp = DeferWindowPos(hdwp, wHint->GetSafeHwnd(), nullptr, margin, hintY, listW - margin, 16, SWP_NOZORDER|SWP_NOACTIVATE); }
        else { wHint->MoveWindow(margin, hintY, listW - margin, 16); }
    }
    if (hdwp) { hdwp = DeferWindowPos(hdwp, m_ModuleList.GetSafeHwnd(), nullptr, margin, listTop, listW, listH, SWP_NOZORDER|SWP_NOACTIVATE); EndDeferWindowPos(hdwp); }
    RedrawWindow(nullptr, nullptr, RDW_INVALIDATE|RDW_ALLCHILDREN|RDW_UPDATENOW);
}
