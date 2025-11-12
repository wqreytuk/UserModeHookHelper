
#include "HookProcDlg.h"
#include <tlhelp32.h>
#include <cwchar>
#include <cwctype>
#include "../HookCoreLib/HookCore.h"

// Local hex formatting (replaces dependency on Helper.h for ToHex)
static std::wstring Hex64(ULONGLONG v) {
    wchar_t buf[32];
    _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"%llX", v);
    return buf;
}

const UINT HookProcDlg::kMsgHookDlgDestroyed = WM_APP + 0x701; // different namespace

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
    m_ModuleList.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    LONG lvStyle = ::GetWindowLong(m_ModuleList.GetSafeHwnd(), GWL_STYLE);
    lvStyle |= LVS_SHOWSELALWAYS; ::SetWindowLong(m_ModuleList.GetSafeHwnd(), GWL_STYLE, lvStyle);
    ::SetWindowPos(m_ModuleList.GetSafeHwnd(), nullptr, 0,0,0,0, SWP_NOMOVE|SWP_NOSIZE|SWP_NOZORDER|SWP_FRAMECHANGED);
    PopulateModuleList();
    return TRUE;
}

void HookProcDlg::OnDestroy() {
    m_ModuleList.Detach();
    CDialogEx::OnDestroy();
    if (CWnd* parent = GetParent()) {
        ::PostMessage(parent->GetSafeHwnd(), HookProcDlg::kMsgHookDlgDestroyed, (WPARAM)this, 0);
    }
}

void HookProcDlg::PopulateModuleList() {
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
            m_ModuleList.SetItemData(idx, (DWORD_PTR)me.modBaseAddr);
            i++;
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
}

void HookProcDlg::OnColumnClickModules(NMHDR* pNMHDR, LRESULT* pResult) {
    LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
    int col = pNMLV->iSubItem;
    if (m_sortColumn == col) m_sortAscending = !m_sortAscending; else { m_sortColumn = col; m_sortAscending = true; }
    m_ModuleList.SortItems(ModuleCompare, (LPARAM)this);
    if (pResult) *pResult = 0;
}

bool HookProcDlg::GetSelectedModule(std::wstring& name, ULONGLONG& base) const {
    int sel = m_ModuleList.GetNextItem(-1, LVNI_SELECTED);
    if (sel == -1) return false;
    name = m_ModuleList.GetItemText(sel, 2).GetString();
    base = (ULONGLONG)m_ModuleList.GetItemData(sel);
    return true;
}

// (ParseAddressText identical to previous version omitted for brevity – initial migration can rely on direct address only)
ULONGLONG HookProcDlg::ParseAddressText(const std::wstring& input, bool& ok) const {
    ok = false; if (input.empty()) return 0ULL; std::wstring t = input; for (auto &c : t) c = towlower(c);
    if (t.rfind(L"0x",0)==0) t = t.substr(2); for (wchar_t c: t){ if(!(iswdigit(c)||(c>='a'&&c<='f'))) return 0ULL; }
    wchar_t* end=nullptr; ULONGLONG v = wcstoull(t.c_str(), &end, 16); if(end && *end==0){ ok=true; return v;} return 0ULL;
}

void HookProcDlg::OnBnClickedApplyHook() {
    CString directStr; GetDlgItemText(IDC_HOOKUI_EDIT_DIRECT, directStr);
    CString offsetStr; GetDlgItemText(IDC_HOOKUI_EDIT_OFFSET, offsetStr);
    std::wstring direct = directStr.GetString();
    bool ok=false; ULONGLONG addr = ParseAddressText(direct, ok);
    if (!ok) { MessageBox(L"Provide hex address (e.g., 0x7FF612341000).", L"Hook", MB_ICONERROR); return; }
    if (m_services) m_services->Log(L"[HookUI] Attempting hook at 0x%llX for pid %u (%s)\n", addr, m_pid, m_name.c_str());
    // Invoke core hook logic.
    bool success = HookCore::ApplyHook(m_pid, addr, m_services);
    if (success) {
        if (m_services) m_services->Log(L"[HookUI] HookCore::ApplyHook succeeded at 0x%llX\n", addr);
        MessageBox(L"Hook applied (basic validation + R/W test).", L"Hook", MB_OK | MB_ICONINFORMATION);
    } else {
        if (m_services) m_services->Log(L"[HookUI] HookCore::ApplyHook failed at 0x%llX\n", addr);
        MessageBox(L"Hook failed (address invalid or memory inaccessible).", L"Hook", MB_OK | MB_ICONERROR);
    }
}

void HookProcDlg::OnSize(UINT nType, int cx, int cy) {
    CDialogEx::OnSize(nType,cx,cy);
    if(!m_ModuleList.GetSafeHwnd()) return;
    // Layout constants
    const int margin=7;
    const int rightPanelMinW = 210; // width needed for controls on right side
    const int interY = 12; // vertical spacing between rows
    const int labelH = 14;
    const int editH = 18;
    const int btnH = 22;
    // Compute dynamic layout split: list gets remaining width after fixed right panel
    int rightPanelW = 250; // base design width
    int availW = cx - (margin*2) - rightPanelW;
    if (availW < 160) availW = 160; // min list width
    if (cx < (margin*2 + rightPanelW + 160)) {
        // If dialog is too narrow, shrink right panel but keep minimum list width
        rightPanelW = cx - (margin*2) - 160;
        if (rightPanelW < rightPanelMinW) rightPanelW = rightPanelMinW;
    }
    int listW = cx - (margin*2) - rightPanelW;
    int topYModulesLabel = 7;
    int listTop = topYModulesLabel + 11;
    int listH = cy - listTop - 60; if(listH < 80) listH = 80;
    // Move list
    m_ModuleList.MoveWindow(margin, listTop, listW, listH);
    // Right panel x origin
    int panelX = margin + listW + margin;
    int y = listTop; // align with list top
    // Position Offset label + edit
    CWnd* wOffsetLabel = GetDlgItem(IDC_HOOKUI_STATIC_OFFSET);
    CWnd* wOffsetEdit  = GetDlgItem(IDC_HOOKUI_EDIT_OFFSET);
    if (wOffsetLabel && wOffsetEdit) {
        wOffsetLabel->MoveWindow(panelX, y, rightPanelW - margin, labelH);
        wOffsetEdit->MoveWindow(panelX, y + labelH + 2, rightPanelW - margin, editH);
        y += labelH + 2 + editH + interY;
    }
    // Direct address label + edit
    CWnd* wDirectLabel = GetDlgItem(IDC_HOOKUI_STATIC_DIRECT);
    CWnd* wDirectEdit  = GetDlgItem(IDC_HOOKUI_EDIT_DIRECT);
    if (wDirectLabel && wDirectEdit) {
        wDirectLabel->MoveWindow(panelX, y, rightPanelW - margin, labelH);
        wDirectEdit->MoveWindow(panelX, y + labelH + 2, rightPanelW - margin, editH);
        y += labelH + 2 + editH + interY;
    }
    // Buttons
    CWnd* wApply = GetDlgItem(IDC_HOOKUI_BTN_APPLY);
    CWnd* wClose = GetDlgItem(IDCANCEL);
    int btnW = (rightPanelW - margin - 5) / 2; if (btnW < 60) btnW = 60;
    if (wApply && wClose) {
        wApply->MoveWindow(panelX, y, btnW, btnH);
        wClose->MoveWindow(panelX + btnW + 5, y, btnW, btnH);
        y += btnH + interY;
    }
    // Hint text near bottom left (keep original resource position relative to bottom)
    CWnd* wHint = GetDlgItem(IDC_HOOKUI_STATIC_HINT);
    if (wHint) {
        int hintY = listTop + listH + 5;
        if (hintY + 16 > cy) hintY = cy - 20;
        wHint->MoveWindow(margin, hintY, listW - margin, 16);
    }
}

void HookProcDlg::OnGetMinMaxInfo(MINMAXINFO* lpMMI) { CDialogEx::OnGetMinMaxInfo(lpMMI); lpMMI->ptMinTrackSize.x=480; lpMMI->ptMinTrackSize.y=260; }

int CALLBACK HookProcDlg::ModuleCompare(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort){ HookProcDlg* self=reinterpret_cast<HookProcDlg*>(lParamSort); if(!self) return 0; ULONGLONG b1=(ULONGLONG)lParam1, b2=(ULONGLONG)lParam2; int r= (b1<b2)?-1: (b1>b2?1:0); return self->m_sortAscending? r:-r; }

void HookProcDlg::OnModuleItemChanged(NMHDR* pNMHDR, LRESULT* pResult){ if(pResult) *pResult=0; }
void HookProcDlg::OnEnSetFocusOffset(){ }
void HookProcDlg::OnEnSetFocusDirect(){ }
void HookProcDlg::OnCustomDrawModules(NMHDR* pNMHDR, LRESULT* pResult){ if(pResult) *pResult=CDRF_DODEFAULT; }
