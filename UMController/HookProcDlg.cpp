// HookProcDlg.cpp - modeless hook dialog implementation
#include "pch.h"
#include "HookProcDlg.h"
#include "Helper.h"
#include "UMController.h"

// Define public static message constant
const UINT HookProcDlg::kMsgHookDlgDestroyed = WM_APP + 0x501;

BEGIN_MESSAGE_MAP(HookProcDlg, CDialogEx)
    ON_BN_CLICKED(IDC_BTN_APPLY_HOOK, &HookProcDlg::OnBnClickedApplyHook)
    ON_WM_SIZE()
    ON_WM_GETMINMAXINFO()
    ON_NOTIFY(LVN_COLUMNCLICK, IDC_LIST_MODULES, &HookProcDlg::OnColumnClickModules)
END_MESSAGE_MAP()

BOOL HookProcDlg::OnInitDialog() {
    CDialogEx::OnInitDialog();
    CString title; title.Format(L"Hook Process PID %lu - %s", m_pid, m_name.c_str());
    SetWindowText(title);
    // Attach list control
    m_ModuleList.Attach(GetDlgItem(IDC_LIST_MODULES)->m_hWnd);
    m_ModuleList.InsertColumn(0, L"Base", LVCFMT_LEFT, 80);
    m_ModuleList.InsertColumn(1, L"Size", LVCFMT_LEFT, 70);
    m_ModuleList.InsertColumn(2, L"Name", LVCFMT_LEFT, 140);
    m_ModuleList.InsertColumn(3, L"Path", LVCFMT_LEFT, 300);
    m_ModuleList.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    PopulateModuleList();
    return TRUE;
}

void HookProcDlg::OnDestroy() {
    m_ModuleList.Detach();
    CDialogEx::OnDestroy();
    // Notify parent that dialog is destroyed so it can clear pointer (wParam = this)
    CWnd* parent = GetParent();
    if (parent && parent->GetSafeHwnd()) {
        // Send the dialog pointer in wParam so parent can distinguish which instance died
        ::PostMessage(parent->GetSafeHwnd(), HookProcDlg::kMsgHookDlgDestroyed, (WPARAM)this, 0);
    }
}

// Lifetime: object allocated with new in parent; parent deletes in destroy handler.

void HookProcDlg::PopulateModuleList() {
    m_ModuleList.DeleteAllItems();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, m_pid);
    if (snap == INVALID_HANDLE_VALUE) return;
    MODULEENTRY32 me = { sizeof(me) };
    int i = 0;
    if (Module32First(snap, &me)) {
        do {
            int idx = m_ModuleList.InsertItem(i, (std::wstring(L"0x") + Helper::ToHex((ULONGLONG)me.modBaseAddr)).c_str());
            m_ModuleList.SetItemText(idx, 1, (std::wstring(L"0x") + Helper::ToHex((ULONGLONG)me.modBaseSize)).c_str());
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
    if (m_sortColumn == col)
        m_sortAscending = !m_sortAscending;
    else {
        m_sortColumn = col;
        m_sortAscending = true;
    }
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

ULONGLONG HookProcDlg::ParseAddressText(const std::wstring& text, bool& ok) const {
    ok = false;
    if (text.empty()) return 0;
    // Simple parse: hex (0x...), decimal, or module+offset (mod+0xOFF / mod+DEC)
    size_t plusPos = text.find(L'+');
    std::wstring modPart, offPart;
    if (plusPos != std::wstring::npos) {
        modPart = text.substr(0, plusPos);
        offPart = text.substr(plusPos + 1);
    }
    auto parseNumber = [&](const std::wstring& s, ULONGLONG& value)->bool {
        if (s.size() > 2 && (s[0] == L'0') && (s[1] == L'x' || s[1] == L'X')) {
            wchar_t* end = nullptr;
            value = wcstoull(s.c_str() + 2, &end, 16);
            return end && *end == 0;
        } else {
            wchar_t* end = nullptr;
            value = wcstoull(s.c_str(), &end, 10);
            return end && *end == 0;
        }
    };
    if (plusPos == std::wstring::npos) {
        ULONGLONG v = 0;
        if (parseNumber(text, v)) { ok = true; return v; }
        return 0;
    } else {
        // module+offset form: locate module base from list
        ULONGLONG base = 0; bool found = false;
        for (int i = 0; i < m_ModuleList.GetItemCount(); ++i) {
            if (_wcsicmp(m_ModuleList.GetItemText(i, 2), modPart.c_str()) == 0) {
                base = (ULONGLONG)m_ModuleList.GetItemData(i); found = true; break;
            }
        }
        if (!found) return 0;
        ULONGLONG off = 0; if (!parseNumber(offPart, off)) return 0;
        ok = true; return base + off;
    }
}

void HookProcDlg::OnBnClickedApplyHook() {
    CString directStr; GetDlgItemText(IDC_EDIT_DIRECT, directStr);
    CString offsetStr; GetDlgItemText(IDC_EDIT_OFFSET, offsetStr);
    std::wstring direct = directStr.GetString();
    std::wstring relOff = offsetStr.GetString();
    ULONGLONG finalAddr = 0; bool addrOk = false;
    if (!direct.empty()) {
        finalAddr = ParseAddressText(direct, addrOk);
    }
    if (!addrOk && !relOff.empty()) {
        // Use module selection + offset
        std::wstring selName; ULONGLONG base=0;
        if (GetSelectedModule(selName, base)) {
            // parse offset (hex or dec)
            bool offOk=false; ULONGLONG off=0;
            if (!relOff.empty()) {
                bool dummy; off = ParseAddressText(relOff, dummy); // reuse parser for numeric
                offOk = (off!=0 || relOff==L"0");
            }
            if (offOk) { finalAddr = base + off; addrOk = true; }
        }
    }
    if (!addrOk) {
        MessageBox(L"Failed to parse address. Provide direct address or select module+offset.", L"Hook", MB_ICONERROR);
        return;
    }
    // Log debug info only (no hooking yet)
    app.GetETW().Log(L"Hook request: pid=%u addr=0x%llX direct='%s' offset='%s'\n", m_pid, finalAddr, direct.c_str(), relOff.c_str());
    MessageBox(L"Hook request logged (debug stub).", L"Hook", MB_OK | MB_ICONINFORMATION);
}

void HookProcDlg::OnSize(UINT nType, int cx, int cy) {
    CDialogEx::OnSize(nType, cx, cy);
    if (!m_ModuleList.GetSafeHwnd()) return;
    const int margin = 7;
    const int rightPanelWidth = 140 + margin + 65 + 65; // rough width occupied by edits/buttons region
    int listWidth = cx - (rightPanelWidth) - (margin * 2);
    if (listWidth < 100) listWidth = 100;
    // Get label bottom so list starts below it
    int labelBottom = margin + 16; // fallback
    if (CWnd* label = GetDlgItem(IDC_STATIC_MODULE)) {
        CRect rc; label->GetWindowRect(&rc); ScreenToClient(&rc);
        labelBottom = rc.bottom + 2;
    }
    int listHeight = cy - labelBottom - margin - 60;
    if (listHeight < 60) listHeight = 60;
    m_ModuleList.MoveWindow(margin, labelBottom, listWidth, listHeight);
    // Reposition right-side controls relative to new width
    auto moveCtrl = [&](int id, int x, int y, int w, int h) {
        CWnd* c = GetDlgItem(id); if (c) c->MoveWindow(x, y, w, h);
    };
    int panelLeft = margin + listWidth + margin;
    moveCtrl(IDC_STATIC_OFFSET, panelLeft, 18, 70, 14);
    moveCtrl(IDC_EDIT_OFFSET, panelLeft, 30, 140, 18);
    moveCtrl(IDC_STATIC_DIRECT, panelLeft, 55, 140, 14);
    moveCtrl(IDC_EDIT_DIRECT, panelLeft, 67, 140, 18);
    moveCtrl(IDC_BTN_APPLY_HOOK, panelLeft, 100, 65, 20);
    moveCtrl(IDCANCEL, panelLeft + 75, 100, 65, 20);
    // Hint label at bottom
    int hintY = margin + listHeight + 25;
    CWnd* hint = GetDlgItem(IDC_STATIC_MODULE); // reuse existing static? original is Modules label - keep
    // Adjust columns: expand Path column to remaining width
    int baseW = m_ModuleList.GetColumnWidth(0);
    int sizeW = m_ModuleList.GetColumnWidth(1);
    int nameW = m_ModuleList.GetColumnWidth(2);
    int pathW = listWidth - (baseW + sizeW + nameW) - 10;
    if (pathW > 50) m_ModuleList.SetColumnWidth(3, pathW);
}

void HookProcDlg::OnGetMinMaxInfo(MINMAXINFO* lpMMI) {
    CDialogEx::OnGetMinMaxInfo(lpMMI);
    lpMMI->ptMinTrackSize.x = 420;
    lpMMI->ptMinTrackSize.y = 260;
}

int CALLBACK HookProcDlg::ModuleCompare(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort) {
    HookProcDlg* self = reinterpret_cast<HookProcDlg*>(lParamSort);
    if (!self) return 0;
    // lParam values are module base addresses stored as item data.
    ULONGLONG base1 = (ULONGLONG)lParam1;
    ULONGLONG base2 = (ULONGLONG)lParam2;
    int col = self->m_sortColumn;
    int result = 0;
    if (col == 0) { // Base
        if (base1 < base2) result = -1; else if (base1 > base2) result = 1; else result = 0;
    } else if (col == 1) { // Size
        auto getSize = [&](ULONGLONG base)->ULONGLONG {
            // Find item by base
            int idx = -1; int cur = self->m_ModuleList.GetNextItem(-1, LVNI_ALL);
            while (cur != -1) { if ((ULONGLONG)self->m_ModuleList.GetItemData(cur) == base) { idx = cur; break; } cur = self->m_ModuleList.GetNextItem(cur, LVNI_ALL); }
            if (idx == -1) return 0;
            CString sizeText = self->m_ModuleList.GetItemText(idx, 1);
            std::wstring s = sizeText.GetString();
            if (s.rfind(L"0x",0)==0) {
                return wcstoull(s.c_str()+2,nullptr,16);
            }
            return wcstoull(s.c_str(),nullptr,10);
        };
        ULONGLONG sz1 = getSize(base1);
        ULONGLONG sz2 = getSize(base2);
        if (sz1 < sz2) result = -1; else if (sz1 > sz2) result = 1; else result = 0;
    } else if (col == 2 || col == 3) { // Name or Path
        auto getText = [&](ULONGLONG base, int c)->std::wstring {
            int idx = -1; int cur = self->m_ModuleList.GetNextItem(-1, LVNI_ALL);
            while (cur != -1) { if ((ULONGLONG)self->m_ModuleList.GetItemData(cur) == base) { idx = cur; break; } cur = self->m_ModuleList.GetNextItem(cur, LVNI_ALL); }
            if (idx == -1) return L"";
            CString t = self->m_ModuleList.GetItemText(idx, c);
            return std::wstring(t.GetString());
        };
        std::wstring t1 = getText(base1, col);
        std::wstring t2 = getText(base2, col);
        result = _wcsicmp(t1.c_str(), t2.c_str());
    }
    return self->m_sortAscending ? result : -result;
}