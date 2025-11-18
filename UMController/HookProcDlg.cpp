// HookProcDlg.cpp - modeless hook dialog implementation
#include "pch.h"
#include "HookProcDlg.h"
#include "Helper.h"
#include "UMController.h"
#include "ProcFlags.h" // for MASTER_X64_DLL_BASENAME / MASTER_X86_DLL_BASENAME

// Define public static message constant
const UINT HookProcDlg::kMsgHookDlgDestroyed = WM_APP + 0x501;

BEGIN_MESSAGE_MAP(HookProcDlg, CDialogEx)
    ON_BN_CLICKED(IDC_BTN_APPLY_HOOK, &HookProcDlg::OnBnClickedApplyHook)
    ON_WM_SIZE()
    ON_WM_GETMINMAXINFO()
    ON_NOTIFY(LVN_COLUMNCLICK, IDC_LIST_MODULES, &HookProcDlg::OnColumnClickModules)
    ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST_MODULES, &HookProcDlg::OnModuleItemChanged)
    ON_EN_SETFOCUS(IDC_EDIT_OFFSET, &HookProcDlg::OnEnSetFocusOffset)
    ON_EN_SETFOCUS(IDC_EDIT_DIRECT, &HookProcDlg::OnEnSetFocusDirect)
    ON_NOTIFY(NM_CUSTOMDRAW, IDC_LIST_MODULES, &HookProcDlg::OnCustomDrawModules)
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
    // Attach hook list control (shows currently applied hooks for this process)
    m_HookList.Attach(GetDlgItem(IDC_LIST_HOOKS)->m_hWnd);
    m_HookList.InsertColumn(0, L"Hook ID", LVCFMT_LEFT, 60);
    m_HookList.InsertColumn(1, L"Address", LVCFMT_LEFT, 80);
    m_HookList.InsertColumn(2, L"Module", LVCFMT_LEFT, 120);
    m_HookList.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    // Keep selection visible when focus moves to offset/edit controls (fix: selection disappears while typing)
    LONG lvStyle = ::GetWindowLong(m_ModuleList.GetSafeHwnd(), GWL_STYLE);
    lvStyle |= LVS_SHOWSELALWAYS;
    ::SetWindowLong(m_ModuleList.GetSafeHwnd(), GWL_STYLE, lvStyle);
    // Force style refresh so LVS_SHOWSELALWAYS takes effect immediately
    ::SetWindowPos(m_ModuleList.GetSafeHwnd(), nullptr, 0,0,0,0, SWP_NOMOVE|SWP_NOSIZE|SWP_NOZORDER|SWP_FRAMECHANGED);
    PopulateModuleList();
    PopulateHookList();
    return TRUE;
}


void HookProcDlg::OnDestroy() {
    m_HookList.Detach();
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

ULONGLONG HookProcDlg::ParseAddressText(const std::wstring& input, bool& ok) const {
    // Enhanced parser supporting:
    //  - windbg style: fffff801`a86f7240 (with optional 0x prefix)
    //  - plain hex: fffff801a86f7240 / 0xfffff801a86f7240
    //  - moduleName+offset (module+0x123 / module+456)
    //  - moduleBase+offset (hexBase+hexOff / hexBase+decOff)
    ok = false;
    if (input.empty()) return 0ULL;
    auto trim = [](const std::wstring& s)->std::wstring {
        size_t a = 0, b = s.size();
        while (a < b && iswspace(s[a])) ++a;
        while (b > a && iswspace(s[b-1])) --b;
        return s.substr(a, b-a);
    };
    std::wstring text = trim(input);
    if (text.empty()) return 0ULL;
    // Remove any backticks (windbg high`low separator)
    std::wstring noTick; noTick.reserve(text.size());
    for (wchar_t c : text) { if (c != L'`') noTick.push_back(c); }
    text.swap(noTick);
    size_t plusPos = text.find(L'+');
    auto parseHexFlexible = [&](const std::wstring& s, ULONGLONG& value)->bool {
        std::wstring t = trim(s);
        if (t.empty()) return false;
        // strip optional 0x
        if (t.size()>2 && t[0]==L'0' && (t[1]==L'x' || t[1]==L'X')) t = t.substr(2);
        // all hex digits? (allow a-fA-F0-9)
        for (wchar_t c : t) { if (!(iswdigit(c) || (c>=L'a'&&c<=L'f') || (c>=L'A'&&c<=L'F'))) return false; }
        wchar_t* end=nullptr; value = wcstoull(t.c_str(), &end, 16); return end && *end==0; };
    auto parseDec = [&](const std::wstring& s, ULONGLONG& value)->bool {
        std::wstring t = trim(s); if (t.empty()) return false;
        for (wchar_t c: t) { if (!iswdigit(c)) return false; }
        wchar_t* end=nullptr; value = wcstoull(t.c_str(), &end, 10); return end && *end==0; };
    auto parseNumberAuto = [&](const std::wstring& s, ULONGLONG& value)->bool {
        // Decide hex vs dec
        std::wstring t = trim(s);
        if (t.empty()) return false;
        if ((t.size()>2 && t[0]==L'0' && (t[1]==L'x'||t[1]==L'X')) || t.find_first_of(L"abcdefABCDEF")!=std::wstring::npos) {
            return parseHexFlexible(t, value);
        }
        // try decimal then hex fallback for very large values w/out letters
        if (parseDec(t, value)) return true;
        return parseHexFlexible(t, value);
    };
    if (plusPos == std::wstring::npos) {
        // Single component: either raw address (hex/dec) or windbg format already normalized
        ULONGLONG addr=0; if (parseNumberAuto(text, addr)) { ok=true; return addr; }
        return 0ULL;
    }
    // base+offset form
    std::wstring basePart = text.substr(0, plusPos);
    std::wstring offPart  = text.substr(plusPos+1);
    ULONGLONG offset=0; if (!parseNumberAuto(offPart, offset)) return 0ULL;
    // Try module name first
    ULONGLONG baseAddr=0; bool moduleNameMatch=false; int nameMatchCount=0; int matchedIndex=-1;
    for (int i=0;i<m_ModuleList.GetItemCount();++i) {
        CString nmC = m_ModuleList.GetItemText(i,2);
        std::wstring nm = nmC.GetString();
        if (_wcsicmp(nm.c_str(), basePart.c_str())==0) {
            nameMatchCount++; matchedIndex = i; moduleNameMatch=true; baseAddr = (ULONGLONG)m_ModuleList.GetItemData(i);
        }
    }
    if (moduleNameMatch) {
        // If duplicate module names discovered, force user to use explicit base address to avoid ambiguity
        if (nameMatchCount > 1) {
            return 0ULL; // caller will interpret ok=false and prompt user
        }
        ok=true; return baseAddr + offset;
    }
    // Not a module name: treat as base address string
    ULONGLONG parsedBase=0; if (!parseNumberAuto(basePart, parsedBase)) return 0ULL;
    // Optional: verify base exists in module list (helps catch typos)
    bool baseExists=false; for (int i=0;i<m_ModuleList.GetItemCount();++i) { if ((ULONGLONG)m_ModuleList.GetItemData(i)==parsedBase) { baseExists=true; break; } }
    if (!baseExists) return 0ULL;
    ok=true; return parsedBase + offset;
}

void HookProcDlg::OnBnClickedApplyHook() {
    // If the target process no longer exists, close this modeless dialog to avoid acting on a dead PID.
    HANDLE hProcCheck = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, m_pid);
    if (!hProcCheck) {
        MessageBox(L"Target process does not appear to be running. Closing dialog.", L"Hook", MB_ICONWARNING);
        // Destroy the dialog window; parent will be notified in OnDestroy and will delete this object.
        DestroyWindow();
        return;
    }
    CloseHandle(hProcCheck);

    CString directStr; GetDlgItemText(IDC_EDIT_DIRECT, directStr);
    CString offsetStr; GetDlgItemText(IDC_EDIT_OFFSET, offsetStr);
    std::wstring direct = directStr.GetString();
    std::wstring relOff = offsetStr.GetString();
    ULONGLONG finalAddr = 0; bool addrOk = false;
    if (!direct.empty()) {
        finalAddr = ParseAddressText(direct, addrOk);
        if (!addrOk) {
            // If user used module+offset form with duplicate module names, show guidance.
            size_t plusPos = direct.find(L'+');
            if (plusPos != std::wstring::npos) {
                std::wstring left = direct.substr(0, plusPos);
                // count matches to explain failure
                int count=0; for (int i=0;i<m_ModuleList.GetItemCount();++i) { if (_wcsicmp(m_ModuleList.GetItemText(i,2), left.c_str())==0) count++; }
                if (count > 1) {
                    MessageBox(L"Multiple modules share that name. Use explicit base address (moduleBase+offset) instead.", L"Hook", MB_ICONWARNING);
                    return;
                }
            }
        }
    }
    if (!addrOk && !relOff.empty()) {
        // Fallback: selection + relative offset (hex/decimal/backtick accepted)
        std::wstring selName; ULONGLONG base=0;
        if (GetSelectedModule(selName, base)) {
            bool offOk=false; ULONGLONG off=0; bool dummy=false;
            off = ParseAddressText(relOff, dummy); // parseNumberAuto semantics
            offOk = dummy; // ok flag returned in dummy
            if (offOk) { finalAddr = base + off; addrOk = true; }
        }
    }
    if (!addrOk) {
        MessageBox(L"Failed to parse address. Acceptable formats:\n  fffff801`a86f7240\n  0xfffff801a86f7240\n  moduleName+0xOFFSET (unique name)\n  moduleBase+offset\nOr select a module and enter an offset.", L"Hook", MB_ICONERROR);
        return;
    }
    // Determine owning module to enforce master DLL exclusion
    std::wstring owningName; bool owningFound=false; ULONGLONG owningBase=0; ULONGLONG owningSize=0;
    for (int i=0;i<m_ModuleList.GetItemCount();++i) {
        ULONGLONG base = (ULONGLONG)m_ModuleList.GetItemData(i);
        // size column text -> parse hex after 0x
        CString sizeText = m_ModuleList.GetItemText(i,1);
        std::wstring szStr = sizeText.GetString(); ULONGLONG szVal=0; bool szOk=false;
        if (!szStr.empty()) {
            if (szStr.rfind(L"0x",0)==0) { wchar_t* end=nullptr; szVal = wcstoull(szStr.c_str()+2,&end,16); if (end && *end==0) szOk=true; }
            else { wchar_t* end=nullptr; szVal = wcstoull(szStr.c_str(),&end,10); if (end && *end==0) szOk=true; }
        }
        if (!szOk) continue;
        if (finalAddr >= base && finalAddr < base + szVal) {
            owningFound=true; owningBase=base; owningSize=szVal; owningName = m_ModuleList.GetItemText(i,2).GetString();
            break;
        }
    }
    if (owningFound) {
        if (_wcsicmp(owningName.c_str(), MASTER_X64_DLL_BASENAME)==0 || _wcsicmp(owningName.c_str(), MASTER_X86_DLL_BASENAME)==0) {
            MessageBox(L"Refusing to hook inside master DLL. Select a target function from another module.", L"Hook", MB_ICONERROR);
            return;
        }
    }
    // TODO: Actual hook invocation (driver/IPC) not implemented here. For now, log details.
    if (m_services) {
        m_services->Log(L"Hook request: pid=%u addr=0x%llX owner=%s base=0x%llX size=0x%llX direct='%s' offset='%s'\n",
            m_pid, finalAddr, owningFound?owningName.c_str():L"(unknown)", owningBase, owningSize, direct.c_str(), relOff.c_str());
    }
    // TODO: Actual hook invocation (driver/IPC) not implemented here. For now, log details.
    if (m_services) {
        m_services->Log(L"Hook request: pid=%u addr=0x%llX owner=%s base=0x%llX size=0x%llX direct='%s' offset='%s'\n",
            m_pid, finalAddr, owningFound?owningName.c_str():L"(unknown)", owningBase, owningSize, direct.c_str(), relOff.c_str());
    }
    MessageBox(L"Hook request parsed and validated (master DLL excluded). Backend not yet implemented.", L"Hook", MB_OK | MB_ICONINFORMATION);
}

void HookProcDlg::OnSize(UINT nType, int cx, int cy) {
    CDialogEx::OnSize(nType, cx, cy);
    if (!m_ModuleList.GetSafeHwnd()) return;
    const int margin = 7;
    // Compute dynamic right panel width based on minimum button/edit widths + margin
    const int editWidth = 140;
    const int buttonWidth = 65;
    const int buttonGap = 10; // gap between Apply and Close buttons to avoid overlap
    const int panelPadding = margin; // space between list and panel
    int rightPanelWidth = editWidth + panelPadding + buttonWidth * 2 + buttonGap; // approximate horizontal footprint
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
    // Place buttons side-by-side with explicit gap to prevent painting overlap.
    int applyX = panelLeft;
    int applyY = 100;
    int closeX = applyX + buttonWidth + buttonGap;
    moveCtrl(IDC_BTN_APPLY_HOOK, applyX, applyY, buttonWidth, 20);
    moveCtrl(IDCANCEL, closeX, applyY, buttonWidth, 20);
    // Force redraw to mitigate stale invalid region causing "overlap" until hover.
    if (CWnd* applyBtn = GetDlgItem(IDC_BTN_APPLY_HOOK)) applyBtn->Invalidate();
    if (CWnd* closeBtn = GetDlgItem(IDCANCEL)) closeBtn->Invalidate();
    // Hint label at bottom
    // Reposition hint label (now has its own ID) below the list but above bottom margin.
    CWnd* hint = GetDlgItem(IDC_STATIC_HINT);
    if (hint && hint->GetSafeHwnd()) {
        CRect rcHint; hint->GetWindowRect(&rcHint); ScreenToClient(&rcHint);
        int hintH = rcHint.Height();
        // Calculate desired Y just below list plus small gap
        int hintY = labelBottom + listHeight + 6;
        // If would overflow, clamp to bottom margin
        if (hintY + hintH + margin > cy) hintY = cy - hintH - margin;
        // Center horizontally within client
        int hintW = rcHint.Width();
        int hintX = (cx - hintW) / 2;
        if (hintX < margin) hintX = margin;
        hint->MoveWindow(hintX, hintY, hintW, hintH);
    }
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

void HookProcDlg::OnModuleItemChanged(NMHDR* pNMHDR, LRESULT* pResult) {
    LPNMLISTVIEW p = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
    if (p && (p->uChanged & LVIF_STATE)) {
        if ((p->uNewState & LVIS_SELECTED) != 0) {
            m_lastSelectedIndex = p->iItem;
        }
    }
    if (pResult) *pResult = 0;
}

void HookProcDlg::OnEnSetFocusOffset() {
    // Restore selection highlight if list lost focus and visual cleared
    if (m_lastSelectedIndex >= 0 && m_lastSelectedIndex < m_ModuleList.GetItemCount()) {
        m_ModuleList.SetItemState(m_lastSelectedIndex, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        m_ModuleList.RedrawItems(m_lastSelectedIndex, m_lastSelectedIndex);
    }
}

void HookProcDlg::OnEnSetFocusDirect() {
    if (m_lastSelectedIndex >= 0 && m_lastSelectedIndex < m_ModuleList.GetItemCount()) {
        m_ModuleList.SetItemState(m_lastSelectedIndex, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        m_ModuleList.RedrawItems(m_lastSelectedIndex, m_lastSelectedIndex);
    }
}

void HookProcDlg::OnCustomDrawModules(NMHDR* pNMHDR, LRESULT* pResult) {
    LPNMLVCUSTOMDRAW cd = reinterpret_cast<LPNMLVCUSTOMDRAW>(pNMHDR);
    if (!cd) { if (pResult) *pResult = 0; return; }
    DWORD stage = cd->nmcd.dwDrawStage;
    if (stage == CDDS_PREPAINT) {
        // Request item notifications
        *pResult = CDRF_NOTIFYITEMDRAW; return;
    }
    if (stage == CDDS_ITEMPREPAINT) {
        int iItem = (int)cd->nmcd.dwItemSpec;
        if (iItem == m_lastSelectedIndex && (m_ModuleList.GetItemState(iItem, LVIS_SELECTED) & LVIS_SELECTED)) {
            // Ask for subitem notifications so we can paint all columns with same highlight
            *pResult = CDRF_NOTIFYSUBITEMDRAW; return;
        }
        *pResult = CDRF_DODEFAULT; return;
    }
    if (stage == (CDDS_ITEMPREPAINT | CDDS_SUBITEM)) {
        int iItem = (int)cd->nmcd.dwItemSpec;
        if (iItem == m_lastSelectedIndex && (m_ModuleList.GetItemState(iItem, LVIS_SELECTED) & LVIS_SELECTED)) {
            // Owner-draw the subitem to ensure active highlight color even when list loses focus.
            // Retrieve subitem rect
            CRect rcSub{};
            LVITEM lvi{}; lvi.mask = LVIF_STATE; lvi.iItem = iItem; lvi.iSubItem = cd->iSubItem;
            // Use LVM_GETSUBITEMRECT
            LVITEMINDEX idx; idx.iItem = iItem; idx.iGroup = 0; // group not used
            RECT r{}; r.top = cd->iSubItem; // per MSDN, top holds subitem index for LVM_GETSUBITEMRECT
            if (m_ModuleList.GetSafeHwnd() && ListView_GetSubItemRect(m_ModuleList.GetSafeHwnd(), iItem, cd->iSubItem, LVIR_BOUNDS, &r)) {
                rcSub = r;
            } else {
                // fallback: use nmcd.rc for entire row (not ideal for multiple columns)
                rcSub = cd->nmcd.rc;
            }
            CDC* dc = CDC::FromHandle(cd->nmcd.hdc);
            if (dc) {
                COLORREF bk = ::GetSysColor(COLOR_HIGHLIGHT);
                COLORREF tx = ::GetSysColor(COLOR_HIGHLIGHTTEXT);
                dc->FillSolidRect(rcSub, bk);
                // Fetch text for this subitem
                CString txt = m_ModuleList.GetItemText(iItem, cd->iSubItem);
                // Adjust rect for some padding
                CRect rcText = rcSub; rcText.left += 4; rcText.right -= 2;
                dc->SetTextColor(tx);
                dc->SetBkColor(bk);
                dc->DrawText(txt, rcText, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
            }
            *pResult = CDRF_SKIPDEFAULT; return;
        }
    }
    *pResult = CDRF_DODEFAULT;
}

void HookProcDlg::PopulateHookList() {
    m_HookList.DeleteAllItems();
    // TODO: read persisted HookSites for this PID and populate entries.
    // For now, display nothing — hook metadata persistence integration pending.
}

int HookProcDlg::AddHookEntry(const std::wstring& hookId, ULONGLONG address, const std::wstring& moduleName) {
    int idx = m_HookList.GetItemCount();
    CString idC(hookId.c_str());
    CString addrC; addrC.Format(L"0x%llX", address);
    int i = m_HookList.InsertItem(idx, idC);
    m_HookList.SetItemText(i, 1, addrC);
    m_HookList.SetItemText(i, 2, moduleName.c_str());
    return i;
}