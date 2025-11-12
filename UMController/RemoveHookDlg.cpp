#include "pch.h"
#include "RemoveHookDlg.h"
#include "Resource.h"
#include "Helper.h"
#include "ProcessManager.h"
#include "FilterCommPort.h"
#include "UMControllerMsgs.h"
#include "RegistryStore.h"
#include "RegistryStore.h"
#include "UMController.h"

IMPLEMENT_DYNAMIC(CRemoveHookDlg, CDialogEx)

CRemoveHookDlg::CRemoveHookDlg(Filter* pFilter, CWnd* pParent)
    : CDialogEx(IDD_REMOVE_HOOK_DLG, pParent), m_pFilter(pFilter) {
}

CRemoveHookDlg::~CRemoveHookDlg() {}

BEGIN_MESSAGE_MAP(CRemoveHookDlg, CDialogEx)
    ON_COMMAND(IDOK, &CRemoveHookDlg::OnOk)
    ON_WM_SIZE()
END_MESSAGE_MAP()

BOOL CRemoveHookDlg::OnInitDialog() {
    CDialogEx::OnInitDialog();
    CListBox* lb = (CListBox*)GetDlgItem(IDC_LIST_PROC);
    if (!lb) return TRUE;
    // Ask kernel for hook NT path list
    if (!m_pFilter) return TRUE;
    std::vector<std::wstring> paths;
    if (!m_pFilter->FLTCOMM_EnumHookPaths(paths)) return TRUE;
    int maxPixel = 0;
    CDC* pDC = lb->GetDC();
    for (const auto &p : paths) {
        std::wstring display = p.empty() ? L"(unknown)" : p;
        lb->AddString(display.c_str());
        if (pDC) {
            CSize sz = pDC->GetTextExtent(display.c_str());
            if (sz.cx > maxPixel) maxPixel = sz.cx;
        }
    }
    if (pDC) lb->ReleaseDC(pDC);
    // Add some padding so long paths don't truncate immediately at edge
    if (maxPixel > 0) lb->SetHorizontalExtent(maxPixel + 20);
    return TRUE;
}

void CRemoveHookDlg::OnOk() {
    CListBox* lb = (CListBox*)GetDlgItem(IDC_LIST_PROC);
    if (!lb) { EndDialog(IDCANCEL); return; }
    int count = lb->GetCount();
    std::vector<int> selectedIndices;
    for (int i = 0; i < count; ++i) {
        if (lb->GetSel(i) > 0) selectedIndices.push_back(i);
    }
    if (selectedIndices.empty()) { EndDialog(IDCANCEL); return; }
    // For each selected index, retrieve the string and remove by hash
    for (int sel : selectedIndices) {
        int len = lb->GetTextLen(sel);
        std::wstring buf;
        buf.resize(len + 1);
        lb->GetText(sel, &buf[0]);
        // trim trailing null if present
        if (!buf.empty() && buf.back() == L'\0') buf.pop_back();
        std::wstring path = buf;
        const UCHAR* bytes = reinterpret_cast<const UCHAR*>(path.c_str());
        size_t bytesLen = path.size() * sizeof(wchar_t);
        ULONGLONG hash = (ULONGLONG)Helper::GetNtPathHash(bytes, bytesLen);
        if (m_pFilter) {
            m_pFilter->FLTCOMM_RemoveHookByHash(hash);
        }
        // Persist removal to registry. If persistence fails, attempt rollback
        if (!RegistryStore::RemovePath(path)) {
            app.GetETW().Log(L"CRemoveHookDlg::OnOk: RegistryStore::RemovePath failed for %s - attempting rollback\n", path.c_str());
            // try to re-add in kernel
            m_pFilter->FLTCOMM_AddHook(path);
            continue; // skip PM updates for this path since rollback occurred
        }

        // Update ProcessManager entries that match this path by hash
        std::vector<DWORD> pids = PM_FindPidsByHash(hash);
        for (DWORD pid : pids) {
            // Clear inHook flag for matching PIDs. Path is unchanged.
            ProcessEntry e;
            if (PM_GetEntryCopyByPid(pid, e)) {
                PM_UpdateEntryFields(pid, e.path, false, e.cmdline);
                // Notify main UI to update this PID's row so the list control
                // reflects the new hook state immediately.
                if (GetParent()) {
                    ::PostMessage(GetParent()->GetSafeHwnd(), WM_APP_UPDATE_PROCESS, (WPARAM)pid, (LPARAM)UPDATE_SOURCE_NOTIFY);
                }
            }
        }
    }

    EndDialog(IDOK);
}

void CRemoveHookDlg::OnSize(UINT nType, int cx, int cy) {
    CDialogEx::OnSize(nType, cx, cy);
    // Resize list box to fill most of client area and reposition buttons at bottom-right
    CListBox* lb = (CListBox*)GetDlgItem(IDC_LIST_PROC);
    CWnd* okBtn = GetDlgItem(IDOK);
    CWnd* cancelBtn = GetDlgItem(IDCANCEL);
    if (!lb || !okBtn || !cancelBtn) return;
    const int margin = 7;
    const int buttonHeight = 18;
    const int buttonWidth = 80;
    int listBottom = cy - margin - buttonHeight - 8; // leave space for buttons
    if (listBottom < 60) listBottom = 60;
    lb->MoveWindow(margin, 20, cx - 2*margin, listBottom - 20);
    int btnY = cy - margin - buttonHeight;
    cancelBtn->MoveWindow(cx - margin - buttonWidth, btnY, buttonWidth, buttonHeight);
    okBtn->MoveWindow(cx - margin - 2*buttonWidth - 8, btnY, buttonWidth, buttonHeight);
}
