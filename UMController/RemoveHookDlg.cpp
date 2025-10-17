#include "pch.h"
#include "RemoveHookDlg.h"
#include "Resource.h"
#include "Helper.h"
#include "ProcessManager.h"

IMPLEMENT_DYNAMIC(CRemoveHookDlg, CDialogEx)

CRemoveHookDlg::CRemoveHookDlg(Filter* pFilter, CWnd* pParent)
    : CDialogEx(IDD_REMOVE_HOOK_DLG, pParent), m_pFilter(pFilter) {
}

CRemoveHookDlg::~CRemoveHookDlg() {}

BEGIN_MESSAGE_MAP(CRemoveHookDlg, CDialogEx)
    ON_COMMAND(IDOK, &CRemoveHookDlg::OnOk)
END_MESSAGE_MAP()

BOOL CRemoveHookDlg::OnInitDialog() {
    CDialogEx::OnInitDialog();
    m_entries = PM_GetAll();
    CListBox* lb = (CListBox*)GetDlgItem(IDC_LIST_PROC);
    if (!lb) return TRUE;
    // Populate with entries that are marked in hook list
    for (const auto &e : m_entries) {
        if (e.bInHookList) {
            std::wstring display = e.path.empty() ? L"(unknown)" : e.path;
            lb->AddString(display.c_str());
        }
    }
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

    // Map selected indices back to m_entries filtered list
    int j = 0;
    for (size_t idx = 0; idx < m_entries.size(); ++idx) {
        if (!m_entries[idx].bInHookList) continue;
        // check if j is in selectedIndices
        if (std::find(selectedIndices.begin(), selectedIndices.end(), j) != selectedIndices.end()) {
            // remove this entry
            const ProcessEntry &e = m_entries[idx];
            const UCHAR* bytes = reinterpret_cast<const UCHAR*>(e.path.c_str());
            size_t bytesLen = e.path.size() * sizeof(wchar_t);
            ULONGLONG hash = (ULONGLONG)Helper::GetNtPathHash(bytes, bytesLen);
            if (m_pFilter) {
                m_pFilter->FLTCOMM_RemoveHookByHash(hash);
            }
            PM_UpdateEntryFields(e.pid, e.path, false, L"");
        }
        ++j;
    }

    EndDialog(IDOK);
}
