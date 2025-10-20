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
END_MESSAGE_MAP()

BOOL CRemoveHookDlg::OnInitDialog() {
    CDialogEx::OnInitDialog();
    CListBox* lb = (CListBox*)GetDlgItem(IDC_LIST_PROC);
    if (!lb) return TRUE;
    // Ask kernel for hook NT path list
    if (!m_pFilter) return TRUE;
    std::vector<std::wstring> paths;
    if (!m_pFilter->FLTCOMM_EnumHookPaths(paths)) return TRUE;
    for (const auto &p : paths) {
        std::wstring display = p.empty() ? L"(unknown)" : p;
        lb->AddString(display.c_str());
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
