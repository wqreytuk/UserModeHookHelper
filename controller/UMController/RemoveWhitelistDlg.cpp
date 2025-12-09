#include "pch.h"
#include "RemoveWhitelistDlg.h"
#include "Resource.h"
#include "Helper.h"
#include "RegistryStore.h"
#include "UMController.h"

IMPLEMENT_DYNAMIC(CRemoveWhitelistDlg, CDialogEx)

CRemoveWhitelistDlg::CRemoveWhitelistDlg(CWnd* pParent)
    : CDialogEx(IDD_REMOVE_WHITELIST_DLG, pParent) {}

CRemoveWhitelistDlg::~CRemoveWhitelistDlg() {}

BEGIN_MESSAGE_MAP(CRemoveWhitelistDlg, CDialogEx)
    ON_COMMAND(IDOK, &CRemoveWhitelistDlg::OnOk)
    ON_WM_SIZE()
END_MESSAGE_MAP()

BOOL CRemoveWhitelistDlg::OnInitDialog() {
    CDialogEx::OnInitDialog();
    CListBox* lb = (CListBox*)GetDlgItem(IDC_LIST_WHITELIST);
    if (!lb) return TRUE;
    // Load whitelist paths from registry
    m_paths.clear();
    if (!RegistryStore::ReadWhitelistPaths(m_paths)) return TRUE;
    int maxPixel = 0;
    CDC* pDC = lb->GetDC();
    for (const auto &p : m_paths) {
        std::wstring display = p.empty() ? L"(unknown)" : p;
        lb->AddString(display.c_str());
        if (pDC) {
            CSize sz = pDC->GetTextExtent(display.c_str());
            if (sz.cx > maxPixel) maxPixel = sz.cx;
        }
    }
    if (pDC) lb->ReleaseDC(pDC);
    if (maxPixel > 0) lb->SetHorizontalExtent(maxPixel + 20);
    return TRUE;
}

void CRemoveWhitelistDlg::OnOk() {
    CListBox* lb = (CListBox*)GetDlgItem(IDC_LIST_WHITELIST);
    if (!lb) { EndDialog(IDCANCEL); return; }
    int count = lb->GetCount();
    std::vector<int> selectedIndices;
    for (int i = 0; i < count; ++i) {
        if (lb->GetSel(i) > 0) selectedIndices.push_back(i);
    }
    if (selectedIndices.empty()) { EndDialog(IDCANCEL); return; }
    // Remove selected paths and corresponding hashes
    for (int sel : selectedIndices) {
        int len = lb->GetTextLen(sel);
        std::wstring buf; buf.resize(len + 1);
        lb->GetText(sel, &buf[0]);
        if (!buf.empty() && buf.back() == L'\0') buf.pop_back();
        std::wstring ntPath = buf;
        const UCHAR* bytes = reinterpret_cast<const UCHAR*>(ntPath.c_str());
        size_t bytesLen = ntPath.size() * sizeof(wchar_t);
        unsigned long long hash = Helper::GetNtPathHash(bytes, bytesLen);
        if (!RegistryStore::RemoveWhitelistPath(ntPath)) {
            app.GetETW().Log(L"RemoveWhitelistDlg: failed to remove path %s\n", ntPath.c_str());
            continue;
        }
        if (!RegistryStore::RemoveWhitelistHash(hash)) {
            app.GetETW().Log(L"RemoveWhitelistDlg: failed to remove hash for %s\n", ntPath.c_str());
        }
    }

    // Restart ObCallback service to reload whitelist
    if (!Helper::UMHH_ObCallback_DriverCheck()) {
        app.GetETW().Log(L"RemoveWhitelistDlg: UMHH_ObCallback_DriverCheck failed\n");
    }

    EndDialog(IDOK);
}

void CRemoveWhitelistDlg::OnSize(UINT nType, int cx, int cy) {
    CDialogEx::OnSize(nType, cx, cy);
    CListBox* lb = (CListBox*)GetDlgItem(IDC_LIST_WHITELIST);
    CWnd* okBtn = GetDlgItem(IDOK);
    CWnd* cancelBtn = GetDlgItem(IDCANCEL);
    if (!lb || !okBtn || !cancelBtn) return;
    const int margin = 7;
    const int buttonHeight = 18;
    const int buttonWidth = 80;
    int listBottom = cy - margin - buttonHeight - 8;
    if (listBottom < 60) listBottom = 60;
    lb->MoveWindow(margin, 20, cx - 2*margin, listBottom - 20);
    int btnY = cy - margin - buttonHeight;
    cancelBtn->MoveWindow(cx - margin - buttonWidth, btnY, buttonWidth, buttonHeight);
    okBtn->MoveWindow(cx - margin - 2*buttonWidth - 8, btnY, buttonWidth, buttonHeight);
}
