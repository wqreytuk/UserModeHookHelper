#pragma once
#include "pch.h"
#include <vector>
#include <string>

class CRemoveWhitelistDlg : public CDialogEx {
    DECLARE_DYNAMIC(CRemoveWhitelistDlg)
public:
    CRemoveWhitelistDlg(CWnd* pParent = nullptr);
    virtual ~CRemoveWhitelistDlg();
    virtual BOOL OnInitDialog();
    afx_msg void OnOk();
    afx_msg void OnSize(UINT nType, int cx, int cy);
    DECLARE_MESSAGE_MAP()
private:
    std::vector<std::wstring> m_paths; // NT or DOS paths from registry
};
