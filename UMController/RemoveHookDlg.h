#pragma once
#include "pch.h"
#include <vector>
#include <string>
#include "ProcessManager.h"
#include "FilterCommPort.h"

class CRemoveHookDlg : public CDialogEx {
    DECLARE_DYNAMIC(CRemoveHookDlg)
public:
    CRemoveHookDlg(Filter* pFilter, CWnd* pParent = nullptr);
    virtual ~CRemoveHookDlg();
    virtual BOOL OnInitDialog();
    afx_msg void OnOk();
    afx_msg void OnSize(UINT nType, int cx, int cy);
    DECLARE_MESSAGE_MAP()
private:
    Filter* m_pFilter;
    std::vector<ProcessEntry> m_entries;
};
