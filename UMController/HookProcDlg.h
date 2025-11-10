// HookProcDlg.h - modeless dialog for choosing hook address
#pragma once
#include <string>
#include <vector>
#include <windows.h>
#include <tlhelp32.h>
#include "resource.h"

class HookProcDlg : public CDialogEx {
public:
    HookProcDlg(DWORD pid, const std::wstring& name, CWnd* parent = nullptr)
        : CDialogEx(IDD_HOOK_PROC_DLG, parent), m_pid(pid), m_name(name) {}

    // Create modeless
    BOOL CreateModeless(CWnd* parent) { return Create(IDD_HOOK_PROC_DLG, parent); }

    	// Sorting (column header click)
    	afx_msg void OnColumnClickModules(NMHDR* pNMHDR, LRESULT* pResult);
        DWORD GetPid() const { return m_pid; }
        // Public message constant so parent can reference it in its message map
        static const UINT kMsgHookDlgDestroyed;
protected:
    virtual void DoDataExchange(CDataExchange* pDX) {
        CDialogEx::DoDataExchange(pDX);
    }
    virtual BOOL OnInitDialog();
    afx_msg void OnDestroy();
    afx_msg void OnBnClickedApplyHook();
    afx_msg void OnSize(UINT nType, int cx, int cy);
    afx_msg void OnGetMinMaxInfo(MINMAXINFO* lpMMI);
    DECLARE_MESSAGE_MAP()

private:
    void PopulateModuleList();
    bool GetSelectedModule(std::wstring& name, ULONGLONG& base) const;
    ULONGLONG ParseAddressText(const std::wstring& text, bool& ok) const; // stub parser

    DWORD m_pid;
    std::wstring m_name;
    CListCtrl m_ModuleList;
    // Sorting state for module list
    int m_sortColumn = 0;
    bool m_sortAscending = true;
    static int CALLBACK ModuleCompare(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort);
};