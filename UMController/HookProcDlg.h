// HookProcDlg.h - modeless dialog for choosing hook address
#pragma once
#include <string>
#include <vector>
#include <windows.h>
#include <tlhelp32.h>
#include "resource.h"
#include "HookInterfaces.h"

class HookProcDlg : public CDialogEx {
public:
    HookProcDlg(DWORD pid, const std::wstring& name, IHookServices* services, CWnd* parent = nullptr)
        : CDialogEx(IDD_HOOK_PROC_DLG, parent), m_pid(pid), m_name(name), m_services(services) {}

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
    afx_msg void OnModuleItemChanged(NMHDR* pNMHDR, LRESULT* pResult);
    afx_msg void OnEnSetFocusOffset();
    afx_msg void OnEnSetFocusDirect();
    afx_msg void OnCustomDrawModules(NMHDR* pNMHDR, LRESULT* pResult);
    DECLARE_MESSAGE_MAP()

private:
    void PopulateModuleList();
    bool GetSelectedModule(std::wstring& name, ULONGLONG& base) const;
    ULONGLONG ParseAddressText(const std::wstring& text, bool& ok) const; // enhanced parser supporting windbg/backtick, module+offset, base+offset

    DWORD m_pid;
    std::wstring m_name;
    CListCtrl m_ModuleList;
    CListCtrl m_HookList;
    // Sorting state for module list
    int m_sortColumn = 0;
    bool m_sortAscending = true;
    static int CALLBACK ModuleCompare(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort);
    int m_lastSelectedIndex = -1; // track last module selection to restore visual state
    void PopulateHookList();
    int AddHookEntry(const std::wstring& hookId, ULONGLONG address, const std::wstring& moduleName);
    IHookServices* m_services = nullptr; // logging / future kernel ops abstraction
};