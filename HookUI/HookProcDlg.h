// HookProcDlg.h - MFC dialog definition for per-process hook UI.
#pragma once
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <string>
#include <afxwin.h>        // core MFC (CWnd, etc.)
#include <afxdialogex.h>   // CDialogEx definition
#include <afxcmn.h>        // common controls (CListCtrl)
#include "HookInterfaces.h"
#include "HookUIResource.h"

class HookProcDlg : public CDialogEx {
public:
    HookProcDlg(DWORD pid, const std::wstring& name, IHookServices* services, CWnd* parent=nullptr);
    BOOL CreateModeless(CWnd* parent);
    static const UINT kMsgHookDlgDestroyed;
protected:
    virtual BOOL OnInitDialog();
    virtual void DoDataExchange(CDataExchange* pDX) { CDialogEx::DoDataExchange(pDX);}    
    afx_msg void OnDestroy();
    afx_msg void OnBnClickedApplyHook();
    afx_msg void OnSize(UINT nType, int cx, int cy);
    afx_msg void OnGetMinMaxInfo(MINMAXINFO* lpMMI);
    afx_msg void OnColumnClickModules(NMHDR* pNMHDR, LRESULT* pResult);
    afx_msg void OnModuleItemChanged(NMHDR* pNMHDR, LRESULT* pResult);
    afx_msg void OnEnSetFocusOffset();
    afx_msg void OnEnSetFocusDirect();
    afx_msg void OnCustomDrawModules(NMHDR* pNMHDR, LRESULT* pResult);
    DECLARE_MESSAGE_MAP()
private:
    void PopulateModuleList();
    bool GetSelectedModule(std::wstring& name, ULONGLONG& base) const;
    ULONGLONG ParseAddressText(const std::wstring& text, bool& ok) const;
    DWORD m_pid; std::wstring m_name; IHookServices* m_services=nullptr; CListCtrl m_ModuleList;
    int m_sortColumn=0; bool m_sortAscending=true; static int CALLBACK ModuleCompare(LPARAM, LPARAM, LPARAM);
};
