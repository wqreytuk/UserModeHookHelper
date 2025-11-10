// HookProcDlg.h - dialog scaffold for per-process hook actions
#pragma once
#include <string>
#include "resource.h"

class HookProcDlg : public CDialogEx {
public:
    HookProcDlg(DWORD pid, const std::wstring& name, CWnd* parent = nullptr)
        : CDialogEx(IDD_HOOK_PROC_DLG, parent), m_pid(pid), m_name(name) {}

protected:
    virtual void DoDataExchange(CDataExchange* pDX) {
        CDialogEx::DoDataExchange(pDX);
    }
    virtual BOOL OnInitDialog() {
        CDialogEx::OnInitDialog();
        // Populate static text controls (search by order added in RC)
        CString info; info.Format(L"PID %lu - %s", m_pid, m_name.c_str());
        // Find first static placeholder with (pid/name) text? Simpler: set window title
        SetWindowText(info);
        return TRUE;
    }
    afx_msg void OnBnClickedHook();
    DECLARE_MESSAGE_MAP()
private:
    DWORD m_pid;
    std::wstring m_name;
};