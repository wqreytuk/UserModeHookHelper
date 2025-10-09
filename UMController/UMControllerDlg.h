
// UMControllerDlg.h : header file
//

#pragma once
#include <vector>
#include <string>
#include <algorithm>
#include <tlhelp32.h>
#include "FilterCommPort.h"
struct ProcessEntry {
	DWORD pid;
	std::wstring name;
	std::wstring path;
	bool bInHookList;
};
extern std::vector<ProcessEntry> g_ProcessList;

// CUMControllerDlg dialog
class CUMControllerDlg : public CDialogEx
{
	// Construction
public:
	virtual BOOL PreCreateWindow(CREATESTRUCT& cs);
	CUMControllerDlg(CWnd* pParent = nullptr);	// standard constructor

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_UMCONTROLLER_DIALOG };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg void OnAddHook();
	afx_msg void OnRemoveHook();
	afx_msg void OnInjectDll();
	DECLARE_MESSAGE_MAP()
public:
	void LoadProcessList();
	void FilterProcessList(const std::wstring& filter);


	afx_msg void OnEnChangeEditSearch();
	afx_msg void OnNMRClickListProc(NMHDR *pNMHDR, LRESULT *pResult);
private:
	Filter m_Filter;
	CListCtrl m_ProcListCtrl;
	bool CheckHookList(const std::wstring& imagePath);
    afx_msg LRESULT OnFatalMessage(WPARAM wParam, LPARAM lParam);
};