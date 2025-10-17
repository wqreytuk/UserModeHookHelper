
// UMControllerDlg.h : header file
//

#pragma once
#include <vector>
#include <string>
#include <algorithm>
#include <tlhelp32.h>
#include "FilterCommPort.h"
#include <unordered_map>
#include <thread>
#include <unordered_set>
#include "ProcessManager.h"

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
	virtual BOOL PreTranslateMessage(MSG* pMsg);
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg void OnAddHook();
	afx_msg void OnRemoveHook();
	afx_msg void OnInjectDll();
	afx_msg void OnAddExecutableToHookList();
	afx_msg void OnRemoveExecutablesFromHookList();
	DECLARE_MESSAGE_MAP()
public:
	void LoadProcessList();
	void FilterProcessList(const std::wstring& filter);


	afx_msg void OnEnChangeEditSearch();
	afx_msg void OnNMRClickListProc(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnLvnColumnclickListProc(NMHDR *pNMHDR, LRESULT *pResult);
    afx_msg LRESULT OnUpdateProcess(WPARAM wParam, LPARAM lParam);
	afx_msg void OnDestroy();
    
private:
	Filter m_Filter;
	CListCtrl m_ProcListCtrl;
	CMenu m_Menu;
	bool CheckHookList(const std::wstring& imagePath);
    afx_msg LRESULT OnFatalMessage(WPARAM wParam, LPARAM lParam);
	// Periodic rescan state
	HANDLE m_RescanEvent = NULL;
	std::thread m_RescanThread;
	unsigned m_RescanIntervalMs = 30000; // default 30s
	// Sorting state
	int m_SortColumn = 0;
	bool m_SortAscending = true;
	static int CALLBACK ProcListCompareFunc(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort);
};