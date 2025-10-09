#pragma once


// ProcList dialog

class ProcList : public CDialogEx
{
	DECLARE_DYNAMIC(ProcList)

public:
	ProcList(CWnd* pParent = nullptr);   // standard constructor
	virtual ~ProcList();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_UMCONTROLLER_DIALOG };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
};
