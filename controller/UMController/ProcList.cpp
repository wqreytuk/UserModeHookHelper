// ProcList.cpp : implementation file
//

#include "pch.h"
#include "UMController.h"
#include "ProcList.h"
#include "afxdialogex.h"


// ProcList dialog

IMPLEMENT_DYNAMIC(ProcList, CDialogEx)

ProcList::ProcList(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_UMCONTROLLER_DIALOG, pParent)
{

}

ProcList::~ProcList()
{
}

void ProcList::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(ProcList, CDialogEx)
END_MESSAGE_MAP()


// ProcList message handlers
