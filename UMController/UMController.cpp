
// UMController.cpp : Defines the class behaviors for the application.
//

#include "pch.h"
#include "framework.h"
#include "UMController.h"
#include "UMControllerDlg.h"
#include "ETW.h"
#include "Helper.h"


#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CUMControllerApp

BEGIN_MESSAGE_MAP(CUMControllerApp, CWinApp)
	ON_COMMAND(ID_HELP, &CWinApp::OnHelp)
END_MESSAGE_MAP()


// CUMControllerApp construction

CUMControllerApp::CUMControllerApp()
{
	// support Restart Manager
	m_dwRestartManagerSupportFlags = AFX_RESTART_MANAGER_SUPPORT_RESTART;

	// TODO: add construction code here,
	// Place all significant initialization in InitInstance
}


// The one and only CUMControllerApp object

CUMControllerApp app;



// CUMControllerApp initialization

BOOL CUMControllerApp::InitInstance()
{
	// Delay ETW provider initialization until after MFC/controls are ready to avoid early ASSERTs
	// InitCommonControlsEx() is required on Windows XP if an application
	// manifest specifies use of ComCtl32.dll version 6 or later to enable
	// visual styles.  Otherwise, any window creation will fail.
	INITCOMMONCONTROLSEX InitCtrls;
	InitCtrls.dwSize = sizeof(InitCtrls);
	// Set this to include all the common control classes you want to use
	// in your application.
	InitCtrls.dwICC = ICC_WIN95_CLASSES;
	InitCommonControlsEx(&InitCtrls);

	CWinApp::InitInstance();

	// Now safe to start ETW tracing (window/dialog not yet created but MFC core initialized)
	GetETW().StartTracer();
	GetETW().Reg();
	// UMHH.BootStart driver can only locate our dll at root directory
	Helper::CopyUmhhDllsToRoot();
	if (!Helper::UMHH_BS_DriverCheck()) {
		Helper::Fatal(L"UMHH_BS_DriverCheck failed\n");
	}
	Helper::UMHH_DriverCheck();

	AfxEnableControlContainer();

	// (Removed) Shell manager creation: not needed since dialog has no shell controls.

	// Activate "Windows Native" visual manager for enabling themes in MFC controls
	CMFCVisualManager::SetDefaultManager(RUNTIME_CLASS(CMFCVisualManagerWindows));

	// Standard initialization
	// If you are not using these features and wish to reduce the size
	// of your final executable, you should remove from the following
	// the specific initialization routines you do not need
	// Change the registry key under which our settings are stored
	// TODO: You should modify this string to be something appropriate
	// such as the name of your company or organization
	SetRegistryKey(_T("Local AppWizard-Generated Applications"));

	CUMControllerDlg dlg;
	m_pMainWnd = &dlg;
	INT_PTR nResponse = dlg.DoModal();
	if (nResponse == IDOK)
	{
		// TODO: Place code here to handle when the dialog is
		//  dismissed with OK
	}
	else if (nResponse == IDCANCEL)
	{
		// TODO: Place code here to handle when the dialog is
		//  dismissed with Cancel
	}
	else if (nResponse == -1)
	{
		TRACE(traceAppMsg, 0, "Warning: dialog creation failed, so application is terminating unexpectedly.\n");
		TRACE(traceAppMsg, 0, "Warning: if you are using MFC controls on the dialog, you cannot #define _AFX_NO_MFC_CONTROLS_IN_DIALOGS.\n");
	}

	// Shell manager not used; no deletion required.

#if !defined(_AFXDLL) && !defined(_AFX_NO_MFC_CONTROLS_IN_DIALOGS)
	ControlBarCleanUp();
#endif

	// Since the dialog has been closed, return FALSE so that we exit the
	//  application, rather than start the application's message pump.
	return FALSE;
}

