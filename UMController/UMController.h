
// UMController.h : main header file for the PROJECT_NAME application
//

#pragma once

#ifndef __AFXWIN_H__
	#error "include 'pch.h' before including this file for PCH"
#endif

#include "resource.h" 		// main symbols
#include "ETW.h"

// CUMControllerApp:
// See UMController.cpp for the implementation of this class
//

class CUMControllerApp : public CWinApp
{
public:
	CUMControllerApp();

	ETW& GetETW() { return m_etw; }
	HWND GetHwnd() { return m_Hwnd; }
	VOID SetHwnd(HWND hwnd){m_Hwnd = hwnd;}
private:
	// App-owned ETW instance (owns lifetime)
	ETW m_etw;
	HWND m_Hwnd;
// Overrides
public:
	virtual BOOL InitInstance();

// Implementation

	DECLARE_MESSAGE_MAP() 
};

extern CUMControllerApp app;

