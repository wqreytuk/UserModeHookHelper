// HookUIFactory.h
// Public factory export declaration for the HookUI DLL.
// Include MFC core header to ensure correct Windows header ordering for HWND/BOOL/DWORD/WINAPI.
#pragma once
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00 // target Windows 10
#endif
#include <afxwin.h>
#include <afxdialogex.h> // CDialogEx
#include <string>
#include "HookInterfaces.h"

// Export macro for this DLL. If HOOKUI_EXPORTS is defined in project settings, we export.
#ifdef HOOKUI_EXPORTS
#define HOOKUI_API extern "C" __declspec(dllexport)
#else
#define HOOKUI_API extern "C" __declspec(dllimport)
#endif

// Unmangled factory function; consumers use GetProcAddress("ShowHookDialog") or import library.
HOOKUI_API BOOL WINAPI ShowHookDialog(HWND hParent, DWORD pid, const wchar_t* processName, IHookServices* services);
