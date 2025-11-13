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
#define HOOKUI_EXPORTS
// Export macro for this DLL. Use dllexport when building, plain extern "C" when consuming.
// (We avoid dllimport to allow GetProcAddress loading without forcing import library semantics.)
#ifdef HOOKUI_EXPORTS
#define HOOKUI_API extern "C" __declspec(dllexport)
#else
#define HOOKUI_API extern "C"
#endif

// Unmangled factory function; consumers use GetProcAddress("ShowHookDialog") or import library.
HOOKUI_API BOOL WINAPI ShowHookDialog(HWND hParent, DWORD pid, const wchar_t* processName, IHookServices* services);
