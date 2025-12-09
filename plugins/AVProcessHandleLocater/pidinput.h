#pragma once
#include <windows.h>

// Simple modal PID input dialog using plain Win32 APIs.
// Call ShowPidInputDialog(hwndOwner, &outPid) to prompt the user.
// Returns true if user pressed OK and outPid contains a positive DWORD.

BOOL ShowPidInputDialog(HWND owner, DWORD* outPid);
