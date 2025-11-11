// UIHelpers.h - small UI helper functions for UMController
#pragma once
#include <string>
#include "ProcFlags.h"

// Format the HookState column text from packed itemdata.
// PF_IN_HOOK_LIST determines if we show detailed info; otherwise returns "No".
std::wstring FormatHookColumn(PROC_ITEMDATA packed);
