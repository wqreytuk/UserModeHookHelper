// UIHelpers.h - small UI helper functions for UMController
#pragma once
#include <string>
#include "ProcFlags.h"

// Format the HookState column text from packed itemdata and hook flag.
std::wstring FormatHookColumn(PROC_ITEMDATA packed, bool bInHookList);
