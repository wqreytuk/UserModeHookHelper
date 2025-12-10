// Lightweight header-only declarations for hook code helpers.
#pragma once
#include <string>
#include <Windows.h>

struct IHookServices {
	virtual VOID HKLog(const wchar_t* fmt, ...) = 0;
};
namespace HookCode {
	// Install caller-provided hook services (logging and helpers).
	void SetHookServices(IHookServices* services);
	// Resolve a kernel/user handle to a display name for the caller.
	// Caller provides its own process handle (for context) and a target handle value.
	// Returns a human-readable name (e.g., object name, file path, section name).
	// On failure, returns an empty string.
	std::wstring ResolveHandleName(HANDLE hCallerProcess, HANDLE hTargetHandle);
}