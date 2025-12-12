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
	namespace NTOBJ {
		std::wstring ResolveHandleName(HANDLE hCallerProcess, HANDLE hTargetHandle);
		bool GetModuleBase(HANDLE hProc, const wchar_t* target_module, DWORD64* base);
	}
	// Check whether wide string `haystack` ends with `suffix`.
	// If ignoreCase is true, comparison is case-insensitive.
	namespace STRLIB { bool WStringEndsWith(const std::wstring& haystack, const std::wstring& suffix, bool ignoreCase); }
	namespace FILTER {
		// connect to filter
		HANDLE ConnectToFilter();
		bool GetProcessHandle(HANDLE m_Port, DWORD pid, HANDLE* outHandle);
	}
}