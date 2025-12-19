// Lightweight header-only declarations for hook code helpers.
#pragma once
#include <string>
#include <Windows.h>

struct IHookServices {
	virtual VOID HKLog(const wchar_t* fmt, ...) = 0;
};
namespace HookCode {

	typedef struct _UNICODE_STRING
	{
		USHORT Length;
		USHORT MaximumLength;
		_Field_size_bytes_part_(MaximumLength, Length) PWCH Buffer;
	} UNICODE_STRING, *PUNICODE_STRING;
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
	namespace STRLIB {
		bool ConvertCharToWchar(const char* src, wchar_t* dst, size_t dstChars);
			
		bool AnsiSubStrCheck(const char *haystack, const char *needle, BOOL CaseInsensitive);

		bool WStringEndsWith(const std::wstring& haystack, const std::wstring& suffix, bool ignoreCase);
	BOOLEAN RtlSuffixUnicodeString(
		_In_ PUNICODE_STRING Suffix,
		_In_ PUNICODE_STRING String2,
		_In_ BOOLEAN CaseInSensitive
	);
	VOID RtlInitUnicodeString(
		_Out_ PUNICODE_STRING DestinationString,
		_In_opt_ PCWSTR SourceString
	);
	}
	namespace FILTER {
		// connect to filter
		HANDLE ConnectToFilter();
		bool GetProcessHandle(HANDLE m_Port, DWORD pid, HANDLE* outHandle);
	}
}