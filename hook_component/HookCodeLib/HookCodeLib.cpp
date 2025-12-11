// HookCodeLib.cpp : 定义静态库的函数。
//

#include "pch.h"
#include "framework.h"
#include "HookCodeLib.h"
#include <vector>
 

#pragma comment(lib, "ntdll.lib")

namespace HookCode {
	static IHookServices* g_services = nullptr;
#define HKLog(...) g_services->HKLog(__VA_ARGS__)
	void SetHookServices(IHookServices* services) {
		g_services = services;
	}
	typedef  DWORD NTSTATUS;
	typedef struct _UNICODE_STRING
	{
		USHORT Length;
		USHORT MaximumLength;
		_Field_size_bytes_part_(MaximumLength, Length) PWCH Buffer;
	} UNICODE_STRING, *PUNICODE_STRING;
	typedef struct _OBJECT_NAME_INFORMATION
	{
		UNICODE_STRING Name;
	} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;
	typedef enum _OBJECT_INFORMATION_CLASS {
		ObjectBasicInformation,
		ObjectNameInformation,
		ObjectTypeInformation,
		ObjectAllInformation,
		ObjectDataInformation
	} OBJECT_INFORMATION_CLASS, *POBJECT_INFORMATION_CLASS;

	typedef NTSTATUS(NTAPI *pfnZWQUERYOBJECT)(
		HANDLE,
		OBJECT_INFORMATION_CLASS,
		PVOID,
		ULONG,
		PULONG
		);

	pfnZWQUERYOBJECT ZWQUERYOBJECT;
	namespace NTOBJ {
		static std::wstring QueryObjectName(HANDLE h) {
			HMODULE hNt = GetModuleHandleW(L"ntdll.dll");
			if (!hNt) return L"";
			ZWQUERYOBJECT = (pfnZWQUERYOBJECT)GetProcAddress(hNt, "ZwQueryObject");
			if (!ZWQUERYOBJECT) return L"";
			ULONG needed = 0;
			ULONG bufSize = 1024;
			std::vector<BYTE> buf(bufSize);
			NTSTATUS st = ZWQUERYOBJECT(h, ObjectNameInformation, buf.data(), bufSize, &needed);
			if (st == (NTSTATUS)0xC0000004) { // STATUS_INFO_LENGTH_MISMATCH
				buf.resize(needed);
				st = ZWQUERYOBJECT(h, ObjectNameInformation, buf.data(), (ULONG)buf.size(), &needed);
			}
			if (st < 0) return L"";
			auto nameInfo = reinterpret_cast<POBJECT_NAME_INFORMATION>(buf.data());
			if (!nameInfo || !nameInfo->Name.Buffer || nameInfo->Name.Length == 0) return L"";
			return std::wstring(nameInfo->Name.Buffer, nameInfo->Name.Length / sizeof(WCHAR));
		}

		std::wstring ResolveHandleName(HANDLE hCallerProcess, HANDLE hTargetHandle) {
			if (!hCallerProcess || !hTargetHandle) return L"";
			// Fast path: if handle belongs to current process, query directly
			if (GetProcessId(hCallerProcess) == GetCurrentProcessId()) {
				std::wstring name = QueryObjectName(hTargetHandle);
				if (name.empty()) {
					wchar_t pathBuf[MAX_PATH] = { 0 };
					DWORD n = GetFinalPathNameByHandleW(hTargetHandle, pathBuf, _countof(pathBuf), FILE_NAME_NORMALIZED);
					if (n > 0 && n < _countof(pathBuf)) name.assign(pathBuf);
				}
				HKLog(L"resolved Name=%s for Handle=0x%x\n", name.c_str(), hTargetHandle);
				return name;
			}
			// Otherwise duplicate into this process
			HANDLE dup = NULL;
			BOOL ok = DuplicateHandle(hCallerProcess, hTargetHandle, GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS);
			if (!ok || !dup) {
				HKLog(L"DuplicateHandle failed gle=%lu", GetLastError());
				return L"";
			}
			std::wstring name = QueryObjectName(dup);
			if (name.empty()) {
				wchar_t pathBuf[MAX_PATH] = { 0 };
				DWORD n = GetFinalPathNameByHandleW(dup, pathBuf, _countof(pathBuf), FILE_NAME_NORMALIZED);
				if (n > 0 && n < _countof(pathBuf)) name.assign(pathBuf);
			}
			CloseHandle(dup);
			return name;
		}
	}
	namespace STRLIB {
		// Check suffix in std::wstring, optional case-insensitive
		bool WStringEndsWith(const std::wstring& haystack, const std::wstring& suffix, bool ignoreCase) {
			if (suffix.size() > haystack.size()) return false;
			size_t start = haystack.size() - suffix.size();
			if (!ignoreCase) {
				return std::equal(suffix.begin(), suffix.end(), haystack.begin() + start);
			}
			for (size_t i = 0; i < suffix.size(); ++i) {
				wchar_t a = haystack[start + i];
				wchar_t b = suffix[i];
				if (towlower(a) != towlower(b)) return false;
			}
			return true;
		}
	}
}