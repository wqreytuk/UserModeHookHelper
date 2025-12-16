// HookCodeLib.cpp : 定义静态库的函数。
//

#include "pch.h"
#include "framework.h"
#include "HookCodeLib.h"
#include <vector>
#include <fltuser.h>
#include "../../drivers/UserModeHookHelper/MacroDef.h"
#include "../../drivers/UserModeHookHelper/UKShared.h"
#include "../../controller/ProcessHackerLib/phlib_expose.h"

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "fltlib.lib")

namespace HookCode {
	static IHookServices* g_services = nullptr;
#define HKLog(...) g_services->HKLog(__VA_ARGS__)
	void SetHookServices(IHookServices* services) {
		g_services = services;
	}
	typedef  DWORD NTSTATUS;
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
		bool GetModuleBase(HANDLE hProc, const wchar_t* target_module, DWORD64* base) {
			bool  isWow64 = false;
			if (0 != PHLIB::IsProcessWow64((PVOID)(ULONG_PTR)hProc, &isWow64)) {
				HKLog(L"failed to call PHLIB::IsProcessWow64\n");
				return false;
			}
			if (0 != PHLIB::PhpEnumProcessModules((PVOID)(ULONG_PTR)(!isWow64), (PVOID)(ULONG_PTR)hProc, (PVOID)target_module, (PVOID)base)) {
				HKLog(L"failed to call PHLIB::PhpEnumProcessModules\n");
				return false;
			}
			return true;
		}
	}
	namespace STRLIB {
		VOID RtlInitUnicodeString(
			_Out_ PUNICODE_STRING DestinationString,
			_In_opt_ PCWSTR SourceString
		)
		{
			if (SourceString)
				DestinationString->MaximumLength = (DestinationString->Length = (USHORT)(wcslen(SourceString) * sizeof(WCHAR))) + sizeof(UNICODE_NULL);
			else
				DestinationString->MaximumLength = DestinationString->Length = 0;

			DestinationString->Buffer = (PWCH)SourceString;
		}
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
		static __forceinline WCHAR
			RtlUpcaseUnicodeChar(WCHAR ch)
		{
			if (ch >= L'a' && ch <= L'z')
				return ch - (L'a' - L'A');
			return ch;
		}

		LONG
			RtlCompareUnicodeStrings(
				const WCHAR* String1,
				SIZE_T Length1,
				const WCHAR* String2,
				SIZE_T Length2,
				BOOLEAN CaseInSensitive
			)
		{
			SIZE_T cch1 = Length1 / sizeof(WCHAR);
			SIZE_T cch2 = Length2 / sizeof(WCHAR);
			SIZE_T min = (cch1 < cch2) ? cch1 : cch2;

			for (SIZE_T i = 0; i < min; i++) {
				WCHAR c1 = String1[i];
				WCHAR c2 = String2[i];

				if (CaseInSensitive) {
					c1 = RtlUpcaseUnicodeChar(c1);
					c2 = RtlUpcaseUnicodeChar(c2);
				}

				if (c1 != c2)
					return (LONG)c1 - (LONG)c2;
			}

			return (LONG)cch1 - (LONG)cch2;
		}
		BOOLEAN RtlSuffixUnicodeString(
				_In_ PUNICODE_STRING Suffix,
				_In_ PUNICODE_STRING String2,
				_In_ BOOLEAN CaseInSensitive
			)
		{
			//
			// RtlSuffixUnicodeString is not exported by ntoskrnl until Win10.
			//

			return String2->Length >= Suffix->Length &&
				RtlCompareUnicodeStrings(String2->Buffer + (String2->Length - Suffix->Length) / sizeof(WCHAR),
					Suffix->Length / sizeof(WCHAR),
					Suffix->Buffer,
					Suffix->Length / sizeof(WCHAR),
					CaseInSensitive) == 0;

		}
	}
	namespace FILTER {
		// connect to filter
		HANDLE ConnectToFilter() {
			HRESULT hResult = S_OK;
			HANDLE m_Port = NULL;
			hResult = FilterConnectCommunicationPort(
				UMHHLP_PORT_NAME,
				0,
				NULL,
				0,
				NULL,
				&m_Port
			);
			if (hResult != S_OK) {
				HKLog(L"failed to call FilterConnectCommunicationPort: 0x%x\n", hResult);
			}
			else
				HKLog(L"successfully connect to minifilterport: 0x%p\n", m_Port);
			return m_Port;
		}
		bool GetProcessHandle(HANDLE m_Port, DWORD pid, HANDLE* outHandle) {
			*outHandle = NULL;
			const size_t msgSize = (sizeof(UMHH_COMMAND_MESSAGE) - 1) + sizeof(DWORD);
			PUMHH_COMMAND_MESSAGE msg = (PUMHH_COMMAND_MESSAGE)malloc(msgSize);
			if (!msg) return false;
			memset(msg, 0, msgSize);
			msg->m_Cmd = CMD_GET_PROCESS_HANDLE;
			memcpy(msg->m_Data, &pid, sizeof(DWORD));

			// Protocol: driver returns an 8-byte handle value regardless of client arch.
			// Read 8 bytes and cast down safely on x86.
			const SIZE_T replySize = 8; // fixed-width handle field
			std::unique_ptr<BYTE[]> reply(new BYTE[replySize]);
			DWORD bytesOut = 0;
			HRESULT hr = FilterSendMessage(m_Port, msg, (DWORD)msgSize, reply.get(), (DWORD)replySize, &bytesOut);
			free(msg);
			if (hr != S_OK || bytesOut != (DWORD)replySize) {
				HKLog(L"GetProcessHandle: FilterSendMessage hr=0x%x bytesOut=%u (expected %u)\n", hr, bytesOut, (unsigned)replySize);
				return false;
			}
			unsigned long long h64 = 0;
			memcpy(&h64, reply.get(), replySize);
			if (h64 == 0) return false;
			*outHandle = (HANDLE)(ULONG_PTR)h64;
			return true;
		}
	}
}