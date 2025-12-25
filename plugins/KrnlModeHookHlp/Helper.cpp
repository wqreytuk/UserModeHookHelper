#include "Helper.h"
#include <Windows.h>
namespace Helper {

	bool InstallAndStartDriverService(
		const std::wstring& serviceName,
		const std::wstring& driverPath
	) {
		bool result = false;

		SC_HANDLE hSCM = OpenSCManagerW(
			nullptr,
			nullptr,
			SC_MANAGER_CREATE_SERVICE
		);
		if (!hSCM)
			return false;

		SC_HANDLE hService = CreateServiceW(
			hSCM,
			serviceName.c_str(),
			serviceName.c_str(),
			SERVICE_START | DELETE | SERVICE_STOP,
			SERVICE_KERNEL_DRIVER,
			SERVICE_DEMAND_START,
			SERVICE_ERROR_IGNORE,
			driverPath.c_str(),
			nullptr,
			nullptr,
			nullptr,
			nullptr,
			nullptr
		);

		if (!hService) {
			if (GetLastError() == ERROR_SERVICE_EXISTS) {
				hService = OpenServiceW(
					hSCM,
					serviceName.c_str(),
					SERVICE_START
				);
			}
		}

		if (hService) {
			if (StartServiceW(hService, 0, nullptr) ||
				GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) {
				result = true;
			}
			CloseServiceHandle(hService);
		}

		CloseServiceHandle(hSCM);
		return result;
	}

	bool ConvertCharToWchar(const char* src, wchar_t* dst, size_t dstChars) {
		if (!src || !dst || dstChars == 0) return false;
		// Simple byte->word expansion: copy each input byte into the low
		// 16 bits of a wchar_t and append a null terminator. This avoids
		// calling Win32 APIs and ignores code pages as requested.
		size_t i = 0;
		for (; i + 1 < dstChars && src[i] != '\0'; ++i) {
			dst[i] = (wchar_t)(unsigned char)src[i];
		}
		if (i >= dstChars) return false; // no room for null terminator
		dst[i] = L'\0';
		return true;
	}

	bool ConvertWcharToChar(const wchar_t* src, char* dst, size_t dstChars) {
		if (!src || !dst || dstChars == 0) return false;
		size_t i = 0;
		for (; i + 1 < dstChars && src[i] != L'\0'; ++i) {
			dst[i] = (char)(src[i] & 0xFF);
		}
		if (i >= dstChars) return false; // no room for null
		dst[i] = '\0';
		return true;
	}
	std::basic_string<TCHAR> GetCurrentDirFilePath(TCHAR* append)
	{
		TCHAR path[MAX_PATH] = { 0 };
		DWORD len = GetModuleFileName(NULL, path, MAX_PATH);
		if (len == 0 || len == MAX_PATH)
			return _T("");

		// Remove the filename to get the directory
		TCHAR* lastSlash = _tcsrchr(path, _T('\\'));
		if (lastSlash)
			*(lastSlash + 1) = _T('\0');

		// Append your custom string
		std::basic_string<TCHAR> fullPath = std::basic_string<TCHAR>(path) + append;
		return fullPath;
	}
}