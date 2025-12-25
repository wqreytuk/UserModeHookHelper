#pragma
#include <TCHAR.h>
#include <string>
namespace Helper {

	bool InstallAndStartDriverService(
		const std::wstring& serviceName,
		const std::wstring& driverPath
	);

	bool ConvertCharToWchar(const char* src, wchar_t* dst, size_t dstChars);
	bool ConvertWcharToChar(const wchar_t* src, char* dst, size_t dstChars);
	std::basic_string<TCHAR> GetCurrentDirFilePath(TCHAR* append);
}