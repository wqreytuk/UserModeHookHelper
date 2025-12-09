#include "pch.h"
// IPC implementation for UMController — uses native ntdll APIs only.
#include "IPC.h"
#include <windows.h>
#include <wchar.h>
#include <string.h>
#include "UMController.h" // for app.GetETW()
#include "Helper.h" // for app.GetETW()
#include "../Shared/LogMacros.h"
#include <sddl.h>
#include "../Shared/SharedMacroDef.h"


// Helper to format named object name into buffer
static void FormatObjectName(PWCHAR out, size_t outCount, PCWSTR fmt, DWORD pid)
{
    // Use swprintf_s for simplicity (UMController is user-mode)
    swprintf_s(out, outCount, fmt, (unsigned)pid);
}

BOOL IPC_SendInject(DWORD pid, PCWSTR dllPath)
{
	if (!dllPath || pid == 0) return FALSE;

	LOG_CTRL_ETW(L"IPC_SendInject: pid=%u dll=%s\n", pid, dllPath);

	// Build signal filename in Win32 form
	WCHAR signalPath[MAX_PATH] = { 0 };
	FormatObjectName(signalPath, RTL_NUMBER_OF(signalPath), USER_IPC_SIGNAL_FILE_FMT, (unsigned)pid);

	// Convert wide DLL path to ANSI bytes because the injector widens bytes back
	// to WCHAR on the target process side.
	int asciiLen = WideCharToMultiByte(CP_ACP, 0, dllPath, -1, NULL, 0, NULL, NULL);
	if (asciiLen <= 0) {
		LOG_CTRL_ETW(L"IPC_SendInject: WideCharToMultiByte failed\n");
		return FALSE;
	}
	char* asciiBuf = new char[asciiLen];
	WideCharToMultiByte(CP_ACP, 0, dllPath, -1, asciiBuf, asciiLen, NULL, NULL);
	// delete signal file first
	DeleteFile(signalPath);
	// Prepare payload: 4 bytes pid (little endian), '$', dll bytes (no null), '$'
	// We'll write as binary file.




	PSECURITY_DESCRIPTOR pSD = nullptr;

	// SDDL: D: (DACL) (A;;GA;;;WD) => Allow Generic All to Everyone
	LPCWSTR sddl = L"D:(A;;GA;;;WD)";

	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
		sddl, SDDL_REVISION_1, &pSD, NULL)) {
		LOG_CTRL_ETW(L"ConvertStringSecurityDescriptorToSecurityDescriptorW failed: 0x%x\n", GetLastError());
		Helper::Fatal(L"ConvertStringSecurityDescriptorToSecurityDescriptorW function call failed\n");
		return FALSE;
	}

	SECURITY_ATTRIBUTES sa = {};
	sa.nLength = sizeof(sa);
	sa.lpSecurityDescriptor = pSD;
	sa.bInheritHandle = FALSE;



	HANDLE hFile = CreateFile(signalPath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		LOG_CTRL_ETW(L"IPC_SendInject: CreateFile %ws failed (%u)\n", signalPath, GetLastError());
		LocalFree(pSD);

		Helper::Fatal(L"create signal file failed\n");
		return FALSE;
	}
	LocalFree(pSD);
	DWORD written = 0;
	// write pid as 4 bytes little-endian
	DWORD pidValue = pid;
	if (!WriteFile(hFile, &pidValue, sizeof(pidValue), &written, NULL) || written != sizeof(pidValue)) {
		LOG_CTRL_ETW(L"IPC_SendInject: WriteFile(pid) failed (%u)\n", GetLastError());
		CloseHandle(hFile);
		return FALSE;
	}
	// write marker '$'
	char marker = '$';
	if (!WriteFile(hFile, &marker, 1, &written, NULL) || written != 1) {
		LOG_CTRL_ETW(L"IPC_SendInject: WriteFile(marker1) failed (%u)\n", GetLastError());
		CloseHandle(hFile);
		return FALSE;
	}
	// write ascii dll path (without terminating null)
	size_t dllBytes = (size_t)(asciiLen - 1); // exclude null
	if (dllBytes > 0) {
		if (!WriteFile(hFile, asciiBuf, (DWORD)dllBytes, &written, NULL) || written != dllBytes) {
			LOG_CTRL_ETW(L"IPC_SendInject: WriteFile(dllPath) failed (%u)\n", GetLastError());
			CloseHandle(hFile);
			return FALSE;
		}
	}
	// write trailing marker '$'
	if (!WriteFile(hFile, &marker, 1, &written, NULL) || written != 1) {
		LOG_CTRL_ETW(L"IPC_SendInject: WriteFile(marker2) failed (%u)\n", GetLastError());
		CloseHandle(hFile);
		return FALSE;
	}

	CloseHandle(hFile);
	delete[] asciiBuf;

	WCHAR event_name[MAX_PATH] = { 0 };
	FormatObjectName(event_name, RTL_NUMBER_OF(event_name), USER_MODE_INJECTION_SIGNAL_EVENT L"%d", (unsigned)pid);
	HANDLE h = OpenEventW(EVENT_MODIFY_STATE, FALSE, event_name);
	if (h) {
		SetEvent(h);
		LOG_CTRL_ETW(L"event=%s signaled, notifying injected dll to process injection request\n", event_name);
	}
	else {
		LOG_CTRL_ETW(L"failed to open event==%s, error=0x%x\n", event_name, GetLastError());
		return FALSE;
	}
	return TRUE;
}
