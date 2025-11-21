// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <stdio.h>  
#include <evntprov.h>
#include "../UMController/HookInterfaces.h"
#include "pidinput.h"
#include <tlhelp32.h>
#include <string>
#include "../UMController/ProcFlags.h"
#include "../UMController/Helper.h"
 

#define AVPHL_X64_DLL L"AvProcessHandleLocated.dll.x64.dll"
#define AVPHL_X86_DLL L"AvProcessHandleLocated.dll.Win32.dll"
#define SIGNAL_FILENAME L"C:\\Users\\Public\\AVPHL.%d"
static const GUID ProviderGUID =
{ 0x3da12c0, 0x27c2, 0x4d75, { 0x95, 0x3a, 0x2c, 0x4e, 0x66, 0xa3, 0x74, 0x64 } };
REGHANDLE g_ProviderHandle;
static void FormatObjectName(PWCHAR out, size_t outCount, PCWSTR fmt, DWORD pid)
{
	// Use swprintf_s for simplicity (UMController is user-mode)
	swprintf_s(out, outCount, fmt, (unsigned)pid);
}

void Log(_In_ PCWSTR Format, ...) {
	WCHAR Buffer[1024];
	va_list args;
	va_start(args, Format);
	_vsnwprintf_s(Buffer, RTL_NUMBER_OF(Buffer) - 1, Format, args);
	va_end(args);
	Buffer[RTL_NUMBER_OF(Buffer) - 1] = L'\0';

	WCHAR Prefixed[1100];
	_snwprintf_s(Prefixed, RTL_NUMBER_OF(Prefixed) - 1, L"[AVPHL]      %s", Buffer);
	Prefixed[RTL_NUMBER_OF(Prefixed) - 1] = L'\0';
	if (g_ProviderHandle)
		EventWriteString(g_ProviderHandle, 0, 0, Prefixed);
	else
		// fall back to debugger output
		OutputDebugStringW(Prefixed);
}
BOOL WriteSignalFile(IHookServices* services,wchar_t* signalPath,DWORD pid) {
	HANDLE hFile = 0;
	if (!services->CreateLowPrivReqFile(signalPath, &hFile)) {
		Log(L"failed to call CreateLowPrivReqFile\n");
		return FALSE;
	}
	DWORD written = 0;
	// write pid as 4 bytes little-endian
	DWORD pidValue = pid;
	if (!WriteFile(hFile, &pidValue, sizeof(pidValue), &written, NULL) || written != sizeof(pidValue)) {
		Log(L"WriteSignalFile: WriteFile(pid) failed (%u)\n", GetLastError());
		CloseHandle(hFile);
		return FALSE;
	}
	return TRUE;
}
bool TryOpenProcWithReadWrite(DWORD pid) {
	HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE, 0, pid);
	if (!h)
		return false;
	CloseHandle(h);
	return true;
}
VOID EntryCode() {
	ULONG status = EventRegister(&ProviderGUID,
		NULL,
		NULL,
		&g_ProviderHandle);


	WCHAR signalPath[MAX_PATH];
	FormatObjectName(signalPath, RTL_NUMBER_OF(signalPath), SIGNAL_FILENAME, (unsigned)GetCurrentProcessId());
	// read out to get to be tested pid
	HANDLE hFile = CreateFileW(signalPath, GENERIC_READ, 0, 0, OPEN_ALWAYS, 0, 0);
	if (hFile == INVALID_HANDLE_VALUE) {
		Log(L"failed to create file=%s, abort\n", signalPath);
		return;
	}
	DWORD targetPid = 0;
	DWORD bytesOut = 0;
	if (!ReadFile(hFile, &targetPid, sizeof(DWORD), &bytesOut, 0)) {
		Log(L"failed to read file=%s, abort\n", signalPath);
		return;
	}
	// skip myself
	if (targetPid == GetCurrentProcessId())
		return;
	if (!TryOpenProcWithReadWrite(targetPid)) {
	// nothing
	}
	else {
		Log(L"AVProcessHandleLocater success, %u can open %u", GetCurrentProcessId(), targetPid);
	}
}

extern "C" __declspec(dllexport) BOOL WINAPI PluginMain(HWND hwnd, IHookServices* services) {
	if (!services) {
		MessageBoxW(NULL, L"Failed to load plugin DLL.", L"Plugin Error", MB_ICONERROR);
		return FALSE;
	}
	if (!services->EnableDebugPrivilege(true)) {
		Log(L"failed to call EnableDebugPrivilege\n");
		return FALSE;
	}
	DWORD pid = 0;
	if (!ShowPidInputDialog(hwnd, &pid)) {
		Log(L"ShowPidInputDialog canceled or failed\n");
		return FALSE;
	}
	Log(L"Plugin: user entered PID=%u\n", pid);


	// Determine this DLL's directory so we can construct the trampoline DLL paths
	HMODULE hThis = NULL;
	if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		reinterpret_cast<LPCWSTR>(&PluginMain), &hThis)) {
		Log(L"GetModuleHandleExW failed: %lu\n", GetLastError());
	}

	wchar_t mePath[MAX_PATH] = { 0 };
	if (hThis) GetModuleFileNameW(hThis, mePath, _countof(mePath));
	std::wstring meDir = L".";
	if (mePath[0]) {
		std::wstring s(mePath);
		size_t p = s.find_last_of(L"/\\");
		if (p != std::wstring::npos) meDir = s.substr(0, p);
		else meDir = s;
	}

	// Enumerate all processes and find those with the master DLL loaded
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE) {
		Log(L"CreateToolhelp32Snapshot failed: %lu\n", GetLastError());
		return TRUE; // nothing to do
	}

	PROCESSENTRY32W pe = { 0 };
	pe.dwSize = sizeof(pe);
	if (!Process32FirstW(snap, &pe)) {
		CloseHandle(snap);
		return TRUE;
	}

	do {
		DWORD targetPid = pe.th32ProcessID;
		if (targetPid == 0 || targetPid == 4) continue;

		bool is64 = false;
		if (!services->IsProcess64(targetPid, is64)) {
			// Could not determine arch; skip
			Log(L"failed to call IsProcess64, this is should not happen in normal circumstance\n");
			continue;
		}

		const wchar_t* masterName = is64 ? MASTER_X64_DLL_BASENAME : MASTER_X86_DLL_BASENAME;
		bool dllLoaded = false;
		// Helper::IsModuleLoaded is available in the host; call via implementation here
		if (!services->IsModuleLoaded(targetPid, masterName, dllLoaded)) { 
			Log(L"failed to call IsModuleLoaded target PID=%u, this is should not happen in normal circumstance\n", targetPid);
			continue; 
		}
		if (!dllLoaded) {
			Log(L"TargetPID=%u arch=%s master dll not loaded, trying force injection\n",targetPid, is64 ? L"x64" : L"x86");
			// continue;
			// my driver is not an early launch driver, so he can not possibly hook all processes
			// some process such as lsass.exe is already started before my driver
			if (!services->ForceInject(targetPid)) {
				Log(L"TargetPID=%u arch=%s, failed to perform force injection, skip\n", targetPid, is64 ? L"x64" : L"x86");
				continue;
			}
			// check again
			const int maxIterations = 50; bool loaded = false;
			for (int iter = 0; iter < maxIterations && !loaded; ++iter) {
				services->IsModuleLoaded(pid, masterName, loaded);
				if (loaded)
					break;
				Sleep(100);
			}
			if (!loaded) {
				Log(L"TargetPID=%u arch=%s, driver report injection success, but user mode can't detect master dll\n", targetPid, is64 ? L"x64" : L"x86");
				continue;
			}
		}
		// Construct trampoline path (do not perform injection here)
		std::wstring tramp = meDir + L"\\" + (is64 ? AVPHL_X64_DLL : AVPHL_X86_DLL);

		// Log candidate target and chosen trampoline path (no injection performed)
		Log(L"Candidate PID=%u arch=%s Dll=%s\n", targetPid, is64 ? L"x64" : L"x86", tramp.c_str());

		// create signal file
		WCHAR signalPath[MAX_PATH];
		FormatObjectName(signalPath, RTL_NUMBER_OF(signalPath), SIGNAL_FILENAME, (unsigned)targetPid);
		if (!WriteSignalFile(services, signalPath, pid)) {
			Log(L"failed to call WriteSignalFile\n");
			continue;
		}

		if (!services->InjectTrampoline(targetPid, tramp.c_str())) {
			Log(L"failed to call InjectTrampoline PID=%u arch=%s Dll=%s\n", targetPid, is64 ? L"x64" : L"x86", tramp.c_str());
			continue;
		}
		// check if dll injected
		const int maxIterations = 50; bool loaded = false;
		for (int iter = 0; iter < maxIterations && !loaded; ++iter) {
			services->IsModuleLoaded(pid, is64 ? AVPHL_X64_DLL : AVPHL_X86_DLL, loaded);
			if (loaded)
				break;
			Sleep(100);
		}

		if (!loaded) {
			Log(L"failed to inject %s\n", is64 ? AVPHL_X64_DLL : AVPHL_X86_DLL);
			continue;
		}

	} while (Process32NextW(snap, &pe));


	CloseHandle(snap);

	return TRUE;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		EntryCode();
		break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

