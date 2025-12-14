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
#include "../ProcessHackerLib/phlib_expose.h"
#include "../../drivers/UserModeHookHelper/UKShared.h"


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

	
	// write target process memory export function 
	/*
		 void* IsProcessWow64(
		 _In_ void* hProc,
		 _Out_ void* IsWow64);
	 void* PhpEnumProcessModules(void* is64,
		 _In_ void* ProcessHandle, void* target_module, void* ModuleBase
	 );
	*/
	HANDLE hProc = NULL;
	if (Helper::GetFilterInstance()) {
		Helper::GetFilterInstance()->FLTCOMM_GetProcessHandle(pid, &hProc);
	}
	else {
		Helper::Fatal(L"helper filter instance NULL\n");
		return FALSE;
	}
	if (!hProc) {
		LOG_CTRL_ETW(L"failed to call FLTCOMM_GetProcessHandle, Pid=%u\n", pid);
		return FALSE;
	}
	bool IsWow64;
	if (0!=(ULONG)(ULONG_PTR)PHLIB::IsProcessWow64((void*)(ULONG_PTR)hProc, (void*)(ULONG_PTR)&IsWow64)) {
		LOG_CTRL_ETW(L"failed to call PHLIB::IsProcessWow64, Pid=%u\n", pid);
		return FALSE;
	}
	bool is64 = !IsWow64;
	std::wstring target_module = is64 ? X64_DLL : X86_DLL;
	PVOID ModuleBase = NULL;
	if (0 != (ULONG)(ULONG_PTR)PHLIB::PhpEnumProcessModules((void*)(ULONG_PTR)is64, (void*)(ULONG_PTR)hProc, (void*)(ULONG_PTR)target_module.c_str(), (void*)(ULONG_PTR)&ModuleBase)) {
		LOG_CTRL_ETW(L"failed to call PHLIB::PhpEnumProcessModules, Pid=%u\n", pid);
		return FALSE;
	}
	// get export function offset of master dll base
	auto s = Helper::GetCurrentDirFilePath((TCHAR*)target_module.c_str());
	DWORD  out_func_offset = 0;
	if (!Helper::CheckExportFromFile(s.c_str(), MASETER_EXP_FUNC_NAME_STR, &out_func_offset)) {
		LOG_CTRL_ETW(L"can not locate export function Name=%s of module Path=%s\n", WIDEN(MASETER_EXP_FUNC_NAME_STR), s.c_str());
		Helper::Fatal(L"IPC: can not locate export function\n");
		return FALSE;
	}

	PVOID master_exp_addr = 0;
	DWORD old_protect = 0;
#ifdef _DEBUG
	if (!::VirtualProtectEx(hProc, (LPVOID)((DWORD64)ModuleBase + out_func_offset + E9_JMP_INSTRUCTION_OPCODE_SIZE), E9_JMP_INSTRUCTION_OPRAND_SIZE, PAGE_EXECUTE_READWRITE, &old_protect)) {
		LOG_CTRL_ETW( L"IPC VirtualProtectEx line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
		return FALSE;
	}

	DWORD e9_jmp_instruction_oprand = 0;
	if (!::ReadProcessMemory(hProc, (LPVOID)((DWORD64)ModuleBase + out_func_offset + E9_JMP_INSTRUCTION_OPCODE_SIZE),
		(LPVOID)&e9_jmp_instruction_oprand, E9_JMP_INSTRUCTION_OPRAND_SIZE, NULL)) {
		
		LOG_CTRL_ETW(L"failed to call ReadProcessMemory to get real export function addr, PID=%u\n", pid);
		return FALSE;
	}
	master_exp_addr = (PVOID)((DWORD64)ModuleBase + out_func_offset + E9_JMP_INSTRUCTION_SIZE + e9_jmp_instruction_oprand);
	if (!::VirtualProtectEx(hProc, (LPVOID)((DWORD64)ModuleBase + out_func_offset + E9_JMP_INSTRUCTION_OPCODE_SIZE), E9_JMP_INSTRUCTION_OPRAND_SIZE, old_protect, &old_protect)) {
		LOG_CTRL_ETW(L"IPC VirtualProtectEx line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
		return FALSE;
	}
#endif


	CHAR asci_dllpath[MAX_PATH] = { 0 };
	Helper::ConvertWcharToChar(dllPath, asci_dllpath, MAX_PATH);
	asci_dllpath[strlen(asci_dllpath)] = IPC_DLL_PATH_END_MARK;
	// try write dll path into process memory
	if (!::VirtualProtectEx(hProc, (LPVOID)master_exp_addr, MAX_PATH, PAGE_EXECUTE_READWRITE, &old_protect)) {
		LOG_CTRL_ETW( L"IPC VirtualProtectEx line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
		return FALSE;
	}
	if(!Helper::WriteProcessMemoryWrap(hProc, master_exp_addr, asci_dllpath,MAX_PATH, NULL)) {
		LOG_CTRL_ETW(L"IPC failed to call WriteProcessMemoryWrap, Pid=%u\n", pid);
		return FALSE;
	}
	if (!::VirtualProtectEx(hProc, (LPVOID)master_exp_addr, MAX_PATH, old_protect, &old_protect)) {
		LOG_CTRL_ETW( L"IPC VirtualProtectEx line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
		return FALSE;
	}


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
