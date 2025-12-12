
#include "phlib_expose.h"
#include "ProcessHackerLib.h"
namespace PHLIB {
	/*NTSTATUS IsProcessWow64Internal(
		_In_ HANDLE hProc,
		_Out_ PBOOLEAN IsWow64);*/
	void* IsProcessWow64(
		_In_ void* hProc,
		_Out_ void* IsWow64) {
		NTSTATUS st =IsProcessWow64Internal((HANDLE)(ULONG_PTR)hProc, (PBOOLEAN)(ULONG_PTR)IsWow64);
		return (void*)(ULONG_PTR)st;
	}
	/*	NTSTATUS PhpEnumProcessModulesX64(
		_In_ HANDLE ProcessHandle, wchar_t *target_module, DWORD64* ModuleBase
	) {
	*/
	void* PhpEnumProcessModules(void* is64,
		_In_ void* ProcessHandle, void* target_module, void* ModuleBase
	) {
		PhInitializeWindowsVersion();
		if ((bool)(ULONG_PTR)is64) {
			NTSTATUS st = PhpEnumProcessModulesX64(
				(HANDLE)(ULONG_PTR)ProcessHandle, (wchar_t*)(ULONG_PTR)target_module, (DWORD64*)(ULONG_PTR)ModuleBase);
			return (void*)(ULONG_PTR)st;
		}
		else {
			NTSTATUS st = PhpEnumProcessModulesWin32(
				(HANDLE)(ULONG_PTR)ProcessHandle, (wchar_t*)(ULONG_PTR)target_module, (DWORD64*)(ULONG_PTR)ModuleBase);
			return (void*)(ULONG_PTR)st;
		} 
	}

	// NTSTATUS GetModuleBase(HANDLE hProc, WCHAR* target_module, DWORD64* out)
	void* GetModuleBase(void* pid, void* target_module, void* out) {
		NTSTATUS st = PhpEnumProcessModules((DWORD)(ULONG_PTR)pid, (wchar_t*)(ULONG_PTR)target_module, (DWORD64*)(ULONG_PTR)out);
		return (PVOID)(ULONG_PTR)st;
	}
	/*
	NTSTATUS PhBuildModuleListWow64(
		_In_ HANDLE ProcessHandle,
		_Out_ PPH_MODULE_LIST_NODE* OutHead
	);
	*/
	void* PhBuildModuleList(
	void* pid,
	 void* OutHead
	) {
		return (void*)(ULONG_PTR)PhBuildModuleListInteranl((DWORD)(ULONG_PTR)pid,
			(PPH_MODULE_LIST_NODE*)(ULONG_PTR)OutHead);
	}

	// void SetHookServices(IHookServices* services)
	void SetHookServices(void* services) {
		SetHookServicesInternal((IHookServices*)(ULONG_PTR)services);
	}
	/*	NTSTATUS
		PhGetProcessIsWow64Internal(
			_In_ DWORD pid,
			_Out_ PBOOLEAN IsWow64
		);*/
	void *PhGetProcessIsWow64( void* pid,
		 void* IsWow64){
		return 	(void*)(ULONG_PTR)PhGetProcessIsWow64Internal(
			(DWORD)(ULONG_PTR)pid,
			(BOOLEAN*)(ULONG_PTR)IsWow64
		);
	}
}