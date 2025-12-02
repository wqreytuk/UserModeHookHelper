
#include "phlib_expose.h"
#include "ProcessHackerLib.h"
namespace PHLIB {

	// NTSTATUS GetModuleBase(HANDLE hProc, WCHAR* target_module, DWORD64* out)
	void* GetModuleBase(void* hProc, void* target_module, void* out) {
		NTSTATUS st = PhpEnumProcessModules((HANDLE)(ULONG_PTR)hProc, (WCHAR*)(ULONG_PTR)target_module, (DWORD64*)(ULONG_PTR)out);
		return (PVOID)(ULONG_PTR)st;
	}
	/*
	NTSTATUS PhBuildModuleListWow64(
		_In_ HANDLE ProcessHandle,
		_Out_ PPH_MODULE_LIST_NODE* OutHead
	);
	*/
	void* PhBuildModuleListWow64(
	void* ProcessHandle,
	 void* OutHead
	) {
		return (void*)(ULONG_PTR)PhBuildModuleListWow64((HANDLE)(ULONG_PTR)ProcessHandle,
			(PPH_MODULE_LIST_NODE*)(ULONG_PTR)OutHead);
	}

	// void SetHookServices(IHookServices* services)
	void SetHookServices(void* services) {
		SetHookServices((IHookServices*)(ULONG_PTR)services);
	}
}