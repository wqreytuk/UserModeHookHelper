
#include "phlib_expose.h"
#include "ProcessHackerLib.h"
namespace PHLIB {

	// NTSTATUS GetModuleBase(HANDLE hProc, WCHAR* target_module, DWORD64* out)
	void* GetModuleBase(void* hProc, void* target_module, void* out) {
		NTSTATUS st = PhpEnumProcessModules((HANDLE)(ULONG_PTR)hProc, (WCHAR*)(ULONG_PTR)target_module, (DWORD64*)(ULONG_PTR)out);
		return (PVOID)(ULONG_PTR)st;
	}


	// void SetHookServices(IHookServices* services)
	void SetHookServices(void* services) {
		SetHookServices((IHookServices*)(ULONG_PTR)services);
	}
}