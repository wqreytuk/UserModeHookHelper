#pragma once
#include <stdio.h>
namespace PHLIB {
	 void* GetModuleBase(void* pid, void* target_module, void* out);
	 void SetHookServices(void* services);
	 void* PhBuildModuleList(
		 void* pid,
		 void* OutHead
	 );
	 void *PhGetProcessIsWow64(void* pid,
		 void* IsWow64);
	 void* IsProcessWow64(
		 _In_ void* hProc,
		 _Out_ void* IsWow64);
	 void* PhpEnumProcessModules(void* is64,
		 _In_ void* ProcessHandle, void* target_module, void* ModuleBase
	 );
}