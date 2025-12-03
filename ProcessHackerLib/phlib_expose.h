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
}