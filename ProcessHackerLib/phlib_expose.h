#pragma once
#include <stdio.h>
namespace PHLIB {
	 void* GetModuleBase(void* hProc, void* target_module, void* out);
	 void SetHookServices(void* services);
}