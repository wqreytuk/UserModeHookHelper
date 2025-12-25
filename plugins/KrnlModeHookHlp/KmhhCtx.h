#pragma once
#include <Windows.h>
#include "HookServices.h"
VOID KmhhCtx_SetHookServices(IHookServices* services);
IHookServices* KmhhCtx_GetHookServices();