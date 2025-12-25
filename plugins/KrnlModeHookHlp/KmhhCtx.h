#pragma once
#include <Windows.h>
#include "HookServices.h"
VOID KmhhCtx_SetHookServices(IHookServices* services);
IHookServices* KmhhCtx_GetHookServices();
 

VOID KmhhCtx_SetTrampolinehDrvBase(PVOID base);
PVOID KmhhCtx_GetTrampolinehDrvBase();



VOID KmhhCtx_SetDbgPromptAbsAddr(PVOID addr);
PVOID KmhhCtx_GetDbgPromptAbsAddr();
