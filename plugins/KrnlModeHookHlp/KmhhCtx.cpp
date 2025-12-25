#include "KmhhCtx.h"
static IHookServices* ctx_services;
static PVOID trampoline_drv_base;
static PVOID dbg_prompt_abs_addr;

VOID KmhhCtx_SetHookServices(IHookServices* services) {
	ctx_services = services;
}
IHookServices* KmhhCtx_GetHookServices() {
	return ctx_services;
}
VOID KmhhCtx_SetTrampolinehDrvBase(PVOID base) {
	trampoline_drv_base = base;
}
PVOID KmhhCtx_GetTrampolinehDrvBase() {
	return trampoline_drv_base;
}


VOID KmhhCtx_SetDbgPromptAbsAddr(PVOID addr) {
	dbg_prompt_abs_addr = addr;
}
PVOID KmhhCtx_GetDbgPromptAbsAddr() {
	return dbg_prompt_abs_addr;
}
