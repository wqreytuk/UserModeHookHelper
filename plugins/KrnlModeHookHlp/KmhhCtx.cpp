#include "KmhhCtx.h"
static IHookServices* ctx_services;
VOID KmhhCtx_SetHookServices(IHookServices* services) {
	ctx_services = services;
}
IHookServices* KmhhCtx_GetHookServices(){
	return ctx_services;
}