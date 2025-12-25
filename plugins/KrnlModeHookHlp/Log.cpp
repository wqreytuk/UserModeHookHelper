#include "Log.h"
#include "KmhhCtx.h"
#include <strsafe.h>
void KMHHLog(_In_ PCWSTR Format, ...) {
	wchar_t buffer[1024];
	va_list ap; 
	va_start(ap, Format);
	_vsnwprintf_s(buffer, _countof(buffer), _TRUNCATE, Format, ap);
	va_end(ap);
	
	if (!KmhhCtx_GetHookServices()) {
		MessageBoxW(NULL, L"Failed to call KmhhCtx_GetHookServices", L"Plugin Error", MB_ICONERROR);
		return;
	}
	return KmhhCtx_GetHookServices()->Log(L"[KMHH]       %s", buffer);
}