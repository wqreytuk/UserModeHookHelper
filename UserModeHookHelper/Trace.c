
#include "Trace.h"
#include "MacroDef.h"

void Log(const WCHAR* format, ...) {
	WCHAR buffer[2000] = { 0 };

	va_list args;
	va_start(args, format);
	RtlStringCchVPrintfW(buffer, ARRAYSIZE(buffer), format, args);
	va_end(args);

	// use compile-time prefix
	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "%ws %ws\n", LOG_PREFIX, buffer);
}