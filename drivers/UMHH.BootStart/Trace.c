
#include "Trace.h"
#include "MacroDef.h"
// Some time conversion helpers are provided by the runtime; declare them
// here to avoid depending on extra headers in this small translation unit.
// Use the same linkage and calling convention as the official
// declarations in ntrtl.h so the compiler doesn't warn about
// inconsistent dll linkage.
NTSYSAPI
NTSTATUS
NTAPI
RtlSystemTimeToLocalTime(
	_In_ PLARGE_INTEGER SystemTime,
	_Out_ PLARGE_INTEGER LocalTime
	);

NTSYSAPI
VOID
NTAPI
RtlTimeToTimeFields(
	_In_ PLARGE_INTEGER Time,
	_Out_ PTIME_FIELDS TimeFields
	);

void Log(const WCHAR* format, ...) {
	WCHAR buffer[2000] = { 0 };

	va_list args;
	va_start(args, format);
	RtlStringCchVPrintfW(buffer, ARRAYSIZE(buffer), format, args);
	va_end(args);

	// Build a timestamp prefix using local time
	LARGE_INTEGER systemTime = { 0 };
	LARGE_INTEGER localTime = { 0 };
	KeQuerySystemTime(&systemTime);
	if (!NT_SUCCESS(RtlSystemTimeToLocalTime(&systemTime, &localTime))) {
		localTime = systemTime;
	}
	TIME_FIELDS tf;
	RtlTimeToTimeFields(&localTime, &tf);
	WCHAR timebuf[64] = { 0 };
	RtlStringCchPrintfW(timebuf, ARRAYSIZE(timebuf), L"[%04hu-%02hu-%02hu %02hu:%02hu:%02hu.%03hu]",
		(tf.Year), (tf.Month), (tf.Day), (tf.Hour), (tf.Minute), (tf.Second), (tf.Milliseconds));

	// Print timestamp, compile-time prefix, and message
	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "%ws %ws %ws\n", timebuf, LOG_PREFIX_OBC, buffer);
}