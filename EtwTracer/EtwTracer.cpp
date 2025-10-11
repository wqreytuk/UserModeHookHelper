#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include "../UMController/ETW.h"
#include <evntrace.h>
#include <evntcons.h>

GUID SessionGuid = {
	0x890e3076, 0x8441, 0x4e13, { 0x90, 0x32, 0xd1, 0x29, 0xa4, 0xa6, 0x40, 0x5a } };


TCHAR SessionName[] = TEXT("UMEtwTracer");


VOID
NTAPI
TraceStop(
	VOID
);

ULONG
NTAPI
TraceStart(
	VOID
);

VOID
WINAPI
TraceEventCallback(
	_In_ PEVENT_RECORD EventRecord
)
{
	if (!EventRecord->UserData)
	{
		return;
	}

	// Collapse duplicate newlines and trim trailing newline
	PWCHAR raw = (PWCHAR)EventRecord->UserData;
	WCHAR cleaned[4096];
	size_t ri = 0;
	bool lastWasNewline = false;
	for (size_t i = 0; raw[i] != L'\0' && ri + 1 < _countof(cleaned); ++i) {
		WCHAR c = raw[i];
		if (c == L'\r') continue;
		if (c == L'\n') {
			if (lastWasNewline) continue;
			cleaned[ri++] = L'\n';
			lastWasNewline = true;
		} else {
			cleaned[ri++] = c;
			lastWasNewline = false;
		}
	}
	if (ri > 0 && cleaned[ri - 1] == L'\n') ri--;
	cleaned[ri] = L'\0';

	// Timestamp
	SYSTEMTIME st;
	GetLocalTime(&st);

	wprintf(L"%04u-%02u-%02u %02u:%02u:%02u.%03u [%u:%u] %s\n",
		st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
		EventRecord->EventHeader.ProcessId,
		EventRecord->EventHeader.ThreadId,
		cleaned);
}
void CreateWaitSignalThread();

int main() {
	CreateWaitSignalThread();
	TraceStop();
	TraceStart();
}
void WaitThreadProc() {
	HANDLE hEvent = OpenEvent(SYNCHRONIZE, FALSE, SIGNALEVENTNAME);
	WaitForSingleObject(hEvent, INFINITE);
	CloseHandle(hEvent);
	MessageBoxA(NULL, "CloseConfirm", "EVT", MB_OK);
	TraceStop();
	exit(0);
}
void CreateWaitSignalThread() {
	ULONG dwThreadId = 0;
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WaitThreadProc, NULL, 0, &dwThreadId);
}

ULONG
NTAPI
TraceStart(
	VOID
)
{
	EVENT_TRACE_LOGFILE TraceLogfile = { 0 };
	TraceLogfile.LoggerName = SessionName;
	TraceLogfile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
	TraceLogfile.EventRecordCallback = &TraceEventCallback;

	TRACEHANDLE TraceHandle = OpenTrace(&TraceLogfile);
	HANDLE hReady = INVALID_HANDLE_VALUE;
	//
	// Start new trace session.
	// For an awesome blogpost on ETW API, see:
	// https://caseymuratori.com/blog_0025
	//

	ULONG ErrorCode;

	TRACEHANDLE TraceSessionHandle = INVALID_PROCESSTRACE_HANDLE;

	BYTE Buffer[sizeof(EVENT_TRACE_PROPERTIES) + 4096];
	RtlZeroMemory(Buffer, sizeof(Buffer));

	PEVENT_TRACE_PROPERTIES EventTraceProperties = (PEVENT_TRACE_PROPERTIES)Buffer;
	EventTraceProperties->Wnode.BufferSize = sizeof(Buffer);
	EventTraceProperties->Wnode.ClientContext = 1; // Use QueryPerformanceCounter, see MSDN
	EventTraceProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	EventTraceProperties->LogFileMode = PROCESS_TRACE_MODE_REAL_TIME;
	EventTraceProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

	ErrorCode = StartTrace(&TraceSessionHandle, SessionName, EventTraceProperties);
	if (ErrorCode != ERROR_SUCCESS)
	{
		goto Exit;
	}

	//
	// Enable tracing of our provider.
	//

	ErrorCode = EnableTrace(TRUE, 0, 0, &ProviderGUID, TraceSessionHandle);
	if (ErrorCode != ERROR_SUCCESS)
	{
		goto Exit;
	}

	// Signal the ready event so the parent UI knows the tracer is up.
	hReady = OpenEvent(EVENT_MODIFY_STATE, FALSE, ETW_TRACER_READY_EVENT);
	if (hReady) {
		SetEvent(hReady);
		CloseHandle(hReady);
	}

	//
	// Open real-time tracing session.
	//

	if (TraceHandle == INVALID_PROCESSTRACE_HANDLE)
	{
		//
		// Synthetic error code.
		//
		ErrorCode = ERROR_FUNCTION_FAILED;
		goto Exit;
	}

	//
	// Process trace events.  This call is blocking.
	//

	ErrorCode = ProcessTrace(&TraceHandle, 1, NULL, NULL);

Exit:
	if (TraceHandle)
	{
		CloseTrace(TraceHandle);
	}

	if (TraceSessionHandle)
	{
		CloseTrace(TraceSessionHandle);
	}

	RtlZeroMemory(Buffer, sizeof(Buffer));
	EventTraceProperties->Wnode.BufferSize = sizeof(Buffer);
	StopTrace(0, SessionName, EventTraceProperties);

	if (ErrorCode != ERROR_SUCCESS)
	{
		printf("Error: %08x\n", ErrorCode);
	}

	return ErrorCode;
}

VOID
NTAPI
TraceStop(
	VOID
)
{
	BYTE Buffer[sizeof(EVENT_TRACE_PROPERTIES) + 4096];
	RtlZeroMemory(Buffer, sizeof(Buffer));

	PEVENT_TRACE_PROPERTIES EventTraceProperties = (PEVENT_TRACE_PROPERTIES)Buffer;
	EventTraceProperties->Wnode.BufferSize = sizeof(Buffer);

	StopTrace(0, SessionName, EventTraceProperties);
}