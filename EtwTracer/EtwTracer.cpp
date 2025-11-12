#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include "../UMController/ETW.h"
#include <evntrace.h>
#include <evntcons.h>
#include <string>
#include <vector>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <atomic>

// Simple asynchronous file logger for ETWTracer.
// Writes each formatted line (same as console output) to a UTF-8 file without
// blocking the ETW callback thread.
namespace {
	std::mutex              gLogMutex;
	std::condition_variable gLogCv;
	std::vector<std::wstring> gPendingLines; // queued lines
	std::atomic<bool>       gLogStop{ false };
	std::thread             gLogThread;
	HANDLE                  gFileHandle = INVALID_HANDLE_VALUE; // Win32 file for overlapped simplicity
	bool                    gUtf8BomWritten = false;
	std::wstring            gLogPath; // chosen path

	void LogThreadProc() {
		std::vector<std::wstring> local;
		while (!gLogStop.load()) {
			{
				std::unique_lock<std::mutex> lk(gLogMutex);
				if (gPendingLines.empty()) {
					gLogCv.wait_for(lk, std::chrono::milliseconds(500));
				}
				if (!gPendingLines.empty()) {
					local.swap(gPendingLines); // take batch
				}
			}
			if (!local.empty() && gFileHandle != INVALID_HANDLE_VALUE) {
				// Write each line as UTF-8.
				for (auto &w : local) {
					// Convert to UTF-8
					if (w.empty()) {
						const char nl[] = "\n";
						DWORD written=0; WriteFile(gFileHandle, nl, sizeof(nl)-1, &written, NULL);
						continue;
					}
					int need = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), NULL, 0, NULL, NULL);
					if (need <= 0) continue;
					std::string utf8(need, '\0');
					// Use &utf8[0] to obtain a writable buffer compatible with pre-C++17 std::string
					WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &utf8[0], need, NULL, NULL);
					// Ensure newline termination
					if (utf8.empty() || utf8.back() != '\n') utf8.push_back('\n');
					DWORD written=0; WriteFile(gFileHandle, utf8.data(), (DWORD)utf8.size(), &written, NULL);
				}
				local.clear();
			}
		}
		// Final flush of remaining lines
		if (gFileHandle != INVALID_HANDLE_VALUE) {
			std::vector<std::wstring> rem;
			{
				std::lock_guard<std::mutex> lk(gLogMutex);
				rem.swap(gPendingLines);
			}
			for (auto &w : rem) {
				int need = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), NULL, 0, NULL, NULL);
				if (need <= 0) continue;
				std::string utf8(need, '\0');
				WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &utf8[0], need, NULL, NULL);
				if (utf8.empty() || utf8.back() != '\n') utf8.push_back('\n');
				DWORD written=0; WriteFile(gFileHandle, utf8.data(), (DWORD)utf8.size(), &written, NULL);
			}
		}
	}

	void StartFileLogging(const std::wstring &path) {
		if (path.empty()) return;
		gLogPath = path;
		gFileHandle = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, NULL,
			OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (gFileHandle == INVALID_HANDLE_VALUE) return;
		// Move to end for append
		SetFilePointer(gFileHandle, 0, NULL, FILE_END);
		// If file newly created (size==0), write UTF-8 BOM for readability in editors
		LARGE_INTEGER sz; if (GetFileSizeEx(gFileHandle, &sz) && sz.QuadPart == 0) {
			const unsigned char bom[3] = { 0xEF,0xBB,0xBF };
			DWORD written=0; WriteFile(gFileHandle, bom, 3, &written, NULL);
			gUtf8BomWritten = true;
		}
		gLogStop.store(false);
		gLogThread = std::thread(LogThreadProc);
	}

	void QueueLogLine(const std::wstring &line) {
		if (gFileHandle == INVALID_HANDLE_VALUE) return; // file logging disabled
		{
			std::lock_guard<std::mutex> lk(gLogMutex);
			gPendingLines.push_back(line);
		}
		gLogCv.notify_one();
	}

	void StopFileLogging() {
		gLogStop.store(true);
		gLogCv.notify_one();
		if (gLogThread.joinable()) gLogThread.join();
		if (gFileHandle != INVALID_HANDLE_VALUE) {
			CloseHandle(gFileHandle);
			gFileHandle = INVALID_HANDLE_VALUE;
		}
	}
}

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

VOID WINAPI TraceEventCallback(_In_ PEVENT_RECORD EventRecord)
{
    if (!EventRecord->UserData) return;
    // Normalize newline sequences
    PWCHAR raw = (PWCHAR)EventRecord->UserData;
    WCHAR cleaned[4096];
    size_t ri = 0; bool lastWasNewline = false;
    for (size_t i = 0; raw[i] != L'\0' && ri + 1 < _countof(cleaned); ++i) {
        WCHAR c = raw[i];
        if (c == L'\r') continue;
        if (c == L'\n') {
            if (lastWasNewline) continue;
            cleaned[ri++] = L'\n'; lastWasNewline = true;
        } else { cleaned[ri++] = c; lastWasNewline = false; }
    }
    if (ri > 0 && cleaned[ri - 1] == L'\n') ri--;
    cleaned[ri] = L'\0';
    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t line[4600];
    _snwprintf_s(line, _TRUNCATE, L"%04u-%02u-%02u %02u:%02u:%02u.%03u [%u:%u] %s\n",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
        EventRecord->EventHeader.ProcessId,
        EventRecord->EventHeader.ThreadId,
        cleaned);
    // Console output immediate
    wprintf(L"%s", line);
    // Queue for file persistence (minus trailing newline to let writer add one)
    std::wstring toQueue(line);
    if (!toQueue.empty() && toQueue.back() == L'\n') toQueue.pop_back();
    QueueLogLine(toQueue);
}
void CreateWaitSignalThread();

int wmain() {
	// Log beside EtwTracer.exe with timestamped filename EtwTracer_YYYYMMDD_HHMMSS.log
	wchar_t exePath[MAX_PATH]; exePath[0]=0;
	GetModuleFileNameW(NULL, exePath, _countof(exePath));
	std::wstring p(exePath);
	size_t pos = p.find_last_of(L"/\\");
	std::wstring folder = (pos==std::wstring::npos) ? L"." : p.substr(0,pos);
	SYSTEMTIME st; GetLocalTime(&st);
	wchar_t stamp[32];
	swprintf_s(stamp, _countof(stamp), L"%04u%02u%02u_%02u%02u%02u", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
	std::wstring logPath = folder + L"\\EtwTracer_" + stamp + L".log";
	StartFileLogging(logPath);
	wprintf(L"[etwtracer] file logging enabled: %s\n", logPath.c_str());
	CreateWaitSignalThread();
	TraceStop(); // ensure clean state
	ULONG ec = TraceStart();
	StopFileLogging();
	return (int)ec;
}
void WaitThreadProc() {
	HANDLE hStop = OpenEvent(SYNCHRONIZE, FALSE, SIGNALEVENTNAME);
	HANDLE hClear = OpenEvent(SYNCHRONIZE, FALSE, ETW_TRACER_CLEAR_EVENT);
	HANDLE handles[2];
	DWORD count = 0;
	if (hStop) handles[count++] = hStop;
	if (hClear) handles[count++] = hClear;
	if (count == 0) {
		TraceStop();
		exit(0);
	}
	for (;;) {
		DWORD r = WaitForMultipleObjects(count, handles, FALSE, INFINITE);
		if (r == WAIT_OBJECT_0) { // stop
			break;
		} else if (count == 2 && r == WAIT_OBJECT_0 + 1) { // clear console only; keep file intact
			system("cls");
			wprintf(L"[cleared by controller]\n");
			// Optionally append marker to file for visibility (non-destructive)
			if (gFileHandle != INVALID_HANDLE_VALUE) {
				const char marker[] = "[cleared by controller]\n"; DWORD written=0; WriteFile(gFileHandle, marker, (DWORD)sizeof(marker)-1, &written, NULL);
			}
		}
	}
	if (hClear) CloseHandle(hClear);
	if (hStop) CloseHandle(hStop);
	TraceStop();
	StopFileLogging();
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