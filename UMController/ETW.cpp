#include "pch.h"
#include "ETW.h"
#include "Helper.h"

 ETW::ETW() {
	// create an event used to signal event trace stop
	m_Event = CreateEvent(NULL, FALSE, FALSE, SIGNALEVENTNAME);
	// open (or create if not existing yet) the clear event used to request console clearing
	m_ClearEvent = CreateEvent(NULL, FALSE, FALSE, ETW_TRACER_CLEAR_EVENT);
}
void ETW::Reg() { 
	ULONG status = EventRegister(&ProviderGUID,
		NULL,
		NULL,
		&m_ProviderHandle);
	assert(ERROR_SUCCESS == status);
}

void ETW::UnReg() {
	if (m_Unregistered) return; // idempotent
	// Signal tracer stop event if valid
	if (m_Event) {
		SetEvent(m_Event);
		CloseHandle(m_Event);
		m_Event = nullptr;
	}
	if (m_ClearEvent) {
		CloseHandle(m_ClearEvent);
		m_ClearEvent = nullptr;
	}
	if (m_ProviderHandle) {
		EventUnregister(m_ProviderHandle);
		m_ProviderHandle = 0;
	}
	m_Unregistered = true;
}

ETW::~ETW() {
	UnReg();
}

void ETW::StartTracer() {
	SHELLEXECUTEINFO sei = { sizeof(sei) };
	sei.fMask = SEE_MASK_NOCLOSEPROCESS; 
	auto s = Helper::GetCurrentModulePath(TEXT("EtwTracer.exe"));
	sei.lpFile = s.c_str();
	sei.nShow = SW_SHOW;

	// Create a named event that the tracer will set when it is ready.
	HANDLE hReady = CreateEvent(NULL, TRUE, FALSE, ETW_TRACER_READY_EVENT);

	BOOL ok = ShellExecuteEx(&sei);
	if (!ok) {
		if (hReady) CloseHandle(hReady);
		return;
	}

	// Wait for the tracer to signal readiness, but don't wait forever.
	const DWORD WAIT_MS = 5000; // 5s timeout
	if (hReady) {
		DWORD r = WaitForSingleObject(hReady, WAIT_MS);
		if (r == WAIT_OBJECT_0) {
			// NULL
		} else if (r == WAIT_TIMEOUT) {
			// NULL
		} else {
			assert(1!=0);
		}
		CloseHandle(hReady);
	}
}

void ETW::Log(_In_ PCWSTR Format, ...) {
	WCHAR Buffer[1024];
	va_list args;

	va_start(args, Format);
	_vsnwprintf_s(Buffer, RTL_NUMBER_OF(Buffer) - 1, Format, args);
	va_end(args);

	Buffer[RTL_NUMBER_OF(Buffer) - 1] = L'\0'; // ensure null-termination

	EventWriteString(m_ProviderHandle, 0, 0, Buffer);
}

void ETW::Clear() {
	// Fire the clear event so the tracer (if running) clears its display.
	if (m_ClearEvent) {
		SetEvent(m_ClearEvent);
	}
}