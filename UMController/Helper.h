#ifndef HELPER_H
#define HELPER_H
#include <string>
#include "FilterCommPort.h"
#define BUFSIZE 1024
#include <memory>
#include <mutex>
class Helper{
public:
	typedef void(*FatalHandlerType)(const wchar_t* message);
	// Hash an NT-style path (as byte buffer). Returns 64-bit FNV-1a hash.
	static DWORD64 GetNtPathHash(UCHAR* str);
	// NEW: get NT (native) image path for a PID. Returns true on success and
	// fills outNtPath with an NT-style path (e.g. "\Device\HarddiskVolume2\...").
	static bool GetFullImageNtPathByPID(DWORD pid, std::wstring& outNtPath);

	// Resolve NT path: try user-mode then kernel fallback via Filter.
	static bool ResolveProcessNtImagePath(DWORD pid, Filter& filter, std::wstring& outNtPath);
	// Try to get process command line (start parameters) from user-mode via WMI.
	static bool GetProcessCommandLineByPID(DWORD pid, std::wstring& outCmdLine);

	static std::basic_string<TCHAR> GetCurrentModulePath(TCHAR* append);
	// Call the configured fatal handler for unrecoverable errors. 
	// New: set a process-wide fatal handler callable from any thread. The
	// handler should perform minimal work (e.g. PostMessage to the UI) and
	// return quickly. If not set, Fatal() will log and return.
	static void SetFatalHandler(FatalHandlerType handler);
	static void Fatal(const wchar_t* message);
private:
	// Shared reusable buffer for path queries. Protected by m_bufMutex.
	static std::unique_ptr<TCHAR[]> m_sharedBuf;
	static size_t m_sharedBufCap;
	static std::mutex m_bufMutex;
};
#endif