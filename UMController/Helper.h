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
	// NOTE: The caller must provide the byte length of the buffer. Do not
	// rely on zero bytes within UTF-16LE strings as a terminator for byte
	// buffers.
	static DWORD64 GetNtPathHash(const UCHAR* buf, size_t byteLen);
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

	// Determine whether the target process is 64-bit. Returns true on success
	// and sets outIs64. On failure returns false and leaves outIs64 unchanged.
	static bool IsProcess64(DWORD pid, bool& outIs64);

	// Check if a module with the given (case-insensitive) base name is loaded
	// in the target process. Returns true on success and sets outPresent.
	// Fails (returns false) if the process cannot be opened or enumerated.
	static bool IsModuleLoaded(DWORD pid, const wchar_t* baseName, bool& outPresent);
private:
	// Shared reusable buffer for path queries. Protected by m_bufMutex.
	static std::unique_ptr<TCHAR[]> m_sharedBuf;
	static size_t m_sharedBufCap;
	static std::mutex m_bufMutex;
};
#endif