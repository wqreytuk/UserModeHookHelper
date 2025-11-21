#ifndef HELPER_H
#define HELPER_H
#include <string>
#include "FilterCommPort.h"
#define BUFSIZE 1024
#include <memory>
#include <mutex>
class Helper {
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
	// Overload: reuse an already opened PROCESS_QUERY_LIMITED_INFORMATION handle
	// to avoid a second OpenProcess. Caller retains ownership of hProcess.
	static bool GetFullImageNtPathFromHandle(HANDLE hProcess, std::wstring& outNtPath);

	// Resolve NT path: try user-mode then kernel fallback via Filter.
	static bool ResolveProcessNtImagePath(DWORD pid, Filter& filter, std::wstring& outNtPath);
	static void UMHH_DriverCheck(); 
	static bool UMHH_BS_DriverCheck();
	// Resolve a DOS/Win32 path (e.g., C:\...) to an NT-style path. Returns
	// true on success and stores a string like "\\Device\\HarddiskVolumeX\\..."
	// If resolution fails, returns false.
	static bool ResolveDosPathToNtPath(const std::wstring& dosPath, std::wstring& outNtPath);
	// Try to get process command line (start parameters) from user-mode via WMI.
	static bool GetProcessCommandLineByPID(DWORD pid, std::wstring& outCmdLine);

	static	bool IsFileExists(TCHAR* szPath);
	static std::basic_string<TCHAR> GetCurrentModulePath(TCHAR* append);
	// Call the configured fatal handler for unrecoverable errors. 
	// New: set a process-wide fatal handler callable from any thread. The
	// handler should perform minimal work (e.g. PostMessage to the UI) and
	// return quickly. If not set, Fatal() will log and return.
	static void SetFatalHandler(FatalHandlerType handler);
	static void Fatal(const wchar_t* message);
	static bool ForceInject(DWORD pid);
	// Determine whether the target process is 64-bit. Returns true on success
	// and sets outIs64. On failure returns false and leaves outIs64 unchanged.
	static bool IsProcess64(DWORD pid, bool& outIs64);
	static bool GetModuleBaseWithPath(DWORD pid, char* mPath, PVOID* base);
	static bool strcasestr_check(const char *haystack, const char *needle);
	// Set the Filter instance used by Helper for kernel queries. The caller
	// should set this once during initialization (e.g., from the dialog).
	static void SetFilterInstance(class Filter* f);
	// craete a file that require nearly no privilege, every can operate
	static bool CreateLowPrivReqFile(wchar_t* filePath,PHANDLE outFileHandle);
	// Check if a module with the given (case-insensitive) base name is loaded
	// in the target process. Returns true on success and sets outPresent.
	// Fails (returns false) if the process cannot be opened or enumerated.
	static bool IsModuleLoaded(DWORD pid, const wchar_t* baseName, bool& outPresent);
	// Convert an integer value to uppercase hexadecimal without leading zeros.
	// Returns L"0" when value==0. Does NOT include any prefix like 0x.
	static std::wstring ToHex(ULONGLONG value);
    // Enable or disable the SeDebugPrivilege for the current process/token.
    // Returns true on success.
    static bool EnableDebugPrivilege(bool enable);
	// Copy UMHH x64 and Win32 DLLs located next to the running executable
	// to the root of C:\ (destination paths: `C:\umhh.dll.x64.dll` and
	// `C:\umhh.dll.Win32.dll`). Returns true if all copies succeeded.
	static bool CopyUmhhDllsToRoot();
	// Toggle the boot-start driver `UMHH.BootStart` according to DesiredEnabled.
	// If DesiredEnabled==true: ensure driver file exists under System32\drivers,
	// create service as boot-start (Start=0) and start it.
	// If DesiredEnabled==false: stop the service if running and set Start to disabled.
	static bool ConfigureBootStartService(bool DesiredEnabled);
private:
	// Shared reusable buffer for path queries. Protected by m_bufMutex.
	static std::unique_ptr<TCHAR[]> m_sharedBuf;
	static size_t m_sharedBufCap;
	static std::mutex m_bufMutex;	// Optional pointer to the Filter instance owned by the UI. May be NULL.
	static Filter* m_filterInstance;
   

};
#endif