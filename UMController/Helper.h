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
	static bool CheckExportFromFile(const wchar_t* dllPath, const char* exportName, DWORD* out_func_offset);
	// NEW: get NT (native) image path for a PID. Returns true on success and
	// fills outNtPath with an NT-style path (e.g. "\Device\HarddiskVolume2\...").
	static bool GetFullImageNtPathByPID(DWORD pid, std::wstring& outNtPath);
	// Overload: reuse an already opened PROCESS_QUERY_LIMITED_INFORMATION handle
	// to avoid a second OpenProcess. Caller retains ownership of hProcess.
	static bool GetFullImageNtPathFromHandle(HANDLE hProcess, std::wstring& outNtPath);
	static bool ReadExportFirstBytesFromFile(const wchar_t* dllPath, const char* exportName, unsigned char outBuf[16]);

	// Resolve NT path: try user-mode then kernel fallback via Filter.
	static bool ResolveProcessNtImagePath(DWORD pid, Filter& filter, std::wstring& outNtPath);
	static void UMHH_DriverCheck(); 
	static bool UMHH_BS_DriverCheck();
	// Check the dedicated OB callback driver/service (UMHH.ObCallback).
	// Returns true if the service is running (or was started successfully).
	static bool UMHH_ObCallback_DriverCheck();
	// Resolve a DOS/Win32 path (e.g., C:\...) to an NT-style path. Returns
	// true on success and stores a string like "\\Device\\HarddiskVolumeX\\..."
	// If resolution fails, returns false.
	static bool ResolveDosPathToNtPath(const std::wstring& dosPath, std::wstring& outNtPath);
	// Try to get process command line (start parameters) from user-mode via WMI.
	static bool GetProcessCommandLineByPID(DWORD pid, std::wstring& outCmdLine);

	static	bool IsFileExists(TCHAR* szPath);
	static std::basic_string<TCHAR> GetCurrentDirFilePath(TCHAR* append);
	// Call the configured fatal handler for unrecoverable errors. 
	// New: set a process-wide fatal handler callable from any thread. The
	// handler should perform minimal work (e.g. PostMessage to the UI) and
	// return quickly. If not set, Fatal() will log and return.
	static void SetFatalHandler(FatalHandlerType handler);
	static void Fatal(const wchar_t* message);
	static bool ResolveNtCreateThreadExSyscallNum(DWORD* sys_call_num);
	static bool ForceInject(DWORD pid);
	static bool GetModuleBase(bool is64, HANDLE hProc,const wchar_t* target_module,DWORD64* base);
	// Determine whether the target process is 64-bit. Returns true on success
	// and sets outIs64. On failure returns false and leaves outIs64 unchanged.
	static bool IsProcess64(DWORD pid, bool& outIs64);
	// Like GetModuleBaseWithPath but uses EnumProcessModulesEx with LIST_MODULES_ALL
	static  bool GetModuleBaseWithPathEx(HANDLE hProcess, const char* mPath, PVOID* base);
	static bool wstrcasestr_check(const wchar_t* haystack, const wchar_t* needle);
	static bool strcasestr_check(const char *haystack, const char *needle);
	// Set the Filter instance used by Helper for kernel queries. The caller
	// should set this once during initialization (e.g., from the dialog).
	static void SetFilterInstance(class Filter* f);
	static   void SetNtCreateThreadExSyscallNum(DWORD num);
	static void SetSysDriverMark(std::wstring sysmark);
	// craete a file that require nearly no privilege, every can operate
	static bool CreateLowPrivReqFile(wchar_t* filePath,PHANDLE outFileHandle);
	// Check if a module with the given (case-insensitive) base name is loaded
	// in the target process. Returns true on success and sets outPresent.
	// Fails (returns false) if the process cannot be opened or enumerated.
	static bool IsModuleLoaded(DWORD pid, const wchar_t* baseName, bool& outPresent);
	// Convert a multibyte `char*` string to wide `wchar_t*`.
	// `dstChars` is the size of `dst` in wchar_t characters (including room for null).
	// Returns true on success, false on failure or insufficient space.
	static bool ConvertCharToWchar(const char* src, wchar_t* dst, size_t dstChars);
	// Reverse of ConvertCharToWchar: copy low byte of each wchar into dst char buffer.
	// `dstChars` is the size of `dst` in bytes (including room for null).
	// Returns true on success, false on failure or insufficient space.
	static bool ConvertWcharToChar(const wchar_t* src, char* dst, size_t dstChars);
	// Convert an integer value to uppercase hexadecimal without leading zeros.
	// Returns L"0" when value==0. Does NOT include any prefix like 0x.
	static std::wstring ToHex(ULONGLONG value);
	static SIZE_T RvaToOffset(void* base, IMAGE_NT_HEADERS64* nth, DWORD rva);
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
	static Filter* GetFilterInstance();
private:
	// Shared reusable buffer for path queries. Protected by m_bufMutex.
	static std::unique_ptr<TCHAR[]> m_sharedBuf;
	static size_t m_sharedBufCap;
	static std::mutex m_bufMutex;	// Optional pointer to the Filter instance owned by the UI. May be NULL.
	static Filter* m_filterInstance;
	static std::wstring m_SysDriverMark;
	static DWORD m_NtCreateThreadExSyscallNum;
   

};
#endif