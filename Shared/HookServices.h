#pragma once
#include <cstdarg>
#include <vector>
// Ensure DWORD definition is available without forcing every user of the
// interface to include Windows.h first. If Windows headers already included
// this will be a harmless re-include.
#ifndef _WINDEF_
#include <Windows.h>
#endif

#include "HookRow.h"

// Unified IHookServices interface shared by UMController, HookUI, and HookCoreLib.
// Provides two logging channels: general (Log) and hook-core diagnostics (LogCore).
struct IHookServices {
	virtual BOOLEAN ReadPrimitive(_In_ LPVOID target_addr, _Out_ LPVOID buffer, _In_ size_t size) = 0;
	virtual BOOLEAN WritePrimitive(_In_ LPVOID target_addr, _In_ LPVOID buffer, _In_ size_t size) = 0;
	virtual bool CheckPeArch(const wchar_t* dllPath, bool& is64) = 0;
	virtual bool WriteProcessMemoryWrap(
		_In_ HANDLE hProcess,
		_In_ LPVOID lpBaseAddress,
		_In_reads_bytes_(nSize) LPCVOID lpBuffer,
		_In_ SIZE_T nSize,
		_Out_opt_ SIZE_T * lpNumberOfBytesWritten
	) = 0;
	virtual void* PhBuildModuleListWow64(void* hProc, void* head) = 0;
	virtual bool ConvertCharToWchar(const char* src, wchar_t* dst, size_t dstChars) = 0;
	virtual bool ConvertWcharToChar(const wchar_t* src, char* dst, size_t dstChars) = 0;
	virtual std::wstring GetCurrentDirFilePath(WCHAR* filename) = 0;
	virtual bool GetHighAccessProcHandle(DWORD pid, HANDLE* hProc) = 0;
    virtual void Log(const wchar_t* fmt, ...) = 0;
	virtual void LogPhlib(const wchar_t* fmt, ...) = 0;
	virtual void LogCore(const wchar_t* fmt, ...) = 0;
	virtual bool EnableDebugPrivilege(bool enable) = 0;
	virtual  bool wstrcasestr_check(const wchar_t* haystack, const wchar_t* needle) = 0;
    // Request the master injected DLL to load a trampoline DLL for the given
    // target process. Returns true if the signal was sent successfully. The
    // caller supplies the absolute path to the trampoline DLL that should be
    // loaded inside the target process.
	virtual bool  GetModuleBase( DWORD pid,const wchar_t* target_module, DWORD64* base) = 0;
    virtual bool InjectTrampoline(DWORD targetPid, const wchar_t* fullDllPath) = 0;
	virtual bool CheckExportFromFile(const wchar_t* dllPath, const char* exportName, DWORD* out_func_offset) = 0;
	virtual bool IsModuleLoaded(DWORD pid, const wchar_t* baseName, bool& outPresent) = 0;
	virtual bool  CreateLowPrivReqFile(wchar_t* filePath, PHANDLE outFileHandle) = 0;
    // Query whether the target process is 64-bit. When successful, returns
    // true and sets `outIs64` to true for 64-bit processes or false for
    // 32-bit (WoW64) processes. Implementations should prefer kernel-backed
    // checks when available so callers in HookUI can rely on authoritative
    // information.
	virtual bool  GetFullImageNtPathByPID(DWORD pid, std::wstring& outNtPath) = 0;
    virtual bool IsProcess64(DWORD targetPid, bool& outIs64) = 0;
    // Persist per-process hook list entries. Uses a shared `HookRow` vector
    // where each HookRow contains the persisted fields; the controller will
    // augment entries with PID+FILETIME when writing to registry.
    virtual bool SaveProcHookList(DWORD pid, DWORD hi, DWORD lo, const std::vector<HookRow>& entries) = 0;
    // Remove a single persisted ProcHookList entry matching PID+FILETIME+HOOKID
    virtual bool RemoveProcHookEntry(DWORD pid, DWORD filetimeHi, DWORD filetimeLo, int hookId) = 0;
    // Remove all persisted ProcHookList entries for a specific PID+FILETIME key
    // This counters SaveProcHookList and clears the entire list for that process instance
    virtual bool RemoveProcHookList(DWORD pid, DWORD filetimeHi, DWORD filetimeLo) = 0;
    // Load persisted ProcHookList entries for a specific PID + creation time
    virtual bool LoadProcHookList(DWORD pid, DWORD filetimeHi, DWORD filetimeLo, std::vector<HookRow>& outEntries) = 0;
	virtual bool ForceInject(DWORD pid) = 0;
    virtual ~IHookServices() {}
};

 
// Base implementation providing default (no-op or false) for all IHookServices methods. 
// Subclasses can override only the methods they actually implement, avoiding boilerplate.
class HookServicesBase : public IHookServices {
public:
	// Memory operations - default:  fail
	virtual BOOLEAN ReadPrimitive(_In_ LPVOID target_addr, _Out_ LPVOID buffer, _In_ size_t size) override {
		(void)target_addr; (void)buffer; (void)size;
		return FALSE;
	}

	virtual BOOLEAN WritePrimitive(_In_ LPVOID target_addr, _In_ LPVOID buffer, _In_ size_t size) override {
		(void)target_addr; (void)buffer; (void)size;
		return FALSE;
	}

	virtual bool WriteProcessMemoryWrap(
		_In_ HANDLE hProcess,
		_In_ LPVOID lpBaseAddress,
		_In_reads_bytes_(nSize) LPCVOID lpBuffer,
		_In_ SIZE_T nSize,
		_Out_opt_ SIZE_T* lpNumberOfBytesWritten
	) override {
		(void)hProcess; (void)lpBaseAddress; (void)lpBuffer; (void)nSize; (void)lpNumberOfBytesWritten;
		return false;
	}

	// PE operations - default: fail
	virtual bool CheckPeArch(const wchar_t* dllPath, bool& is64) override {
		(void)dllPath; (void)is64;
		return false;
	}

	virtual bool CheckExportFromFile(const wchar_t* dllPath, const char* exportName, DWORD* out_func_offset) override {
		(void)dllPath; (void)exportName; (void)out_func_offset;
		return false;
	}

	// String utilities - default: fail
	virtual bool ConvertCharToWchar(const char* src, wchar_t* dst, size_t dstChars) override {
		(void)src; (void)dst; (void)dstChars;
		return false;
	}

	virtual bool ConvertWcharToChar(const wchar_t* src, char* dst, size_t dstChars) override {
		(void)src; (void)dst; (void)dstChars;
		return false;
	}

	virtual bool wstrcasestr_check(const wchar_t* haystack, const wchar_t* needle) override {
		(void)haystack; (void)needle;
		return false;
	}

	// File/Path operations - default: fail or empty
	virtual std::wstring GetCurrentDirFilePath(WCHAR* filename) override {
		(void)filename;
		return std::wstring();
	}

	virtual bool CreateLowPrivReqFile(wchar_t* filePath, PHANDLE outFileHandle) override {
		(void)filePath; (void)outFileHandle;
		return false;
	}

	// Process operations - default: fail
	virtual bool GetHighAccessProcHandle(DWORD pid, HANDLE* hProc) override {
		(void)pid; (void)hProc;
		return false;
	}

	virtual bool IsProcess64(DWORD targetPid, bool& outIs64) override {
		(void)targetPid; (void)outIs64;
		return false;
	}

	virtual bool GetFullImageNtPathByPID(DWORD pid, std::wstring& outNtPath) override {
		(void)pid; (void)outNtPath;
		return false;
	}

	virtual bool EnableDebugPrivilege(bool enable) override {
		(void)enable;
		return false;
	}

	virtual bool ForceInject(DWORD pid) override {
		(void)pid;
		return false;
	}

	// Module operations - default: fail
	virtual bool GetModuleBase(DWORD pid, const wchar_t* target_module, DWORD64* base) override {
		(void)pid; (void)target_module; (void)base;
		return false;
	}

	virtual bool IsModuleLoaded(DWORD pid, const wchar_t* baseName, bool& outPresent) override {
		(void)pid; (void)baseName; (void)outPresent;
		return false;
	}

	virtual void* PhBuildModuleListWow64(void* hProc, void* head) override {
		(void)hProc; (void)head;
		return nullptr;
	}

	// Injection operations - default: fail
	virtual bool InjectTrampoline(DWORD targetPid, const wchar_t* fullDllPath) override {
		(void)targetPid; (void)fullDllPath;
		return false;
	}

	// Hook persistence operations - default: fail
	virtual bool SaveProcHookList(DWORD pid, DWORD hi, DWORD lo, const std::vector<HookRow>& entries) override {
		(void)pid; (void)hi; (void)lo; (void)entries;
		return false;
	}

	virtual bool RemoveProcHookEntry(DWORD pid, DWORD filetimeHi, DWORD filetimeLo, int hookId) override {
		(void)pid; (void)filetimeHi; (void)filetimeLo; (void)hookId;
		return false;
	}

	virtual bool RemoveProcHookList(DWORD pid, DWORD filetimeHi, DWORD filetimeLo) override {
		(void)pid; (void)filetimeHi; (void)filetimeLo;
		return false;
	}

	virtual bool LoadProcHookList(DWORD pid, DWORD filetimeHi, DWORD filetimeLo, std::vector<HookRow>& outEntries) override {
		(void)pid; (void)filetimeHi; (void)filetimeLo; (void)outEntries;
		return false;
	}

	// Logging - default: no-op (silent)
	virtual void Log(const wchar_t* fmt, ...) override {
		(void)fmt;
		// Default:  do nothing (silent)
	}

	virtual void LogPhlib(const wchar_t* fmt, ...) override {
		(void)fmt;
		// Default: do nothing
	}

	virtual void LogCore(const wchar_t* fmt, ...) override {
		(void)fmt;
		// Default: do nothing
	}

	virtual ~HookServicesBase() {}
};