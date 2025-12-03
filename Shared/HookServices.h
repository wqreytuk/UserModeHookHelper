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
	virtual void* PhBuildModuleListWow64(void* hProc, void* head) = 0;
	virtual bool ConvertCharToWchar(const char* src, wchar_t* dst, size_t dstChars) = 0;
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
	virtual bool  GetModuleBase(bool is64, DWORD pid,const wchar_t* target_module, DWORD64* base) = 0;
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
    // Load persisted ProcHookList entries for a specific PID + creation time
    virtual bool LoadProcHookList(DWORD pid, DWORD filetimeHi, DWORD filetimeLo, std::vector<HookRow>& outEntries) = 0;
	virtual bool ForceInject(DWORD pid) = 0;
    virtual ~IHookServices() {}
};
