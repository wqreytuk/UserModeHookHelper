#pragma once
#include <cstdarg>
// Ensure DWORD definition is available without forcing every user of the
// interface to include Windows.h first. If Windows headers already included
// this will be a harmless re-include.
#ifndef _WINDEF_
#include <Windows.h>
#endif

// Unified IHookServices interface shared by UMController, HookUI, and HookCoreLib.
// Provides two logging channels: general (Log) and hook-core diagnostics (LogCore).
struct IHookServices {
    virtual void Log(const wchar_t* fmt, ...) = 0;
    virtual void LogCore(const wchar_t* fmt, ...) = 0;
    // Request the master injected DLL to load a trampoline DLL for the given
    // target process. Returns true if the signal was sent successfully. The
    // caller supplies the absolute path to the trampoline DLL that should be
    // loaded inside the target process.
    virtual bool InjectTrampoline(DWORD targetPid, const wchar_t* fullDllPath) = 0;
    // Query whether the target process is 64-bit. When successful, returns
    // true and sets `outIs64` to true for 64-bit processes or false for
    // 32-bit (WoW64) processes. Implementations should prefer kernel-backed
    // checks when available so callers in HookUI can rely on authoritative
    // information.
    virtual bool IsProcess64(DWORD targetPid, bool& outIs64) = 0;
    virtual ~IHookServices() {}
};
