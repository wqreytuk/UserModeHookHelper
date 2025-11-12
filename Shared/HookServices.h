#pragma once
#include <cstdarg>

// Unified IHookServices interface shared by UMController, HookUI, and HookCoreLib.
// Provides two logging channels: general (Log) and hook-core diagnostics (LogCore).
struct IHookServices {
    virtual void Log(const wchar_t* fmt, ...) = 0;
    virtual void LogCore(const wchar_t* fmt, ...) = 0;
    virtual ~IHookServices() {}
};
