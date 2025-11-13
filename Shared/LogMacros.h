#pragma once
// LogMacros.h - central logging prefix helpers.
// Usage: LOG_CTRL(svcs, L"message %d", value);
//        LOG_UI(svcs, L"message %s", str);
//        LOG_CORE(svcs, L"core detail %x", val);
// These macros prepend a stable module tag and forward to IHookServices::Log.
// They intentionally avoid relying on LogCore to keep a single formatting path.
#include "HookServices.h"

// Controller module logging
#define LOG_CTRL(svcs, fmt, ...) (svcs)->Log(L"[UMCtrl] " fmt, __VA_ARGS__)
// Hook UI logging
#define LOG_UI(svcs, fmt, ...)   (svcs)->Log(L"[HookUI]     " fmt, __VA_ARGS__)
// Hook core logging (can still use LogCore directly if desired)
#define LOG_CORE(svcs, fmt, ...) (svcs)->LogCore(L"" fmt, __VA_ARGS__)

// Direct controller ETW logging when an IHookServices* is not available but global 'app' is.
// Use in UMController sources: LOG_CTRL_ETW(L"message %d", val);
#ifdef _UMCONTROLLER_ENV_DEFINED // Optionally gate if you define this in project settings
#define LOG_CTRL_ETW(fmt, ...) app.GetETW().Log(L"[UMCtrl] " fmt, __VA_ARGS__)
#else
#define LOG_CTRL_ETW(fmt, ...) app.GetETW().Log(L"[UMCtrl]     " fmt, __VA_ARGS__)
#endif

