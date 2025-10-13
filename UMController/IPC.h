#ifndef IPC_H
#define IPC_H
// Shared IPC constants between UMController and umhh.x64
#pragma once

// Format strings for named section and event. Use printf-style with pid as unsigned.
#define IPC_SECTION_FMT L"\\BaseNamedObjects\\inject_section.%u"
#define IPC_EVENT_FMT   L"\\BaseNamedObjects\\inject_event.%u"

// Optional prefixes
#define IPC_SECTION_PREFIX L"inject_section."
#define IPC_EVENT_PREFIX   L"inject_event."

// IPC API: write a null-terminated UTF-16 DLL path into the per-pid
// named section and signal the corresponding per-pid named event.
// Returns TRUE on success, FALSE on failure.

BOOL IPC_SendInject(DWORD pid, PCWSTR dllPath);

#endif
