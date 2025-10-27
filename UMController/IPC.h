
#pragma once

#define USER_IPC_EVENT_FILE_FMT    L"C:\\users\\public\\inject_event.%u"  
#define DLL_IPC_EVENT_FILE_FMT    L"\\??\\" USER_IPC_EVENT_FILE_FMT

#define USER_IPC_SIGNAL_FILE_FMT L"C:\\Users\\Public\\signal.bin.%u"
#define DLL_IPC_SIGNAL_FILE_FMT L"\\??\\" USER_IPC_SIGNAL_FILE_FMT


// IPC API: write a null-terminated UTF-16 DLL path into the per-pid
// named section and signal the corresponding per-pid named event.
// Returns TRUE on success, FALSE on failure.

BOOL IPC_SendInject(DWORD pid, PCWSTR dllPath);
