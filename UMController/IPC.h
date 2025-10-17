
#pragma once
// Optional prefixes
#define IPC_SECTION L"inject_section.%u"
#define IPC_EVENT   L"inject_event.%u"

#define DLL_IPC_SECTION_FMT    L"\\BaseNamedObjects\\" IPC_SECTION 
#define DLL_IPC_EVENT_FMT    L"\\BaseNamedObjects\\" IPC_EVENT 

#define USER_IPC_SECTION_FMT    L"\\Global\\" IPC_SECTION 
#define USER_IPC_EVENT_FMT    L"\\Global\\" IPC_EVENT 

// IPC API: write a null-terminated UTF-16 DLL path into the per-pid
// named section and signal the corresponding per-pid named event.
// Returns TRUE on success, FALSE on failure.

BOOL IPC_SendInject(DWORD pid, PCWSTR dllPath);
