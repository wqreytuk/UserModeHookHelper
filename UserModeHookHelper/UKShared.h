#ifndef UKSHARED_H
#define UKSHARED_H

#define CMD_CHECK_HOOK_LIST 0
// Request the image path for a PID. Payload: DWORD pid in m_Data.
#define CMD_GET_IMAGE_PATH_BY_PID 1
// Add a hook entry. Payload: ULONGLONG hash followed by optional null-terminated
// UTF-16LE NT path string in m_Data (hash first). If no path is provided,
// the kernel will store an entry with no path.
#define CMD_ADD_HOOK 2
// Remove a hook entry by hash. Payload: ULONGLONG hash in m_Data.
#define CMD_REMOVE_HOOK 3
// Kernel -> user notification for process create/exit. Payload: DWORD pid; BOOLEAN Create (1=create,0=exit)
#define CMD_PROCESS_NOTIFY 4
// User-mode sends its base directory where DLLs live so kernel can locate DLL to inject.
#define CMD_SET_USER_DIR 5
// Kernel notifies user-mode an APC was queued for a PID (used to start a short-lived checker)
#define CMD_APC_QUEUED 6
// Request kernel to enumerate hook list NT paths. Kernel returns a sequence
// of null-terminated wide strings concatenated; user-mode should provide a
// large reply buffer (or reissue with a larger buffer) and parse the list.
#define CMD_ENUM_HOOKS 7
// (CMD_RESOLVE_NT_PATH removed - NT path resolution is performed in user-mode)

typedef struct _UMHH_COMMAND_MESSAGE {
	DWORD m_Cmd;
	unsigned char m_Data[1];
}UMHH_COMMAND_MESSAGE, *PUMHH_COMMAND_MESSAGE;

#define UMHH_MSG_HEADER_SIZE FIELD_OFFSET(UMHH_COMMAND_MESSAGE, m_Data)

#define X64_DLL L"umhh.x64.dll"
#define X86_DLL L"umhh.x86.dll"
#endif