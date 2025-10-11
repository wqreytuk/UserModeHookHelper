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

typedef struct _UMHH_COMMAND_MESSAGE {
	DWORD m_Cmd;
	unsigned char m_Data[1];
}UMHH_COMMAND_MESSAGE, *PUMHH_COMMAND_MESSAGE;

#define UMHH_MSG_HEADER_SIZE FIELD_OFFSET(UMHH_COMMAND_MESSAGE, m_Data)

#endif