#ifndef UKSHARED_H
#define UKSHARED_H

#define CMD_CHECK_HOOK_LIST 0
// Request the image path for a PID. Payload: DWORD pid in m_Data.
#define CMD_GET_IMAGE_PATH_BY_PID 1

typedef struct _UMHH_COMMAND_MESSAGE {
	DWORD m_Cmd;
	unsigned char m_Data[1];
}UMHH_COMMAND_MESSAGE, *PUMHH_COMMAND_MESSAGE;
#endif