#ifndef MACRO_DEF_H
#define MACRO_DEF_H
// MiniFilter Communication Port Related Definition
#define DRIVER_NAME L"UMHH"
#define LOG_PREFIX L"[" DRIVER_NAME L"]"
#define UMHHLP_PORT_NAME L"\\" DRIVER_NAME L".FLT_COMM_PORT"
#define COMM_MAX_CONNECTION	1024

#ifndef MAX_PATH
#define MAX_PATH 256
#endif

#ifndef STATUS_INVALID_CID
#define STATUS_INVALID_CID 0xC000000B
#endif

#endif