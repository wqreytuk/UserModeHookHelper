#ifndef MACRO_DEF_H
#define MACRO_DEF_H
// MiniFilter Communication Port Related Definition
#define DRIVER_NAME L"UMHH"
#define LOG_PREFIX L"[" DRIVER_NAME L"]"
#define UMHHLP_PORT_NAME L"\\" DRIVER_NAME L".FLT_COMM_PORT"
#define COMM_MAX_CONNECTION	1024
#define BS_SERVICE_NAME L"UMHH.BootStart"
#define SERVICE_NAME L"UserModeHookHelper"
#define UMHH_OB_CALLBACK_SERVICE_NAME L"UMHH.ObCallback"
// Registry persistence vendor/key definitions. Vendor name is configurable
// here so kernel and user-mode code use the same value.
#define REG_VENDOR_NAME L"GIAO"
#define REG_PERSIST_SUBKEY L"SOFTWARE\\" REG_VENDOR_NAME L"\\" SERVICE_NAME
#define REG_PERSIST_REGPATH L"\\Registry\\Machine\\" REG_PERSIST_SUBKEY

#ifndef MAX_PATH
#define MAX_PATH 256
#endif

#ifndef STATUS_INVALID_CID
#define STATUS_INVALID_CID 0xC000000B
#endif

#endif