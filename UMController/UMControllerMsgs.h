// UMControllerMsgs.h - shared message IDs and constants used across UMController
#pragma once

// Custom app messages
#define WM_APP_FATAL (WM_APP + 0x100)
#define WM_APP_UPDATE_PROCESS (WM_APP + 0x101)

// lParam values for WM_APP_UPDATE_PROCESS to identify the source
#define UPDATE_SOURCE_LOAD 1
#define UPDATE_SOURCE_NOTIFY 2
