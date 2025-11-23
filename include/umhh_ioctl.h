#pragma once

// Kernel-only IOCTL header for UMHH.BootStart
#include <ntddk.h>

// Device and symbolic link names
#define UMHH_BOOT_START_DRIVER_NAME L"UMHH.BootStart"
#define UMHH_DEVICE_NAME     L"\\Device\\" UMHH_BOOT_START_DRIVER_NAME
// Kernel-side symbolic link needs to be under \DosDevices so user-mode can open \\.\<name>
#define UMHH_DOSLINK_NAME_KERNEL    L"\\DosDevices\\" UMHH_BOOT_START_DRIVER_NAME
#define UMHH_DOSLINK_NAME_USER      L"\\.\\" UMHH_BOOT_START_DRIVER_NAME

// Custom device type
#define FILE_DEVICE_UMHH 0x8000

// IOCTLs
#define IOCTL_UMHH_SET_INJECT_QUEUE_STATE CTL_CODE(FILE_DEVICE_UMHH, 0x800, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_UMHH_QUERY_PENDING_COUNT    CTL_CODE(FILE_DEVICE_UMHH, 0x801, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

typedef struct _UMHH_INJECT_QUEUE_STATE {
    ULONG SuspendQueue; // 0 = resume queuing, 1 = suspend queuing
} UMHH_INJECT_QUEUE_STATE, *PUMHH_INJECT_QUEUE_STATE;

typedef struct _UMHH_PENDING_COUNT {
    ULONG Count;
} UMHH_PENDING_COUNT, *PUMHH_PENDING_COUNT;
