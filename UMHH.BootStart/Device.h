#pragma once
#include <ntddk.h>

NTSTATUS UMHH_CreateDeviceObjects(PDRIVER_OBJECT DriverObject);
VOID     UMHH_DeleteDeviceObjects(PDRIVER_OBJECT DriverObject);
