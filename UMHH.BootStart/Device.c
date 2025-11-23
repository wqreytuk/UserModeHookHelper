#include "Common.h"
#include "../include/umhh_ioctl.h"
#include "DriverCtx.h"
#include "Inject.h"
#include "Trace.h"

// forward declare MiniUnload so we can call it from work item
extern VOID MiniUnload(ULONG Flags);

static WORK_QUEUE_ITEM g_UnloadWorkItem;

VOID UMHH_UnloadWorker(PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    Log(L"UMHH_UnloadWorker: performing deferred unload as requested by user-mode\n");
    // perform cleanup similar to DriverUnload path; call MiniUnload
    MiniUnload(0);
}

PDEVICE_OBJECT g_DeviceObject = NULL;
UNICODE_STRING g_SymLink;

NTSTATUS UMHH_DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS UMHH_DispatchIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION st = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG inLen = st->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = st->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG_PTR info = 0;

    switch (st->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_UMHH_SET_INJECT_QUEUE_STATE:
        if (inLen < sizeof(UMHH_INJECT_QUEUE_STATE)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        {
            PUMHH_INJECT_QUEUE_STATE p = (PUMHH_INJECT_QUEUE_STATE)Irp->AssociatedIrp.SystemBuffer;
            if (p->SuspendQueue) {
                DriverCtx_SetSuspendInjectQueue(TRUE);
                Log(L"IOCTL: Suspend inject queue requested by user-mode\n");
                // If there are no pending injects, schedule unload
                if (Inject_GetPendingCount() == 0) {
                    Log(L"No pending injects; scheduling deferred unload\n");
                    ExInitializeWorkItem(&g_UnloadWorkItem, UMHH_UnloadWorker, NULL);
                    ExQueueWorkItem(&g_UnloadWorkItem, DelayedWorkQueue);
                }
            } else {
                DriverCtx_SetSuspendInjectQueue(FALSE);
                Log(L"IOCTL: Resume inject queue requested by user-mode\n");
            }
            status = STATUS_SUCCESS;
        }
        break;
    case IOCTL_UMHH_QUERY_PENDING_COUNT:
        if (outLen < sizeof(UMHH_PENDING_COUNT)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        {
            UMHH_PENDING_COUNT cnt = { 0 };
            cnt.Count = Inject_GetPendingCount();
            RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &cnt, sizeof(cnt));
            info = sizeof(cnt);
            status = STATUS_SUCCESS;
        }
        break;
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS UMHH_CreateDeviceObjects(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING devName;
    RtlInitUnicodeString(&devName, UMHH_DEVICE_NAME);
    NTSTATUS st = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &g_DeviceObject);
    if (!NT_SUCCESS(st)) {
        Log(L"Failed to create device object: 0x%08x\n", st);
        return st;
    }

    RtlInitUnicodeString(&g_SymLink, UMHH_DOSLINK_NAME_KERNEL);
    IoCreateSymbolicLink(&g_SymLink, &devName);

    DriverObject->MajorFunction[IRP_MJ_CREATE] = UMHH_DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = UMHH_DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = UMHH_DispatchIoControl;

    return STATUS_SUCCESS;
}

VOID UMHH_DeleteDeviceObjects(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    if (g_SymLink.Buffer) {
        IoDeleteSymbolicLink(&g_SymLink);
        RtlInitUnicodeString(&g_SymLink, L"");
    }
    if (g_DeviceObject) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }
}
