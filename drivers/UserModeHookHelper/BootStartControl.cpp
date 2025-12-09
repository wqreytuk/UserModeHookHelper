#include "BootStartControl.h"

#if defined(_KERNEL_MODE) || defined(_NTDDK_)

#include <ntddk.h>

BOOLEAN BS_SendSuspendInjectQueue(BOOLEAN suspend)
{
    UNICODE_STRING symLink;
    PFILE_OBJECT fileObject = NULL;
    PDEVICE_OBJECT deviceObject = NULL;
    NTSTATUS status;
    KEVENT event;
    IO_STATUS_BLOCK iosb;

    RtlInitUnicodeString(&symLink, UMHH_DOSLINK_NAME_KERNEL);

    status = IoGetDeviceObjectPointer(&symLink, (ACCESS_MASK)(FILE_READ_DATA | FILE_WRITE_DATA), &fileObject, &deviceObject);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    // Build input buffer
    UMHH_INJECT_QUEUE_STATE in = { 0 };
    in.SuspendQueue = suspend ? (ULONG)1 : (ULONG)0;

    KeInitializeEvent(&event, NotificationEvent, FALSE);
    PIRP irp = IoBuildDeviceIoControlRequest(
            (ULONG)IOCTL_UMHH_SET_INJECT_QUEUE_STATE,
            deviceObject,
            (PVOID)&in,
            (ULONG)sizeof(in),
            (PVOID)NULL,
            (ULONG)0,
            (BOOLEAN)FALSE,
            &event,
            &iosb);

    if (!irp) {
        ObDereferenceObject(fileObject);
        return FALSE;
    }

    status = IoCallDriver(deviceObject, irp);
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = iosb.Status;
    }

    ObDereferenceObject(fileObject);
    return NT_SUCCESS(status) ? TRUE : FALSE;
}

#endif
