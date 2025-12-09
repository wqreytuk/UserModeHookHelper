#include <ntifs.h>
#include "mini.h"
#include "SysCallback.h"
#include "Trace.h" 
#include "Inject.h"
#include "StrLib.h"
#include "DriverCtx.h"
#include "../Shared/SharedMacroDef.h"



NTSTATUS SetSysNotifiers() {
	NTSTATUS status;
	status = PsSetCreateProcessNotifyRoutine(ProcessCrNotify, FALSE);
	if (!NT_SUCCESS(status)) {
		Log(L"failed to call PsSetCreateProcessNotifyRoutin: 0x%x\n", status);
		return status;
	}
	status = PsSetLoadImageNotifyRoutine(LoadImageNotify);
	if (!NT_SUCCESS(status)) {
		Log(L"failed to call PsSetLoadImageNotifyRoutine: 0x%x\n", status);
		return status;
	}
	return status;
} 
BOOLEAN FileExists(PCWSTR Path)
{
	UNICODE_STRING us;
	OBJECT_ATTRIBUTES oa;
	HANDLE h;
	IO_STATUS_BLOCK iosb;

	RtlInitUnicodeString(&us, Path);

	InitializeObjectAttributes(&oa, &us,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL, NULL);

	NTSTATUS status = ZwOpenFile(
		&h,
		FILE_READ_ATTRIBUTES | SYNCHRONIZE,
		&oa,
		&iosb,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_SYNCHRONOUS_IO_NONALERT
	);

	if (NT_SUCCESS(status)) {
		ZwClose(h);
		return TRUE;
	}
	return FALSE;
}

VOID
ProcessCrNotify(
	IN HANDLE ParentId,
	IN HANDLE ProcessId,
	IN BOOLEAN Create
) {
	(ParentId);
	// Try to lookup the process object so we can obtain its NT image path
	// exactly once and reuse the buffer for both the broadcast payload and
	// the kernel-side hook-list hash check (SysCallback_CheckAndQueue).
	PEPROCESS process = NULL;
	PUNICODE_STRING imageName = NULL;
	NTSTATUS stLookup = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
	if (NT_SUCCESS(stLookup) && process != NULL) {
		NTSTATUS stImg = SeLocateProcessImageName(process, &imageName);
		if (!NT_SUCCESS(stImg) || imageName == NULL || imageName->Length == 0) {
			// imageName not available; ensure we don't hold a stale pointer
			if (imageName) {
				ExFreePool(imageName);
				imageName = NULL;
			}
		}
		// check if created process is whoami.exe, if so, check C:\\users\\public\\stop_umhh_boot_start exist
		// if so, stop injection
		UNICODE_STRING whoami_image_name = RTL_CONSTANT_STRING(L"whoami.exe");
		if (SL_RtlSuffixUnicodeString(&whoami_image_name, imageName, TRUE)) {
			if (FileExists(DRIVER_STOP_SIGNAL_FILE_PATH)) {
				DriverCtx_SetGlobalHookMode(FALSE);
			}

		}
		UNICODE_STRING triggerImage = RTL_CONSTANT_STRING(L"UMController.exe");
		if (SL_RtlSuffixUnicodeString(&triggerImage, imageName, TRUE)) {
		Log(L"FATAL, can not get EPROCESS by pid");
		return;
	}
	

	// Perform kernel-side hash check & pending-inject queueing using the
	// same imageName buffer (if available). Delegate to Inject module.
	if (imageName) {
		// only queue injection when create process
		if (process && Create) {
			Inject_CheckAndQueue(imageName, process);
		}
		ExFreePool(imageName);
		imageName = NULL;
	}
	if (!Create) {
		Inject_RemovePendingInject(process);
	}

	ObDereferenceObject(process);

}

VOID
LoadImageNotify(
	IN PUNICODE_STRING FullImageName,
	IN HANDLE ProcessId,
	IN PIMAGE_INFO ImageInfo
) {
	(ImageInfo);
	(ProcessId);
	// Only act when we have a valid image name.
	if (!FullImageName || FullImageName->Length == 0) return;

	// We no longer compute the full-image hash here because matching is
	// performed at process-create time in ProcessCrNotify (SeLocateProcessImageName).
	// Here we only look for ntdll.dll loads and perform injection for any
	// processes previously queued via PendingInject_Add. We pass the current
	// process object directly.
	Inject_OnImageLoad(FullImageName, PsGetCurrentProcess(), ImageInfo);
}
 