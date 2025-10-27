#include "SysCallback.h"
#include "Trace.h"
#include "FltCommPort.h"
#include "Inject.h"
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

VOID
ProcessCrNotify(
	IN HANDLE ParentId,
	IN HANDLE ProcessId,
	IN BOOLEAN Create
) {
	(ParentId);
	// Broadcast to any connected user-mode clients. ProcessId is a HANDLE-sized
	// value; we cast to DWORD to send the PID. If high bits exist on 64-bit
	// systems they are truncated, but PIDs fit in 32-bits on Windows.
	DWORD pid = (DWORD)(ULONG_PTR)ProcessId;
	ULONG notified = 0;

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
	}
	if (!process) {
		Log(L"FATAL, can not get EPROCESS by pid");
		return;
	}
	// Broadcast (caller retains ownership of imageName)
	NTSTATUS st = Comm_BroadcastProcessNotify(pid, Create, &notified, imageName);
	// Log(L"broad cast %d image: %wZ create: %d\n", pid, imageName, Create);
	if (!NT_SUCCESS(st)) {
		Log(L"Comm_BroadcastProcessNotify failed: 0x%x\n", st);
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
 