#include "SysCallback.h"
#include "Trace.h"
#include "FltCommPort.h"
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
	NTSTATUS st = Comm_BroadcastProcessNotify(pid, Create, &notified);
	if (!NT_SUCCESS(st)) {
		Log(L"Comm_BroadcastProcessNotify failed: 0x%x\n", st);
	}
}

VOID
LoadImageNotify(
	IN PUNICODE_STRING FullImageName,
	IN HANDLE ProcessId,
	IN PIMAGE_INFO ImageInfo
) {
	(FullImageName);
	(ProcessId);
	(ImageInfo);
}