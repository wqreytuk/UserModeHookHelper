#include "SysCallback.h"
#include "Trace.h"
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
	(ProcessId);
	(Create);
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