#ifndef SYSCALLBACK_H
#define SYSCALLBACK_H
#include "Common.h"
NTSTATUS SetSysNotifiers();
 
VOID
ProcessCrNotify(
	IN HANDLE ParentId,
	IN HANDLE ProcessId,
	IN BOOLEAN Create
);

VOID
LoadImageNotify(
	IN PUNICODE_STRING FullImageName,
	IN HANDLE ProcessId,
	IN PIMAGE_INFO ImageInfo
);
#endif
