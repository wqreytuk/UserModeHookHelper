#ifndef mini_h
#define mini_h
#include "Common.h"
NTSTATUS
MiniUnload(
	FLT_FILTER_UNLOAD_FLAGS Flags
);


// Dummy PreCreate callback
FLT_PREOP_CALLBACK_STATUS
MiniPreCreateCallback(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID* CompletionContext
);

BOOLEAN Mini_WriteKernelMemory(PVOID Address, const VOID* Buffer, SIZE_T Size);
BOOLEAN Mini_ReadKernelMemory(PVOID Address, VOID* Buffer, SIZE_T Size);

#endif