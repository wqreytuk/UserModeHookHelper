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

// PreRead callback
FLT_PREOP_CALLBACK_STATUS
MiniPreReadCallback(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Outptr_result_maybenull_ PVOID *CompletionContext
);

// Stream handle context used to mark blocked handles
typedef struct _UMHH_STREAMHANDLE_CTX {
	BOOLEAN Blocked;
} UMHH_STREAMHANDLE_CTX, *PUMHH_STREAMHANDLE_CTX;


#endif