#ifndef INJECT_H
#define INJECT_H

#include "Common.h"

// Initialize/uninitialize injection subsystem
NTSTATUS Inject_Init(VOID);
VOID Inject_Uninit(VOID);

// Queue check: compute hash of supplied image name and add pid to pending list
VOID Inject_CheckAndQueue(PUNICODE_STRING ImageName, DWORD pid);

// Returns TRUE if pid is in pending list
BOOLEAN Inject_PendingExists(ULONG pid);

// Remove pending entry for pid
VOID Inject_RemovePending(ULONG pid);

// Called from load-image notify to test for ntdll and perform injection
VOID Inject_OnImageLoad(PUNICODE_STRING FullImageName, DWORD pid);

// Placeholder actual injection call (exported for tests)
VOID Inject_Perform(ULONG pid);

#endif
