#ifndef PORTCTX_H
#define PORTCTX_H

#include "Common.h"
#include "FltCommPort.h"

/*
 * PortCtx module
 *
 * Purpose:
 *   Encapsulate management of per-client communication port contexts
 *   (COMM_CONTEXT). Provides allocation, insertion, removal, and cleanup
 *   APIs so callers do not manipulate list/lock directly.
 *
 * API contract:
 *   - PortCtx_Init/PortCtx_Uninit manage lifecycle. Call Init during
 *     DriverEntry and Uninit during unload. Uninit frees all remaining
 *     COMM_CONTEXT entries.
 *   - PortCtx_CreateAndInsert(UserProcessId, ClientPort) allocates a new
 *     COMM_CONTEXT, initializes it, inserts it into the module-private list,
 *     and returns the pointer. Caller owns no further responsibilities for
 *     list-linking; use PortCtx_RemoveAndFree to remove and free it.
 *   - PortCtx_RemoveAndFree(ctx) safely unlinks (if linked) and frees ctx.
 *
 * Thread-safety:
 *   All functions take internal locks. Callers must not access the list or
 *   lock directly.
 */

NTSTATUS PortCtx_Init(VOID);
VOID PortCtx_Uninit(VOID);
PCOMM_CONTEXT PortCtx_CreateAndInsert(HANDLE UserProcessId, PFLT_PORT ClientPort);
/* Unlink the context from the module list (if linked) and drop the list's
 * ownership reference. The actual free happens when refcount reaches zero.
 */
VOID PortCtx_Remove(PCOMM_CONTEXT ctx);

/* Reference helpers. Call PortCtx_Reference before using a PCOMM_CONTEXT to
 * ensure it won't be freed while in use. PortCtx_Reference returns TRUE if
 * the caller now holds a reference. Call PortCtx_Dereference when done.
 */
BOOLEAN PortCtx_Reference(PCOMM_CONTEXT ctx);
VOID PortCtx_Dereference(PCOMM_CONTEXT ctx);

/* Lookup + reference: finds the COMM_CONTEXT matching a connection cookie
 * (the pointer stored as ConnectionCookie) and takes a reference while the
 * list lock is held. Returns NULL if not found or already removed.
 */
PCOMM_CONTEXT PortCtx_FindAndReferenceByCookie(PVOID ConnectionCookie);

// Create a snapshot array of active PCOMM_CONTEXT references. The caller
// receives an allocated array of PCOMM_CONTEXT pointers (NonPagedPool) and
// the count. The references in the array have been incremented and must be
// released by calling PortCtx_FreeSnapshot.
NTSTATUS PortCtx_Snapshot(PCOMM_CONTEXT** outArray, PULONG outCount);
VOID PortCtx_FreeSnapshot(PCOMM_CONTEXT* array, ULONG count);

#endif
