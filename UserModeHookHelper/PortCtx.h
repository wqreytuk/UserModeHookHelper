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
VOID PortCtx_RemoveAndFree(PCOMM_CONTEXT ctx);

#endif
