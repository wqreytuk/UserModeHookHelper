#include "PortCtx.h"
#include "Tag.h"
#include "Trace.h"

static LIST_ENTRY s_PortCtxList;
static ERESOURCE s_PortCtxListLock;

NTSTATUS PortCtx_Init(VOID) {
    InitializeListHead(&s_PortCtxList);
    ExInitializeResourceLite(&s_PortCtxListLock);
    return STATUS_SUCCESS;
}

VOID PortCtx_Uninit(VOID) {
    ExAcquireResourceExclusiveLite(&s_PortCtxListLock, TRUE);
    while (!IsListEmpty(&s_PortCtxList)) {
        PLIST_ENTRY entry = RemoveHeadList(&s_PortCtxList);
        PCOMM_CONTEXT ctx = CONTAINING_RECORD(entry, COMM_CONTEXT, m_entry);
        ctx->m_Removed = TRUE;
        /* Drop the list's ownership reference; actual free happens in
         * PortCtx_Dereference when last user drops their refs.
         */
        PortCtx_Dereference(ctx);
    }
    InitializeListHead(&s_PortCtxList);
    ExReleaseResourceLite(&s_PortCtxListLock);
    ExDeleteResourceLite(&s_PortCtxListLock);
}

PCOMM_CONTEXT PortCtx_CreateAndInsert(HANDLE UserProcessId, PFLT_PORT ClientPort) {
    PCOMM_CONTEXT ctx = ExAllocatePoolWithTag(NonPagedPool, sizeof(COMM_CONTEXT), tag_ctx);
    if (!ctx) return NULL;
    RtlZeroMemory(ctx, sizeof(COMM_CONTEXT));
    InitializeListHead(&ctx->m_entry);
    ctx->m_UserProcessId = UserProcessId;
    ctx->m_ClientPort = ClientPort;
    ctx->m_RefCount = 1; /* list owns initial reference */
    ctx->m_Removed = FALSE;

    ExAcquireResourceExclusiveLite(&s_PortCtxListLock, TRUE);
    InsertTailList(&s_PortCtxList, &ctx->m_entry);
    ExReleaseResourceLite(&s_PortCtxListLock);

    return ctx;
}

VOID PortCtx_Remove(PCOMM_CONTEXT ctx) {
    if (!ctx) return;
    /* Mark removed under exclusive lock and unlink from the list if linked. */
    ExAcquireResourceExclusiveLite(&s_PortCtxListLock, TRUE);
    ctx->m_Removed = TRUE;
    if (!IsListEmpty(&s_PortCtxList)) {
        if (ctx->m_entry.Flink != &ctx->m_entry) {
            RemoveEntryList(&ctx->m_entry);
        }
    }
    ExReleaseResourceLite(&s_PortCtxListLock);

    /* Drop the list's ownership reference. The context will be freed when the
     * refcount reaches zero.
     */
    PortCtx_Dereference(ctx);
}

BOOLEAN PortCtx_Reference(PCOMM_CONTEXT ctx) {
    if (!ctx) return FALSE;
    /* Acquire shared lock to synchronize with exclusive removals/uninit. */
    ExAcquireResourceSharedLite(&s_PortCtxListLock, TRUE);
    if (ctx->m_Removed) {
        /* Can't reference removed ctx. */
        ExReleaseResourceLite(&s_PortCtxListLock);
        return FALSE;
    }
    InterlockedIncrement(&ctx->m_RefCount);
    ExReleaseResourceLite(&s_PortCtxListLock);
    return TRUE;
}

VOID PortCtx_Dereference(PCOMM_CONTEXT ctx) {
    if (!ctx) return;
    LONG v = InterlockedDecrement(&ctx->m_RefCount);
    if (v == 0) {
        ExFreePoolWithTag(ctx, tag_ctx);
    }
}

PCOMM_CONTEXT PortCtx_FindAndReferenceByCookie(PVOID ConnectionCookie) {
    if (!ConnectionCookie) return NULL;
    PCOMM_CONTEXT found = NULL;
    ExAcquireResourceSharedLite(&s_PortCtxListLock, TRUE);
    for (PLIST_ENTRY e = s_PortCtxList.Flink; e != &s_PortCtxList; e = e->Flink) {
        PCOMM_CONTEXT ctx = CONTAINING_RECORD(e, COMM_CONTEXT, m_entry);
        if (ctx == (PCOMM_CONTEXT)ConnectionCookie) {
            if (!ctx->m_Removed) {
                InterlockedIncrement(&ctx->m_RefCount);
                found = ctx;
            }
            break;
        }
    }
    ExReleaseResourceLite(&s_PortCtxListLock);
    return found;
}
