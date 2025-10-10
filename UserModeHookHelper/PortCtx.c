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
        ExFreePoolWithTag(ctx, tag_ctx);
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
    ctx->m_RefCount = 0;

    ExAcquireResourceExclusiveLite(&s_PortCtxListLock, TRUE);
    InsertTailList(&s_PortCtxList, &ctx->m_entry);
    ExReleaseResourceLite(&s_PortCtxListLock);

    return ctx;
}

VOID PortCtx_RemoveAndFree(PCOMM_CONTEXT ctx) {
    if (!ctx) return;
    ExAcquireResourceExclusiveLite(&s_PortCtxListLock, TRUE);
    // If the global list was already emptied (for example during driver unload)
    // don't attempt to touch the ctx->m_entry pointers which may no longer be
    // linked. Instead only remove the entry when the global list is non-empty.
    if (!IsListEmpty(&s_PortCtxList)) {
        if (ctx->m_entry.Flink != &ctx->m_entry) {
            RemoveEntryList(&ctx->m_entry);
        }
    }
    ExReleaseResourceLite(&s_PortCtxListLock);
    ExFreePoolWithTag(ctx, tag_ctx);
}
