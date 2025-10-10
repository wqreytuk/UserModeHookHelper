#include "DriverCtx.h"

static PFLT_FILTER s_Filter = NULL;
static PFLT_PORT s_ServerPort = NULL;

VOID DriverCtx_SetFilter(PFLT_FILTER Filter) {
    s_Filter = Filter;
}
PFLT_FILTER DriverCtx_GetFilter(VOID) {
    return s_Filter;
}
VOID DriverCtx_SetServerPort(PFLT_PORT ServerPort) {
    s_ServerPort = ServerPort;
}
PFLT_PORT DriverCtx_GetServerPort(VOID) {
    return s_ServerPort;
}
VOID DriverCtx_ClearServerPort(VOID) {
    s_ServerPort = NULL;
}
VOID DriverCtx_ClearFilter(VOID) {
    s_Filter = NULL;
}
