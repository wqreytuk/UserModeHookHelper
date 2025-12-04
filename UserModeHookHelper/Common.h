#ifndef Common_h
#define Common_h
#pragma warning(push)
#pragma warning(disable:4141)
#include <fltkernel.h>
#pragma warning(pop)
#include <ntstrsafe.h>
#include "MacroDef.h"
#include "Tag.h"
// Global driver state has been encapsulated into dedicated modules:
// - DriverCtx (filter + server port)
// - PortCtx (client port contexts)
// - HookList (hook entries)

typedef struct _ACG_MitigationOffPos {
	ULONG mitigation;
	UCHAR acg_pos;
	UCHAR acg_audit_pos;
}ACG_MitigationOffPos, PACG_MitigationOffPos;
#endif