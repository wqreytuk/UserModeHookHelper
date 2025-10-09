#ifndef Common_h
#define Common_h
#pragma warning(push)
#pragma warning(disable:4141)
#include <fltkernel.h>
#pragma warning(pop)
#include <ntstrsafe.h>
#include "MacroDef.h"
#include "Tag.h"
typedef struct _GLOBAL_V {
	PFLT_FILTER			m_Filter;
	PFLT_PORT			m_ServerPort;
	
	LIST_ENTRY m_PortCtxList;
	ERESOURCE m_PortCtxListLock;

}GLOBAL_V, *PGLOBAL_V;
extern GLOBAL_V gVar;
#endif