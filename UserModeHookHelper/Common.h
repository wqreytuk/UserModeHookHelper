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
	// Hook list: stores 64-bit FNV-1a hashes of NT image paths
	LIST_ENTRY m_HookList;
	ERESOURCE m_HookListLock;

}GLOBAL_V, *PGLOBAL_V;
extern GLOBAL_V gVar;
#endif