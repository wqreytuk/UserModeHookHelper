#ifndef LISTLIB_H
#define LISTLIB_H
#include "Common.h"

// LIST_FOR_EACH_ENTRY(PMyStruct item, PLIST_ENTRY &g_ListHead, ListEntry)
#define LIST_FOR_EACH_ENTRY(pos, head, member, type) \
    for (PLIST_ENTRY _entry = (head)->Flink; \
         _entry != (head) && ((pos) = CONTAINING_RECORD(_entry, type, member), 1); \
         _entry = _entry->Flink)
#endif