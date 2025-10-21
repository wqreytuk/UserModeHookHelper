// ProcFlags.h
// Encodes per-process metadata (PID + flags) into the list control's item data.
// Layout (64-bit item data):
//   bits 0-31  : PID
//   bits 32-63 : Flags
// This keeps the full 32-bit PID intact while allowing up to 32 flag bits.
// If compiled for 32-bit (not expected here), only lower 32-bits are used and
// we fall back to storing just the PID (flags truncated) to avoid collisions.
#ifndef PROCFLAGS_H
#define PROCFLAGS_H
#include <Windows.h>
#include "../UserModeHookHelper/UKShared.h"
// Flag bit definitions (stored starting at bit 32 of the 64-bit item data)
#define PF_IN_HOOK_LIST      0x00000001u  // process is currently in hook list
#define PF_MASTER_DLL_LOADED 0x00000002u  // master/injection helper DLL already loaded
#define PF_IS_64BIT          0x00000004u  // target process is 64-bit


    typedef unsigned long long PROC_ITEMDATA;
    #define PID_FROM_ITEMDATA(v)   ((DWORD)((v) & 0xFFFFFFFFull))
    #define FLAGS_FROM_ITEMDATA(v) ((DWORD)(((v) >> 32) & 0xFFFFFFFFull))
    #define MAKE_ITEMDATA(pid, flags) ( (PROC_ITEMDATA)( ( (unsigned long long)(pid) & 0xFFFFFFFFull) | ( ((unsigned long long)(flags) & 0xFFFFFFFFull) << 32 ) ) )


	 
// Master DLL base name (adjust if actual deployed helper DLL differs)
#define MASTER_X64_DLL_BASENAME X64_DLL
#define MASTER_X86_DLL_BASENAME X86_DLL

#endif