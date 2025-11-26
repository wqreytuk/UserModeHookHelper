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
// Early-break mark: set when user marks this process for early break handling
#define PF_EARLY_BREAK_MARKED 0x00000008u
// Forced injection marker: set when an entry was Force-Injected by the user
#define PF_FORCED             0x00000010u


    typedef unsigned long long PROC_ITEMDATA;

#if defined(_WIN64)
    inline PROC_ITEMDATA MakeItemData(DWORD pid, DWORD flags) {
        return ( (static_cast<unsigned long long>(pid) & 0xFFFFFFFFULL) |
                 ((static_cast<unsigned long long>(flags) & 0xFFFFFFFFULL) << 32) );
    }
    inline DWORD PidFromItemData(PROC_ITEMDATA v) {
        return static_cast<DWORD>(v & 0xFFFFFFFFULL);
    }
    inline DWORD FlagsFromItemData(PROC_ITEMDATA v) {
        return static_cast<DWORD>((v >> 32) & 0xFFFFFFFFULL);
    }
#else
    // 32-bit build: cannot safely shift by 32; store only PID, flags unavailable.
    inline PROC_ITEMDATA MakeItemData(DWORD pid, DWORD /*flags*/) { return static_cast<PROC_ITEMDATA>(pid); }
    inline DWORD PidFromItemData(PROC_ITEMDATA v) { return static_cast<DWORD>(v); }
    inline DWORD FlagsFromItemData(PROC_ITEMDATA /*v*/) { return 0; }
#endif

    // Backward compatibility macros (replace usage gradually)
    #define MAKE_ITEMDATA(pid, flags) MakeItemData((pid),(flags))
    #define PID_FROM_ITEMDATA(v)      PidFromItemData((v))
    #define FLAGS_FROM_ITEMDATA(v)    FlagsFromItemData((v))


	 
// Master DLL base name (adjust if actual deployed helper DLL differs)
#define MASTER_X64_DLL_BASENAME X64_DLL
#define MASTER_X86_DLL_BASENAME X86_DLL

#endif