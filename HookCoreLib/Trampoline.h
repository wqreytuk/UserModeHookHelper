#pragma once
#include <string>
#include <vector>
#include "../Shared/HookServices.h" // shared interface (no windows.h here to avoid MFC ordering issue)
namespace HookCore {

#define CCIPC_HOOK_POINT 0x1658c 
#define PLACEHOLDER_FUNCIONT_OFFSET2 0x59f0
#define PLACEHOLDER_SECOND_FUNCIONT_OFFSET2 0x5AD4
// #define READ_OUT_LEN_ORIASMCODE_LEN 0xc 
#define ORIGINAL_BYTE_COUNT_FOR_DETERMINE 0x20
 

#define stage_0_xoreaxeaxret_size 3
	// #define PLACEHOLDER_FUNCIONT_OFFSET PLACEHOLDER_FUNCIONT_OFFSET2+stage_0_xoreaxeaxret_size
// #define PLACEHOLDER_SECOND_FUNCIONT_OFFSET PLACEHOLDER_SECOND_FUNCIONT_OFFSET2+stage_0_xoreaxeaxret_size
#define stage_0_placeholder_size 8
// #define stage_1_shellcode_size 0x56+READ_OUT_LEN_ORIASMCODE_LEN-6
#define stage_2_shellcode_size 0x2c
#define stage_1_oriAsmCodeOffset 0x4a
#define ff25jmpsize 6
#define stage_1_next_ins_offset 0x23
#define stage_1_next_ins_offset_second_ff25 stage_1_oriAsmCodeOffset+ff25jmpsize+READ_OUT_LEN_ORIASMCODE_LEN

#define stage_2_call_offset 0x1b
#define stage_2_ff25_offset 0x28
#define ff25offset_size 4

#define shellcode_call_offset 50

#define SHELLCODE_LEN 100
//#define SHELLCODE_LEN 0xa0

#define stage2_back_to_stage_1_offset 0x23
#define TOTAL_LEN 	 stage_0_placeholder_size + stage_1_shellcode_size 	+ READ_OUT_LEN_ORIASMCODE_LEN + ff25jmpsize + stage_0_placeholder_size + stage_2_shellcode_size + stage_0_placeholder_size + stage_0_placeholder_size + SHELLCODE_LEN

#define fixedTotal_LEN TOTAL_LEN+stage_0_placeholder_size-SHELLCODE_LEN+stage_0_xoreaxeaxret_size

#define wide_char_patch_value_underscore 0x5f

#define recover_byte_offset 0x1f
#define recover_word_offset 0x59
#define recover_byte_value wide_char_patch_value_underscore
#define recover_word_value 0x63 


	bool ConstructTrampoline_x64(IHookServices* services, HANDLE hProcess, PVOID hook_addr, PVOID target_base,
		PVOID tramp_dll_base, DWORD stage_1_func_offset, DWORD stage_2_func_offset);
}