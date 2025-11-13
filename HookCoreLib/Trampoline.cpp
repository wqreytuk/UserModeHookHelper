#include "Trampoline.h"
#include "../Shared/LogMacros.h"
#include "Disasm.h"
namespace HookCore {
	UCHAR xor_eax_eax_ret[stage_0_xoreaxeaxret_size] = { 0x31,0xc0,0xc3 };
	bool ConstructTrampoline_x64(IHookServices* services, HANDLE hProcess, PVOID hook_addr, PVOID target_base,
		PVOID tramp_dll_base, DWORD stage_1_func_offset, DWORD stage_2_func_offset) {
		DWORD bytesout = 0;
		DWORD offset = (DWORD)((DWORD64)hook_addr - (DWORD64)target_base);
		DWORD old = 0;
		DWORD PLACEHOLDER_FUNCIONT_OFFSET = stage_1_func_offset + (DWORD64)tramp_dll_base + stage_0_xoreaxeaxret_size;
		DWORD64 shellcodeAdd = PLACEHOLDER_FUNCIONT_OFFSET + (DWORD64)tramp_dll_base + stage_0_placeholder_size;
		DWORD placeholder_func_1Old = 0;
		UCHAR* original_asm_code = 0;
		SIZE_T original_asm_len = 0;
		SIZE_T stage_1_shellcode_size = 0;
		SIZE_T READ_OUT_LEN_ORIASMCODE_LEN = 0;

		if (!::VirtualProtectEx(hProcess, (LPVOID)(PLACEHOLDER_FUNCIONT_OFFSET + (DWORD64)tramp_dll_base),
			fixedTotal_LEN, PAGE_EXECUTE_READWRITE, &placeholder_func_1Old)) {
			if (services)
				LOG_CORE(services, L"ConstructTrampoline line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
			return false;
		}
		if (!::WriteProcessMemory(hProcess, (LPVOID)(PLACEHOLDER_FUNCIONT_OFFSET - stage_0_xoreaxeaxret_size + (DWORD64)tramp_dll_base),
			(void*)(&xor_eax_eax_ret), stage_0_xoreaxeaxret_size, NULL)) {
			if (services)
				LOG_CORE(services, L"ConstructTrampoline line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
			return false;
		}

		if (!::WriteProcessMemory(hProcess, (LPVOID)(PLACEHOLDER_FUNCIONT_OFFSET + (DWORD64)tramp_dll_base), (void*)(&shellcodeAdd),
			stage_0_placeholder_size, NULL)) {
			if (services)
				LOG_CORE(services, L"ConstructTrampoline line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
			return false;
		}

	//	UCHAR originalAsmCode[READ_OUT_LEN_ORIASMCODE_LEN] = { 0 };
			// this is actuall a very difficult work, I need to use capstone to calculate correct asm code edge
			// and consider call instruction
			// the best way is not invade call instruction, because it is hard to recover, I need to 
			// consider range limitation in
			// but seme time we can not get 6 bytes unless we invade into call or condition jump instruction
			// there is a way to use jmp, but it will take a register to save target address, we can't possibly know 
			// which register is available, so we can only use ff25, which require a second trampoline pit near the
			// original hook addr, I pass it as a parameter to current function
			// read 0x20 bytes out is totally enough
			UCHAR target_process_ori_asm_code[ORIGINAL_BYTE_COUNT_FOR_DETERMINE] = { 0 };
			if (!::VirtualProtectEx(hProcess, (LPVOID)(offset + (DWORD64)target_base), ORIGINAL_BYTE_COUNT_FOR_DETERMINE, PAGE_EXECUTE_READ, &old)) {
				if (services)
					LOG_CORE(services, L"ConstructTrampoline line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
				return false;
			}
			if (!::ReadProcessMemory(hProcess, (LPVOID)(offset + (DWORD64)target_base), (void*)target_process_ori_asm_code,
				ORIGINAL_BYTE_COUNT_FOR_DETERMINE, NULL)) {
				if (services)
					LOG_CORE(services, L"ConstructTrampoline line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
				return false;
			}
			auto r = DetermineCodeEdge_x64(target_process_ori_asm_code, sizeof(target_process_ori_asm_code), (DWORD64)hook_addr, 6);
			if (r.type != DecideResultType::SUCCESS) {
				if (services)
					LOG_CORE(services, L"DetermineCodeEdge result type: %d\n message: %s\n", r.type, r.message.c_str());
				return false;
			}
			
			// if there is a relative instruction involved, we'll need extra 8 bytes to save this destination

			original_asm_code = (UCHAR*)malloc(r.preserveLen);
			if (!::ReadProcessMemory(hProcess, (LPVOID)(offset + (DWORD64)target_base), (void*)original_asm_code,
				r.preserveLen, NULL)) {
				if (services)
					LOG_CORE(services, L"ConstructTrampoline line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
				return false;
			}
				original_asm_len = r.preserveLen;
				READ_OUT_LEN_ORIASMCODE_LEN = r.preserveLen;
				stage_1_shellcode_size = 0x56 + READ_OUT_LEN_ORIASMCODE_LEN - 6;
			if (!::VirtualProtectEx(hProcess, (LPVOID)(offset + (DWORD64)target_base), ORIGINAL_BYTE_COUNT_FOR_DETERMINE, old, &old)) {
				if (services)
					LOG_CORE(services, L"ConstructTrampoline line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
				return false;
			}
		DWORD64 stage_2_addr = 0; 
		{
			UCHAR *stage_1 = (UCHAR*)malloc(stage_1_shellcode_size);
			UCHAR temp[stage_1_oriAsmCodeOffset] = { 0x9c , 0x50 , 0x53 , 0x51 , 0x52 , 0x56 , 0x57 , 0x55 , 0x90 , 0x41 , 0x50 , 0x41 , 0x51 , 0x41 , 0x52 , 0x41 , 0x53 , 0x41 , 0x54 , 0x41 ,
	 0x55 , 0x41 , 0x56 , 0x41 , 0x57 , 0x90 , 0x90 , 0x90 , 0x90 , 0xff , 0x25 , 0xbd , 0xb8 , 0xff , 0xff , 0x90 , 0x90 , 0x90 , 0x90 , 0x90 ,
	 0x90 , 0x90 , 0x90 , 0x90 , 0x90 , 0x90 , 0x90 , 0x90 , 0x90 , 0x90 , 0x41 , 0x5f , 0x41 , 0x5e , 0x41 , 0x5d , 0x41 , 0x5c , 0x41 , 0x5b ,
	 0x41 , 0x5a , 0x41 , 0x59 , 0x41 , 0x58 , 0x5d , 0x5f , 0x5e , 0x5a , 0x59 , 0x5b , 0x58 , 0x9d };
			for (size_t i = 0; i < stage_1_oriAsmCodeOffset; i++)
			{
				*(UCHAR*)(stage_1 + i) = temp[i];
			}
			for (size_t i = 0; i < READ_OUT_LEN_ORIASMCODE_LEN; i++)
			{
				*(UCHAR*)(stage_1 + stage_1_oriAsmCodeOffset + i) = original_asm_code[i];
			}
			*(WORD*)(stage_1 + stage_1_oriAsmCodeOffset + READ_OUT_LEN_ORIASMCODE_LEN) = 0x25ff;

			stage_2_addr = (DWORD64)tramp_dll_base + PLACEHOLDER_FUNCIONT_OFFSET + stage_0_placeholder_size + stage_1_shellcode_size + stage_0_placeholder_size;
			// 59f0+8+8-6+56+c
			DWORD64 ff25_nex_ins_addr = (DWORD64)tramp_dll_base + PLACEHOLDER_FUNCIONT_OFFSET + stage_0_placeholder_size
				+ stage_1_next_ins_offset;

			DWORD ff25offset = ((DWORD64)tramp_dll_base + PLACEHOLDER_FUNCIONT_OFFSET + fixedTotal_LEN - 8 - ff25_nex_ins_addr) & 0xffffffff;
			*(DWORD*)(stage_1 + stage_1_next_ins_offset - 4) = ff25offset;

			if (!::WriteProcessMemory(hProcess, (LPVOID)((DWORD64)tramp_dll_base + PLACEHOLDER_FUNCIONT_OFFSET + fixedTotal_LEN - 8),
				(void*)(&stage_2_addr), stage_1_shellcode_size, NULL)) {
				if (services)
					LOG_CORE(services, L"ConstructTrampoline line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
				return false;
			}
			 
			ff25offset = 0xffffffff & (stage_2_addr - stage_0_placeholder_size - (PLACEHOLDER_FUNCIONT_OFFSET +
				(DWORD64)tramp_dll_base + stage_0_placeholder_size + stage_1_next_ins_offset_second_ff25));
			*(DWORD*)(stage_1 + stage_1_oriAsmCodeOffset + READ_OUT_LEN_ORIASMCODE_LEN + ff25jmpsize - 4) = ff25offset;
	 
			if (!::WriteProcessMemory(hProcess, (LPVOID)(PLACEHOLDER_FUNCIONT_OFFSET + (DWORD64)tramp_dll_base + stage_0_placeholder_size),
				(void*)(stage_1), stage_1_shellcode_size, NULL)) {
				if (services)
					LOG_CORE(services, L"ConstructTrampoline line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
				return false;
			}
		}
		{
			DWORD64 retAddr = (DWORD64)target_base + offset + READ_OUT_LEN_ORIASMCODE_LEN;
			// 	stage_2_addr+ stage_0_placeholder_size 
			if (!::WriteProcessMemory(hProcess, (LPVOID)(stage_2_addr - stage_0_placeholder_size), (void*)(&retAddr), stage_0_placeholder_size, NULL)) {
				if (services)
					LOG_CORE(services, L"ConstructTrampoline line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
				return false;
			}
		}
		 
		{
			UCHAR stage_2_shellcode[stage_2_shellcode_size] = { 0x48, 0x89, 0xe7, 0x48, 0x83, 0xe4,
				0xf0, 0x48, 0x83, 0xec, 0x50, 0x48, 0x89, 0xf8, 0x48, 0x05, 0x80,
				0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x20, 0xff, 0x15, 0x3a, 0x23,
				0x00, 0x00, 0x48, 0x83, 0xc4, 0x50, 0x48, 0x89, 0xfc, 0xff, 0x25, 0x8d, 0xb8, 0xff, 0xff };
			 
			DWORD64 calladdr = stage_2_addr + stage_2_shellcode_size;
			DWORD64 ff25addr = stage_2_addr + stage_2_shellcode_size + stage_0_placeholder_size;
			// stage_2_call_offset
			DWORD callOffsetVal = (calladdr - (stage_2_call_offset + stage_2_addr + ff25offset_size)) & 0xffffffff;
			// stage_2_ff25_offset
			DWORD ff25OffsetVal = (ff25addr - (stage_2_ff25_offset + stage_2_addr + ff25offset_size)) & 0xffffffff;
			*(DWORD*)(stage_2_shellcode + stage_2_call_offset) = callOffsetVal;
			*(DWORD*)(stage_2_shellcode + stage_2_ff25_offset) = ff25OffsetVal;

			if (!::WriteProcessMemory(hProcess, (LPVOID)(stage_2_addr), (void*)(stage_2_shellcode), stage_2_shellcode_size, NULL)) {
				if (services)
					LOG_CORE(services, L"ConstructTrampoline line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
				return false;
			} 
			DWORD64 ShellcodecallAddr = (DWORD64)tramp_dll_base + stage_2_func_offset;
			
			if (!::WriteProcessMemory(hProcess, (LPVOID)(calladdr), (void*)(&ShellcodecallAddr), stage_0_placeholder_size, NULL)) {
				if (services)
					LOG_CORE(services, L"ConstructTrampoline line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
				return false;
			}
			DWORD64 _2_back_to_1 = stage2_back_to_stage_1_offset + PLACEHOLDER_FUNCIONT_OFFSET + (DWORD64)tramp_dll_base + stage_0_placeholder_size;
			if (!::WriteProcessMemory(hProcess, (LPVOID)(ff25addr), (void*)(&_2_back_to_1), stage_0_placeholder_size, NULL)) {
				if (services)
					LOG_CORE(services, L"ConstructTrampoline line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
				return false;
			}
		}

		if (!VirtualProtectEx(hProcess, (LPVOID)(PLACEHOLDER_FUNCIONT_OFFSET + (DWORD64)tramp_dll_base), 
			fixedTotal_LEN, placeholder_func_1Old, &placeholder_func_1Old)) {
			if (services)
				LOG_CORE(services, L"ConstructTrampoline line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
			return false;
		}

		DWORD64 PLACEHOLDER_SECOND_FUNCIONT_OFFSET = stage_2_func_offset + stage_0_xoreaxeaxret_size;
		{
			if (!::VirtualProtectEx(hProcess, (LPVOID)(PLACEHOLDER_SECOND_FUNCIONT_OFFSET - stage_0_xoreaxeaxret_size + (DWORD64)tramp_dll_base),
				stage_0_xoreaxeaxret_size + SHELLCODE_LEN, PAGE_EXECUTE_READWRITE, &old)) {
				if (services)
					LOG_CORE(services, L"ConstructTrampoline line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
				return false;
			} 
			if (!::WriteProcessMemory(hProcess, (LPVOID)(PLACEHOLDER_SECOND_FUNCIONT_OFFSET - stage_0_xoreaxeaxret_size + (DWORD64)tramp_dll_base),
				(void*)(&xor_eax_eax_ret), stage_0_xoreaxeaxret_size, NULL)) {
				if (services)
					LOG_CORE(services, L"ConstructTrampoline line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
				return false;
			}
			 
			// this 
			 	UCHAR myshellcode[SHELLCODE_LEN] =
			{
		0x66, 0x8B, 0x02,               // 0x00: 66 8B 02

		// test ax, ax                   ; if zero => length == 0 -> RET
		0x66, 0x85, 0xC0,               // 0x03: 66 85 C0

		// je  L_RET                     ; if ax==0 jump to ret
		0x74, 0x11,                     // 0x06: 74 11   ; jump to offset 0x19+? (computed)

		// cmp ax, 0x007B ('{')          ; compare first wchar to '{'
		0x66, 0x3D, 0x7B, 0x00,         // 0x08: 66 3D 7B 00

		// jne L_RET                     ; if not '{' -> ret
		0x75, 0x0B,                     // 0x0C: 75 0B

		// test r8, r8                    ; if r8 == 0 -> skip write -> ret
		0x4D, 0x85, 0xC0,               // 0x0E: 4D 85 C0

		// je  L_RET                      ; if r8==0 jump to ret
		0x74, 0x06,                     // 0x11: 74 06


		// mov word ptr [r8], 0           ; write zero (little-endian imm16 = 0x0000)
		0x66, 0x41, 0xC7, 0x00, 0x00, 0x00, // 0x13: 66 41 C7 00 00 00

		// ret
		0xC3                            // 0x19: C3
			};
			 
			UCHAR myshellcode2[SHELLCODE_LEN] =
			{
			0x66,0x8B,0x02,                   // mov ax, word ptr [rdx]
	0x66,0x85,0xC0,                   // test ax, ax
	0x74,0x55,                        // je  +0x56 -> final ret
	0x66,0x3D,0x7B,0x00,              // cmp ax, 0x007B
	0x74,0x4a,                        // je  +0x05 -> write underscore
	0x48,0x8B,0x02,                   // mov rax, qword ptr [rdx]
	0x48,0xBB,0x63,0x00,0x63,0x00,0x47,0x00,0x65,0x00,   // movabs rbx, 0x0065004700630063
	0x48,0x39,0xD8,                   // cmp rax, rbx
	0x75,0x3d,                        // jne +0x3E -> final ret
	0x48,0x8B,0x42,0x08,              // mov rax, qword ptr [rdx + 8]
	0x48,0xBB,0x69,0x00,0x72,0x00,0x65,0x00,0x6E,0x00,   // movabs rbx, 0x006E006500720069
	0x48,0x39,0xD8,                   // cmp rax, rbx
	0x75,0x2a,                        // jne +0x30 -> final ret
	0x48,0x8B,0x42,0x10,              // mov rax, qword ptr [rdx + 16]
	0x48,0xBB,0x65,0x00,0x76,0x00,0x63,0x00,0x45,0x00,   // movabs rbx, 0x0045006300760065
	0x48,0x39,0xD8,                   // cmp rax, rbx
	0x75,0x17,                        // jne +0x28 -> final ret
	0x8B,0x42,0x18,                   // mov eax, dword ptr [rdx + 24]
	0xB9,0x6E,0x00,0x74,0x00,         // mov ecx, 0x0074006E
	0x39,0xC8,                        // cmp eax, ecx
	0x75,0xb,                        // jne +0x22 -> final ret
	0x66,0xC7,0x02,0x2B,0x00,         // mov word ptr [rdx], 0x002B   ; write '+'
	0xC3,                             // ret

	//; write underscore branch
	0x66,0xC7,0x02,0x5F,0x00,         // mov word ptr [rdx], 0x005F   ; write '_'
	0xC3,                             // ret


			};


			if (!::WriteProcessMemory(hProcess, (LPVOID)((DWORD64)tramp_dll_base + PLACEHOLDER_SECOND_FUNCIONT_OFFSET), (void*)(myshellcode2),
				SHELLCODE_LEN, NULL)) {
				if (services)
					LOG_CORE(services, L"ConstructTrampoline line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
				return false;
			} 
			if (!::VirtualProtectEx(hProcess, (LPVOID)(PLACEHOLDER_SECOND_FUNCIONT_OFFSET - stage_0_xoreaxeaxret_size + (DWORD64)tramp_dll_base),
				stage_0_xoreaxeaxret_size + SHELLCODE_LEN, old, &old)) {
				if (services)
					LOG_CORE(services, L"ConstructTrampoline line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
				return false;
			} 
		}
		 
		if (!VirtualProtectEx(hProcess, (LPVOID)((DWORD64)target_base + offset), ff25jmpsize, PAGE_EXECUTE_READWRITE, &old)) {
			if (services)
				LOG_CORE(services, L"ConstructTrampoline line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
			return false;
		}

		UCHAR finalINs[ff25jmpsize] = { 0 };
		*(WORD*)finalINs = 0x25ff;

		*(DWORD*)(finalINs + 2) = (PLACEHOLDER_FUNCIONT_OFFSET + (DWORD64)tramp_dll_base - ((DWORD64)target_base + offset + READ_OUT_LEN_ORIASMCODE_LEN)) & 0xffffffff;
		
		if (!::WriteProcessMemory(hProcess, (LPVOID)((DWORD64)target_base + offset), (void*)(finalINs), ff25jmpsize, NULL)) {
			if (services)
				LOG_CORE(services, L"ConstructTrampoline line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
			return false;
		}
		
		if (!::VirtualProtectEx(hProcess, (LPVOID)((DWORD64)target_base + offset), ff25jmpsize, old, &old)) {
			if (services)
				LOG_CORE(services, L"ConstructTrampoline line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
			return false;
		}

		if (services)
			LOG_CORE(services, L"trampoline construct success\n");
	
		return true;
	}
}
