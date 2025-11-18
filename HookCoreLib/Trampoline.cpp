#include "Trampoline.h"
#include "../Shared/LogMacros.h"
#include "Disasm.h"
namespace HookCore {
	UCHAR xor_eax_eax_ret[stage_0_xoreaxeaxret_size] = { 0x31,0xc0,0xc3 };
	bool RemoveHook(IHookServices* services, HANDLE hProc, PVOID hook_addr, PVOID trampoline_dll_base,
		DWORD64 stage_2_func_offset,DWORD original_asm_code_len) {
		if (!services) {
			MessageBoxW(NULL, L"Fatal Error! services is NULL!", L"Hook", MB_OK | MB_ICONINFORMATION);
			return false;
		}
		DWORD old = 0;
		// read out
		if (!::VirtualProtectEx(hProc, (LPVOID)(stage_2_func_offset + (DWORD64)trampoline_dll_base),
			TRAMPOLINE_PLACEHOLDER_FUNCTION_SIZE, PAGE_EXECUTE_READWRITE, &old)) {
			LOG_CORE(services, L"ConstructTrampoline line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
			return false;
		}
		UCHAR* original_asm_code = (UCHAR*)malloc(original_asm_code_len);
		if (!::ReadProcessMemory(hProc, (LPVOID)(stage_2_func_offset + 0x200 + (DWORD64)trampoline_dll_base),
			(void*)(original_asm_code), original_asm_code_len, NULL)) {
			LOG_CORE(services, L"ConstructTrampoline line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
			return false;
		}
		if (!::VirtualProtectEx(hProc, (LPVOID)(stage_2_func_offset + (DWORD64)trampoline_dll_base),
			TRAMPOLINE_PLACEHOLDER_FUNCTION_SIZE, old, &old)) {
			LOG_CORE(services, L"ConstructTrampoline line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
			return false;
		}
		// write back
		if (!::VirtualProtectEx(hProc, (LPVOID)(hook_addr), original_asm_code_len, PAGE_EXECUTE_READWRITE, &old)) {
			LOG_CORE(services, L"ConstructTrampoline line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
			return false;
		}
		if (!::WriteProcessMemory(hProc, (LPVOID)(hook_addr),
			(void*)(original_asm_code), original_asm_code_len, NULL)) {
			LOG_CORE(services, L"ConstructTrampoline line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
			return false;
		}
		if (!::VirtualProtectEx(hProc, (LPVOID)(hook_addr), original_asm_code_len, old, &old)) {
			LOG_CORE(services, L"ConstructTrampoline line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
			return false;
		}
		return true;
	}
	bool	InstallHook(IHookServices* services, HANDLE hProc, PVOID hook_addr, PVOID trampoline_pit, PVOID trampoline_addr) {

		if (!services) {
			MessageBoxW(NULL, L"Fatal Error! services is NULL!", L"Hook", MB_OK | MB_ICONINFORMATION);
			return false;
		}
		DWORD placeholder_func_1Old = 0;
		if (!::VirtualProtectEx(hProc, hook_addr,
			ff25jmpsize, PAGE_EXECUTE_READWRITE, &placeholder_func_1Old)) {
			if (services)
				LOG_CORE(services, L"InstallHook line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
			return false;
		}
		UCHAR ff25[ff25jmpsize] = { 0xff,0x25,0,0,0,0 };
		DWORD64 _ = (DWORD64)trampoline_pit - (DWORD64)hook_addr - ff25jmpsize;
		LOG_CORE(services, L"hooksite ff25 operand: 0x%x\n", _);
		*(DWORD*)(ff25 + 2) = (DWORD64)trampoline_pit - (DWORD64)hook_addr - ff25jmpsize;

		if (!::WriteProcessMemory(hProc, trampoline_pit,
			(void*)(&trampoline_addr), sizeof(PVOID), NULL)) {
			if (services)
				LOG_CORE(services, L"InstallHook line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
			return false;
		}
		if (!::WriteProcessMemory(hProc, hook_addr,
			(void*)(ff25), ff25jmpsize, NULL)) {
			if (services)
				LOG_CORE(services, L"InstallHook line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
			return false;
		} 

		if (!::VirtualProtectEx(hProc, hook_addr,
			ff25jmpsize, placeholder_func_1Old, &placeholder_func_1Old)) {
			if (services)
				LOG_CORE(services, L"InstallHook line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
			return false;
		}

		// if (!FlushInstructionCache(hProc, hook_addr, ff25jmpsize)) {
		// 	if (services)
		// 		LOG_CORE(services, L"InstallHook line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
		// 	return false;
		// }

		return true;
	}
	bool ConstructTrampoline_x64(IHookServices* services, HANDLE hProcess, PVOID hook_addr, PVOID target_base,
		PVOID tramp_dll_base, DWORD stage_1_func_offset, DWORD stage_2_func_offset,DWORD64 hook_code_addr, DWORD* out_original_asm_len) {

		if (!services) {
			MessageBoxW(NULL,L"Fatal Error! services is NULL!", L"Hook", MB_OK | MB_ICONINFORMATION);
			return false;
		}
		DWORD bytesout = 0;
		DWORD offset = (DWORD)((DWORD64)hook_addr - (DWORD64)target_base);
		DWORD old = 0;
		DWORD PLACEHOLDER_FUNCIONT_OFFSET = stage_1_func_offset + stage_0_xoreaxeaxret_size;
		DWORD64 shellcodeAdd = PLACEHOLDER_FUNCIONT_OFFSET + (DWORD64)tramp_dll_base + stage_0_placeholder_size;
		DWORD placeholder_func_1Old = 0;
		UCHAR* original_asm_code = 0;
		SIZE_T original_asm_len = 0;
		SIZE_T stage_1_shellcode_size = 0;
		SIZE_T READ_OUT_LEN_ORIASMCODE_LEN = 0;

		DWORD stage_2_func_offset_real = stage_2_func_offset;
		stage_2_func_offset = stage_1_func_offset + 0x250;

		if (!::VirtualProtectEx(hProcess, (LPVOID)(stage_1_func_offset + (DWORD64)tramp_dll_base),
			TRAMPOLINE_PLACEHOLDER_FUNCTION_SIZE, PAGE_EXECUTE_READWRITE, &placeholder_func_1Old)) {
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

			// since we may patch saved original asm code, we need to save the real original asm code at another place
			// I'll chose 0x200 of stage_2_func_offset
			if (!::VirtualProtectEx(hProcess, (LPVOID)(stage_2_func_offset_real + (DWORD64)tramp_dll_base),
				TRAMPOLINE_PLACEHOLDER_FUNCTION_SIZE, PAGE_EXECUTE_READWRITE, &old)) {
				LOG_CORE(services, L"ConstructTrampoline line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
				return false;
			}
			*out_original_asm_len = r.preserveLen;
			if (!::WriteProcessMemory(hProcess, (LPVOID)(stage_2_func_offset_real + 0x200 + (DWORD64)tramp_dll_base),
				(void*)(original_asm_code), r.preserveLen, NULL)) {
				LOG_CORE(services, L"ConstructTrampoline line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
				return false;
			}
			if (!::VirtualProtectEx(hProcess, (LPVOID)(stage_2_func_offset_real + (DWORD64)tramp_dll_base),
				TRAMPOLINE_PLACEHOLDER_FUNCTION_SIZE, old, &old)) {
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
			// now we have read out the original asm code we need to save
			// we ned to handle a case which is call or jmp instruction to be the last instruction
			// we have totaly 0x36B in stage 1 placeholder function, so we can just construct new jmp code at offset 0x200
			std::vector<uint8_t> v(original_asm_code, original_asm_code + r.preserveLen);
			DWORD64 rip_rel_target_addr = ResolveRipRelativeTarget(hProcess, stage_1_func_offset + (DWORD64)tramp_dll_base, v);
			if (rip_rel_target_addr) {
				// zero indicates that there is no control flow instruction in original instruction, there is no need to construct trampoline code
				// otherwise, we need to modify original asm code and write a ff25 instruction and a pit at 0x200 of stage_1_func_offset
				BYTE ff25StubAddr[6] = { 0xff,0x25,0,0,0,0 };
				if (!::WriteProcessMemory(hProcess, (LPVOID)(OFFSET_FOR_TRAMPOLINE_REL_INS_STAGE_1 + stage_1_func_offset + (DWORD64)tramp_dll_base), (void*)(ff25StubAddr),
					6, NULL)) {
					if (services)
						LOG_CORE(services, L"ConstructTrampoline line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
					return false;
				}
				if (!::WriteProcessMemory(hProcess, (LPVOID)(OFFSET_FOR_TRAMPOLINE_REL_INS_STAGE_1 + stage_1_func_offset + (DWORD64)tramp_dll_base + ff25jmpsize), (void*)(&rip_rel_target_addr),
					8, NULL)) {
					if (services)
						LOG_CORE(services, L"ConstructTrampoline line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
					return false;
				}
				if (!PatchLastInstruction(
					original_asm_code,
					r.preserveLen,
					stage_1_oriAsmCodeOffset + stage_1_func_offset + (DWORD64)tramp_dll_base,
					OFFSET_FOR_TRAMPOLINE_REL_INS_STAGE_1 + stage_1_func_offset + (DWORD64)tramp_dll_base)) {
					if (services)
						LOG_CORE(services, L"failed to patch the last instruction");
					return false;
				}
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
			// reconstrcut stage 2 shellcode
/*
mov qword ptr [rip+0x11223344], rsp
and rsp,0xfffffffffffffff0
sub rsp,0x50
push rdi
mov rdi, qword ptr [rip+0x11223344]
mov QWORD PTR [rsp+0x20],rdi
pop rdi
call QWORD PTR [rip+0x233a]
add rsp,0x50
mov rsp, qword ptr [rip+0x11223344]
jmp qword ptr [rip+0x11223344]
*/
			UCHAR stage_2_shellcode[stage_2_shellcode_size] = { 0x48, 0x89, 0xE3, 0x48, 0x83, 0xE4, 0xF0, 0x48, 0x83, 0xEC, 0x50, 0x48, 0x89, 0x5C, 0x24,
				0x20, 0xFF, 0x15, 0x3A, 0x23, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x50, 0x48, 0x89, 0xDC, 0xFF, 0x25, 0x44, 0x33, 0x22, 0x11 };
			


			DWORD64 calladdr = stage_2_addr + stage_2_shellcode_size;

			int call_offset = 0x12;
			*(DWORD*)(stage_2_shellcode + call_offset) = calladdr - stage_2_addr - 0x16;

			DWORD64 ff25addr = stage_2_addr + stage_2_shellcode_size + stage_0_placeholder_size;
			int jmp_offset = 0x1f;
			*(DWORD*)(stage_2_shellcode + jmp_offset) = ff25addr - stage_2_addr - 0x23;
			 
			if (!::WriteProcessMemory(hProcess, (LPVOID)(stage_2_addr), (void*)(stage_2_shellcode), stage_2_shellcode_size, NULL)) {
				if (services)
					LOG_CORE(services, L"ConstructTrampoline line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
				return false;
			} 
			DWORD64 ShellcodecallAddr = (DWORD64)tramp_dll_base + stage_2_func_offset_real;
			
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

		if (!VirtualProtectEx(hProcess, (LPVOID)(stage_1_func_offset + (DWORD64)tramp_dll_base),
			TRAMPOLINE_PLACEHOLDER_FUNCTION_SIZE, placeholder_func_1Old, &placeholder_func_1Old)) {
			if (services)
				LOG_CORE(services, L"ConstructTrampoline line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
			return false;
		}

		DWORD64 PLACEHOLDER_SECOND_FUNCIONT_OFFSET = stage_2_func_offset + stage_0_xoreaxeaxret_size;
		{
			if (!::VirtualProtectEx(hProcess, (LPVOID)(stage_2_func_offset_real + (DWORD64)tramp_dll_base),
				TRAMPOLINE_PLACEHOLDER_FUNCTION_SIZE, PAGE_EXECUTE_READWRITE, &old)) {
				if (services)
					LOG_CORE(services, L"ConstructTrampoline line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
				return false;
			}
			UCHAR ff25_hook_code [6]= { 0xff,0x25,0,0,0,0 };
			if (!::WriteProcessMemory(hProcess, (LPVOID)(stage_2_func_offset_real  + (DWORD64)tramp_dll_base),
				(void*)(ff25_hook_code), 6, NULL)) {
				if (services)
					LOG_CORE(services, L"ConstructTrampoline line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
				return false;
			}
			if (!::WriteProcessMemory(hProcess, (LPVOID)(stage_2_func_offset_real  +(DWORD64)tramp_dll_base+6),
				(void*)(&hook_code_addr), sizeof(DWORD64), NULL)) {
				if (services)
					LOG_CORE(services, L"ConstructTrampoline line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
				return false;
			}
		
			if (!::VirtualProtectEx(hProcess, (LPVOID)(stage_2_func_offset_real + (DWORD64)tramp_dll_base),
				TRAMPOLINE_PLACEHOLDER_FUNCTION_SIZE, old, &old)) {
				if (services)
					LOG_CORE(services, L"ConstructTrampoline line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
				return false;
			} 
		}
		 
		
		if (services)
			LOG_CORE(services, L"trampoline construct success\n");
	
		return true;
	}
}
