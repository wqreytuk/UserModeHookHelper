#include "Disasm.h"
#include "capstone/capstone.h"
namespace HookCore {

	// Helper: check if instruction is a CALL
	static bool InsnIsCall(csh handle, cs_insn *ins) {
		return cs_insn_group(handle, ins, CS_GRP_CALL) != 0;
	}

	// Helper: check if instruction is any jump (conditional or unconditional)
	static bool InsnIsJump(csh handle, cs_insn *ins) {
		return cs_insn_group(handle, ins, CS_GRP_JUMP) != 0;
	}

	// Helper: check if instruction is RET
	static bool InsnIsRet(csh handle, cs_insn *ins) {
		return cs_insn_group(handle, ins, CS_GRP_RET) != 0;
	}

	enum PatchType {
		PT_CALL,
		PT_JMP,
		PT_JCC,
		PT_UNSUPPORTED
	};

	static PatchType ClassifyInstruction(const cs_insn* ins)
	{
		switch (ins->id) {

		case X86_INS_CALL:
			return PT_CALL;

		case X86_INS_JMP:
			return PT_JMP;

		default:
			// conditional jumps: Jcc = JAE/JBE/JZ/JNZ/etc.
			if ((ins->id >= X86_INS_JAE && ins->id <= X86_INS_JE) ||
				(ins->id >= X86_INS_JB && ins->id <= X86_INS_JP) ||
				(ins->id >= X86_INS_JCXZ && ins->id <= X86_INS_JRCXZ))
				return PT_JCC;

			return PT_UNSUPPORTED;
		}
	}

	bool PatchLastInstruction(
		BYTE* code,                   // IN/OUT
		size_t codeSize,
		UINT64 newBaseAddr,           // absolute address where code[] lives
		UINT64 ff25StubAddr          // absolute address of ff25 stub
	) { 

		// ----- decode -----
		csh handle;
		cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

		cs_insn* ins = cs_malloc(handle);
		BYTE* p = code;
		size_t remaining = codeSize;
		UINT64 rip = newBaseAddr;

		size_t lastOffset = 0;
		cs_insn* last = nullptr;
		// rip will be updated by cs_disasm_iter to point to the address AFTER the
		// decoded instruction. After the loop finishes, rip holds the next RIP
		// (i.e. end address of the last instruction). Use that and the last
		// instruction size to compute the start address deterministically. If
		// something unexpected happens, fall back to ins->address.
		while (cs_disasm_iter(handle, (const uint8_t**)&p, &remaining, &rip, ins)) {
			last = ins;
		}
		if (!last) {
			cs_free(ins, 1);
			cs_close(&handle);
			return false;
		}

		PatchType type = ClassifyInstruction(last);
		if (type == PT_UNSUPPORTED) {
			cs_free(ins, 1);
			cs_close(&handle);
			return false;
		}

		// compute instruction boundaries defensively
		size_t insLen = last->size;
		UINT64 inferred_nextRip = rip; // rip after loop should be next IP
		UINT64 insAddr = 0;
		if (inferred_nextRip >= insLen) {
			insAddr = inferred_nextRip - (UINT64)insLen;
		}
		else {
			insAddr = last->address; // fallback
		}
		lastOffset = (size_t)(insAddr - newBaseAddr);
		BYTE* patchPtr = code + lastOffset;
		// We'll compute the rel32 relative to the size of the instruction
		// actually written (branchSize), not the original instruction length.
		// branchSize will be determined per-patch below.

		// ---------- PATCH LOGIC ----------
		if (type == PT_CALL) {
			// CALL rel32 → E8 rel32
			BYTE buf[5];
			buf[0] = 0xE8;
			int branchSize = 5;
			if ((INT64)ff25StubAddr - (INT64)(insAddr + (UINT64)branchSize) < (INT64)INT_MIN ||
				(INT64)ff25StubAddr - (INT64)(insAddr + (UINT64)branchSize) > (INT64)INT_MAX) {
				cs_free(ins, 1);
				cs_close(&handle);
				return false; // rel32 can't encode
			}
			*(INT32*)&buf[1] = (INT32)((INT64)ff25StubAddr - (INT64)(insAddr + (UINT64)branchSize));

			if (branchSize > (int)insLen) return false;
			memcpy(patchPtr, buf, branchSize);
			for (size_t i = branchSize; i < insLen; i++) patchPtr[i] = 0x90;
		}
		else if (type == PT_JMP) {
			// JMP rel32 → E9 rel32
			BYTE buf[5];
			buf[0] = 0xE9;
			int branchSize = 5;
			if ((INT64)ff25StubAddr - (INT64)(insAddr + (UINT64)branchSize) < (INT64)INT_MIN ||
				(INT64)ff25StubAddr - (INT64)(insAddr + (UINT64)branchSize) > (INT64)INT_MAX) {
				cs_free(ins, 1);
				cs_close(&handle);
				return false; // rel32 can't encode
			}
			*(INT32*)&buf[1] = (INT32)((INT64)ff25StubAddr - (INT64)(insAddr + (UINT64)branchSize));

			if (branchSize > (int)insLen) return false;
			memcpy(patchPtr, buf, branchSize);
			for (size_t i = branchSize; i < insLen; i++) patchPtr[i] = 0x90;
		}
		else if (type == PT_JCC) {

			// two forms:
			//   7x ib        (short Jcc, 2 bytes)
			//   0F 8x id     (long Jcc, 6 bytes)

			if (insLen == 2 && (patchPtr[0] & 0xF0) == 0x70) {
				// short Jcc → CANNOT grow to 6 bytes → fail
				return false;
			}

			if (insLen >= 6 && patchPtr[0] == 0x0F) {
				// long conditional
				BYTE jcc = patchPtr[1]; // keep condition opcode
				BYTE buf[6];
				buf[0] = 0x0F;
				buf[1] = jcc;
				int branchSize = 6;
				if ((INT64)ff25StubAddr - (INT64)(insAddr + (UINT64)branchSize) < (INT64)INT_MIN ||
					(INT64)ff25StubAddr - (INT64)(insAddr + (UINT64)branchSize) > (INT64)INT_MAX) {
					cs_free(ins, 1);
					cs_close(&handle);
					return false; // rel32 can't encode
				}
				*(INT32*)&buf[2] = (INT32)((INT64)ff25StubAddr - (INT64)(insAddr + (UINT64)branchSize));

				if (branchSize > (int)insLen) return false;
				memcpy(patchPtr, buf, branchSize);
				for (size_t i = branchSize; i < insLen; i++) patchPtr[i] = 0x90;
			}
			else {
				return false;
			}
		}

		cs_free(ins, 1);
		cs_close(&handle);
		return true;
	}

	bool PatchLastInstruction_x86(
		BYTE* code,                   // IN/OUT
		size_t codeSize,
		UINT32 newBaseAddr,           // absolute address where code[] lives
		UINT32 ff25StubAddr           // absolute address of ff25 stub
	) {

		// ----- decode -----
		csh handle;
		cs_open(CS_ARCH_X86, CS_MODE_32, &handle);
		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

		cs_insn* ins = cs_malloc(handle);
		BYTE* p = code;
		size_t remaining = codeSize;
		UINT32 eip = newBaseAddr;

		size_t lastOffset = 0;
		cs_insn* last = nullptr;
		while (cs_disasm_iter(handle, (const uint8_t**)&p, &remaining, (DWORD64*)&eip, ins)) {
			last = ins;
		}
		if (!last) {
			cs_free(ins, 1);
			cs_close(&handle);
			return false;
		}

		PatchType type = ClassifyInstruction(last);
		if (type == PT_UNSUPPORTED) {
			cs_free(ins, 1);
			cs_close(&handle);
			return false;
		}

		size_t insLen = last->size;
		UINT32 inferred_nextEip = eip;
		UINT32 insAddr = 0;
		if (inferred_nextEip >= insLen) {
			insAddr = inferred_nextEip - (UINT32)insLen;
		}
		else {
			insAddr = (UINT32)last->address;
		}
		lastOffset = (size_t)(insAddr - newBaseAddr);
		BYTE* patchPtr = code + lastOffset;

		if (type == PT_CALL) {
			BYTE buf[5];
			buf[0] = 0xE8;
			int branchSize = 5;
			int64_t rel = (int64_t)(int32_t)ff25StubAddr - (int64_t)(insAddr + (UINT32)branchSize);
			if (rel < INT32_MIN || rel > INT32_MAX) {
				cs_free(ins, 1);
				cs_close(&handle);
				return false;
			}
			*(INT32*)&buf[1] = (INT32)rel;

			if (branchSize > (int)insLen) return false;
			memcpy(patchPtr, buf, branchSize);
			for (size_t i = branchSize; i < insLen; i++) patchPtr[i] = 0x90;
		}
		else if (type == PT_JMP) {
			BYTE buf[5];
			buf[0] = 0xE9;
			int branchSize = 5;
			int64_t rel = (int64_t)(int32_t)ff25StubAddr - (int64_t)(insAddr + (UINT32)branchSize);
			if (rel < INT32_MIN || rel > INT32_MAX) {
				cs_free(ins, 1);
				cs_close(&handle);
				return false;
			}
			*(INT32*)&buf[1] = (INT32)rel;

			if (branchSize > (int)insLen) return false;
			memcpy(patchPtr, buf, branchSize);
			for (size_t i = branchSize; i < insLen; i++) patchPtr[i] = 0x90;
		}
		else if (type == PT_JCC) {
			if (insLen == 2 && (patchPtr[0] & 0xF0) == 0x70) {
				// short Jcc -> cannot grow
				cs_free(ins, 1);
				cs_close(&handle);
				return false;
			}

			if (insLen >= 6 && patchPtr[0] == 0x0F) {
				BYTE jcc = patchPtr[1];
				BYTE buf[6];
				buf[0] = 0x0F;
				buf[1] = jcc;
				int branchSize = 6;
				int64_t rel = (int64_t)(int32_t)ff25StubAddr - (int64_t)(insAddr + (UINT32)branchSize);
				if (rel < INT32_MIN || rel > INT32_MAX) {
					cs_free(ins, 1);
					cs_close(&handle);
					return false;
				}
				*(INT32*)&buf[2] = (INT32)rel;

				if (branchSize > (int)insLen) return false;
				memcpy(patchPtr, buf, branchSize);
				for (size_t i = branchSize; i < insLen; i++) patchPtr[i] = 0x90;
			}
			else {
				cs_free(ins, 1);
				cs_close(&handle);
				return false;
			}
		}

		cs_free(ins, 1);
		cs_close(&handle);
		return true;
	}

	uint64_t ResolveRipRelativeTarget(
		HANDLE hProcess,
		uint64_t hookSiteBase,
		const std::vector<uint8_t>& codeBytes
	) {
		csh handle;
		cs_insn* insn = nullptr;

		if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
			return 0;

		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

		size_t count = cs_disasm(
			handle,
			codeBytes.data(),
			codeBytes.size(),
			hookSiteBase,
			0,
			&insn
		);

		if (count == 0) {
			cs_close(&handle);
			return 0;
		}

		const cs_insn& last = insn[count - 1];
		const cs_detail* detail = last.detail;

		uint64_t target = 0;

		// --------------------------------------
		// Case 1: Direct CALL / JMP / Jcc (imm)
		// --------------------------------------
		if (detail->x86.op_count == 1 &&
			detail->x86.operands[0].type == X86_OP_IMM)
		{
			target = detail->x86.operands[0].imm;
			cs_free(insn, count);
			cs_close(&handle);
			return target;
		}

		// ---------------------------------------------------
		// Case 2: RIP-relative INDIRECT CALL/JMP (FF 15 / FF 25)
		// This uses:   [RIP + displacement]
		// ---------------------------------------------------
		if (detail->x86.op_count == 1 &&
			detail->x86.operands[0].type == X86_OP_MEM)
		{
			const cs_x86_op& op = detail->x86.operands[0];

			// Only allow RIP-relative memory operands:
			if (op.mem.base == X86_REG_RIP)
			{
				uint64_t rip_after = last.address + last.size;
				uint64_t effective_addr = rip_after + op.mem.disp;

				// Read 8-byte pointer from remote process
				uint64_t resolved = 0;
				SIZE_T bytesRead = 0;

				if (ReadProcessMemory(
					hProcess,
					(LPCVOID)effective_addr,
					&resolved,
					sizeof(resolved),
					&bytesRead)
					&& bytesRead == sizeof(resolved))
				{
					target = resolved;  // final resolved jump/call destination
				}
			}
		}

		cs_free(insn, count);
		cs_close(&handle);

		return target;
	}

	uint64_t ResolveKernelRipRelativeTarget(
		IHookServices* services,
		uint64_t hookSiteBase,
		const std::vector<uint8_t>& codeBytes
	) {
		csh handle;
		cs_insn* insn = nullptr;

		if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
			return 0;

		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

		size_t count = cs_disasm(
			handle,
			codeBytes.data(),
			codeBytes.size(),
			hookSiteBase,
			0,
			&insn
		);

		if (count == 0) {
			cs_close(&handle);
			return 0;
		}

		const cs_insn& last = insn[count - 1];
		const cs_detail* detail = last.detail;

		uint64_t target = 0;

		// --------------------------------------
		// Case 1: Direct CALL / JMP / Jcc (imm)
		// --------------------------------------
		if (detail->x86.op_count == 1 &&
			detail->x86.operands[0].type == X86_OP_IMM)
		{
			target = detail->x86.operands[0].imm;
			cs_free(insn, count);
			cs_close(&handle);
			return target;
		}

		// ---------------------------------------------------
		// Case 2: RIP-relative INDIRECT CALL/JMP (FF 15 / FF 25)
		// This uses:   [RIP + displacement]
		// ---------------------------------------------------
		if (detail->x86.op_count == 1 &&
			detail->x86.operands[0].type == X86_OP_MEM)
		{
			const cs_x86_op& op = detail->x86.operands[0];

			// Only allow RIP-relative memory operands:
			if (op.mem.base == X86_REG_RIP)
			{
				uint64_t rip_after = last.address + last.size;
				uint64_t effective_addr = rip_after + op.mem.disp;

				// Read 8-byte pointer from remote process
				uint64_t resolved = 0;
				SIZE_T bytesRead = 0;

				if (services->ReadPrimitive(
					 
					(LPVOID)effective_addr,
					&resolved,
					sizeof(resolved))
					&& (resolved!=0))
				{
					target = resolved;  // final resolved jump/call destination
				}
			}
		}

		cs_free(insn, count);
		cs_close(&handle);

		return target;
	}
	DecideResult  DetermineCodeEdge_x64(const uint8_t* buffer, size_t bufSize, uint64_t codeAddr, size_t minNeeded) {
		DecideResult res;
		res.type = DecideResultType::FAIL_CS_ERROR;
		res.preserveLen = 0;

		if (!buffer || bufSize == 0) {
			res.type = DecideResultType::FAIL_INSUFFICIENT_BYTES;
			res.message = "buffer empty";
			return res;
		}

		csh handle = 0;
		if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
			res.message = "cs_open failed";
			return res;
		}

		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
		cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
#if defined(CS_OPT_MNEMONIC)
		cs_option(handle, CS_OPT_MNEMONIC, CS_OPT_MNEMONIC_DEFAULT);
#endif

		cs_insn* insn = nullptr;
		// disassemble entire buffer (capstone returns array of cs_insn)
		size_t count = cs_disasm(handle, buffer, bufSize, codeAddr, 0, &insn);
		if (count == 0) {
			res.type = DecideResultType::FAIL_CS_ERROR;
			res.message = "capstone failed to disassemble buffer (count==0)";
			cs_close(&handle);
			return res;
		}

		size_t total = 0;
		bool terminalEncountered = false;

		for (size_t i = 0; i < count; ++i) {
			cs_insn* cur = &insn[i];
			size_t sz = cur->size;

			bool isCall = InsnIsCall(handle, cur);
			bool isJump = InsnIsJump(handle, cur);
			bool isRet = InsnIsRet(handle, cur);

			// classify conditional vs unconditional jump:
			bool isUncondJmp = false;
			if (isJump) {
				// unconditional JMP has specific id X86_INS_JMP
				if (cur->id == X86_INS_JMP) isUncondJmp = true;
			}

			// control-flow categories we treat as 'terminal' (CALL, conditional jmp, unconditional jmp, RET)
			bool isControlFlow = isCall || isJump || isRet;

			// If this is a control-flow instruction:
			if (isControlFlow) {
				// If it's the first instruction at the patch site:
				if (total == 0) {
					// If single insn is large enough, accept it and stop
					if (sz >= minNeeded) {
						res.type = DecideResultType::SUCCESS;
						res.preserveLen = sz;
						res.message = "first instruction is control-flow but big enough to cover minNeeded";
						cs_free(insn, count);
						cs_close(&handle);
						return res;
					}
					else {
						// cannot safely apply 6-byte patch here — instruction too short
						res.type = DecideResultType::FAIL_SHORT_CF_FIRST;
						res.preserveLen = 0;
						res.message = "first instruction is CALL/Jcc/JMP/RET and is shorter than minNeeded; use 12-byte fallback";
						cs_free(insn, count);
						cs_close(&handle);
						return res;
					}
				}
				else {
					// not first: include it as the last instruction, then stop scanning
					total += sz;
					terminalEncountered = true;
					if (total >= minNeeded) {
						res.type = DecideResultType::SUCCESS;
						res.preserveLen = total;
						res.message = "control-flow encountered; included as terminal instruction; preserveLen >= minNeeded";
					}
					else {
						res.type = DecideResultType::FAIL_SHORT_CF_MID;
						res.preserveLen = total;
						res.message = "control-flow encountered before reaching minNeeded; preserveLen < minNeeded; fallback needed";
					}
					cs_free(insn, count);
					cs_close(&handle);
					return res;
				}
			}
			else {
				// normal instruction
				total += sz;
				if (total >= minNeeded) {
					res.type = DecideResultType::SUCCESS;
					res.preserveLen = total;
					res.message = "enough bytes accumulated; no unsafe control-flow seen";
					cs_free(insn, count);
					cs_close(&handle);
					return res;
				}
				// else continue
			}
		}

		// if we exited the loop without decision, we've exhausted the disassembled buffer
		// either we didn't reach minNeeded or we found nothing terminal but buffer too small
		if (total >= minNeeded) {
			res.type = DecideResultType::SUCCESS;
			res.preserveLen = total;
			res.message = "disassembly ended but total >= minNeeded";
		}
		else {
			res.type = DecideResultType::FAIL_INSUFFICIENT_BYTES;
			res.preserveLen = total;
			res.message = "ran out of buffer before reaching minNeeded; read more bytes";
		}

		cs_free(insn, count);
		cs_close(&handle);
		return res;

	}

	DecideResult  DetermineCodeEdge_x86(const uint8_t* buffer, size_t bufSize, uint32_t codeAddr, size_t minNeeded) {
		DecideResult res;
		res.type = DecideResultType::FAIL_CS_ERROR;
		res.preserveLen = 0;

		if (!buffer || bufSize == 0) {
			res.type = DecideResultType::FAIL_INSUFFICIENT_BYTES;
			res.message = "buffer empty";
			return res;
		}

		csh handle = 0;
		if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK) {
			res.message = "cs_open failed";
			return res;
		}

		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
		cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
#if defined(CS_OPT_MNEMONIC)
		cs_option(handle, CS_OPT_MNEMONIC, CS_OPT_MNEMONIC_DEFAULT);
#endif

		cs_insn* insn = nullptr;
		size_t count = cs_disasm(handle, buffer, bufSize, codeAddr, 0, &insn);
		if (count == 0) {
			res.type = DecideResultType::FAIL_CS_ERROR;
			res.message = "capstone failed to disassemble buffer (count==0)";
			cs_close(&handle);
			return res;
		}

		size_t total = 0;
		for (size_t i = 0; i < count; ++i) {
			cs_insn* cur = &insn[i];
			size_t sz = cur->size;

			bool isCall = InsnIsCall(handle, cur);
			bool isJump = InsnIsJump(handle, cur);
			bool isRet = InsnIsRet(handle, cur);

			// classify conditional vs unconditional jump:
			bool isUncondJmp = false;
			if (isJump) {
				if (cur->id == X86_INS_JMP) isUncondJmp = true;
			}

			bool isControlFlow = isCall || isJump || isRet;

			if (isControlFlow) {
				if (total == 0) {
					if (sz >= minNeeded) {
						res.type = DecideResultType::SUCCESS;
						res.preserveLen = sz;
						res.message = "first instruction is control-flow but big enough to cover minNeeded";
						cs_free(insn, count);
						cs_close(&handle);
						return res;
					}
					else {
						res.type = DecideResultType::FAIL_SHORT_CF_FIRST;
						res.preserveLen = 0;
						res.message = "first instruction is CALL/Jcc/JMP/RET and is shorter than minNeeded; use fallback";
						cs_free(insn, count);
						cs_close(&handle);
						return res;
					}
				}
				else {
					total += sz;
					if (total >= minNeeded) {
						res.type = DecideResultType::SUCCESS;
						res.preserveLen = total;
						res.message = "control-flow encountered; included as terminal instruction; preserveLen >= minNeeded";
					}
					else {
						res.type = DecideResultType::FAIL_SHORT_CF_MID;
						res.preserveLen = total;
						res.message = "control-flow encountered before reaching minNeeded; preserveLen < minNeeded; fallback needed";
					}
					cs_free(insn, count);
					cs_close(&handle);
					return res;
				}
			}
			else {
				total += sz;
				if (total >= minNeeded) {
					res.type = DecideResultType::SUCCESS;
					res.preserveLen = total;
					res.message = "enough bytes accumulated; no unsafe control-flow seen";
					cs_free(insn, count);
					cs_close(&handle);
					return res;
				}
			}
		}

		if (total >= minNeeded) {
			res.type = DecideResultType::SUCCESS;
			res.preserveLen = total;
			res.message = "disassembly ended but total >= minNeeded";
		}
		else {
			res.type = DecideResultType::FAIL_INSUFFICIENT_BYTES;
			res.preserveLen = total;
			res.message = "ran out of buffer before reaching minNeeded; read more bytes";
		}

		cs_free(insn, count);
		cs_close(&handle);
		return res;

	}

uint64_t ResolveLeaInstruction(HANDLE hProcess, uint64_t startAddr, size_t maxRead) {
	if (!hProcess || startAddr == 0) return 0;

	size_t readLen = 64; // initial read
	const char matchStr[] = "0x%p\n";
	const size_t matchLen = sizeof(matchStr) - 1; // without null

	// We'll progressively read larger buffers up to maxRead
	while (readLen <= maxRead) {
		std::vector<uint8_t> buf(readLen);
		SIZE_T bytesRead = 0;
		if (!ReadProcessMemory(hProcess, (LPCVOID)startAddr, buf.data(), readLen, &bytesRead) || bytesRead == 0) {
			return 0;
		}

		csh handle = 0;
		if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) return 0;
		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

		cs_insn* insn = nullptr;
		size_t count = cs_disasm(handle, buf.data(), bytesRead, startAddr, 0, &insn);
		if (count > 0) {
			for (size_t i = 0; i < count; ++i) {
				const cs_insn& cur = insn[i];
				if (cur.id != X86_INS_LEA) continue;
				const cs_detail* detail = cur.detail;
				if (!detail) continue;
				if (detail->x86.op_count < 2) continue;
				const cs_x86_op& op2 = detail->x86.operands[1];
				if (op2.type != X86_OP_MEM) continue;

				// Resolve effective address if possible
				uint64_t eff = 0;
				if (op2.mem.base == X86_REG_RIP) {
					int64_t disp = op2.mem.disp;
					uint64_t rip_after = cur.address + cur.size;
					eff = (uint64_t)((int64_t)rip_after + disp);
				}
				else if (op2.mem.base == X86_REG_INVALID) {
					// absolute addressing -> disp holds absolute address
					eff = (uint64_t)op2.mem.disp;
				}
				else {
					// cannot resolve register-based memory operand here
					continue;
				}

				if (eff == 0) continue;

				// Read remote memory at eff to check for the ASCII pattern
				char probe[64] = {0};
				SIZE_T pr = 0;
				if (ReadProcessMemory(hProcess, (LPCVOID)eff, probe, matchLen, &pr) && pr == matchLen) {
					if (memcmp(probe, matchStr, matchLen) == 0) {
						uint64_t foundAddr = cur.address;
						cs_free(insn, count);
						cs_close(&handle);
						return foundAddr;
					}
				}
			}
			cs_free(insn, count);
		}
		cs_close(&handle);

		// grow readLen conservatively
		if (readLen < 256) readLen += 16; else readLen += 256;
		if (readLen > maxRead) readLen = maxRead;
	}

	return 0;
}

uint32_t ResolveRipRelativeTarget_x86(
	HANDLE hProcess,
	uint32_t hookSiteBase,
	const std::vector<uint8_t>& codeBytes
)
{
	csh handle;
	cs_insn* insn = nullptr;

	if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
		return 0;

	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	size_t count = cs_disasm(
		handle,
		codeBytes.data(),
		codeBytes.size(),
		hookSiteBase,
		0,
		&insn
	);

	if (count == 0) {
		cs_close(&handle);
		return 0;
	}

	const cs_insn& last = insn[count - 1];
	const cs_detail* detail = last.detail;

	uint32_t target = 0;

	// Case 1: direct immediate operand (CALL rel32 / JMP rel32 / Jcc imm)
	if (detail->x86.op_count == 1 && detail->x86.operands[0].type == X86_OP_IMM) {
		target = (uint32_t)detail->x86.operands[0].imm;
		cs_free(insn, count);
		cs_close(&handle);
		return target;
	}

	// Case 2: memory operand - could be [eip + disp] encoded as mem with base == X86_REG_INVALID
	if (detail->x86.op_count == 1 && detail->x86.operands[0].type == X86_OP_MEM) {
		const cs_x86_op& op = detail->x86.operands[0];

		// Heuristic: Capstone for 32-bit EIP-relative memory often presents the operand
		// with base == X86_REG_INVALID and mem.disp being the absolute address, or
		// sometimes with mem.base == X86_REG_EIP. Handle both.
		uint32_t effective = 0;
		if (op.mem.base == X86_REG_EIP) {
			uint32_t eip_after = (uint32_t)(last.address + last.size);
			effective = (uint32_t)((int32_t)eip_after + (int32_t)op.mem.disp);
		}
		else if (op.mem.base == X86_REG_INVALID) {
			// In some capstone builds disp may already be absolute
			effective = (uint32_t)op.mem.disp;
		}

		if (effective != 0) {
			// Read a pointer-sized value (4 bytes) from remote process
			uint32_t resolved = 0;
			SIZE_T bytesRead = 0;
			if (ReadProcessMemory(hProcess, (LPCVOID)effective, &resolved, sizeof(resolved), &bytesRead) && bytesRead == sizeof(resolved)) {
				target = resolved;
			}
		}
	}

	cs_free(insn, count);
	cs_close(&handle);
	return target;
}
}