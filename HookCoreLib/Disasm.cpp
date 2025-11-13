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
}