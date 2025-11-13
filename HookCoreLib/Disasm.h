#pragma once
#include <string>
#include <vector>
namespace HookCore {
	enum class DecideResultType {
		SUCCESS,                // preserveLen valid
		FAIL_SHORT_CF_FIRST,    // first instruction is CALL/Jcc/JMP/RET and size < minNeeded
		FAIL_SHORT_CF_MID,      // encountered CF insn after bytes < minNeeded
		FAIL_INSUFFICIENT_BYTES,// ran out of bytes while trying
		FAIL_CS_ERROR           // capstone failure
	};

	struct DecideResult {
		DecideResultType type;
		size_t preserveLen;     // valid if type == SUCCESS
		std::string message;    // human-readable reason
		uint64_t rel_ins_dest;	// relative instruction destination
	};

	DecideResult DetermineCodeEdge_x64(const uint8_t* buffer, size_t bufSize, uint64_t codeAddr, size_t minNeeded = 6);
}
	 