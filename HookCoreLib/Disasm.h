#pragma once
#include <string>
#include <vector>
#include <Windows.h>
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
	};

	DecideResult DetermineCodeEdge_x64(const uint8_t* buffer, size_t bufSize, uint64_t codeAddr, size_t minNeeded = 6);
	uint64_t ResolveRipRelativeTarget(
		HANDLE hProcess,
		uint64_t hookSiteBase,
		const std::vector<uint8_t>& codeBytes
	);

	bool PatchLastInstruction(
		BYTE* code,                   // IN/OUT
		size_t codeSize,
		UINT64 newBaseAddr,           // absolute address where code[] lives
		UINT64 ff25StubAddr          // absolute address of ff25 stub
	);
}
	 