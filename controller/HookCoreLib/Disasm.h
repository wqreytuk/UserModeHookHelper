#pragma once
#include <string>
#include <vector>
#include <Windows.h>
#include "HookCore.h"
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
	DecideResult DetermineCodeEdge_x86(const uint8_t* buffer, size_t bufSize, uint32_t codeAddr, size_t minNeeded = 6);
	uint64_t ResolveRipRelativeTarget(
		HANDLE hProcess,
		uint64_t hookSiteBase,
		const std::vector<uint8_t>& codeBytes
	);
	uint64_t ResolveKernelRipRelativeTarget(
		IHookServices* services,
		uint64_t hookSiteBase,
		const std::vector<uint8_t>& codeBytes
	);
	uint32_t ResolveRipRelativeTarget_x86(
		HANDLE hProcess,
		uint32_t hookSiteBase,
		const std::vector<uint8_t>& codeBytes
	);

	// Search forward from startAddr in the remote process for the first LEA
	// instruction and return the resolved effective address when the LEA uses
	// RIP-relative addressing (e.g., lea rax, [rip+disp]). Returns 0 on failure
	// or if the LEA cannot be resolved to an absolute address.
	uint64_t ResolveLeaInstruction(HANDLE hProcess, uint64_t startAddr, size_t maxRead = 8192);
	bool PatchLastInstruction(
		BYTE* code,                   // IN/OUT
		size_t codeSize,
		UINT64 newBaseAddr,           // absolute address where code[] lives
		UINT64 ff25StubAddr          // absolute address of ff25 stub
	);

	// x86 (32-bit) variant of PatchLastInstruction
	bool PatchLastInstruction_x86(
		BYTE* code,                   // IN/OUT
		size_t codeSize,
		UINT32 newBaseAddr,           // absolute address where code[] lives
		UINT32 ff25StubAddr           // absolute address of ff25 stub
	);
}
	 