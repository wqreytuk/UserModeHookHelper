#include "HookCore.h"
// Implementation-private Windows requirements (ok to include here; not exposed to MFC users before afx headers).
#include <windows.h>
#include <tlhelp32.h>
#include <algorithm>
#include "../UserModeHookHelper/UKShared.h" // for X64_DLL / X86_DLL names
#include "../Shared/LogMacros.h" 
#include "Trampoline.h"

namespace HookCore {
#define E9_JMP_INSTRUCTION_SIZE 0x5
#define E9_JMP_INSTRUCTION_OPCODE_SIZE 0x1
#define E9_JMP_INSTRUCTION_OPRAND_SIZE 0x4
	static const intptr_t MAX_DELTA = 0x7FFFFFFF; // ?GB

// Align helpers
	static SIZE_T AlignDown(SIZE_T addr, SIZE_T gran) {
		return (addr / gran) * gran;
	}
	static SIZE_T AlignUp(SIZE_T addr, SIZE_T gran) {
		return ((addr + gran - 1) / gran) * gran;
	}
	bool EnumerateModules(DWORD pid, std::vector<ModuleInfo>& out) {
		out.clear();
		HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
		if (snap == INVALID_HANDLE_VALUE) return false;
		MODULEENTRY32 me{ sizeof(me) }; int i = 0;
		if (Module32First(snap, &me)) {
			do {
				ModuleInfo mi; mi.name = me.szModule; mi.path = me.szExePath; mi.base = (ULONGLONG)me.modBaseAddr; mi.size = (ULONGLONG)me.modBaseSize; out.push_back(std::move(mi));
			} while (Module32Next(snap, &me));
		}
		CloseHandle(snap);
		return true;
	}
	std::wstring FindOwningModule(DWORD pid, ULONGLONG address, PVOID* moduleBase) {
		std::vector<ModuleInfo> mods; if (!EnumerateModules(pid, mods)) return L"";
		for (auto &m : mods) {
			if (address >= m.base && address < m.base + m.size) {
				*moduleBase = (PVOID)m.base;
				return m.name;
			}
		}
		return L"";
	}
	// Minimal proof-of-capability hook: validate the address belongs to a loaded module in the
	// target process, then attempt a read + write-back of the first byte at that address.
	// This establishes required permissions & memory accessibility without altering code.
	// Returns true on success, false otherwise. Real hook logic (trampoline/IAT/etc.) will
	// replace this in future iterations.
	bool ApplyHook(DWORD pid, ULONGLONG address, IHookServices* services, DWORD64 hook_code_addr, int hook_id, DWORD *out_ori_asm_code_len,PVOID* out_trampoline_pit) {
		PVOID trampoline_dll_base = 0;
		std::wstring trampFullPath;
		SIZE_T bytesout = 0;
		PVOID module_base = 0;


		if (!services) {
			MessageBoxW(NULL, L"Fatal Error! services is NULL!", L"Hook", MB_OK | MB_ICONINFORMATION);
			return false;
		}
		if (address == 0) { if (services) services->LogCore(L"ApplyHook: address is 0 (invalid).\n"); return false; }
		std::wstring owning = FindOwningModule(pid, address, &module_base);
		if (owning.empty()) {
			if (services)
				services->LogCore(L"ApplyHook: address 0x%llX not within any module for pid %u.\n", address, pid);
			return false;
		}
		if (!module_base) {
			if (services)
				LOG_CORE(services, L"weird, found owner module %s but failed to get module base\n", owning.c_str());
			return false;
		}
		// Guard: forbid hooking our own master injection DLL (either x64 or x86 build name).
		// Use canonical names from UKShared.h rather than hard-coded prefix logic.
		{
			auto equalsIgnoreCase = [](const std::wstring& a, const wchar_t* b) -> bool {
				if (!b) return false; size_t blen = wcslen(b); if (a.size() != blen) return false;
				for (size_t i = 0; i < blen; ++i) {
					wchar_t ca = towlower(a[i]); wchar_t cb = towlower(b[i]);
					if (ca != cb) return false;
				}
				return true;
			};
			if (equalsIgnoreCase(owning, X64_DLL) || equalsIgnoreCase(owning, X86_DLL)) {
				if (services)
					services->LogCore(L"ApplyHook: refusing to hook master DLL %s (address 0x%llX).\n", owning.c_str(), address);
				return false;
			}
		}
		if (services) services->LogCore(L"ApplyHook: address 0x%llX belongs to module %s (pid %u).\n", address, owning.c_str(), pid);

		// here we begin the real bussiness, we'll need a template dll project which will contain hundreds of export function
		// for us to write hook trampoline
		// first we'll send signal to our master dll so he can load that template dll for us, then we check the module list again to
		// ensure that tempalte dll is loaded into target process

		// --- Trampoline load signaling & verification ---
		// Locate the already-injected master DLL (umhh.dll.*) in the target process so we can
		// derive the architecture and choose the matching trampoline DLL name. Then request
		// the master to load the trampoline via our file-based IPC (IPC_SendInject). Finally
		// poll for up to 5 seconds to confirm the trampoline DLL appears in the module list.
		std::wstring masterNameFound; // canonical name (architecture-specific)
		std::wstring masterPathFound; // full path to master DLL inside target process
		{
			std::vector<ModuleInfo> mods; EnumerateModules(pid, mods);
			auto equalsIgnoreCase = [](const std::wstring& a, const wchar_t* b) -> bool {
				if (!b) return false; size_t blen = wcslen(b); if (a.size() != blen) return false;
				for (size_t i = 0; i < blen; ++i) { if (towlower(a[i]) != towlower(b[i])) return false; }
				return true;
			};
			for (auto &m : mods) {
				if (equalsIgnoreCase(m.name, X64_DLL)) { masterNameFound = X64_DLL; masterPathFound = m.path; break; }
				if (equalsIgnoreCase(m.name, X86_DLL)) { masterNameFound = X86_DLL; masterPathFound = m.path; break; }
			}
		}
		if (masterNameFound.empty()) {
			if (services)
				services->LogCore(L"ApplyHook: master DLL not found in target process (expected %s or %s); aborting trampoline load.\n", X64_DLL, X86_DLL);
			return false;
		}
		else {
			// Build full path to trampoline DLL based on directory of master DLL already loaded
			// in the target process (the two DLLs live side-by-side).
			std::wstring baseDir;
			if (!masterPathFound.empty()) {
				baseDir = masterPathFound;
				size_t pos = baseDir.find_last_of(L"\\/");
				if (pos != std::wstring::npos) baseDir.erase(pos);
			}
			std::wstring trampName = (masterNameFound == X64_DLL) ? TRAMP_X64_DLL : TRAMP_X86_DLL;
			trampFullPath = baseDir + L"\\" + trampName;
			if (services) services->LogCore(L"ApplyHook: requesting trampoline inject %s (path=%s).\n", trampName.c_str(), trampFullPath.c_str());
			bool signaled = services ? services->InjectTrampoline(pid, trampFullPath.c_str()) : false;
			if (services) services->LogCore(L"ApplyHook: InjectTrampoline result: %s.\n", signaled ? L"success" : L"failure");
			if (signaled) {
				// Poll up to 5 seconds (50 * 100ms) for trampoline module presence.
				const int maxIterations = 50; bool loaded = false;
				for (int iter = 0; iter < maxIterations && !loaded; ++iter) {
					std::vector<ModuleInfo> mods; EnumerateModules(pid, mods);
					for (auto &m : mods) {
						if (_wcsicmp(m.name.c_str(), trampName.c_str()) == 0) {
							trampoline_dll_base = (PVOID)m.base;
							loaded = true;
							break;
						}
					}
					if (!loaded) Sleep(100);
				}
				if (services) services->LogCore(L"ApplyHook: trampoline DLL %s %s after signaling.\n", trampName.c_str(), loaded ? L"detected" : L"NOT detected within 5s");
				if (!loaded) {
					LOG_CORE(services, L"ApplyHook: can not continue because trampoline DLL is not laoded");
					return false;
				}
			}
		}

		// try open process with suitable access
		HANDLE hProc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
		if (!hProc) {
			if (services)
				services->LogCore(L"failed to open target process, error: 0x%x\n", GetLastError());
			return false;
		}
		// probe target process memory to locate a suitable near locate for allocating trampoline code addr
		PVOID trampoline_pit = AllocNearRemote(hProc, address, sizeof(void*));
		if (!trampoline_pit) {
			if (services)
				LOG_CORE(services, L"failed to find a suitable memory region for trampoline code address\n");
			return false;
		}


		HMODULE tramp_dll_handle = LoadLibraryW(trampFullPath.c_str());
		if (!tramp_dll_handle) {
			if (services)
				LOG_CORE(services, L"failed to call LoadLibraryW with %s, error: 0x%x\n", trampFullPath.c_str(), GetLastError());
			return false;
		}
		// Resolve export by hook-specific name (trampoline_stage_1_num_##)
		char stage_1_func_name[64] = {0};
		sprintf_s(stage_1_func_name, "trampoline_stage_1_num_%03d", hook_id);
		PVOID tramp_stage_1_addr = GetProcAddress(tramp_dll_handle, stage_1_func_name);
		if (!tramp_stage_1_addr) {
			if (services)
				LOG_CORE(services, L"failed to call GetProcAddress to get %S function adress, error: 0x%x\n", stage_1_func_name, GetLastError());
			return false;
		}

		tramp_stage_1_addr = (PVOID)((DWORD64)tramp_stage_1_addr - (DWORD64)tramp_dll_handle + (DWORD64)trampoline_dll_base);

		// there is a pivot in export table, we need to get that jmp instruction oprand to calculate real function address
		DWORD e9_jmp_instruction_oprand = 0;
		if (!::ReadProcessMemory(hProc, (LPVOID)((DWORD64)tramp_stage_1_addr + E9_JMP_INSTRUCTION_OPCODE_SIZE), (LPVOID)&e9_jmp_instruction_oprand, E9_JMP_INSTRUCTION_OPRAND_SIZE, &bytesout)) {
			if (services)
				LOG_CORE(services, L"failed to call WriteProcessMemory to write trampoline code addr 0x%p to trampoline pit 0x%p, error: 0x%x\n",
					tramp_stage_1_addr, trampoline_pit, GetLastError());
			return false;
		}
		tramp_stage_1_addr = (PVOID)((DWORD64)tramp_stage_1_addr + E9_JMP_INSTRUCTION_SIZE + e9_jmp_instruction_oprand);

		// Resolve stage 2 export using the same hook-specific naming
		char stage_2_func_name[64] = {0};
		sprintf_s(stage_2_func_name, "trampoline_stage_2_num_%03d", hook_id);
		PVOID tramp_stage_2_addr = GetProcAddress(tramp_dll_handle, stage_2_func_name);
		if (!tramp_stage_2_addr) {
			if (services)
				LOG_CORE(services, L"failed to call GetProcAddress to get %S function adress, error: 0x%x\n", stage_2_func_name, GetLastError());
			return false;
		}

		tramp_stage_2_addr = (PVOID)((DWORD64)tramp_stage_2_addr - (DWORD64)tramp_dll_handle + (DWORD64)trampoline_dll_base);

		// there is a pivot in export table, we need to get that jmp instruction oprand to calculate real function address
		e9_jmp_instruction_oprand = 0;
		if (!::ReadProcessMemory(hProc, (LPVOID)((DWORD64)tramp_stage_2_addr + E9_JMP_INSTRUCTION_OPCODE_SIZE), (LPVOID)&e9_jmp_instruction_oprand, E9_JMP_INSTRUCTION_OPRAND_SIZE, &bytesout)) {
			if (services)
				LOG_CORE(services, L"failed to call WriteProcessMemory to write trampoline code addr 0x%p to trampoline pit 0x%p, error: 0x%x\n",
					tramp_stage_1_addr, trampoline_pit, GetLastError());
			return false;
		}
		tramp_stage_2_addr = (PVOID)((DWORD64)tramp_stage_2_addr + E9_JMP_INSTRUCTION_SIZE + e9_jmp_instruction_oprand);
		
		if (!FreeLibrary(tramp_dll_handle)) {
			LOG_CORE(services, L"failed to free trampoline dll from UMController\n");
		}

		DWORD stage_1_func_offset = (DWORD)((DWORD64)tramp_stage_1_addr - (DWORD64)trampoline_dll_base);
		DWORD stage_2_func_offset = (DWORD)((DWORD64)tramp_stage_2_addr - (DWORD64)trampoline_dll_base);
		DWORD original_asm_code_len = 0;
		if (!ConstructTrampoline_x64(services, hProc, (PVOID)address, module_base, trampoline_dll_base, 
			stage_1_func_offset, stage_2_func_offset, hook_code_addr, &original_asm_code_len)) {
			if (services)
				LOG_CORE(services, L"ConstructTrampoline_x64 failed\n");
			return false;
		}
		if (!InstallHook(services, hProc, (PVOID)address, trampoline_pit,
			(PVOID)(stage_1_func_offset + (DWORD64)trampoline_dll_base + 0x3+0x8))) {
			if (services)
				LOG_CORE(services, L"InstallHook failed\n");
			// recover original asm code
			if (!RemoveHookInternal(services, hProc, (PVOID)address, trampoline_dll_base, stage_2_func_offset, original_asm_code_len)) {
				LOG_CORE(services, L"remove hook failed\n");
			}
			return false;
		}
		*out_trampoline_pit = trampoline_pit;
		*out_ori_asm_code_len = original_asm_code_len;
		return true;
	}
	bool RemoveHook(DWORD pid, ULONGLONG address, IHookServices* services, DWORD hook_id, DWORD ori_asm_code_len,PVOID trampoline_pit) { 
		PVOID trampoline_dll_base = 0;
		std::wstring trampFullPath;
		SIZE_T bytesout = 0;
		PVOID module_base = 0;


		if (!services) {
			MessageBoxW(NULL, L"Fatal Error! services is NULL!", L"Hook", MB_OK | MB_ICONERROR);
			return false;
		}
		if (address == 0) {
			services->LogCore(L"RemoveHook: address is 0 (invalid).\n");
			return false;
		}
		std::wstring owning = FindOwningModule(pid, address, &module_base);
		if (owning.empty()) {
			 services->LogCore(L"RemoveHook: address 0x%llX not within any module for pid %u.\n", address, pid);
			return false;
		}
		if (!module_base) {
			LOG_CORE(services, L"weird, found owner module %s but failed to get module base\n", owning.c_str());
			return false;
		}
		

		if (services) services->LogCore(L"RemoveHook: address 0x%llX belongs to module %s (pid %u).\n", address, owning.c_str(), pid);

		
		std::wstring masterNameFound; // canonical name (architecture-specific)
		std::wstring masterPathFound; // full path to master DLL inside target process
		{
			std::vector<ModuleInfo> mods; EnumerateModules(pid, mods);
			auto equalsIgnoreCase = [](const std::wstring& a, const wchar_t* b) -> bool {
				if (!b) return false; size_t blen = wcslen(b); if (a.size() != blen) return false;
				for (size_t i = 0; i < blen; ++i) { if (towlower(a[i]) != towlower(b[i])) return false; }
				return true;
			};
			for (auto &m : mods) {
				if (equalsIgnoreCase(m.name, X64_DLL)) { masterNameFound = X64_DLL; masterPathFound = m.path; break; }
				if (equalsIgnoreCase(m.name, X86_DLL)) { masterNameFound = X86_DLL; masterPathFound = m.path; break; }
			}
		}
		if (masterNameFound.empty()) {
			services->LogCore(L"RemoveHook: master DLL not found in target process (expected %s or %s); aborting trampoline load.\n", X64_DLL, X86_DLL);
			return false;
		}
		else {
			// Build full path to trampoline DLL based on directory of master DLL already loaded
			// in the target process (the two DLLs live side-by-side).
			std::wstring baseDir;
			if (!masterPathFound.empty()) {
				baseDir = masterPathFound;
				size_t pos = baseDir.find_last_of(L"\\/");
				if (pos != std::wstring::npos) baseDir.erase(pos);
			}
			std::wstring trampName = (masterNameFound == X64_DLL) ? TRAMP_X64_DLL : TRAMP_X86_DLL;
			trampFullPath = baseDir + L"\\" + trampName;

			// Poll up to 5 seconds (50 * 100ms) for trampoline module presence.
			const int maxIterations = 50; bool loaded = false;
			for (int iter = 0; iter < maxIterations && !loaded; ++iter) {
				std::vector<ModuleInfo> mods; EnumerateModules(pid, mods);
				for (auto &m : mods) {
					if (_wcsicmp(m.name.c_str(), trampName.c_str()) == 0) {
						trampoline_dll_base = (PVOID)m.base;
						loaded = true;
						break;
					}
				}
				if (!loaded) Sleep(100);
			}
			services->LogCore(L"ApplyHook: trampoline DLL %s %s after signaling.\n", trampName.c_str(), loaded ? L"detected" : L"NOT detected within 5s");
			if (!loaded) {
				LOG_CORE(services, L"RemoveHook: can not continue because trampoline DLL is not laoded");
				return false;
			}
		}

		// try open process with suitable access
		HANDLE hProc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
		if (!hProc) {
			if (services)
				services->LogCore(L"failed to open target process, error: 0x%x\n", GetLastError());
			return false;
		} 
		// deallocate trampoline allocted when ApplyHook
		if (!VirtualFreeEx(hProc, trampoline_pit, 0, MEM_RELEASE)) {
			LOG_CORE(services, L"failed to call VirtualFreeEx to free trampoline pit, error: 0x%x\n", GetLastError());
			return false;
		}
		HMODULE tramp_dll_handle = LoadLibraryW(trampFullPath.c_str());
		if (!tramp_dll_handle) {
			if (services)
				LOG_CORE(services, L"failed to call LoadLibraryW with %s, error: 0x%x\n", trampFullPath.c_str(), GetLastError());
			return false;
		}
		char stage_1_func_name[] = "trampoline_stage_1_num_001";
		sprintf_s(stage_1_func_name, "trampoline_stage_1_num_%03d", hook_id);
		PVOID tramp_stage_1_addr = GetProcAddress(tramp_dll_handle, stage_1_func_name);
		if (!tramp_stage_1_addr) {
			if (services)
				LOG_CORE(services, L"failed to call GetProcAddress to get trampoline_stage_1_num_001 function adress, error: 0x%x\n", GetLastError());
			return false;
		}

		tramp_stage_1_addr = (PVOID)((DWORD64)tramp_stage_1_addr - (DWORD64)tramp_dll_handle + (DWORD64)trampoline_dll_base);

		// there is a pivot in export table, we need to get that jmp instruction oprand to calculate real function address
		DWORD e9_jmp_instruction_oprand = 0;
		if (!::ReadProcessMemory(hProc, (LPVOID)((DWORD64)tramp_stage_1_addr + E9_JMP_INSTRUCTION_OPCODE_SIZE), (LPVOID)&e9_jmp_instruction_oprand, E9_JMP_INSTRUCTION_OPRAND_SIZE, &bytesout)) {
			if (services)
				LOG_CORE(services, L"failed to call ReadProcessMemory to get export function real address, error: 0x%x\n", GetLastError());
			return false;
		}
		tramp_stage_1_addr = (PVOID)((DWORD64)tramp_stage_1_addr + E9_JMP_INSTRUCTION_SIZE + e9_jmp_instruction_oprand);

		char stage_2_func_name[] = "trampoline_stage_2_num_001";
		sprintf_s(stage_2_func_name, "trampoline_stage_2_num_%03d", hook_id);
		PVOID tramp_stage_2_addr = GetProcAddress(tramp_dll_handle, stage_2_func_name);
		if (!tramp_stage_2_addr) {
			if (services)
				LOG_CORE(services, L"failed to call GetProcAddress to get trampoline_stage_2_num_001 function adress, error: 0x%x\n", GetLastError());
			return false;
		}

		tramp_stage_2_addr = (PVOID)((DWORD64)tramp_stage_2_addr - (DWORD64)tramp_dll_handle + (DWORD64)trampoline_dll_base);

		// there is a pivot in export table, we need to get that jmp instruction oprand to calculate real function address
		e9_jmp_instruction_oprand = 0;
		if (!::ReadProcessMemory(hProc, (LPVOID)((DWORD64)tramp_stage_2_addr + E9_JMP_INSTRUCTION_OPCODE_SIZE), (LPVOID)&e9_jmp_instruction_oprand, E9_JMP_INSTRUCTION_OPRAND_SIZE, &bytesout)) {
			if (services)
				LOG_CORE(services, L"failed to call ReadProcessMemory to get export function real address, error: 0x%x\n", GetLastError());
			return false;
		}
		tramp_stage_2_addr = (PVOID)((DWORD64)tramp_stage_2_addr + E9_JMP_INSTRUCTION_SIZE + e9_jmp_instruction_oprand);

		if (!FreeLibrary(tramp_dll_handle)) {
			LOG_CORE(services, L"failed to free trampoline dll from UMController\n");
		}

		DWORD stage_1_func_offset = (DWORD)((DWORD64)tramp_stage_1_addr - (DWORD64)trampoline_dll_base);
		DWORD stage_2_func_offset = (DWORD)((DWORD64)tramp_stage_2_addr - (DWORD64)trampoline_dll_base);

		// finally remove hook
		if (!RemoveHookInternal(services, hProc, (PVOID)address, trampoline_dll_base, stage_2_func_offset, ori_asm_code_len)) {
			LOG_CORE(services, L"failed to call RemoveHookInternal\n");
			return false;
		}
		return true;
	}
	// Decide minimal safe preserve length for FF25 (requires minNeeded bytes).
	// buffer: bytes buffer (must contain at least enough bytes), bufSize its size,
	// codeAddr: base address used for disassembly (affects resolved immediates).

	LPVOID AllocNearRemote(HANDLE hProcess, ULONGLONG target, SIZE_T size) {
		if (!hProcess || !target || size == 0) return nullptr;

		// Get allocation granularity locally (same on system)
		SYSTEM_INFO si;
		GetSystemInfo(&si);
		SIZE_T gran = si.dwAllocationGranularity ? si.dwAllocationGranularity : 0x10000;

		uintptr_t base = (uintptr_t)target;

		// compute user-space bounds (conservative)
		const uintptr_t USER_MIN = 0x10000ULL;
		const uintptr_t USER_MAX = 0x00007FFFFFFEFFFFULL;
		uintptr_t lowLimit = (base > (uintptr_t)MAX_DELTA) ? (base - (uintptr_t)MAX_DELTA) : USER_MIN;
		if (lowLimit < USER_MIN) lowLimit = USER_MIN;
		uintptr_t highLimit = base + (uintptr_t)MAX_DELTA;
		if (highLimit > USER_MAX) highLimit = USER_MAX;

		// quick bail if impossible
		if (size > (highLimit - lowLimit)) return nullptr;

		// determine max steps (in gran units) to scan
		intptr_t maxSteps = (intptr_t)((highLimit - lowLimit) / gran) + 1;

		// scan outward from target: step 0, +gran, -gran, +2*gran, -2*gran, ...
		for (intptr_t step = 0; step <= maxSteps; ++step) {
			intptr_t offsets[2] = { (intptr_t)step, -(intptr_t)step };
			for (int side = 0; side < 2; ++side) {
				if (step == 0 && side == 1) continue; // avoid duplicate
				intptr_t off = offsets[side];
				intptr_t probe = (intptr_t)base + off * (intptr_t)gran;
				if ((uintptr_t)probe < lowLimit || (uintptr_t)probe > highLimit) continue;

				SIZE_T probeAddr = (SIZE_T)AlignDown((SIZE_T)probe, gran);

				// Query remote region
				MEMORY_BASIC_INFORMATION mbi;
				SIZE_T q = VirtualQueryEx(hProcess, (LPCVOID)probeAddr, &mbi, sizeof(mbi));
				if (q == 0) continue;

				if (mbi.State == MEM_FREE) {
					uintptr_t regionBase = (uintptr_t)mbi.BaseAddress;
					SIZE_T regionSize = mbi.RegionSize;

					// choose a candidate inside this free region near probeAddr
					uintptr_t allocCandidate = probeAddr;
					if (allocCandidate < regionBase) allocCandidate = regionBase;
					allocCandidate = AlignUp(allocCandidate, gran);

					if (allocCandidate + size > regionBase + regionSize) {
						// try at region base
						allocCandidate = AlignUp(regionBase, gran);
						if (allocCandidate + size > regionBase + regionSize) continue; // not enough room
					}

					// sanity bounds check
					if (allocCandidate < lowLimit || (allocCandidate + size) > highLimit) continue;

					// attempt VirtualAllocEx at allocCandidate
					LPVOID p = VirtualAllocEx(hProcess, (LPVOID)allocCandidate, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
					if (p) return p; // success
					// else: race or failure, continue scanning
				}

				// otherwise not free: skip ?further probing will handle other regions
			}
		}

		// fallback: try a normal VirtualAllocEx(NULL, ...) which may allocate far (not useful for FF25),
		// but could be acceptable if you plan to use 12-byte mov/jmp fallback.
		LPVOID fallback = VirtualAllocEx(hProcess, NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		return fallback;
	}
}

