#include "HookCore.h"
// Implementation-private Windows requirements (ok to include here; not exposed to MFC users before afx headers).
#include <windows.h>
#include <tlhelp32.h>
#include <algorithm>
#include "../drivers/UserModeHookHelper/UKShared.h" // for X64_DLL / X86_DLL names
#include "../Shared/LogMacros.h" 
#include "Trampoline.h"
#include "../../Shared/SharedMacroDef.h"
#include <psapi.h>"
#include "../ProcessHackerLib/phlib_expose.h"

namespace HookCore {
#define E9_JMP_INSTRUCTION_SIZE 0x5
#define E9_JMP_INSTRUCTION_OPCODE_SIZE 0x1
#define E9_JMP_INSTRUCTION_OPRAND_SIZE 0x4
	static const intptr_t MAX_DELTA = 0x7FFFFFFF; // ?GB
	static IHookServices* g_hookServices = nullptr;
	IHookServices* GetHookServices() {
		return g_hookServices;
	}
	void SetHookServices(IHookServices* services) {
		g_hookServices = services;
	}
	static std::wstring Hex64(ULONGLONG v) {
		wchar_t buf[32];
		_snwprintf_s(buf, _countof(buf), _TRUNCATE, L"%llX", v);
		return buf;
	}
// Align helpers
	static SIZE_T AlignDown(SIZE_T addr, SIZE_T gran) {
		return (addr / gran) * gran;
	}
	static SIZE_T AlignUp(SIZE_T addr, SIZE_T gran) {
		return ((addr + gran - 1) / gran) * gran;
	}
	bool EnumerateModules(DWORD pid, std::vector<ModuleInfo>& out) {
		out.clear();
		PPH_MODULE_LIST_NODE head = NULL;
		LONG status = (LONG)(ULONG_PTR)PHLIB::PhBuildModuleList((void*)(ULONG_PTR)pid, (void*)(ULONG_PTR)&head);
		if (status != 0) {
			LOG_CORE(g_hookServices, L"failed to call PHLIB::PhBuildModuleList, Status=0x%x\n", status);
			MessageBoxW(NULL,L"failed to call PHLIB::PhBuildModuleList", L"HookDlg", MB_ICONERROR);
			return false;
		}
		for (PPH_MODULE_LIST_NODE n = head; n != NULL; n = n->Next) {
			// Extract module name from path
			std::wstring name = n->Path ? std::wstring(n->Path) : L"";
			size_t pos = name.find_last_of(L"\\");
			std::wstring justName = (pos != std::wstring::npos) ? name.substr(pos + 1) : name;
			

			ModuleInfo mi;
			mi.name = justName;
			mi.path = name;
			mi.base = (ULONGLONG)n->Base;
			mi.size = (ULONGLONG)n->Size;
			out.push_back(std::move(mi));
		}
		// Free list
		while (head) { auto* next = head->Next; if (head->Path) free(head->Path); free(head); head = next; }
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
	bool ApplyHook(DWORD pid, ULONGLONG address, IHookServices* services,
		DWORD64 hook_code_addr, int hook_id, DWORD *out_ori_asm_code_len,
		PVOID* out_trampoline_pit, PVOID* out_ori_asm_code_addr) {
		PVOID trampoline_dll_base = 0;
		std::wstring trampFullPath;
		SIZE_T bytesout = 0;
		PVOID module_base = 0;
		bool is64 = false;
		HANDLE hProc = NULL;

		if (!services) {
			MessageBoxW(NULL, L"Fatal Error! services is NULL!", L"Hook", MB_OK | MB_ICONINFORMATION);
			return false;
		}
		if (!services->IsProcess64(pid, is64)) {
			LOG_CORE(services, L"failed to call IsProcess64 target Pid=%u\n", pid);
			return false;
		}

		// try open process with suitable access
		// we should request dirver to get a high access process handle
		if (!services->GetHighAccessProcHandle(pid, &hProc)) {
			LOG_CORE(services, L"failed to call GetHighAccessProcHandle target Pid=%u\n", pid);
			return false;
		}

		if (!hProc) {
			if (services)
				services->LogCore(L"failed to open target process, error: 0x%x\n", GetLastError());
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
			WCHAR temp_tramp_name[MAX_PATH] = { 0 };
			memcpy(temp_tramp_name, trampName.c_str(), trampName.size() * sizeof(WCHAR));
			auto s = services->GetCurrentDirFilePath(temp_tramp_name);

			trampFullPath = s;
			if (services) 
				services->LogCore(L"ApplyHook: requesting trampoline inject %s (path=%s).\n",
					trampName.c_str(), trampFullPath.c_str());
			bool signaled = services ? services->InjectTrampoline(pid, trampFullPath.c_str()) : false;
			if (services) services->LogCore(L"ApplyHook: InjectTrampoline result: %s.\n", signaled ? L"success" : L"failure");
			if (signaled) {
				// Poll up to 5 seconds (50 * 100ms) for trampoline module presence.
				const int maxIterations = 50; bool loaded = false;
				for (int iter = 0; iter < maxIterations && !loaded; ++iter) {
					//  GetModuleBase(bool is64, HANDLE hProc, wchar_t* target_module, DWORD64* base) = 0;
					services->GetModuleBase(is64, pid, trampName.c_str(), (DWORD64*)&trampoline_dll_base);

					if (trampoline_dll_base != NULL) {
						loaded = true;
						break;
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
		// probe target process memory to locate a suitable near locate for allocating trampoline code addr
		PVOID trampoline_pit = AllocNearRemote(hProc, address, sizeof(void*));
		if (!trampoline_pit) {
			if (services)
				LOG_CORE(services, L"failed to find a suitable memory region for trampoline code address\n");
			return false;
		}

		// Resolve export by hook-specific name (trampoline_stage_1_num_##)
		char stage_1_func_name[64] = { 0 };
		sprintf_s(stage_1_func_name, "trampoline_stage_1_num_%03d", hook_id);
		DWORD stage_1_func_offset = 0;
		if (!services->CheckExportFromFile(trampFullPath.c_str(), stage_1_func_name, &stage_1_func_offset)) {
			LOG_CORE(services, L"required export function not found in dll Path=%s\n", trampFullPath.c_str());
			return false;
		}

		PVOID tramp_stage_1_addr = (PVOID)(stage_1_func_offset + (DWORD64)trampoline_dll_base);

		// there is a pivot in export table, we need to get that jmp instruction oprand to calculate real function address
		// this situation only happends when we're using DEBUG build of trampoline.dll, in relase version, what we get is
		// the real address of treampoline export function
#ifdef _DEBUG
		DWORD e9_jmp_instruction_oprand = 0;
		if (!::ReadProcessMemory(hProc, (LPVOID)((DWORD64)tramp_stage_1_addr + E9_JMP_INSTRUCTION_OPCODE_SIZE),
			(LPVOID)&e9_jmp_instruction_oprand, E9_JMP_INSTRUCTION_OPRAND_SIZE, &bytesout)) {
			if (services)
				LOG_CORE(services, L"failed to call ReadProcessMemory to write trampoline code addr 0x%p to trampoline pit 0x%p, error: 0x%x\n",
					tramp_stage_1_addr, trampoline_pit, GetLastError());
			return false;
		}
		tramp_stage_1_addr = (PVOID)((DWORD64)tramp_stage_1_addr + E9_JMP_INSTRUCTION_SIZE + e9_jmp_instruction_oprand);
#endif
		// Resolve stage 2 export using the same hook-specific naming
		char stage_2_func_name[64] = { 0 };
		sprintf_s(stage_2_func_name, "trampoline_stage_2_num_%03d", hook_id);
		DWORD stage_2_func_offset = 0;
		if (!services->CheckExportFromFile(trampFullPath.c_str(), stage_2_func_name, &stage_2_func_offset)) {
			LOG_CORE(services, L"required export function not found in dll Path=%s\n", trampFullPath.c_str());
			return false;
		}
		PVOID tramp_stage_2_addr = (PVOID)(stage_2_func_offset + (DWORD64)trampoline_dll_base);

#ifdef _DEBUG
		e9_jmp_instruction_oprand = 0;
		if (!::ReadProcessMemory(hProc, (LPVOID)((DWORD64)tramp_stage_2_addr + E9_JMP_INSTRUCTION_OPCODE_SIZE), (LPVOID)&e9_jmp_instruction_oprand, E9_JMP_INSTRUCTION_OPRAND_SIZE, &bytesout)) {
			if (services)
				LOG_CORE(services, L"failed to call WriteProcessMemory to write trampoline code addr 0x%p to trampoline pit 0x%p, error: 0x%x\n",
					tramp_stage_1_addr, trampoline_pit, GetLastError());
			return false;
		}
		tramp_stage_2_addr = (PVOID)((DWORD64)tramp_stage_2_addr + E9_JMP_INSTRUCTION_SIZE + e9_jmp_instruction_oprand);
#endif

		stage_1_func_offset = (DWORD)((DWORD64)tramp_stage_1_addr - (DWORD64)trampoline_dll_base);
		stage_2_func_offset = (DWORD)((DWORD64)tramp_stage_2_addr - (DWORD64)trampoline_dll_base);
		DWORD original_asm_code_len = 0;
		*out_ori_asm_code_addr = (PVOID)(stage_2_func_offset + (DWORD64)trampoline_dll_base + OFFSET_FOR_ORIGINAL_ASM_CODE_SAVE);
		if (is64) {
			if (!ConstructTrampoline_x64(services, hProc, (PVOID)address, module_base, trampoline_dll_base,
				stage_1_func_offset, stage_2_func_offset, hook_code_addr, &original_asm_code_len)) {
				if (services)
					LOG_CORE(services, L"ConstructTrampoline_x64 failed\n");
				return false;
			}
		}
		else {
			if (!ConstructTrampoline_x86(services, hProc, (PVOID)address, module_base, trampoline_dll_base,
				stage_1_func_offset, stage_2_func_offset, hook_code_addr, &original_asm_code_len)) {
				if (services)
					LOG_CORE(services, L"ConstructTrampoline_x64 failed\n");
				return false;
			}
		}
		if (!InstallHook(services, hProc, (PVOID)address, trampoline_pit,
			(PVOID)(stage_1_func_offset + (DWORD64)trampoline_dll_base + 0x3 + (is64 ? 0x8 : 0x4)),is64)) {
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
	bool RemoveHook(DWORD pid, ULONGLONG address, IHookServices* services, DWORD hook_id, DWORD ori_asm_code_len, PVOID trampoline_pit) {
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

		const wchar_t* dllName = X64_DLL;
		bool dllLoaded = false;
		services->IsModuleLoaded(pid, dllName, dllLoaded);
		
		if (!dllLoaded){
			services->LogCore(L"RemoveHook: master DLL not found in target process (expected %s or %s); aborting trampoline load.\n", X64_DLL, X86_DLL);
			return false;
		}
		else {
			// Build full path to trampoline DLL based on directory of master DLL already loaded
			// in the target process (the two DLLs live side-by-side).
			
			bool is64 = false;
			services->IsProcess64(pid, is64);
			std::wstring trampName = is64 ? TRAMP_X64_DLL : TRAMP_X86_DLL;
			WCHAR tramp_name_wide[MAX_PATH] = { 0 };
			memcpy(tramp_name_wide, trampName.c_str(), sizeof(WCHAR)*trampName.size());
			trampFullPath = services->GetCurrentDirFilePath(tramp_name_wide);
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
			services->LogCore(L"RemoveHook: trampoline DLL %s %s\n", trampName.c_str(), loaded ? L"detected" : L"NOT detected within 5s");
			if (!loaded) {
				LOG_CORE(services, L"RemoveHook: can not continue because trampoline DLL is not laoded");
				return false;
			}
		}

		// try open process with suitable access
		HANDLE hProc = NULL;
		if (!services->GetHighAccessProcHandle(pid, &hProc)) {
			LOG_CORE(services, L"failed to call GetHighAccessProcHandle target Pid=%u\n", pid);
			return false;
		}
		// deallocate trampoline allocted when ApplyHook
		if (!VirtualFreeEx(hProc, trampoline_pit, 0, MEM_RELEASE)) {
			LOG_CORE(services, L"failed to call VirtualFreeEx to free trampoline pit, error: 0x%x\n", GetLastError());
			// not a critical error, so we won't return here
			 //return false;
		}
		// we can't use LoadLibraryW here, because the dll maybe win32, we should use file based function to check
		// if required export function exist
		char stage_1_func_name[64] = { 0 };
		sprintf_s(stage_1_func_name, "trampoline_stage_1_num_%03d", hook_id);
		DWORD stage_1_func_offset = 0;
		if (!services->CheckExportFromFile(trampFullPath.c_str(), stage_1_func_name, &stage_1_func_offset)) {
			LOG_CORE(services, L"required export function not found in dll Path=%s\n", trampFullPath.c_str());
			CloseHandle(hProc);
			return false;
		}

		PVOID tramp_stage_1_addr = (PVOID)(stage_1_func_offset + (DWORD64)trampoline_dll_base);

		// there is a pivot in export table, we need to get that jmp instruction oprand to calculate real function address
		// this situation only happends when we're using DEBUG build of trampoline.dll, in relase version, what we get is
		// the real address of treampoline export function
#ifdef _DEBUG
		DWORD e9_jmp_instruction_oprand = 0;
		if (!::ReadProcessMemory(hProc, (LPVOID)((DWORD64)tramp_stage_1_addr + E9_JMP_INSTRUCTION_OPCODE_SIZE),
			(LPVOID)&e9_jmp_instruction_oprand, E9_JMP_INSTRUCTION_OPRAND_SIZE, &bytesout)) {
			if (services)
				LOG_CORE(services, L"failed to call ReadProcessMemory to write trampoline code addr 0x%p to trampoline pit 0x%p, error: 0x%x\n",
					tramp_stage_1_addr, trampoline_pit, GetLastError());
			CloseHandle(hProc);
			return false;
		}
		tramp_stage_1_addr = (PVOID)((DWORD64)tramp_stage_1_addr + E9_JMP_INSTRUCTION_SIZE + e9_jmp_instruction_oprand);
#endif
		// Resolve stage 2 export using the same hook-specific naming
		char stage_2_func_name[64] = { 0 };
		sprintf_s(stage_2_func_name, "trampoline_stage_2_num_%03d", hook_id);
		DWORD stage_2_func_offset = 0;
		if (!services->CheckExportFromFile(trampFullPath.c_str(), stage_2_func_name, &stage_2_func_offset)) {
			LOG_CORE(services, L"required export function not found in dll Path=%s\n", trampFullPath.c_str());
			CloseHandle(hProc);
			return false;
		}
		PVOID tramp_stage_2_addr = (PVOID)(stage_2_func_offset + (DWORD64)trampoline_dll_base);

#ifdef _DEBUG
		e9_jmp_instruction_oprand = 0;
		if (!::ReadProcessMemory(hProc, (LPVOID)((DWORD64)tramp_stage_2_addr + E9_JMP_INSTRUCTION_OPCODE_SIZE), (LPVOID)&e9_jmp_instruction_oprand, E9_JMP_INSTRUCTION_OPRAND_SIZE, &bytesout)) {
			if (services)
				LOG_CORE(services, L"failed to call WriteProcessMemory to write trampoline code addr 0x%p to trampoline pit 0x%p, error: 0x%x\n",
					tramp_stage_1_addr, trampoline_pit, GetLastError());
			CloseHandle(hProc);
			return false;
		}
		tramp_stage_2_addr = (PVOID)((DWORD64)tramp_stage_2_addr + E9_JMP_INSTRUCTION_SIZE + e9_jmp_instruction_oprand);
#endif

		stage_1_func_offset = (DWORD)((DWORD64)tramp_stage_1_addr - (DWORD64)trampoline_dll_base);
		stage_2_func_offset = (DWORD)((DWORD64)tramp_stage_2_addr - (DWORD64)trampoline_dll_base);

		// finally remove hook
		if (!RemoveHookInternal(services, hProc, (PVOID)address, trampoline_dll_base, stage_2_func_offset, ori_asm_code_len)) {
			LOG_CORE(services, L"failed to call RemoveHookInternal\n");
			CloseHandle(hProc);
			return false;
		}
		CloseHandle(hProc);
		return true;
	}


	// to disable hook, I need the address where the original asm code is saved
	// so I can read it out and write back to hook address
	bool DisableHook(DWORD pid, ULONGLONG hook_address, IHookServices* services,
		PVOID ori_asm_code_addr, DWORD ori_asm_code_len) {
		if (!services) {
			MessageBoxW(NULL, L"Fatal Error! services is NULL!", L"Hook", MB_OK | MB_ICONERROR);
			return false;
		}

		// try open process with suitable access
		HANDLE hProc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
		if (!hProc) {
			LOG_CORE(services, L"failed to open target process, error: 0x%x\n", GetLastError());
			return false;
		}
		DWORD old_protect = 0;

		// read out
		if (!::VirtualProtectEx(hProc, (LPVOID)(ori_asm_code_addr), ori_asm_code_len, PAGE_EXECUTE_READWRITE, &old_protect)) {
			if (services)
				LOG_CORE(services, L"DisableHook line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
			return false;
		}
		UCHAR* ori_asm_code = (UCHAR*)malloc(ori_asm_code_len);
		if (!::ReadProcessMemory(hProc, (LPVOID)(ori_asm_code_addr), (void*)(ori_asm_code), ori_asm_code_len, NULL)) {
			LOG_CORE(services, L"DisableHook line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
			return false;
		}
		if (!::VirtualProtectEx(hProc, (LPVOID)(ori_asm_code_addr), ori_asm_code_len, old_protect, &old_protect)) {
			LOG_CORE(services, L"DisableHook line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
			return false;
		}

		// write back
		if (!::VirtualProtectEx(hProc, (LPVOID)(hook_address), ori_asm_code_len, PAGE_EXECUTE_READWRITE, &old_protect)) {
			if (services)
				LOG_CORE(services, L"DisableHook line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
			return false;
		}
		if (!::WriteProcessMemory(hProc, (LPVOID)(hook_address), (void*)(ori_asm_code), ori_asm_code_len, NULL)) {
			LOG_CORE(services, L"DisableHook line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
			return false;
		}
		if (!::VirtualProtectEx(hProc, (LPVOID)(hook_address), ori_asm_code_len, old_protect, &old_protect)) {
			LOG_CORE(services, L"DisableHook line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
			return false;
		}

		return true;
	}
	bool EnableHook(DWORD pid, ULONGLONG hook_address, IHookServices* services, PVOID trampoline_pit) {
		if (!services) {
			MessageBoxW(NULL, L"Fatal Error! services is NULL!", L"Hook", MB_OK | MB_ICONERROR);
			return false;
		}

		// try open process with suitable access
		HANDLE hProc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
		if (!hProc) {
			LOG_CORE(services, L"failed to open target process, error: 0x%x\n", GetLastError());
			return false;
		}
		DWORD old_protect = 0;

		// read out
		if (!::VirtualProtectEx(hProc, (LPVOID)(hook_address), 6, PAGE_EXECUTE_READWRITE, &old_protect)) {
			if (services)
				LOG_CORE(services, L"EnableHook line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
			return false;
		}
		UCHAR hook_code[6] = { 0xff,0x25,0,0,0,0 };
		*(DWORD*)(hook_code + 2) = (DWORD64)trampoline_pit - hook_address - 6;
		if (!::WriteProcessMemory(hProc, (LPVOID)(hook_address), (void*)(hook_code), 6, NULL)) {
			LOG_CORE(services, L"EnableHook line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
			return false;
		}
		if (!::VirtualProtectEx(hProc, (LPVOID)(hook_address), 6, old_protect, &old_protect)) {
			LOG_CORE(services, L"EnableHook line number: %d, error code: 0x%x\n", __LINE__, GetLastError());
			return false;
		}
		return true;
	}
	// Decide minimal safe preserve length for FF25 (requires minNeeded bytes).
	// buffer: bytes buffer (must contain at least enough bytes), bufSize its size,
	// codeAddr: base address used for disassembly (affects resolved immediates) 
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

