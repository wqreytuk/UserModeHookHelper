#include "HookCore.h"
// Implementation-private Windows requirements (ok to include here; not exposed to MFC users before afx headers).
#include <windows.h>
#include <tlhelp32.h>
#include <algorithm>
#include "../UserModeHookHelper/UKShared.h" // for X64_DLL / X86_DLL names

namespace HookCore {
    bool EnumerateModules(DWORD pid, std::vector<ModuleInfo>& out) {
        out.clear();
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snap == INVALID_HANDLE_VALUE) return false;
        MODULEENTRY32 me{ sizeof(me) }; int i=0;
        if (Module32First(snap, &me)) {
            do {
                ModuleInfo mi; mi.name = me.szModule; mi.path = me.szExePath; mi.base = (ULONGLONG)me.modBaseAddr; mi.size = (ULONGLONG)me.modBaseSize; out.push_back(std::move(mi));
            } while (Module32Next(snap, &me));
        }
        CloseHandle(snap);
        return true;
    }
    std::wstring FindOwningModule(DWORD pid, ULONGLONG address) {
        std::vector<ModuleInfo> mods; if(!EnumerateModules(pid, mods)) return L"";
        for (auto &m : mods) {
            if (address >= m.base && address < m.base + m.size) return m.name;
        }
        return L"";
    }
    // Minimal proof-of-capability hook: validate the address belongs to a loaded module in the
    // target process, then attempt a read + write-back of the first byte at that address.
    // This establishes required permissions & memory accessibility without altering code.
    // Returns true on success, false otherwise. Real hook logic (trampoline/IAT/etc.) will
    // replace this in future iterations.
    bool ApplyHook(DWORD pid, ULONGLONG address, IHookServices* services) {
        if (address == 0) { if (services) services->LogCore(L"ApplyHook: address is 0 (invalid).\n"); return false; }
        std::wstring owning = FindOwningModule(pid, address);
        if (owning.empty()) { if (services) services->LogCore(L"ApplyHook: address 0x%llX not within any module for pid %u.\n", address, pid); return false; }
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
                if (services) services->LogCore(L"ApplyHook: refusing to hook master DLL %s (address 0x%llX).\n", owning.c_str(), address);
                return false;
            }
        }
        if (services) services->LogCore(L"ApplyHook: address 0x%llX belongs to module %s (pid %u).\n", address, owning.c_str(), pid);

		// here we begin the real bussiness, we'll need a template dll project which will contain hundreds of export function
		// for us to write hook trampoline
		// first we'll send signal to our master dll so he can load that template dll for us, then we check the module list again to
		// ensure that tempalte dll is loaded into target process

        HANDLE hProcess = ::OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hProcess) { if (services) services->LogCore(L"ApplyHook: OpenProcess failed (err=%lu).\n", GetLastError()); return false; }

        BYTE original{}; SIZE_T bytesRead = 0;
        if (!::ReadProcessMemory(hProcess, (LPCVOID)address, &original, sizeof(original), &bytesRead) || bytesRead != sizeof(original)) {
            if (services) services->LogCore(L"ApplyHook: ReadProcessMemory failed at 0x%llX (err=%lu).\n", address, GetLastError());
            ::CloseHandle(hProcess);
            return false;
        }
        if (services) services->LogCore(L"ApplyHook: ReadProcessMemory succeeded (original byte=0x%02X).\n", original);
        SIZE_T bytesWritten = 0;
        if (!::WriteProcessMemory(hProcess, (LPVOID)address, &original, sizeof(original), &bytesWritten) || bytesWritten != sizeof(original)) {
            if (services) services->LogCore(L"ApplyHook: WriteProcessMemory failed at 0x%llX (err=%lu).\n", address, GetLastError());
            ::CloseHandle(hProcess);
            return false;
        }
        if (services) services->LogCore(L"ApplyHook: WriteProcessMemory succeeded (no-op test). Hook complete.\n");
        ::CloseHandle(hProcess);
        return true;
    }
}
