#pragma once
#include <string>
#include <vector>
#include <tuple>

namespace RegistryStore {
    // Read all persisted hook NT paths into out vector. Returns true on success
    // (including the case of an empty key). Uses HKLM and REG_PERSIST_SUBKEY.
    bool ReadHookPaths(std::vector<std::wstring>& outPaths);

    // Replace the persisted HookPaths value with the provided list. Returns
    // true on success.
    bool WriteHookPaths(const std::vector<std::wstring>& paths);

    // Convenience helpers: add or remove a single NT path to the persisted list.
    bool AddPath(const std::wstring& ntPath);
    bool RemovePath(const std::wstring& ntPath);

    // NT path resolution cache (for performance at UI startup)
    // Stored in same registry subkey to keep consistency with kernel hook list persistence.
    // Value name: NtPathCache (REG_MULTI_SZ). Each entry formatted as:
    //    <16-hex-hash>=<NT_PATH>
    // Where hash is Helper::GetNtPathHash over the NT path bytes.
    // Composite startup cache (PID + creation FILETIME) -> NT path.
    // REG_MULTI_SZ value name: NtProcCache. Each line formatted as:
    //    PID:HIGH:LOW=NT_PATH
    // Where HIGH/LOW are hex 8-digit FILETIME parts. Example:
    //    12A4:01D9F2AB:7B3C1E40=\Device\HarddiskVolume3\Windows\System32\notepad.exe
    bool ReadCompositeProcCache(std::vector<std::tuple<DWORD, DWORD, DWORD, std::wstring>>& outEntries);
    bool WriteCompositeProcCache(const std::vector<std::tuple<DWORD, DWORD, DWORD, std::wstring>>& entries);
    // Persisted per-process hook entries. Value name: ProcHookList (REG_MULTI_SZ)
    // Each line formatted as:
    //   PID:HIGH:LOW:HOOKID:ORI_LEN:TRAMP_PIT:ADDR=MODULE
    // Where ADDR and TRAMP_PIT are unsigned 64-bit hex and HOOKID/ORI_LEN are 32-bit hex.
    bool ReadProcHookList(std::vector<std::tuple<DWORD, DWORD, DWORD, int, DWORD, unsigned long long, unsigned long long, unsigned long long, std::wstring>>& outEntries);
    bool WriteProcHookList(const std::vector<std::tuple<DWORD, DWORD, DWORD, int, DWORD, unsigned long long, unsigned long long, unsigned long long, std::wstring>>& entries);
    // Remove a single persisted ProcHookList entry matching PID, FILETIME hi/lo and hook id.
    bool RemoveProcHookEntry(DWORD pid, DWORD filetimeHi, DWORD filetimeLo, int hookId);
}
