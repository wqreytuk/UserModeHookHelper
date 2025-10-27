#pragma once
#include <string>
#include <vector>

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
}
