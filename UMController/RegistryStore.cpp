#include "pch.h"
#include "RegistryStore.h"
#include <windows.h>
#include <vector>
#include <tuple>
#include "../UserModeHookHelper/MacroDef.h"
#include "ETW.h"
#include "UMController.h"

static const wchar_t* VALUE_NAME = L"HookPaths";
static const wchar_t* COMPOSITE_VALUE_NAME = L"NtProcCache"; // new composite key cache

bool RegistryStore::ReadHookPaths(std::vector<std::wstring>& outPaths) {
    outPaths.clear();
    HKEY hKey = NULL;
    // Open HKLM\SOFTWARE\<vendor>\UserModeHookHelper
    LONG r = RegOpenKeyExW(HKEY_LOCAL_MACHINE, REG_PERSIST_SUBKEY, 0, KEY_READ, &hKey);
    if (r != ERROR_SUCCESS) {
        // Treat missing key as empty list
        app.GetETW().Log(L"RegistryStore::ReadHookPaths: RegOpenKeyExW failed (%d) - treating as empty\n", r);
        return true;
    }

    DWORD type = 0;
    DWORD dataSize = 0;
    r = RegQueryValueExW(hKey, VALUE_NAME, NULL, &type, NULL, &dataSize);
    if (r != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        if (r == ERROR_FILE_NOT_FOUND) return true; // no value yet
        app.GetETW().Log(L"RegistryStore::ReadHookPaths: RegQueryValueExW size failed (%d)\n", r);
        return false;
    }
    if (type != REG_MULTI_SZ) {
        app.GetETW().Log(L"RegistryStore::ReadHookPaths: unexpected value type %u\n", type);
        RegCloseKey(hKey);
        return false;
    }

    if (dataSize == 0) { RegCloseKey(hKey); return true; }

    std::vector<wchar_t> buf(dataSize / sizeof(wchar_t));
    r = RegQueryValueExW(hKey, VALUE_NAME, NULL, NULL, reinterpret_cast<LPBYTE>(buf.data()), &dataSize);
    RegCloseKey(hKey);
    if (r != ERROR_SUCCESS) {
        app.GetETW().Log(L"RegistryStore::ReadHookPaths: RegQueryValueExW read failed (%d)\n", r);
        return false;
    }

    // Parse REG_MULTI_SZ
    size_t idx = 0;
    size_t wcCount = dataSize / sizeof(wchar_t);
    while (idx < wcCount) {
        if (buf[idx] == L'\0') { ++idx; continue; }
        std::wstring s(&buf[idx]);
        outPaths.push_back(s);
        idx += s.size() + 1;
    }
    return true;
}

bool RegistryStore::WriteHookPaths(const std::vector<std::wstring>& paths) {
    // Build REG_MULTI_SZ buffer
    std::vector<wchar_t> buf;
    for (const auto &p : paths) {
        buf.insert(buf.end(), p.begin(), p.end());
        buf.push_back(L'\0');
    }
    // Ensure double-null termination
    if (buf.empty() || buf.back() != L'\0') buf.push_back(L'\0');
    if (buf.empty() || buf.back() != L'\0') buf.push_back(L'\0');

    // Create or open key with write access
    HKEY hKey = NULL;
    DWORD disp = 0;
    LONG r = RegCreateKeyExW(HKEY_LOCAL_MACHINE, REG_PERSIST_SUBKEY, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, &disp);
    if (r != ERROR_SUCCESS) {
        app.GetETW().Log(L"RegistryStore::WriteHookPaths: RegCreateKeyExW failed (%d)\n", r);
        return false;
    }

    LONG rr = RegSetValueExW(hKey, VALUE_NAME, 0, REG_MULTI_SZ, reinterpret_cast<const BYTE*>(buf.data()), (DWORD)(buf.size() * sizeof(wchar_t)));
    RegCloseKey(hKey);
    if (rr != ERROR_SUCCESS) {
        app.GetETW().Log(L"RegistryStore::WriteHookPaths: RegSetValueExW failed (%d)\n", rr);
        return false;
    }
    return true;
}

bool RegistryStore::AddPath(const std::wstring& ntPath) {
    std::vector<std::wstring> paths;
    if (!ReadHookPaths(paths)) return false;
    // Avoid duplicates (case-insensitive compare)
    for (const auto &p : paths) {
        if (_wcsicmp(p.c_str(), ntPath.c_str()) == 0) return true;
    }
    paths.push_back(ntPath);
    return WriteHookPaths(paths);
}

bool RegistryStore::RemovePath(const std::wstring& ntPath) {
    std::vector<std::wstring> paths;
    if (!ReadHookPaths(paths)) return false;
    bool found = false;
    std::vector<std::wstring> out;
    for (const auto &p : paths) {
        if (!found && _wcsicmp(p.c_str(), ntPath.c_str()) == 0) { found = true; continue; }
        out.push_back(p);
    }
    if (!found) return true; // nothing to do
    return WriteHookPaths(out);
}

// Read composite process cache entries (PID:HIGH:LOW=NT_PATH)
bool RegistryStore::ReadCompositeProcCache(std::vector<std::tuple<DWORD, DWORD, DWORD, std::wstring>>& outEntries) {
    outEntries.clear();
    HKEY hKey = NULL;
    LONG r = RegOpenKeyExW(HKEY_LOCAL_MACHINE, REG_PERSIST_SUBKEY, 0, KEY_READ, &hKey);
    if (r != ERROR_SUCCESS) {
        app.GetETW().Log(L"RegistryStore::ReadCompositeProcCache: RegOpenKeyExW failed (%d) - treating as empty\n", r);
        return true; // missing key => empty
    }
    DWORD type=0, dataSize=0;
    r = RegQueryValueExW(hKey, COMPOSITE_VALUE_NAME, NULL, &type, NULL, &dataSize);
    if (r != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        if (r == ERROR_FILE_NOT_FOUND) return true; // no value
        app.GetETW().Log(L"RegistryStore::ReadCompositeProcCache: RegQueryValueExW size failed (%d)\n", r);
        return false;
    }
    if (type != REG_MULTI_SZ) {
        app.GetETW().Log(L"RegistryStore::ReadCompositeProcCache: unexpected type %u\n", type);
        RegCloseKey(hKey);
        return false;
    }
    if (dataSize == 0) { RegCloseKey(hKey); return true; }
    std::vector<wchar_t> buf(dataSize/sizeof(wchar_t));
    r = RegQueryValueExW(hKey, COMPOSITE_VALUE_NAME, NULL, NULL, reinterpret_cast<LPBYTE>(buf.data()), &dataSize);
    RegCloseKey(hKey);
    if (r != ERROR_SUCCESS) {
        app.GetETW().Log(L"RegistryStore::ReadCompositeProcCache: read failed (%d)\n", r);
        return false;
    }
    size_t idx=0, wcCount=dataSize/sizeof(wchar_t);
    while (idx < wcCount) {
        if (buf[idx] == L'\0') { ++idx; continue; }
        std::wstring line(&buf[idx]);
        idx += line.size()+1;
        size_t eq = line.find(L'=');
        if (eq == std::wstring::npos) continue;
        std::wstring key = line.substr(0, eq);
        std::wstring path = line.substr(eq+1);
        // Split key PID:HIGH:LOW (hex digits)
        size_t c1 = key.find(L':'); if (c1==std::wstring::npos) continue;
        size_t c2 = key.find(L':', c1+1); if (c2==std::wstring::npos) continue;
        std::wstring pidPart = key.substr(0, c1);
        std::wstring highPart = key.substr(c1+1, c2-c1-1);
        std::wstring lowPart = key.substr(c2+1);
        DWORD pid=0, hi=0, lo=0;
        swscanf_s(pidPart.c_str(), L"%lx", &pid);
        swscanf_s(highPart.c_str(), L"%lx", &hi);
        swscanf_s(lowPart.c_str(), L"%lx", &lo);
        if (!path.empty()) outEntries.emplace_back(pid, hi, lo, path);
    }
    return true;
}

bool RegistryStore::WriteCompositeProcCache(const std::vector<std::tuple<DWORD, DWORD, DWORD, std::wstring>>& entries) {
    std::vector<wchar_t> buf;
    for (auto &t : entries) {
        DWORD pid = std::get<0>(t);
        DWORD hi = std::get<1>(t);
        DWORD lo = std::get<2>(t);
        const std::wstring &path = std::get<3>(t);
        if (path.empty()) continue; // skip empty paths
        // Build header separately to avoid truncation; then append full path.
        wchar_t header[32];
        _snwprintf_s(header, _TRUNCATE, L"%08lX:%08lX:%08lX=", pid, hi, lo);
        std::wstring line;
        line.reserve(wcslen(header) + path.size());
        line.append(header);
        line.append(path);
        buf.insert(buf.end(), line.c_str(), line.c_str() + line.size());
        buf.push_back(L'\0');
    }
    // Ensure final double-null terminator for REG_MULTI_SZ
    if (buf.empty() || buf.back() != L'\0') buf.push_back(L'\0');
    buf.push_back(L'\0');
    HKEY hKey=NULL; DWORD disp=0;
    LONG r = RegCreateKeyExW(HKEY_LOCAL_MACHINE, REG_PERSIST_SUBKEY, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, &disp);
    if (r != ERROR_SUCCESS) {
        app.GetETW().Log(L"RegistryStore::WriteCompositeProcCache: RegCreateKeyExW failed (%d)\n", r);
        return false;
    }
    LONG rr = RegSetValueExW(hKey, COMPOSITE_VALUE_NAME, 0, REG_MULTI_SZ, reinterpret_cast<const BYTE*>(buf.data()), (DWORD)(buf.size()*sizeof(wchar_t)));
    RegCloseKey(hKey);
    if (rr != ERROR_SUCCESS) {
        app.GetETW().Log(L"RegistryStore::WriteCompositeProcCache: RegSetValueExW failed (%d)\n", rr);
        return false;
    }
    return true;
}
