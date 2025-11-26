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
static const wchar_t* PROCHOOK_VALUE_NAME = L"ProcHookList"; // per-process hook list
static const wchar_t* EARLYBREAK_VALUE_NAME = L"EarlyBreakList"; // per-process early-break marks (NT paths)
static const wchar_t* FORCED_VALUE_NAME = L"ForcedList"; // per-process forced injection marks (PID:HI:LOW)

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

// Format: PID:HIGH:LOW:HOOKID:ORI_LEN:ORI_ADDR:TRAMP_PIT:ADDR=MODULE
// (ADDR/ORI_ADDR/TRAMP_PIT hex 64-bit, HOOKID/ORI_LEN hex)
bool RegistryStore::ReadProcHookList(std::vector<std::tuple<DWORD, DWORD, DWORD, int, DWORD, unsigned long long, unsigned long long, unsigned long long, std::wstring>>& outEntries) {
    outEntries.clear();
    HKEY hKey = NULL;
    LONG r = RegOpenKeyExW(HKEY_LOCAL_MACHINE, REG_PERSIST_SUBKEY, 0, KEY_READ, &hKey);
    if (r != ERROR_SUCCESS) return true; // treat missing as empty
    DWORD type=0, dataSize=0;
    r = RegQueryValueExW(hKey, PROCHOOK_VALUE_NAME, NULL, &type, NULL, &dataSize);
    if (r != ERROR_SUCCESS) { RegCloseKey(hKey); if (r == ERROR_FILE_NOT_FOUND) return true; return false; }
    if (type != REG_MULTI_SZ) { RegCloseKey(hKey); return false; }
    if (dataSize == 0) { RegCloseKey(hKey); return true; }
    std::vector<wchar_t> buf(dataSize/sizeof(wchar_t));
    r = RegQueryValueExW(hKey, PROCHOOK_VALUE_NAME, NULL, NULL, reinterpret_cast<LPBYTE>(buf.data()), &dataSize);
    RegCloseKey(hKey);
    if (r != ERROR_SUCCESS) return false;
    size_t idx=0, wcCount=dataSize/sizeof(wchar_t);
    while (idx < wcCount) {
        if (buf[idx] == L'\0') { ++idx; continue; }
        std::wstring line(&buf[idx]);
        idx += line.size()+1;
        size_t eq = line.find(L'='); if (eq == std::wstring::npos) continue;
        std::wstring key = line.substr(0, eq);
        std::wstring module = line.substr(eq+1);
        // key: PID:HIGH:LOW:HOOKID:ORI_LEN:TRAMP_PIT:ADDR
        std::vector<std::wstring> parts;
        size_t pos = 0; while (true) {
            size_t p = key.find(L':', pos);
            if (p == std::wstring::npos) { parts.push_back(key.substr(pos)); break; }
            parts.push_back(key.substr(pos, p-pos)); pos = p+1;
        }
        if (parts.size() != 8) continue;
        DWORD pid=0, hi=0, lo=0; int hookid=0; DWORD ori_len=0; unsigned long long ori_addr=0; unsigned long long tramp_pit=0; unsigned long long addr=0;
        swscanf_s(parts[0].c_str(), L"%lx", &pid);
        swscanf_s(parts[1].c_str(), L"%lx", &hi);
        swscanf_s(parts[2].c_str(), L"%lx", &lo);
        swscanf_s(parts[3].c_str(), L"%x", &hookid);
        swscanf_s(parts[4].c_str(), L"%x", &ori_len);
        // parse 64-bit hex for original code address, trampoline pit and address
        swscanf_s(parts[5].c_str(), L"%llx", &ori_addr);
        swscanf_s(parts[6].c_str(), L"%llx", &tramp_pit);
        swscanf_s(parts[7].c_str(), L"%llx", &addr);
        outEntries.emplace_back(pid, hi, lo, hookid, ori_len, ori_addr, tramp_pit, addr, module);
    }
    return true;
}

bool RegistryStore::WriteProcHookList(const std::vector<std::tuple<DWORD, DWORD, DWORD, int, DWORD, unsigned long long, unsigned long long, unsigned long long, std::wstring>>& entries) {
    std::vector<wchar_t> buf;
    for (auto &t : entries) {
        DWORD pid = std::get<0>(t);
        DWORD hi = std::get<1>(t);
        DWORD lo = std::get<2>(t);
        int hookid = std::get<3>(t);
        DWORD ori_len = std::get<4>(t);
        unsigned long long ori_addr = std::get<5>(t);
        unsigned long long tramp_pit = std::get<6>(t);
        unsigned long long addr = std::get<7>(t);
        const std::wstring &module = std::get<8>(t);
        if (module.empty()) continue;
        wchar_t header[192];
        _snwprintf_s(header, _TRUNCATE, L"%08lX:%08lX:%08lX:%08X:%08X:%016llX:%016llX:%016llX=", pid, hi, lo, (unsigned int)hookid, (unsigned int)ori_len, ori_addr, tramp_pit, addr);
        std::wstring line = header;
        line.append(module);
        buf.insert(buf.end(), line.c_str(), line.c_str() + line.size());
        buf.push_back(L'\0');
    }
    if (buf.empty() || buf.back() != L'\0') buf.push_back(L'\0');
    buf.push_back(L'\0');
    HKEY hKey = NULL; DWORD disp=0;
    LONG r = RegCreateKeyExW(HKEY_LOCAL_MACHINE, REG_PERSIST_SUBKEY, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, &disp);
    if (r != ERROR_SUCCESS) return false;
    LONG rr = RegSetValueExW(hKey, PROCHOOK_VALUE_NAME, 0, REG_MULTI_SZ, reinterpret_cast<const BYTE*>(buf.data()), (DWORD)(buf.size()*sizeof(wchar_t)));
    RegCloseKey(hKey);
    return rr == ERROR_SUCCESS;
}

bool RegistryStore::ReadEarlyBreakMarks(std::vector<std::wstring>& outNtPaths) {
    outNtPaths.clear();
    HKEY hKey = NULL;
    LONG r = RegOpenKeyExW(HKEY_LOCAL_MACHINE, REG_PERSIST_SUBKEY, 0, KEY_READ, &hKey);
    if (r != ERROR_SUCCESS) return true; // treat missing as empty
    DWORD type = 0; DWORD dataSize = 0;
    r = RegQueryValueExW(hKey, EARLYBREAK_VALUE_NAME, NULL, &type, NULL, &dataSize);
    if (r != ERROR_SUCCESS) { RegCloseKey(hKey); if (r == ERROR_FILE_NOT_FOUND) return true; return false; }
    if (type != REG_MULTI_SZ) { RegCloseKey(hKey); return false; }
    if (dataSize == 0) { RegCloseKey(hKey); return true; }
    std::vector<wchar_t> buf(dataSize/sizeof(wchar_t));
    r = RegQueryValueExW(hKey, EARLYBREAK_VALUE_NAME, NULL, NULL, reinterpret_cast<LPBYTE>(buf.data()), &dataSize);
    RegCloseKey(hKey);
    if (r != ERROR_SUCCESS) return false;
    size_t idx = 0, wcCount = dataSize/sizeof(wchar_t);
    while (idx < wcCount) {
        if (buf[idx] == L'\0') { ++idx; continue; }
        std::wstring s(&buf[idx]);
        outNtPaths.push_back(s);
        idx += s.size() + 1;
    }
    return true;
}

bool RegistryStore::AddEarlyBreakMark(const std::wstring& ntPath) {
    std::vector<std::wstring> marks;
    if (!ReadEarlyBreakMarks(marks)) return false;
    for (auto &m : marks) { if (_wcsicmp(m.c_str(), ntPath.c_str()) == 0) return true; }
    marks.push_back(ntPath);
    std::vector<wchar_t> buf;
    for (auto &s : marks) { buf.insert(buf.end(), s.c_str(), s.c_str() + s.size()); buf.push_back(L'\0'); }
    if (buf.empty() || buf.back() != L'\0') buf.push_back(L'\0');
    HKEY hKey = NULL; DWORD disp=0;
    LONG r = RegCreateKeyExW(HKEY_LOCAL_MACHINE, REG_PERSIST_SUBKEY, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, &disp);
    if (r != ERROR_SUCCESS) return false;
    LONG rr = RegSetValueExW(hKey, EARLYBREAK_VALUE_NAME, 0, REG_MULTI_SZ, reinterpret_cast<const BYTE*>(buf.data()), (DWORD)(buf.size()*sizeof(wchar_t)));
    RegCloseKey(hKey);
    return rr == ERROR_SUCCESS;
}

bool RegistryStore::RemoveEarlyBreakMark(const std::wstring& ntPath) {
    std::vector<std::wstring> marks;
    if (!ReadEarlyBreakMarks(marks)) return false;
    std::vector<std::wstring> out;
    bool removed = false;
    for (auto &m : marks) {
        if (!removed && _wcsicmp(m.c_str(), ntPath.c_str()) == 0) { removed = true; continue; }
        out.push_back(m);
    }
    if (!removed) return true;
    if (out.empty()) {
        HKEY hKey = NULL; LONG r = RegOpenKeyExW(HKEY_LOCAL_MACHINE, REG_PERSIST_SUBKEY, 0, KEY_SET_VALUE, &hKey);
        if (r == ERROR_SUCCESS) { RegDeleteValueW(hKey, EARLYBREAK_VALUE_NAME); RegCloseKey(hKey); }
        return true;
    }
    std::vector<wchar_t> buf;
    for (auto &s : out) { buf.insert(buf.end(), s.c_str(), s.c_str() + s.size()); buf.push_back(L'\0'); }
    if (buf.empty() || buf.back() != L'\0') buf.push_back(L'\0');
    HKEY hKey = NULL; DWORD disp=0;
    LONG r = RegCreateKeyExW(HKEY_LOCAL_MACHINE, REG_PERSIST_SUBKEY, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, &disp);
    if (r != ERROR_SUCCESS) return false;
    LONG rr = RegSetValueExW(hKey, EARLYBREAK_VALUE_NAME, 0, REG_MULTI_SZ, reinterpret_cast<const BYTE*>(buf.data()), (DWORD)(buf.size()*sizeof(wchar_t)));
    RegCloseKey(hKey);
    return rr == ERROR_SUCCESS;
}

bool RegistryStore::ReadForcedMarks(std::vector<std::tuple<DWORD, DWORD, DWORD>>& outEntries) {
    outEntries.clear();
    HKEY hKey = NULL;
    LONG r = RegOpenKeyExW(HKEY_LOCAL_MACHINE, REG_PERSIST_SUBKEY, 0, KEY_READ, &hKey);
    if (r != ERROR_SUCCESS) return true; // treat missing as empty
    DWORD type=0, dataSize=0;
    r = RegQueryValueExW(hKey, FORCED_VALUE_NAME, NULL, &type, NULL, &dataSize);
    if (r != ERROR_SUCCESS) { RegCloseKey(hKey); if (r == ERROR_FILE_NOT_FOUND) return true; return false; }
    if (type != REG_MULTI_SZ) { RegCloseKey(hKey); return false; }
    if (dataSize == 0) { RegCloseKey(hKey); return true; }
    std::vector<wchar_t> buf(dataSize/sizeof(wchar_t));
    r = RegQueryValueExW(hKey, FORCED_VALUE_NAME, NULL, NULL, reinterpret_cast<LPBYTE>(buf.data()), &dataSize);
    RegCloseKey(hKey);
    if (r != ERROR_SUCCESS) return false;
    size_t idx=0, wcCount=dataSize/sizeof(wchar_t);
    while (idx < wcCount) {
        if (buf[idx] == L'\0') { ++idx; continue; }
        std::wstring line(&buf[idx]);
        idx += line.size()+1;
        // parse PID:HIGH:LOW
        size_t c1 = line.find(L':'); if (c1==std::wstring::npos) continue;
        size_t c2 = line.find(L':', c1+1); if (c2==std::wstring::npos) continue;
        std::wstring pidPart = line.substr(0, c1);
        std::wstring highPart = line.substr(c1+1, c2-c1-1);
        std::wstring lowPart = line.substr(c2+1);
        DWORD pid=0, hi=0, lo=0;
        swscanf_s(pidPart.c_str(), L"%lx", &pid);
        swscanf_s(highPart.c_str(), L"%lx", &hi);
        swscanf_s(lowPart.c_str(), L"%lx", &lo);
        outEntries.emplace_back(pid, hi, lo);
    }
    return true;
}

bool RegistryStore::WriteForcedMarks(const std::vector<std::tuple<DWORD, DWORD, DWORD>>& entries) {
    std::vector<wchar_t> buf;
    for (auto &t : entries) {
        DWORD pid = std::get<0>(t);
        DWORD hi = std::get<1>(t);
        DWORD lo = std::get<2>(t);
        wchar_t header[64]; _snwprintf_s(header, _TRUNCATE, L"%08lX:%08lX:%08lX", pid, hi, lo);
        std::wstring line = header;
        buf.insert(buf.end(), line.c_str(), line.c_str() + line.size());
        buf.push_back(L'\0');
    }
    if (buf.empty() || buf.back() != L'\0') buf.push_back(L'\0');
    buf.push_back(L'\0');
    HKEY hKey = NULL; DWORD disp=0;
    LONG r = RegCreateKeyExW(HKEY_LOCAL_MACHINE, REG_PERSIST_SUBKEY, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, &disp);
    if (r != ERROR_SUCCESS) return false;
    LONG rr = RegSetValueExW(hKey, FORCED_VALUE_NAME, 0, REG_MULTI_SZ, reinterpret_cast<const BYTE*>(buf.data()), (DWORD)(buf.size()*sizeof(wchar_t)));
    RegCloseKey(hKey);
    return rr == ERROR_SUCCESS;
}

bool RegistryStore::AddForcedMark(DWORD pid, DWORD hi, DWORD lo) {
    std::vector<std::tuple<DWORD, DWORD, DWORD>> entries;
    if (!ReadForcedMarks(entries)) return false;
    for (auto &t : entries) {
        if (std::get<0>(t) == pid && std::get<1>(t) == hi && std::get<2>(t) == lo) return true;
    }
    entries.emplace_back(pid, hi, lo);
    return WriteForcedMarks(entries);
}

bool RegistryStore::RemoveForcedMark(DWORD pid, DWORD hi, DWORD lo) {
    std::vector<std::tuple<DWORD, DWORD, DWORD>> entries;
    if (!ReadForcedMarks(entries)) return false;
    std::vector<std::tuple<DWORD, DWORD, DWORD>> out;
    bool removed = false;
    for (auto &t : entries) {
        if (!removed && std::get<0>(t) == pid && std::get<1>(t) == hi && std::get<2>(t) == lo) { removed = true; continue; }
        out.push_back(t);
    }
    if (!removed) return true;
    return WriteForcedMarks(out);
}

bool RegistryStore::RemoveProcHookEntry(DWORD pid, DWORD filetimeHi, DWORD filetimeLo, int hookId) {
    std::vector<std::tuple<DWORD, DWORD, DWORD, int, DWORD, unsigned long long, unsigned long long, unsigned long long, std::wstring>> entries;
    if (!ReadProcHookList(entries)) return false;
    std::vector<std::tuple<DWORD, DWORD, DWORD, int, DWORD, unsigned long long, unsigned long long, unsigned long long, std::wstring>> out;
    bool removed = false;
    for (auto &t : entries) {
        DWORD p = std::get<0>(t);
        DWORD hi = std::get<1>(t);
        DWORD lo = std::get<2>(t);
        int hid = std::get<3>(t);
        if (!removed && p == pid && hi == filetimeHi && lo == filetimeLo && hid == hookId) {
            removed = true; continue;
        }
        out.push_back(t);
    }
    if (!removed) return true; // nothing to do
    return WriteProcHookList(out);
}

bool RegistryStore::ReadBoolSetting(const wchar_t* name, bool defaultValue, bool& outValue) {
    outValue = defaultValue;
    HKEY hKey = NULL;
        // Try 64-bit view first so we match driver behavior on x64 systems
        LONG r = RegOpenKeyExW(HKEY_LOCAL_MACHINE, REG_PERSIST_SUBKEY, 0, KEY_READ | KEY_WOW64_64KEY, &hKey);
        if (r == ERROR_SUCCESS) {
            DWORD type = 0; DWORD data = 0; DWORD dataSize = sizeof(data);
            LONG q = RegQueryValueExW(hKey, name, NULL, &type, reinterpret_cast<LPBYTE>(&data), &dataSize);
            RegCloseKey(hKey);
            if (q == ERROR_SUCCESS) {
                if (type == REG_DWORD) outValue = (data != 0);
                return true;
            }
            // fall through to try default view if value isn't present in 64-bit view
        }

        // Fallback: try default view (useful if value was previously written by 32-bit process)
        hKey = NULL;
        r = RegOpenKeyExW(HKEY_LOCAL_MACHINE, REG_PERSIST_SUBKEY, 0, KEY_READ, &hKey);
        if (r != ERROR_SUCCESS) return true; // treat missing as default
        DWORD type = 0; DWORD data = 0; DWORD dataSize = sizeof(data);
        r = RegQueryValueExW(hKey, name, NULL, &type, reinterpret_cast<LPBYTE>(&data), &dataSize);
        RegCloseKey(hKey);
        if (r != ERROR_SUCCESS) return true;
        if (type == REG_DWORD) outValue = (data != 0);
        return true;
}

bool RegistryStore::WriteBoolSetting(const wchar_t* name, bool value) {
    HKEY hKey = NULL; DWORD disp=0;
    // Create/open in 64-bit view so driver can read it
    LONG r = RegCreateKeyExW(HKEY_LOCAL_MACHINE, REG_PERSIST_SUBKEY, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_WOW64_64KEY, NULL, &hKey, &disp);
    if (r != ERROR_SUCCESS) return false;
    DWORD data = value ? 1 : 0;
    LONG rr = RegSetValueExW(hKey, name, 0, REG_DWORD, reinterpret_cast<const BYTE*>(&data), sizeof(data));
    RegCloseKey(hKey);
    return rr == ERROR_SUCCESS;
}

bool RegistryStore::ReadGlobalHookMode(bool& outEnabled) {
    return ReadBoolSetting(L"EnableGlobalHookMode", false, outEnabled);
}

bool RegistryStore::WriteGlobalHookMode(bool enabled) {
    return WriteBoolSetting(L"EnableGlobalHookMode", enabled);
}
