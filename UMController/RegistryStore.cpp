#include "pch.h"
#include "RegistryStore.h"
#include <windows.h>
#include <vector>
#include <tuple>
#include "../UserModeHookHelper/MacroDef.h"
#include "ETW.h"
#include "UMController.h"
#include "Helper.h"
#include "../Shared/LogMacros.h"


static const wchar_t* VALUE_NAME = L"HookPaths";
static const wchar_t* COMPOSITE_VALUE_NAME = L"NtProcCache"; // new composite key cache
static const wchar_t* PROCHOOK_VALUE_NAME = L"ProcHookList"; // per-process hook list
static const wchar_t* EARLYBREAK_VALUE_NAME = L"EarlyBreakList"; // per-process early-break marks (NT paths)
static const wchar_t* FORCED_VALUE_NAME = L"ForcedList"; // per-process forced injection marks (PID:HI:LOW)
static const wchar_t* WHITELIST_PATHS_NAME = L"WhitelistPaths"; // NT paths allowed/ignored
static const wchar_t* WHITELIST_HASHES_NAME = L"WhitelistHashes"; // NT path hashes
static const wchar_t* PPL_ELEVATED_LIST_NAME = L"PplElevatedList"; // PID:HI:LOW entries for manual elevate
static const wchar_t* PPL_UNPROTECTED_LIST_NAME = L"PplUnprotectedList"; // PID:HI:LOW entries for manual unprotect
static const wchar_t* PPL_ORIGINAL_PROT_LIST_NAME = L"PplOriginalProtList"; // PID:HI:LOW=HEX32 original protection

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
    // Delegate to the filtered variant with no filtering (backwards compatible)

	

    return RegistryStore::ReadProcHookList(0, 0, 0, outEntries);
}

bool RegistryStore::ReadProcHookList(DWORD filterPid, DWORD filterHi, DWORD filterLo, std::vector<std::tuple<DWORD, DWORD, DWORD, int, DWORD, unsigned long long, unsigned long long, unsigned long long, std::wstring>>& outEntries) {
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

        // If filtering requested, only include tuples that match PID + FILETIME hi/lo
        if (filterPid != 0 || filterHi != 0 || filterLo != 0) {
            if (pid != filterPid) continue;
            if (filterHi != 0 || filterLo != 0) {
                if (hi != filterHi || lo != filterLo) continue;
            }
            else {
                // caller supplied pid but zero FILETIME: only accept entries with hi==0 && lo==0
                if (hi != 0 || lo != 0) continue;
            }
        }

        outEntries.emplace_back(pid, hi, lo, hookid, ori_len, ori_addr, tramp_pit, addr, module);
    }
    return true;
}

bool RegistryStore::WriteProcHookList(const std::vector<std::tuple<DWORD, DWORD, DWORD, int, DWORD, unsigned long long, unsigned long long, unsigned long long, std::wstring>>& entries) {
    // Merge with existing entries to avoid overwriting prior hooks.
    std::vector<std::tuple<DWORD, DWORD, DWORD, int, DWORD, unsigned long long, unsigned long long, unsigned long long, std::wstring>> existing;
    ReadProcHookList(existing); // treat failures as empty; we will rewrite anyway

    // Use a composite key PID:HI:LO:HOOKID to de-duplicate and replace if same key.
    struct Key { DWORD pid, hi, lo; int hookid; };
    auto makeKey = [](const std::tuple<DWORD, DWORD, DWORD, int, DWORD, unsigned long long, unsigned long long, unsigned long long, std::wstring>& t)->Key {
        return Key{ std::get<0>(t), std::get<1>(t), std::get<2>(t), std::get<3>(t) };
    };
    std::vector<std::tuple<DWORD, DWORD, DWORD, int, DWORD, unsigned long long, unsigned long long, unsigned long long, std::wstring>> merged;
    merged.reserve(existing.size() + entries.size());

    // Start with existing; we will later replace matching keys from new entries.
    merged = existing;

    // For each new entry, either replace existing with same key or append.
    for (auto &ne : entries) {
        Key nk = makeKey(ne);
        bool replaced = false;
        for (auto &ex : merged) {
            Key ek = makeKey(ex);
            if (ek.pid == nk.pid && ek.hi == nk.hi && ek.lo == nk.lo && ek.hookid == nk.hookid) {
                ex = ne; // replace existing record with updated details
                replaced = true;
                break;
            }
        }
        if (!replaced) merged.push_back(ne);
    }

    // Serialize to REG_MULTI_SZ
    std::vector<wchar_t> buf;
    for (auto &t : merged) {
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
        std::wstring line = header; line.append(module);
        buf.insert(buf.end(), line.c_str(), line.c_str() + line.size()); buf.push_back(L'\0');
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

// PPL Elevated Marks (PID:HI:LOW)
bool RegistryStore::ReadPplElevatedMarks(std::vector<std::tuple<DWORD, DWORD, DWORD>>& outEntries) {
    outEntries.clear();
    HKEY hKey = NULL;
    LONG r = RegOpenKeyExW(HKEY_LOCAL_MACHINE, REG_PERSIST_SUBKEY, 0, KEY_READ, &hKey);
    if (r != ERROR_SUCCESS) return true; // treat missing as empty
    DWORD type=0, dataSize=0;
    r = RegQueryValueExW(hKey, PPL_ELEVATED_LIST_NAME, NULL, &type, NULL, &dataSize);
    if (r != ERROR_SUCCESS) { RegCloseKey(hKey); if (r == ERROR_FILE_NOT_FOUND) return true; return false; }
    if (type != REG_MULTI_SZ) { RegCloseKey(hKey); return false; }
    if (dataSize == 0) { RegCloseKey(hKey); return true; }
    std::vector<wchar_t> buf(dataSize/sizeof(wchar_t));
    r = RegQueryValueExW(hKey, PPL_ELEVATED_LIST_NAME, NULL, NULL, reinterpret_cast<LPBYTE>(buf.data()), &dataSize);
    RegCloseKey(hKey);
    if (r != ERROR_SUCCESS) return false;
    size_t idx=0, wcCount=dataSize/sizeof(wchar_t);
    while (idx < wcCount) {
        if (buf[idx] == L'\0') { ++idx; continue; }
        std::wstring line(&buf[idx]);
        idx += line.size()+1;
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

bool RegistryStore::WritePplElevatedMarks(const std::vector<std::tuple<DWORD, DWORD, DWORD>>& entries) {
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
    LONG rr = RegSetValueExW(hKey, PPL_ELEVATED_LIST_NAME, 0, REG_MULTI_SZ, reinterpret_cast<const BYTE*>(buf.data()), (DWORD)(buf.size()*sizeof(wchar_t)));
    RegCloseKey(hKey);
    return rr == ERROR_SUCCESS;
}

bool RegistryStore::AddPplElevatedMark(DWORD pid, DWORD hi, DWORD lo) {
    std::vector<std::tuple<DWORD, DWORD, DWORD>> entries; if (!ReadPplElevatedMarks(entries)) return false;
    for (auto &t : entries) { if (std::get<0>(t)==pid && std::get<1>(t)==hi && std::get<2>(t)==lo) return true; }
    entries.emplace_back(pid, hi, lo);
    return WritePplElevatedMarks(entries);
}

bool RegistryStore::RemovePplElevatedMark(DWORD pid, DWORD hi, DWORD lo) {
    std::vector<std::tuple<DWORD, DWORD, DWORD>> entries; if (!ReadPplElevatedMarks(entries)) return false;
    std::vector<std::tuple<DWORD, DWORD, DWORD>> out; bool removed=false;
    for (auto &t : entries) { if (!removed && std::get<0>(t)==pid && std::get<1>(t)==hi && std::get<2>(t)==lo) { removed=true; continue; } out.push_back(t); }
    if (!removed) return true;
    return WritePplElevatedMarks(out);
}

// PPL Unprotected Marks (PID:HI:LOW)
bool RegistryStore::ReadPplUnprotectedMarks(std::vector<std::tuple<DWORD, DWORD, DWORD>>& outEntries) {
    outEntries.clear();
    HKEY hKey = NULL;
    LONG r = RegOpenKeyExW(HKEY_LOCAL_MACHINE, REG_PERSIST_SUBKEY, 0, KEY_READ, &hKey);
    if (r != ERROR_SUCCESS) return true; // treat missing as empty
    DWORD type=0, dataSize=0;
    r = RegQueryValueExW(hKey, PPL_UNPROTECTED_LIST_NAME, NULL, &type, NULL, &dataSize);
    if (r != ERROR_SUCCESS) { RegCloseKey(hKey); if (r == ERROR_FILE_NOT_FOUND) return true; return false; }
    if (type != REG_MULTI_SZ) { RegCloseKey(hKey); return false; }
    if (dataSize == 0) { RegCloseKey(hKey); return true; }
    std::vector<wchar_t> buf(dataSize/sizeof(wchar_t));
    r = RegQueryValueExW(hKey, PPL_UNPROTECTED_LIST_NAME, NULL, NULL, reinterpret_cast<LPBYTE>(buf.data()), &dataSize);
    RegCloseKey(hKey);
    if (r != ERROR_SUCCESS) return false;
    size_t idx=0, wcCount=dataSize/sizeof(wchar_t);
    while (idx < wcCount) {
        if (buf[idx] == L'\0') { ++idx; continue; }
        std::wstring line(&buf[idx]);
        idx += line.size()+1;
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

bool RegistryStore::WritePplUnprotectedMarks(const std::vector<std::tuple<DWORD, DWORD, DWORD>>& entries) {
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
    LONG rr = RegSetValueExW(hKey, PPL_UNPROTECTED_LIST_NAME, 0, REG_MULTI_SZ, reinterpret_cast<const BYTE*>(buf.data()), (DWORD)(buf.size()*sizeof(wchar_t)));
    RegCloseKey(hKey);
    return rr == ERROR_SUCCESS;
}

bool RegistryStore::AddPplUnprotectedMark(DWORD pid, DWORD hi, DWORD lo) {
    std::vector<std::tuple<DWORD, DWORD, DWORD>> entries; if (!ReadPplUnprotectedMarks(entries)) return false;
    for (auto &t : entries) { if (std::get<0>(t)==pid && std::get<1>(t)==hi && std::get<2>(t)==lo) return true; }
    entries.emplace_back(pid, hi, lo);
    return WritePplUnprotectedMarks(entries);
}

bool RegistryStore::RemovePplUnprotectedMark(DWORD pid, DWORD hi, DWORD lo) {
    std::vector<std::tuple<DWORD, DWORD, DWORD>> entries; if (!ReadPplUnprotectedMarks(entries)) return false;
    std::vector<std::tuple<DWORD, DWORD, DWORD>> out; bool removed=false;
    for (auto &t : entries) { if (!removed && std::get<0>(t)==pid && std::get<1>(t)==hi && std::get<2>(t)==lo) { removed=true; continue; } out.push_back(t); }
    if (!removed) return true;
    return WritePplUnprotectedMarks(out);
}

// PPL Original Protection (PID:HI:LOW=HEX32)
bool RegistryStore::ReadPplOriginalProt(std::vector<std::tuple<DWORD, DWORD, DWORD, DWORD>>& outEntries) {
    outEntries.clear();
    HKEY hKey = NULL;
    LONG r = RegOpenKeyExW(HKEY_LOCAL_MACHINE, REG_PERSIST_SUBKEY, 0, KEY_READ, &hKey);
    if (r != ERROR_SUCCESS) return true; // treat missing as empty
    DWORD type=0, dataSize=0;
    r = RegQueryValueExW(hKey, PPL_ORIGINAL_PROT_LIST_NAME, NULL, &type, NULL, &dataSize);
    if (r != ERROR_SUCCESS) { RegCloseKey(hKey); if (r == ERROR_FILE_NOT_FOUND) return true; return false; }
    if (type != REG_MULTI_SZ) { RegCloseKey(hKey); return false; }
    if (dataSize == 0) { RegCloseKey(hKey); return true; }
    std::vector<wchar_t> buf(dataSize/sizeof(wchar_t));
    r = RegQueryValueExW(hKey, PPL_ORIGINAL_PROT_LIST_NAME, NULL, NULL, reinterpret_cast<LPBYTE>(buf.data()), &dataSize);
    RegCloseKey(hKey);
    if (r != ERROR_SUCCESS) return false;
    size_t idx=0, wcCount=dataSize/sizeof(wchar_t);
    while (idx < wcCount) {
        if (buf[idx] == L'\0') { ++idx; continue; }
        std::wstring line(&buf[idx]);
        idx += line.size()+1;
        size_t eq = line.find(L'='); if (eq == std::wstring::npos) continue;
        std::wstring key = line.substr(0, eq);
        std::wstring val = line.substr(eq+1);
        size_t c1 = key.find(L':'); if (c1==std::wstring::npos) continue;
        size_t c2 = key.find(L':', c1+1); if (c2==std::wstring::npos) continue;
        std::wstring pidPart = key.substr(0, c1);
        std::wstring highPart = key.substr(c1+1, c2-c1-1);
        std::wstring lowPart = key.substr(c2+1);
        DWORD pid=0, hi=0, lo=0, prot=0;
        swscanf_s(pidPart.c_str(), L"%lx", &pid);
        swscanf_s(highPart.c_str(), L"%lx", &hi);
        swscanf_s(lowPart.c_str(), L"%lx", &lo);
        swscanf_s(val.c_str(), L"%lx", &prot);
        outEntries.emplace_back(pid, hi, lo, prot);
    }
    return true;
}

bool RegistryStore::WritePplOriginalProt(const std::vector<std::tuple<DWORD, DWORD, DWORD, DWORD>>& entries) {
    std::vector<wchar_t> buf;
    for (auto &t : entries) {
        DWORD pid = std::get<0>(t);
        DWORD hi = std::get<1>(t);
        DWORD lo = std::get<2>(t);
        DWORD prot = std::get<3>(t);
        wchar_t header[64]; _snwprintf_s(header, _TRUNCATE, L"%08lX:%08lX:%08lX=%08lX", pid, hi, lo, prot);
        std::wstring line = header;
        buf.insert(buf.end(), line.c_str(), line.c_str() + line.size());
        buf.push_back(L'\0');
    }
    if (buf.empty() || buf.back() != L'\0') buf.push_back(L'\0');
    buf.push_back(L'\0');
    HKEY hKey = NULL; DWORD disp=0;
    LONG r = RegCreateKeyExW(HKEY_LOCAL_MACHINE, REG_PERSIST_SUBKEY, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, &disp);
    if (r != ERROR_SUCCESS) return false;
    LONG rr = RegSetValueExW(hKey, PPL_ORIGINAL_PROT_LIST_NAME, 0, REG_MULTI_SZ, reinterpret_cast<const BYTE*>(buf.data()), (DWORD)(buf.size()*sizeof(wchar_t)));
    RegCloseKey(hKey);
    return rr == ERROR_SUCCESS;
}

bool RegistryStore::AddPplOriginalProt(DWORD pid, DWORD hi, DWORD lo, DWORD prot) {
    // Merge behavior: replace existing entry for same PID:HI:LO
    std::vector<std::tuple<DWORD, DWORD, DWORD, DWORD>> entries;
    ReadPplOriginalProt(entries); // treat failure as empty
    bool replaced = false;
    for (auto &e : entries) {
        if (std::get<0>(e)==pid && std::get<1>(e)==hi && std::get<2>(e)==lo) { std::get<3>(e)=prot; replaced=true; break; }
    }
    if (!replaced) entries.emplace_back(pid, hi, lo, prot);
    return WritePplOriginalProt(entries);
}

bool RegistryStore::GetPplOriginalProt(DWORD pid, DWORD hi, DWORD lo, DWORD& outProt) {
    outProt = 0;
    std::vector<std::tuple<DWORD, DWORD, DWORD, DWORD>> entries;
    if (!ReadPplOriginalProt(entries)) return false;
    for (auto &e : entries) {
        if (std::get<0>(e)==pid && std::get<1>(e)==hi && std::get<2>(e)==lo) { outProt = std::get<3>(e); return true; }
    }
    return false;
}

bool RegistryStore::RemovePplOriginalProt(DWORD pid, DWORD hi, DWORD lo) {
    std::vector<std::tuple<DWORD, DWORD, DWORD, DWORD>> entries;
    if (!ReadPplOriginalProt(entries)) return false;
    std::vector<std::tuple<DWORD, DWORD, DWORD, DWORD>> out;
    bool removed=false;
    for (auto &e : entries) {
        if (!removed && std::get<0>(e)==pid && std::get<1>(e)==hi && std::get<2>(e)==lo) { removed=true; continue; }
        out.push_back(e);
    }
    if (!removed) return true;
    return WritePplOriginalProt(out);
}

bool RegistryStore::RemoveProcHookEntry(DWORD pid, DWORD filetimeHi, DWORD filetimeLo, int hookId) {
    // Read only entries matching the provided PID + FILETIME so we don't load others.
    std::vector<std::tuple<DWORD, DWORD, DWORD, int, DWORD, unsigned long long, unsigned long long, unsigned long long, std::wstring>> entries;
    if (!ReadProcHookList(pid, filetimeHi, filetimeLo, entries)) return false;
    std::vector<std::tuple<DWORD, DWORD, DWORD, int, DWORD, unsigned long long, unsigned long long, unsigned long long, std::wstring>> all;
    // Load all entries (unfiltered) so we can rewrite the full list without the removed item.
    if (!ReadProcHookList(all)) return false;
    bool removed = false;
    for (auto &t : all) {
        DWORD p = std::get<0>(t);
        DWORD hi = std::get<1>(t);
        DWORD lo = std::get<2>(t);
        int hid = std::get<3>(t);
        if (!removed && p == pid && hi == filetimeHi && lo == filetimeLo && hid == hookId) {
            removed = true; continue;
        }
        // keep
        ;
    }
    if (!removed) return true; // nothing to do
    // Build new vector excluding the removed item
    std::vector<std::tuple<DWORD, DWORD, DWORD, int, DWORD, unsigned long long, unsigned long long, unsigned long long, std::wstring>> out;
    out.reserve(all.size());
    for (auto &t : all) {
        DWORD p = std::get<0>(t);
        DWORD hi = std::get<1>(t);
        DWORD lo = std::get<2>(t);
        int hid = std::get<3>(t);
        if (p == pid && hi == filetimeHi && lo == filetimeLo && hid == hookId) continue;
        out.push_back(t);
    }
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

// Whitelist Paths (REG_MULTI_SZ of NT paths)
bool RegistryStore::ReadWhitelistPaths(std::vector<std::wstring>& outNtPaths) {
    outNtPaths.clear();
    HKEY hKey = NULL;
    LONG r = RegOpenKeyExW(HKEY_LOCAL_MACHINE, REG_PERSIST_SUBKEY, 0, KEY_READ, &hKey);
    if (r != ERROR_SUCCESS) return true; // treat missing as empty
    DWORD type=0, dataSize=0;
    r = RegQueryValueExW(hKey, WHITELIST_PATHS_NAME, NULL, &type, NULL, &dataSize);
    if (r != ERROR_SUCCESS) { RegCloseKey(hKey); if (r == ERROR_FILE_NOT_FOUND) return true; return false; }
    if (type != REG_MULTI_SZ) { RegCloseKey(hKey); return false; }
    if (dataSize == 0) { RegCloseKey(hKey); return true; }
    std::vector<wchar_t> buf(dataSize/sizeof(wchar_t));
    r = RegQueryValueExW(hKey, WHITELIST_PATHS_NAME, NULL, NULL, reinterpret_cast<LPBYTE>(buf.data()), &dataSize);
    RegCloseKey(hKey);
    if (r != ERROR_SUCCESS) return false;
    size_t idx=0, wcCount=dataSize/sizeof(wchar_t);
    while (idx < wcCount) {
        if (buf[idx] == L'\0') { ++idx; continue; }
        std::wstring s(&buf[idx]);
        outNtPaths.push_back(s);
        idx += s.size() + 1;
    }
    return true;
}

static bool WriteMultiSz(HKEY root, const wchar_t* subkey, const wchar_t* valueName, const std::vector<std::wstring>& entries) {
    std::vector<wchar_t> buf;
    for (auto &s : entries) { buf.insert(buf.end(), s.c_str(), s.c_str() + s.size()); buf.push_back(L'\0'); }
    if (buf.empty() || buf.back() != L'\0') buf.push_back(L'\0');
    buf.push_back(L'\0');
    HKEY hKey = NULL; DWORD disp=0;
    LONG r = RegCreateKeyExW(root, subkey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, &disp);
    if (r != ERROR_SUCCESS) return false;
    LONG rr = RegSetValueExW(hKey, valueName, 0, REG_MULTI_SZ, reinterpret_cast<const BYTE*>(buf.data()), (DWORD)(buf.size()*sizeof(wchar_t)));
    RegCloseKey(hKey);
    return rr == ERROR_SUCCESS;
}

bool RegistryStore::AddWhitelistPath(const std::wstring& ntPath) {
    std::vector<std::wstring> paths; if (!ReadWhitelistPaths(paths)) return false;
    for (auto &p : paths) { if (_wcsicmp(p.c_str(), ntPath.c_str()) == 0) return true; }
    paths.push_back(ntPath);
    return WriteMultiSz(HKEY_LOCAL_MACHINE, REG_PERSIST_SUBKEY, WHITELIST_PATHS_NAME, paths);
}

bool RegistryStore::RemoveWhitelistPath(const std::wstring& ntPath) {
    std::vector<std::wstring> paths; if (!ReadWhitelistPaths(paths)) return false;
    std::vector<std::wstring> out; bool removed=false;
    for (auto &p : paths) { if (!removed && _wcsicmp(p.c_str(), ntPath.c_str()) == 0) { removed=true; continue; } out.push_back(p); }
    if (!removed) return true;
    if (out.empty()) {
        HKEY hKey = NULL; LONG r = RegOpenKeyExW(HKEY_LOCAL_MACHINE, REG_PERSIST_SUBKEY, 0, KEY_SET_VALUE, &hKey);
        if (r == ERROR_SUCCESS) { RegDeleteValueW(hKey, WHITELIST_PATHS_NAME); RegCloseKey(hKey); }
        return true;
    }
    return WriteMultiSz(HKEY_LOCAL_MACHINE, REG_PERSIST_SUBKEY, WHITELIST_PATHS_NAME, out);
}

// Whitelist Hashes (REG_MULTI_SZ of hex 64-bit hash strings)
bool RegistryStore::ReadWhitelistHashes(std::vector<unsigned long long>& outHashes) {
    outHashes.clear();
    HKEY hKey = NULL;
    LONG r = RegOpenKeyExW(HKEY_LOCAL_MACHINE, REG_PERSIST_SUBKEY, 0, KEY_READ, &hKey);
    if (r != ERROR_SUCCESS) return true; // treat missing as empty
    DWORD type=0, dataSize=0;
    r = RegQueryValueExW(hKey, WHITELIST_HASHES_NAME, NULL, &type, NULL, &dataSize);
    if (r != ERROR_SUCCESS) { RegCloseKey(hKey); if (r == ERROR_FILE_NOT_FOUND) return true; return false; }
    if (type != REG_MULTI_SZ) { RegCloseKey(hKey); return false; }
    if (dataSize == 0) { RegCloseKey(hKey); return true; }
    std::vector<wchar_t> buf(dataSize/sizeof(wchar_t));
    r = RegQueryValueExW(hKey, WHITELIST_HASHES_NAME, NULL, NULL, reinterpret_cast<LPBYTE>(buf.data()), &dataSize);
    RegCloseKey(hKey);
    if (r != ERROR_SUCCESS) return false;
    size_t idx=0, wcCount=dataSize/sizeof(wchar_t);
    while (idx < wcCount) {
        if (buf[idx] == L'\0') { ++idx; continue; }
        std::wstring s(&buf[idx]);
        unsigned long long hv=0; swscanf_s(s.c_str(), L"%llx", &hv);
        outHashes.push_back(hv);
        idx += s.size() + 1;
    }
    return true;
}

bool RegistryStore::AddWhitelistHash(unsigned long long hash) {
    std::vector<unsigned long long> hashes; if (!ReadWhitelistHashes(hashes)) return false;
    for (auto &h : hashes) { if (h == hash) return true; }
    hashes.push_back(hash);
    // format to strings
    std::vector<std::wstring> strs; strs.reserve(hashes.size());
    for (auto &h : hashes) { wchar_t b[32]; _snwprintf_s(b, _TRUNCATE, L"%016llX", h); strs.emplace_back(b); }
    return WriteMultiSz(HKEY_LOCAL_MACHINE, REG_PERSIST_SUBKEY, WHITELIST_HASHES_NAME, strs);
}

bool RegistryStore::RemoveWhitelistHash(unsigned long long hash) {
    std::vector<unsigned long long> hashes; if (!ReadWhitelistHashes(hashes)) return false;
    std::vector<unsigned long long> out; bool removed=false;
    for (auto &h : hashes) { if (!removed && h == hash) { removed=true; continue; } out.push_back(h); }
    if (!removed) return true;
    if (out.empty()) {
        HKEY hKey = NULL; LONG r = RegOpenKeyExW(HKEY_LOCAL_MACHINE, REG_PERSIST_SUBKEY, 0, KEY_SET_VALUE, &hKey);
        if (r == ERROR_SUCCESS) { RegDeleteValueW(hKey, WHITELIST_HASHES_NAME); RegCloseKey(hKey); }
        return true;
    }
    std::vector<std::wstring> strs; strs.reserve(out.size());
    for (auto &h : out) { wchar_t b[32]; _snwprintf_s(b, _TRUNCATE, L"%016llX", h); strs.emplace_back(b); }
    return WriteMultiSz(HKEY_LOCAL_MACHINE, REG_PERSIST_SUBKEY, WHITELIST_HASHES_NAME, strs);
}
