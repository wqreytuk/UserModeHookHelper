// dllmain.cpp : Plugin entry for KrnlModeHookHlp.

#include "pch.h"
#include <vector>
#include <string>
#include <algorithm>
#include <CommCtrl.h>
#include <commdlg.h>
#include <TlHelp32.h>
#include <cwctype>
#include <cwchar>
#include <cstdio>
#include <cstdlib>
#include <shlwapi.h>
#include <intrin.h>
#include "resource.h"
#include "HookServices.h"
#include "KmhhCtx.h"
#include "Log.h"
#include "HookRow.h"
#include "SharedMacroDef.h"
#include "../controller/HookCoreLib/HookCore.h"
#include "Helper.h"
#include "MacroDef.h"
#include "Kernel.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "Shlwapi.lib")

namespace {
    struct HookSequenceEntry {
        std::wstring module;
        std::wstring offset;
        std::wstring dllPath;
        std::wstring exportName;
    };

    struct HookSequenceResult {
        HookSequenceEntry entry;
        HookRow row{};
        bool success = false;
        std::wstring status;
        ULONGLONG address = 0;
    };

    struct HookSequenceContext {
        DWORD pid = 0;
        IHookServices* services = nullptr;
        ULONG64 hookIdMask[4]{};
        std::vector<HookRow> persisted;
    };

    static const wchar_t kPluginBaseKey[] = REG_PERSIST_SUBKEY L"\\Plugins\\KrnlModeHookHlp";
    static const wchar_t kPluginHookValue[] = L"HookList";
    static const wchar_t kPluginBootValue[] = L"CacheBootTime";

    std::wstring BuildAddressSubKeyName(ULONGLONG address) {
        wchar_t suffix[32];
        _snwprintf_s(suffix, _TRUNCATE, L"Hook_%016llX", address);
        return std::wstring(suffix);
    }

    void DeletePluginKey(const std::wstring& path) {
        LONG rc = RegDeleteTreeW(HKEY_LOCAL_MACHINE, path.c_str());
        if (rc != ERROR_SUCCESS && rc != ERROR_FILE_NOT_FOUND) {
            SHDeleteKeyW(HKEY_LOCAL_MACHINE, path.c_str());
        }
    }

    bool QueryBootFileTime(ULONGLONG& outFt) {
        FILETIME ftNow{};
        GetSystemTimeAsFileTime(&ftNow);
        ULARGE_INTEGER now{};
        now.LowPart = ftNow.dwLowDateTime;
        now.HighPart = ftNow.dwHighDateTime;
        const ULONGLONG ticksPerMs = 10000ULL;
        ULONGLONG uptimeMs = GetTickCount64();
        outFt = now.QuadPart - (uptimeMs * ticksPerMs);
        return true;
    }

    bool ParseHookValue(const std::wstring& value, HookRow& outRow) {
        size_t start = 0;
        auto nextField = [&](std::wstring& field) -> bool {
            size_t colon = value.find(L':', start);
            if (colon == std::wstring::npos) return false;
            field = value.substr(start, colon - start);
            start = colon + 1;
            return true;
        };
        std::wstring hookIdStr, oriLenStr, oriAddrStr, trampStr;
        if (!nextField(hookIdStr) || !nextField(oriLenStr) || !nextField(oriAddrStr) || !nextField(trampStr)) return false;
        std::wstring payload = value.substr(start);
        unsigned int hookId = 0;
        DWORD oriLen = 0;
        unsigned long long oriAddr = 0;
        unsigned long long trampPit = 0;
        if (swscanf_s(hookIdStr.c_str(), L"%x", &hookId) != 1) return false;
        if (swscanf_s(oriLenStr.c_str(), L"%x", &oriLen) != 1) return false;
        if (swscanf_s(oriAddrStr.c_str(), L"%llx", &oriAddr) != 1) return false;
        if (swscanf_s(trampStr.c_str(), L"%llx", &trampPit) != 1) return false;
        HookRow row{};
        row.id = static_cast<int>(hookId);
        row.ori_asm_code_len = oriLen;
        row.ori_asm_code_addr = oriAddr;
        row.trampoline_pit = trampPit;
        size_t bar = payload.find(L'|');
        if (bar == std::wstring::npos) {
            row.module = payload;
            row.expFunc.clear();
        } else {
            row.module = payload.substr(0, bar);
            row.expFunc = payload.substr(bar + 1);
        }
        outRow = std::move(row);
        return true;
    }

    bool LoadPersistedHookRows(DWORD pid, std::vector<HookRow>& outRows) {
        UNREFERENCED_PARAMETER(pid);
        outRows.clear();
        ULONGLONG bootFt = 0;
        QueryBootFileTime(bootFt);
        HKEY hBase = nullptr;
        LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kPluginBaseKey, 0, KEY_READ | KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &hBase);
        if (rc == ERROR_FILE_NOT_FOUND) return true;
        if (rc != ERROR_SUCCESS) {
            KMHHLog(L"Failed to open plugin cache key (%ld)", rc);
            return false;
        }
        DWORD type = 0; ULONGLONG storedBoot = 0; DWORD size = sizeof(storedBoot);
        bool stale = (RegQueryValueExW(hBase, kPluginBootValue, nullptr, &type, reinterpret_cast<LPBYTE>(&storedBoot), &size) != ERROR_SUCCESS) ||
            type != REG_QWORD || storedBoot != bootFt;
        if (stale) {
            RegCloseKey(hBase);
            DeletePluginKey(kPluginBaseKey);
            return true;
        }
        for (DWORD index = 0;; ++index) {
            wchar_t subName[64];
            DWORD subLen = _countof(subName);
            FILETIME lastWrite{};
            rc = RegEnumKeyExW(hBase, index, subName, &subLen, nullptr, nullptr, nullptr, &lastWrite);
            if (rc == ERROR_NO_MORE_ITEMS) break;
            if (rc != ERROR_SUCCESS) continue;
            ULONGLONG address = 0;
            if (swscanf_s(subName, L"Hook_%llx", &address) != 1) continue;
            HKEY hSub = nullptr;
            if (RegOpenKeyExW(hBase, subName, 0, KEY_READ | KEY_WOW64_64KEY, &hSub) != ERROR_SUCCESS) continue;
            DWORD valueType = 0; DWORD valueSize = 0;
            if (RegQueryValueExW(hSub, kPluginHookValue, nullptr, &valueType, nullptr, &valueSize) != ERROR_SUCCESS || valueType != REG_SZ || valueSize == 0) {
                RegCloseKey(hSub);
                continue;
            }
            std::vector<wchar_t> buffer(valueSize / sizeof(wchar_t));
            if (RegQueryValueExW(hSub, kPluginHookValue, nullptr, nullptr, reinterpret_cast<LPBYTE>(buffer.data()), &valueSize) != ERROR_SUCCESS) {
                RegCloseKey(hSub);
                continue;
            }
            RegCloseKey(hSub);
            std::wstring value(buffer.data());
            HookRow row{};
            if (!ParseHookValue(value, row)) continue;
            row.address = address;
            outRows.push_back(std::move(row));
        }
        RegCloseKey(hBase);
        return true;
    }

    bool SavePersistedHookRows(DWORD pid, const std::vector<HookRow>& rows) {
        UNREFERENCED_PARAMETER(pid);
        DeletePluginKey(std::wstring(kPluginBaseKey));
        if (rows.empty()) return true;
        HKEY hBase = nullptr; DWORD disp = 0;
        LONG rc = RegCreateKeyExW(HKEY_LOCAL_MACHINE, kPluginBaseKey, 0, nullptr, REG_OPTION_NON_VOLATILE,
            KEY_WRITE | KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, nullptr, &hBase, &disp);
        if (rc != ERROR_SUCCESS) {
            KMHHLog(L"Failed to create plugin cache root (%ld)", rc);
            return false;
        }
        ULONGLONG bootFt = 0;
        QueryBootFileTime(bootFt);
        RegSetValueExW(hBase, kPluginBootValue, 0, REG_QWORD, reinterpret_cast<const BYTE*>(&bootFt), sizeof(bootFt));
        for (const auto& row : rows) {
            if (row.address == 0 || row.module.empty()) continue;
            std::wstring subName = BuildAddressSubKeyName(row.address);
            HKEY hSub = nullptr; DWORD dispSub = 0;
            rc = RegCreateKeyExW(hBase, subName.c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_WOW64_64KEY, nullptr, &hSub, &dispSub);
            if (rc != ERROR_SUCCESS) {
                KMHHLog(L"Failed to create subkey %s (%ld)", subName.c_str(), rc);
                continue;
            }
            wchar_t header[256];
            _snwprintf_s(header, _TRUNCATE, L"%08X:%08X:%016llX:%016llX:", (unsigned int)(row.id & 0xFFFFFFFF),
                (unsigned int)row.ori_asm_code_len, row.ori_asm_code_addr, row.trampoline_pit);
            std::wstring value = header;
            value.append(row.module);
            if (!row.expFunc.empty()) {
                value.push_back(L'|');
                value.append(row.expFunc);
            }
            DWORD bytes = static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t));
            rc = RegSetValueExW(hSub, kPluginHookValue, 0, REG_SZ, reinterpret_cast<const BYTE*>(value.c_str()), bytes);
            if (rc != ERROR_SUCCESS) {
                KMHHLog(L"Failed to save hook entry for 0x%llX (err %ld)", row.address, rc);
            }
            RegCloseKey(hSub);
        }
        RegCloseKey(hBase);
        return true;
    }

    struct KmhhCreateContext {
        HWND parent = nullptr;
        IHookServices* services = nullptr;
    };

    HINSTANCE g_hInstance = nullptr;
    HWND g_hDialog = nullptr;
    HWND g_hHookList = nullptr;
    IHookServices* g_services = nullptr;

    void EnsureCommonControls() {
        static bool initialized = false;
        if (initialized) return;
        INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_LISTVIEW_CLASSES };
        InitCommonControlsEx(&icc);
        initialized = true;
    }

    void CenterRelativeToParent(HWND hwnd, HWND parent) {
        if (!IsWindow(hwnd)) return;
        RECT rcDlg{}; GetWindowRect(hwnd, &rcDlg);
        int dlgW = rcDlg.right - rcDlg.left;
        int dlgH = rcDlg.bottom - rcDlg.top;
        HMONITOR monitor = MonitorFromWindow(parent && IsWindow(parent) ? parent : hwnd, MONITOR_DEFAULTTONEAREST);
        MONITORINFO mi{ sizeof(mi) };
        if (!GetMonitorInfoW(monitor, &mi)) {
            SystemParametersInfoW(SPI_GETWORKAREA, 0, &mi.rcWork, 0);
        }
        RECT work = mi.rcWork;
        int x = work.left + ((work.right - work.left) - dlgW) / 2;
        int y = work.top + ((work.bottom - work.top) - dlgH) / 2;
        MoveWindow(hwnd, x, y, dlgW, dlgH, FALSE);
    }

    void SetupHookListColumns(HWND list) {
        ListView_SetExtendedListViewStyleEx(list, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES,
            LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
        LVCOLUMNW col{}; col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        col.pszText = const_cast<LPWSTR>(L"Hook ID"); col.cx = 70; col.iSubItem = 0;
        ListView_InsertColumn(list, 0, &col);
        col.pszText = const_cast<LPWSTR>(L"Address"); col.cx = 120; col.iSubItem = 1;
        ListView_InsertColumn(list, 1, &col);
        col.pszText = const_cast<LPWSTR>(L"Target"); col.cx = 150; col.iSubItem = 2;
        ListView_InsertColumn(list, 2, &col);
        col.pszText = const_cast<LPWSTR>(L"State"); col.cx = 80; col.iSubItem = 3;
        ListView_InsertColumn(list, 3, &col);
    }

    void Trim(std::wstring& s) {
        size_t start = 0;
        while (start < s.size() && iswspace(s[start])) ++start;
        size_t end = s.size();
        while (end > start && iswspace(s[end - 1])) --end;
        s = s.substr(start, end - start);
    }

    std::wstring NormalizePath(const std::wstring& input) {
        if (input.empty()) return input;
        wchar_t buffer[MAX_PATH] = {};
        if (_wfullpath(buffer, input.c_str(), _countof(buffer))) return buffer;
        return input;
    }

    std::wstring ExtractFileName(const std::wstring& path) {
        if (path.empty()) return path;
        const wchar_t* name = PathFindFileNameW(path.c_str());
        return name ? name : path;
    }

    bool PromptHookSequenceFile(HWND hwnd, std::wstring& outPath) {
        wchar_t buffer[MAX_PATH] = {};
        OPENFILENAMEW ofn{};
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = hwnd;
        ofn.lpstrFilter = L"Hook Sequence (*.hookseq)\0*.hookseq\0All Files (*.*)\0*.*\0";
        ofn.lpstrFile = buffer;
        ofn.nMaxFile = _countof(buffer);
        ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
        ofn.lpstrDefExt = L"hookseq";
        if (!GetOpenFileNameW(&ofn)) return false;
        outPath.assign(buffer);
        return true;
    }

    bool LoadHookSequenceFile(const std::wstring& path, DWORD& targetPid, std::vector<HookSequenceEntry>& entries, std::wstring& error) {
        entries.clear();
        targetPid = 0;
		FILE* f = nullptr;
		_wfopen_s(&f,path.c_str(), L"rt, ccs=UNICODE");
        if (!f)
			_wfopen_s(&f,path.c_str(), L"rt, ccs=UTF-8");
        if (!f) {
			KMHHLog(L"Failed to open hook sequence file, Error=0x%x\n", GetLastError());
            return false;
        }
        wchar_t line[1024];
        HookSequenceEntry current;
        auto flushEntry = [&]() {
            if (!current.module.empty() || !current.offset.empty() || !current.dllPath.empty() || !current.exportName.empty()) {
                entries.push_back(current);
                current = HookSequenceEntry{};
            }
        };
        while (fgetws(line, _countof(line), f)) {
            std::wstring s(line);
            while (!s.empty() && (s.back() == L'\r' || s.back() == L'\n')) s.pop_back();
            Trim(s);
            if (s.empty()) continue;
            if (s[0] == L'#' || (s.size() >= 2 && s[0] == L'/' && s[1] == L'/')) continue;
            if (_wcsicmp(s.c_str(), L"[hook]") == 0) { flushEntry(); continue; }
            size_t eq = s.find(L'=');
            if (eq == std::wstring::npos) continue;
            std::wstring key = s.substr(0, eq);
            std::wstring val = s.substr(eq + 1);
            Trim(key); Trim(val);
            if (_wcsicmp(key.c_str(), L"targetPid") == 0) targetPid = (DWORD)_wtol(val.c_str());
            else if (_wcsicmp(key.c_str(), L"module") == 0) current.module = val;
            else if (_wcsicmp(key.c_str(), L"offset") == 0) current.offset = val;
            else if (_wcsicmp(key.c_str(), L"dllPath") == 0) current.dllPath = NormalizePath(val);
            else if (_wcsicmp(key.c_str(), L"export") == 0) current.exportName = val;
        }
        fclose(f);
        flushEntry();
        if (entries.empty()) {
            error = L"No hooks found in sequence file.";
            return false;
        }
        return true;
    }

    bool EnsureProcessAlive(DWORD pid) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return false;
        PROCESSENTRY32W pe{ sizeof(pe) };
        bool found = false;
        if (Process32FirstW(snap, &pe)) {
            do {
                if (pe.th32ProcessID == pid) { found = true; break; }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
        return found;
    }

    ULONGLONG ParseAddressText(const std::wstring& input, bool& ok) {
        ok = false;
        if (input.empty()) return 0ULL;
        std::wstring t(input);
        for (auto& c : t) c = towlower(c);
        if (t.rfind(L"0x", 0) == 0) t = t.substr(2);
        std::wstring stripped;
        stripped.reserve(t.size());
        for (wchar_t c : t) if (c != L'`') stripped.push_back(c);
        for (wchar_t c : stripped) {
            if (!(iswdigit(c) || (c >= L'a' && c <= L'f'))) return 0ULL;
        }
        wchar_t* end = nullptr;
        ULONGLONG v = wcstoull(stripped.c_str(), &end, 16);
        if (end && *end == 0) { ok = true; return v; }
        return 0ULL;
    }

    bool InitializeHookContext(DWORD pid, IHookServices* services, HookSequenceContext& ctx, std::wstring& error) {
        ctx = HookSequenceContext{};
        ctx.pid = pid;
        ctx.services = services;

        if (!LoadPersistedHookRows(pid, ctx.persisted)) {
            error = L"Failed to read plugin persistence.";
            return false;
        }
        for (const auto& row : ctx.persisted) {
            if (row.id >= 0 && row.id < (int)TRAMPOLINE_EXP_NUM_MAX) {
                _bittestandset((LONG*)ctx.hookIdMask, row.id);
            }
        }
        return true;
    }

    int AllocateHookId(HookSequenceContext& ctx) {
        for (int i = 0; i < (int)TRAMPOLINE_EXP_NUM_MAX; ++i) {
            if (!_bittest((LONG*)ctx.hookIdMask, i)) {
                _bittestandset((LONG*)ctx.hookIdMask, i);
                return i;
            }
        }
        return -1;
    }

    void ReleaseHookId(HookSequenceContext& ctx, int id) {
        if (id < 0) return;
        _bittestandreset((LONG*)ctx.hookIdMask, id);
    }

    bool CopyHookDllToTemp(const std::wstring& source, std::wstring& outPath, std::wstring& outModuleName) {
        wchar_t exePath[MAX_PATH] = {};
        if (!GetModuleFileNameW(nullptr, exePath, _countof(exePath))) {
            outPath = source;
            outModuleName = ExtractFileName(source);
            return false;
        }
        std::wstring folder(exePath);
        size_t pos = folder.find_last_of(L"\\/");
        folder = (pos == std::wstring::npos) ? L"." : folder.substr(0, pos);
        folder += L"\\" HOOK_CODE_TEMP_DIR_NAME;
        if (!CreateDirectoryW(folder.c_str(), nullptr)) {
            if (GetLastError() != ERROR_ALREADY_EXISTS) {
                outPath = source;
                outModuleName = ExtractFileName(source);
                return false;
            }
        }
        SYSTEMTIME st; GetLocalTime(&st);
        wchar_t ts[64];
        swprintf(ts, _countof(ts), L"%04d%02d%02d_%02d%02d%02d_%03d",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        std::wstring newName = std::wstring(ts) + L"_" + ExtractFileName(source);
        std::wstring dest = folder + L"\\" + newName;
        if (CopyFileW(source.c_str(), dest.c_str(), FALSE)) {
            outPath = dest;
            outModuleName = newName;
            return true;
        }
        outPath = source;
        outModuleName = ExtractFileName(source);
        return false;
    }

    void PersistHookRows(const HookSequenceContext& ctx) {
        if (!SavePersistedHookRows(ctx.pid, ctx.persisted)) {
            KMHHLog(L"Failed to update kernel hook cache for pid %u", ctx.pid);
        }
    }

	bool RemoveExistingHook(HookSequenceContext& ctx, ULONGLONG address, std::wstring& error) {
		auto it = std::find_if(ctx.persisted.begin(), ctx.persisted.end(), [&](const HookRow& row) {
			return row.address == address;
		});
		if (it == ctx.persisted.end()) return true;

		// remove hook
		{
			UCHAR* ori_asm_code = (UCHAR*)malloc(it->ori_asm_code_len);
			KRNL::ReadPrimitive((LPVOID)it->ori_asm_code_addr, ori_asm_code, it->ori_asm_code_len);
			KRNL::WritePrimitive((LPVOID)it->address, ori_asm_code, it->ori_asm_code_len);
		}

		ReleaseHookId(ctx, it->id);
		ctx.persisted.erase(it);
		return true;
	}

	bool ApplyHookEntry(HookSequenceContext& ctx, const HookSequenceEntry& entry, HookRow& outRow, std::wstring& error) {
		if (!ctx.services) {
			error = L"Hook services unavailable.";
			return false;
		}
		if (entry.module.empty() || entry.offset.empty() || entry.dllPath.empty() || entry.exportName.empty()) {
			error = L"Invalid hook entry (missing fields).";
			return false;
		}
		// only support x64 kernel hook for now
		bool is64 = TRUE;
		bool dll64 = false;
		if (!ctx.services->CheckPeArch(entry.dllPath.c_str(), dll64)) {
			error = L"Hook DLL architecture check failed.";
			return false;
		}
		if (dll64 != is64) {
			error = L"Hook DLL architecture mismatches target process.";
			return false;
		}
		char exportNameA[MAX_PATH] = {};
		if (!ctx.services->ConvertWcharToChar(entry.exportName.c_str(), exportNameA, _countof(exportNameA))) {
			error = L"Failed to convert export name.";
			return false;
		}
		DWORD hookCodeOffset = 0;
		if (!ctx.services->CheckExportFromFile(entry.dllPath.c_str(), exportNameA, &hookCodeOffset)) {
			KMHHLog(L"Export not found in hook DLL, Path=%s\n", entry.dllPath.c_str());
			return false;
		}
		if (!hookCodeOffset) {
			KMHHLog(L"Hook export offset is zero, can NOT continue\n");
			return false;
		}
		DWORD64 moduleBase = 0;
		
		{
			char a[MAX_PATH] = { 0 };
			Helper::ConvertWcharToChar(entry.module.c_str(), a, MAX_PATH);
			KRNL::GetDriverBase(a, (PVOID*)&moduleBase);
		}
		if (!moduleBase) {
			KMHHLog(L"failed to get target module base\n");
			return false;
		}
		bool offsetOk = false;
		ULONGLONG offset = ParseAddressText(entry.offset, offsetOk);
		if (!offsetOk) {
			error = L"Invalid offset format.";
			return false;
		}
		ULONGLONG address = moduleBase + offset;
		if (!RemoveExistingHook(ctx, address, error)) {
			return false;
		}
		std::wstring injectPath = entry.dllPath;
		std::wstring runtimeDllName;
		CopyHookDllToTemp(entry.dllPath, injectPath, runtimeDllName);
	 
		DWORD64 hookDllBase = 0;
		// load injectPath to kernel
		if (!Helper::InstallAndStartDriverService(runtimeDllName, injectPath)) {
			KMHHLog(L"Failed to call Helper::InstallAndStartDriverService, target Path=%s\n", injectPath.c_str());
			return false;
		}
		{
			char a[MAX_PATH] = { 0 };
			Helper::ConvertWcharToChar(runtimeDllName.c_str(), a, MAX_PATH);
			KRNL::GetDriverBase(a, (PVOID*)&hookDllBase);
		}
        if (!hookDllBase) {
			KMHHLog(L"failed to get hookDllBase\n");
            return false;
        }
        int hookId = AllocateHookId(ctx);
        if (hookId < 0) {
			KMHHLog(L"No hook IDs available\n");
            return false;
        }
        DWORD oriLen = 0;
        PVOID trampolinePit = nullptr;
        PVOID oriAsmAddr = nullptr;
       
		DWORD stage_1_func_offset = 0;
		DWORD stage_2_func_offset = 0;
		DWORD ori_asm_code_len = 0;
		DWORD64 trampoline_pit = 0;
		// get stage 1 and stage 2 export function address
		{
			char stage_1_func_name[64] = { 0 };
			sprintf_s(stage_1_func_name, "trampoline_stage_1_num_%03d", hookId);
			if (!ctx.services->CheckExportFromFile(entry.dllPath.c_str(), stage_1_func_name, &stage_1_func_offset)) {
				KMHHLog(L"STAGE_1 required export function not found in dll Path=%s\n", entry.dllPath.c_str());
				return false;
			}

			char stage_2_func_name[64] = { 0 };
			sprintf_s(stage_2_func_name, "trampoline_stage_2_num_%03d", hookId);
			if (!ctx.services->CheckExportFromFile(entry.dllPath.c_str(), stage_2_func_name, &stage_2_func_offset)) {
				KMHHLog(L"STAGE_2 required export function not found in dll Path=%s\n", entry.dllPath.c_str());
				return false;
			}

			oriAsmAddr = (PVOID)((DWORD64)KmhhCtx_GetTrampolinehDrvBase() + stage_2_func_offset + OFFSET_FOR_ORIGINAL_ASM_CODE_SAVE);
		}
		// apply hook
		{
			PVOID hook_point =(PVOID) address;

// #define DEBUG
#ifdef DEBUG

			{
				// remove hook first
				UCHAR* ori_asm_code = (UCHAR*)malloc(0xa);
				KRNL::ReadPrimitive((LPVOID)((DWORD64)LdrCtx_GetToDeskBase() + TO_DESK_TRAMPOLINE_CODE_STAGE_2_OFFSET + OFFSET_FOR_ORIGINAL_ASM_CODE_SAVE),
					ori_asm_code, 0xa);
				KRNL::WritePrimitive((LPVOID)hook_point, ori_asm_code, 0xa);
			}
#endif //  DEBUG

			DWORD64 hook_code_addr = hookDllBase + hookCodeOffset;
		
			// I need to check if the trampoline address is exceeding 4GB range, if so, I need to use nt!DbgPrompt
			// this function is exported, I saved its abs addr into KMHH context
			DWORD64 trampoline_addr = (DWORD64)KmhhCtx_GetTrampolinehDrvBase() + stage_1_func_offset 
				+ stage_0_xoreaxeaxret_size + stage_0_placeholder_size;
			DWORD64 next_rip = (DWORD64)hook_point + ff25jmpsize;
			DWORD64  distance = (next_rip > trampoline_addr) ? (next_rip - trampoline_addr) : (trampoline_addr - next_rip);
			if (distance > 0xFFFFFFFF) {
				 trampoline_pit = (DWORD64)KmhhCtx_SetDbgPromptAbsAddr + hookId * 8;
				// write trampoline address to pit
				if (!KRNL::WritePrimitive((PVOID)trampoline_pit, (PVOID)&trampoline_addr, sizeof(DWORD64))) {
					KMHHLog(L"failed to call WritePrimitive at line=%u\n", __LINE__); 
					return false;
				}
			}
			else {
			// otherwise, trampoline pit will be a fixed offset of starge_2_func_offset
				trampoline_pit = (DWORD64)KmhhCtx_GetTrampolinehDrvBase() + stage_2_func_offset + TRAMPOLINE_PIT_OFFSET_STAGE_2_FUNC;
				// write trampoline address to pit
				if (!KRNL::WritePrimitive((PVOID)trampoline_pit, (PVOID)&trampoline_addr, sizeof(DWORD64))) {
					KMHHLog(L"failed to call WritePrimitive at line=%u\n", __LINE__);
					return false;
				}
			}
			if (!HookCore::ConstructKernelTrampolineX64_Wrapper(KmhhCtx_GetHookServices(), hook_point, (PVOID)moduleBase,				KmhhCtx_GetTrampolinehDrvBase(), stage_1_func_offset, stage_2_func_offset, hook_code_addr, &ori_asm_code_len)
				) {
				KMHHLog(L"failed to call HookCore::ConstructKernelTrampolineX64_Wrapper\n");
				return false;
			}

			// install hook
			{
				UCHAR ff25[0x6] = { 0xff,0x25,0,0,0,0 };
				*(DWORD*)(ff25 + 2) = (DWORD)((DWORD64)trampoline_pit - ((DWORD64)hook_point + 0x6));
				if (!KRNL::WritePrimitive(hook_point, (void*)(ff25), 0x6)) {
					KMHHLog(L"InstallHook line number: %d\n", __LINE__);
					return FALSE;
				}
			}
		}


        HookRow row{};
        row.id = hookId;
        row.address = address;
        row.module = entry.module;
        row.expFunc = ExtractFileName(entry.dllPath) + L"!" + entry.exportName;
        row.ori_asm_code_len = ori_asm_code_len;
        row.trampoline_pit = (unsigned long long)trampoline_pit;
        row.ori_asm_code_addr = (unsigned long long)oriAsmAddr;
        ctx.persisted.push_back(row);
        outRow = row;
        return true;
    }

	bool RollbackHooks(HookSequenceContext& ctx, const std::vector<HookRow>& applied) {
		for (auto it = applied.rbegin(); it != applied.rend(); ++it) {
			// remove hook
			{
				UCHAR* ori_asm_code = (UCHAR*)malloc(it->ori_asm_code_len);
				KRNL::ReadPrimitive((LPVOID)it->ori_asm_code_addr, ori_asm_code, it->ori_asm_code_len);
				KRNL::WritePrimitive((LPVOID)it->address, ori_asm_code, it->ori_asm_code_len);
			}
			ReleaseHookId(ctx, it->id);
			auto pos = std::find_if(ctx.persisted.begin(), ctx.persisted.end(), [&](const HookRow& row) { return row.id == it->id; });
			if (pos != ctx.persisted.end()) ctx.persisted.erase(pos);
		}
		return true;
	}

    void UpdateHookList(HWND list, const std::vector<HookSequenceResult>& results) {
        if (!IsWindow(list)) return;
        ListView_DeleteAllItems(list);
        for (const auto& res : results) {
            std::wstring idText = res.success ? std::to_wstring(res.row.id) : L"-";
            wchar_t addrBuf[32] = L"-";
            ULONGLONG addr = res.success ? res.row.address : res.address;
            if (addr) swprintf(addrBuf, _countof(addrBuf), L"0x%llX", addr);
            std::wstring targetText = res.success ? res.row.expFunc : (res.entry.module + L"+" + res.entry.offset);
            LVITEMW item{};
            item.mask = LVIF_TEXT;
            item.pszText = const_cast<LPWSTR>(idText.c_str());
            int rowIndex = ListView_InsertItem(list, &item);
            ListView_SetItemText(list, rowIndex, 1, addrBuf);
            ListView_SetItemText(list, rowIndex, 2, const_cast<LPWSTR>(targetText.c_str()));
            ListView_SetItemText(list, rowIndex, 3, const_cast<LPWSTR>(res.status.c_str()));
        }
    }

    void HandleApplySequence(HWND hwnd) {
        if (!g_services) {
            MessageBoxW(hwnd, L"Hook services are unavailable.", L"Hook Sequence", MB_ICONERROR);
            return;
        }
        std::wstring seqPath;
        if (!PromptHookSequenceFile(hwnd, seqPath)) return;
        DWORD targetPid = 0;
        std::vector<HookSequenceEntry> entries;
        std::wstring parseError;
        if (!LoadHookSequenceFile(seqPath, targetPid, entries, parseError)) {
            MessageBoxW(hwnd, parseError.c_str(), L"Hook Sequence", MB_ICONERROR);
            return;
        } 
        if (!EnsureProcessAlive(targetPid)) {
            MessageBoxW(hwnd, L"Target process is not running.", L"Hook Sequence", MB_ICONWARNING);
            return;
        }
        HookSequenceContext ctx;
        std::wstring initError;
        if (!InitializeHookContext(targetPid, g_services, ctx, initError)) {
            MessageBoxW(hwnd, initError.c_str(), L"Hook Sequence", MB_ICONERROR);
            return;
        }
        std::vector<HookRow> appliedThisRun;
        std::vector<HookSequenceResult> results;
        bool overallSuccess = true;
        for (const auto& entry : entries) {
            HookSequenceResult res;
            res.entry = entry;
            bool addrOk = false;
            DWORD64 base = 0;
            if (g_services->GetModuleBase(targetPid, entry.module.c_str(), &base) && base) {
                ULONGLONG off = ParseAddressText(entry.offset, addrOk);
                if (addrOk) res.address = base + off;
            }
            HookRow newRow;
            std::wstring applyError;
            if (ApplyHookEntry(ctx, entry, newRow, applyError)) {
                res.success = true;
                res.row = newRow;
                res.status = L"Applied";
                appliedThisRun.push_back(newRow);
                KMHHLog(L"Applied hook %s+%s (hook id %d)", entry.module.c_str(), entry.offset.c_str(), newRow.id);
            }
            else {
                res.success = false;
                res.status = applyError;
                results.push_back(res);
                KMHHLog(L"Hook sequence entry failed: %s", applyError.c_str());
                RollbackHooks(ctx, appliedThisRun);
                PersistHookRows(ctx);
                UpdateHookList(g_hHookList, results);
                MessageBoxW(hwnd, applyError.c_str(), L"Hook Sequence", MB_OK | MB_ICONERROR);
                overallSuccess = false;
                break;
            }
            results.push_back(res);
        }

        if (overallSuccess) {
            PersistHookRows(ctx);
            UpdateHookList(g_hHookList, results);
            wchar_t msg[128];
            swprintf(msg, _countof(msg), L"Applied %zu hooks.", appliedThisRun.size());
            MessageBoxW(hwnd, msg, L"Hook Sequence", MB_OK | MB_ICONINFORMATION);
        }
    }

    INT_PTR CALLBACK KmhhDialogProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) {
        switch (msg) {
        case WM_INITDIALOG:
        {
            auto* ctx = reinterpret_cast<KmhhCreateContext*>(lParam);
            g_services = ctx ? ctx->services : nullptr;
            HWND hList = GetDlgItem(hDlg, IDC_KMHH_LIST_HOOKS);
            SetupHookListColumns(hList);
            g_hHookList = hList;
            CenterRelativeToParent(hDlg, ctx ? ctx->parent : nullptr);
            return TRUE;
        }
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
            case IDC_KMHH_BTN_APPLY_SEQ:
                HandleApplySequence(hDlg);
                return TRUE;
            case IDCANCEL:
                DestroyWindow(hDlg);
                return TRUE;
            default:
                break;
            }
            break;
        case WM_CLOSE:
            DestroyWindow(hDlg);
            return TRUE;
        case WM_DESTROY:
            if (g_hDialog == hDlg) g_hDialog = nullptr;
            g_hHookList = nullptr;
            return TRUE;
        }
        return FALSE;
    }
}

extern "C" __declspec(dllexport) void PluginMain(HWND parentHwnd, IHookServices* services) {
	KmhhCtx_SetHookServices(services);

	// check if trampoline sys is loaded
	if (!KmhhCtx_GetTrampolinehDrvBase()) {
		KMHHLog(L"trampoline driver not loaded yet, loading now...\n");
		if (!Helper::InstallAndStartDriverService(WIDEN(TRAMPOLINE_DRV_NAME), Helper::GetCurrentDirFilePath((TCHAR*)WIDEN(TRAMPOLINE_DRV_NAME)))) {
			KMHHLog(L"failed to call InstallAndStartDriverService\n");
			return;
		}
	}
	PVOID trampoline_drv_base = NULL;
	if (0 != KRNL::GetDriverBase(TRAMPOLINE_DRV_NAME, &trampoline_drv_base)) {
		KMHHLog(L"failed to call GetDriverBase\n");
		return;
	}

	KmhhCtx_SetTrampolinehDrvBase(trampoline_drv_base);

	// set nt!DbgPrompt functin address
	PVOID krnl_base = NULL;
	if (0 != KRNL::GetDriverBase(NTKRNL_NAME, &krnl_base)) {
		KMHHLog(L"failed to call GetDriverBase to get kernel base\n");
		return;
	}
	DWORD dbg_prompt_offset = 0;
	services->CheckExportFromFile(WIDEN(NTKRNL_PATH), DBG_EXPORT_FUNC, &dbg_prompt_offset);
	KmhhCtx_SetDbgPromptAbsAddr((PVOID)(dbg_prompt_offset + (DWORD64)krnl_base));

    EnsureCommonControls();
    if (g_hDialog && IsWindow(g_hDialog)) {
        ShowWindow(g_hDialog, SW_SHOWNORMAL);
        SetForegroundWindow(g_hDialog);
        return;
    }
    KmhhCreateContext ctx{ parentHwnd, services };
    HWND dlg = CreateDialogParamW(g_hInstance, MAKEINTRESOURCEW(IDD_KMHH_DIALOG), parentHwnd, KmhhDialogProc, reinterpret_cast<LPARAM>(&ctx));
    if (!dlg) {
        MessageBoxW(parentHwnd,
            L"Failed to create Kernel Mode Hook Helper dialog.",
            L"KrnlModeHookHlp",
            MB_ICONERROR);
        return;
    }
    g_hDialog = dlg;
    ShowWindow(dlg, SW_SHOWNORMAL);
    UpdateWindow(dlg);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        g_hInstance = hModule;
    }
    else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
        g_hDialog = nullptr;
        g_services = nullptr;
        g_hHookList = nullptr;
    }
    return TRUE;
}

