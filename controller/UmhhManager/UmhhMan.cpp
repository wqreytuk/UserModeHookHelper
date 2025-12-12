#include <windows.h>
#include <tlhelp32.h>
#include <winsvc.h>
#include <vector>
#include <string>
#include <algorithm>
#include <iostream>
#include <sstream>
#include <atlbase.h>
#include "../../Shared/SharedMacroDef.h"
typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	_Field_size_bytes_part_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
// Resolve DOS path to NT path using ntdll's RtlDosPathNameToNtPathName_U
typedef BOOLEAN (NTAPI *PFN_RtlDosPathNameToNtPathName_U)(PCWSTR DosName, PUNICODE_STRING NtName, PWSTR *FilePart, PVOID Reserved);
static	bool DosToNtPath(const std::wstring& dosPath, std::wstring& outNtPath) {
		if (dosPath.empty()) return false;

		// Prefer least-privilege handle for path resolution: request only
		// FILE_READ_ATTRIBUTES and include BACKUP_SEMANTICS to allow directories.
		DWORD share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
		DWORD flags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS;
		HANDLE h = CreateFileW(dosPath.c_str(), FILE_READ_ATTRIBUTES, share, NULL, OPEN_EXISTING, flags, NULL);
		if (h == INVALID_HANDLE_VALUE) {
			// Fallback to GENERIC_READ only if necessary
			h = CreateFileW(dosPath.c_str(), GENERIC_READ, share, NULL, OPEN_EXISTING, flags, NULL);
			if (h == INVALID_HANDLE_VALUE) return false;
		}

		WCHAR finalPath[MAX_PATH * 2];
		DWORD len = GetFinalPathNameByHandleW(h, finalPath, _countof(finalPath), FILE_NAME_NORMALIZED);
		CloseHandle(h);
		if (len == 0 || len >= _countof(finalPath)) return false;

		std::wstring fp(finalPath);
		// Strip the Windows extended path prefix if present
		const std::wstring prefix = L"\\\\?\\";
		if (fp.rfind(prefix, 0) == 0) fp = fp.substr(prefix.size());

		// If path starts with drive letter (e.g., C:\), map it to device name
		if (fp.size() >= 2 && fp[1] == L':') {
			WCHAR drive[] = L"X:";
			drive[0] = fp[0];
			WCHAR deviceName[32768];
			DWORD rc = QueryDosDeviceW(drive, deviceName, _countof(deviceName));
			if (rc == 0) {
				outNtPath = std::wstring(L"\\??\\") + fp;
				return true;
			}
			std::wstring device(deviceName);
			std::wstring rest = fp.substr(2); // includes leading backslash
			outNtPath = device + rest;
			return true;
		}

		// Otherwise assume already an NT path
		outNtPath = fp;
		return true;
}

// FNV-1a 64-bit over UTF-16 bytes
static unsigned long long ComputeNtPathHash(const std::wstring& ntPath) {
	const unsigned long long FNV_offset = 14695981039346656037ULL;
	const unsigned long long FNV_prime = 1099511628211ULL;
	unsigned long long h = FNV_offset;
	const BYTE* bytes = reinterpret_cast<const BYTE*>(ntPath.c_str());
	size_t len = ntPath.size() * sizeof(wchar_t);
	for (size_t i = 0; i < len; ++i) { h ^= (unsigned long long)bytes[i]; h *= FNV_prime; }
	return h;
}

static void Trim(std::wstring& s) {
	auto notspace = [](wchar_t c) { return !iswspace(c); };
	s.erase(s.begin(), std::find_if(s.begin(), s.end(), notspace));
	s.erase(std::find_if(s.rbegin(), s.rend(), notspace).base(), s.end());
}

static std::vector<std::wstring> SplitNames(const std::wstring& input) {
	std::vector<std::wstring> out; std::wstringstream ss(input); std::wstring item;
	while (std::getline(ss, item, L',')) { Trim(item); if (!item.empty()) out.push_back(item); }
	return out;
}

static bool WriteMultiSz(HKEY root, const std::wstring& subKey, const std::wstring& valueName, const std::vector<std::wstring>& items) {
	CRegKey key; if (key.Create(root, subKey.c_str()) != ERROR_SUCCESS) return false;
	// Build REG_MULTI_SZ buffer
	size_t totalChars = 1; // final double-null
	for (auto& s : items) totalChars += s.size() + 1;
	std::vector<wchar_t> buf; buf.resize(totalChars);
	size_t pos = 0; for (auto& s : items) { memcpy(&buf[pos], s.c_str(), s.size() * sizeof(wchar_t)); pos += s.size(); buf[pos++] = L'\0'; }
	buf[pos++] = L'\0';
	LONG res = RegSetValueExW(key, valueName.c_str(), 0, REG_MULTI_SZ, reinterpret_cast<const BYTE*>(buf.data()), (DWORD)(buf.size() * sizeof(wchar_t)));
	return res == ERROR_SUCCESS;
}

static bool ReadMultiSz(HKEY root, const std::wstring& subKey, const std::wstring& valueName, std::vector<std::wstring>& items) {
	items.clear(); CRegKey key; if (key.Open(root, subKey.c_str(), KEY_READ) != ERROR_SUCCESS) return false;
	DWORD type = 0, size = 0; if (RegQueryValueExW(key, valueName.c_str(), nullptr, &type, nullptr, &size) != ERROR_SUCCESS || type != REG_MULTI_SZ || size == 0) return false;
	std::vector<wchar_t> buf; buf.resize(size / sizeof(wchar_t)); if (RegQueryValueExW(key, valueName.c_str(), nullptr, &type, reinterpret_cast<BYTE*>(buf.data()), &size) != ERROR_SUCCESS) return false;
	// parse
	const wchar_t* p = buf.data(); while (*p) { std::wstring s(p); items.push_back(s); p += s.size() + 1; }
	return true;
}

static bool AppendValues(const std::wstring& valueName, const std::vector<std::wstring>& toAdd) {
	std::vector<std::wstring> current; ReadMultiSz(HKEY_LOCAL_MACHINE, REG_PERSIST_SUBKEY, valueName, current);
	for (auto& s : toAdd) {
		if (std::find_if(current.begin(), current.end(), [&](const std::wstring& x) { return _wcsicmp(x.c_str(), s.c_str()) == 0; }) == current.end()) {
			current.push_back(s);
		}
	}
	return WriteMultiSz(HKEY_LOCAL_MACHINE, REG_PERSIST_SUBKEY, valueName, current);
}

static bool DeleteValues(const std::wstring& valueName, const std::vector<std::wstring>& toDel) {
	std::vector<std::wstring> current; if (!ReadMultiSz(HKEY_LOCAL_MACHINE, REG_PERSIST_SUBKEY, valueName, current)) return false;
	current.erase(std::remove_if(current.begin(), current.end(), [&](const std::wstring& x) {
		return std::find_if(toDel.begin(), toDel.end(), [&](const std::wstring& y) { return _wcsicmp(x.c_str(), y.c_str()) == 0; }) != toDel.end();
	}), current.end());
	return WriteMultiSz(HKEY_LOCAL_MACHINE, REG_PERSIST_SUBKEY, valueName, current);
}

static bool ClearValues(const std::wstring& valueName) {
	CRegKey key; if (key.Create(HKEY_LOCAL_MACHINE, REG_PERSIST_SUBKEY) != ERROR_SUCCESS) return false;
	LONG res = key.DeleteValue(valueName.c_str()); return res == ERROR_SUCCESS || res == ERROR_FILE_NOT_FOUND;
}

static void PrintUsage() {
	std::wcout << L"Usage:\n"
		L"  blman process -a name1[,name2,...]   Append blocked process names\n"
		L"  blman process -d name1[,name2,...]   Delete process names\n"
		L"  blman process -c                    Clear all process names\n"
		L"  blman process -l                    List process names\n"
		L"  blman dll     -a name1[,name2,...]   Append dll names\n"
		L"  blman dll     -d name1[,name2,...]   Delete dll names\n"
		L"  blman dll     -c                    Clear all dll names\n"
		L"  blman dll     -l                    List dll names\n"
		L"  blman whitelist -a pePath[,pePath...]  Add PE NT-path hashes to WhitelistHashes\n"
		L"  blman whitelist -d hexHash[,hexHash...] Delete hashes from WhitelistHashes\n"
		L"  blman whitelist -l                     List WhitelistHashes\n"
		L"  blman prot -a name1[,name2,...]        Append protected process names\n"
		L"  blman prot -d name1[,name2,...]        Delete protected process names\n"
		L"  blman prot -c                           Clear protected process names\n"
		L"  blman prot -l                           List protected process names\n";
	std::wcout << L"\nExtra:\n"
		L"  UmhhMan hookseq -o path\\out.hooseq \n"
		L"    -add module,offsetHex,dllPath,export [-add ...]\n"
		L"\nNotes:\n"
		L"  - The hookseq file omits PID; HookUI applies to its current target.\n"
		L"  - offsetHex is the module-relative offset (hex), e.g., 1F0.\n";
}

static bool IsProcessRunning(const wchar_t* exeName, DWORD& outPid) {
	outPid = 0; HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) return false;
	PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
	if (Process32FirstW(hSnap, &pe)) {
		do {
			if (_wcsicmp(pe.szExeFile, exeName) == 0) { outPid = pe.th32ProcessID; CloseHandle(hSnap); return true; }
		} while (Process32NextW(hSnap, &pe));
	}
	CloseHandle(hSnap); return false;
}

// (removed misplaced global hookseq block)

static bool TerminateProcessByPid(DWORD pid) {
	if (!pid) return false;
	HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
	if (!h) return false;
	BOOL ok = TerminateProcess(h, 0);
	CloseHandle(h);
	return ok == TRUE;
}

static bool RestartService(const wchar_t* svcName) {
	SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
	if (!scm) return false;
	SC_HANDLE svc = OpenServiceW(scm, svcName, SERVICE_STOP | SERVICE_START | SERVICE_QUERY_STATUS);
	if (!svc) {
		CloseServiceHandle(scm);
		// consider succeed if service not exist
		return true; 
	}
	SERVICE_STATUS_PROCESS ssp{}; DWORD bytes = 0;
	if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &bytes)) {
		if (ssp.dwCurrentState != SERVICE_STOPPED && ssp.dwCurrentState != SERVICE_STOP_PENDING) {
			SERVICE_STATUS ss{}; ControlService(svc, SERVICE_CONTROL_STOP, &ss);
			for (int i = 0; i < 50; ++i) {
				Sleep(100);
				QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &bytes); 
				if (ssp.dwCurrentState == SERVICE_STOPPED) 
					break; 
			}
		}
	}
	BOOL startOk = StartServiceW(svc, 0, nullptr);
	CloseServiceHandle(svc); 
	CloseServiceHandle(scm);
	return startOk == TRUE;
}

int wmain(int argc, wchar_t* argv[]) {
	if (argc < 3) { PrintUsage(); return 1; }
	std::wstring category = argv[1]; Trim(category);
	std::wstring option = argv[2]; Trim(option);
	std::wstring names = (argc >= 4) ? argv[3] : L"";
	std::vector<std::wstring> list = SplitNames(names);

	// Special mode: build hook sequence file
	if (_wcsicmp(category.c_str(), L"hookseq") == 0) {
		std::wstring outPath;
		struct Entry { std::wstring module; std::wstring offset; std::wstring dllPath; std::wstring exportName; };
		std::vector<Entry> entries;
		// Parse remaining args starting from argv[2]
		for (int i = 2; i < argc; ++i) {
			if (_wcsicmp(argv[i], L"-o") == 0 && i+1 < argc) {
				outPath = argv[++i];
			} else if (_wcsicmp(argv[i], L"-add") == 0 && i+1 < argc) {
				std::wstring spec = argv[++i];
				std::wstring parts[4]; int idx = 0; size_t start = 0;
				while (idx < 4) {
					size_t pos = spec.find(L',', start);
					std::wstring token = (pos==std::wstring::npos) ? spec.substr(start) : spec.substr(start, pos-start);
					parts[idx++] = token; if (pos==std::wstring::npos) break; start = pos+1;
				}
				if (idx == 4 && !parts[0].empty() && !parts[1].empty() && !parts[2].empty() && !parts[3].empty()) {
					entries.push_back({ parts[0], parts[1], parts[2], parts[3] });
				} else {
					wprintf(L"Invalid -add format. Expected module,offsetHex,dllPath,export\n");
					return 2;
				}
			}
		}
		if (outPath.empty()) { wprintf(L"Missing -o output path.\n"); return 2; }
		if (entries.empty()) { wprintf(L"No -add entries provided.\n"); return 2; }
		FILE* f = _wfopen(outPath.c_str(), L"wt, ccs=UNICODE");
		if (!f) { wprintf(L"Failed to open output: %s\n", outPath.c_str()); return 3; }
		fwprintf(f, L"# UserModeHookHelper hook sequence file\n");
		for (auto &e : entries) {
			fwprintf(f, L"[hook]\n");
			fwprintf(f, L"module=%s\n", e.module.c_str());
			fwprintf(f, L"offset=%s\n", e.offset.c_str());
			fwprintf(f, L"dllPath=%s\n", e.dllPath.c_str());
			fwprintf(f, L"export=%s\n\n", e.exportName.c_str());
		}
		fclose(f);
		wprintf(L"Wrote hook sequence to %s\n", outPath.c_str());
		return 0;
	}

	std::wstring valueName; bool isWhitelist = false; bool isProt = false;
	if (_wcsicmp(category.c_str(), L"process") == 0) valueName = REG_BLOCKED_PROCESS_NAME;
	else if (_wcsicmp(category.c_str(), L"dll") == 0) valueName = REG_BLOCKED_DLL_NAME;
	else if (_wcsicmp(category.c_str(), L"whitelist") == 0) { valueName = REG_WHITELIST_HASHES; isWhitelist = true; }
	else if (_wcsicmp(category.c_str(), L"prot") == 0) { valueName = REG_PROTECTED_PROCESS_NAME; isProt = true; }
	else { PrintUsage(); return 1; }

	bool ok = false;
	if (_wcsicmp(option.c_str(), L"-a") == 0) {
		if (list.empty()) { PrintUsage(); return 1; }
		if (isWhitelist) {
			std::vector<std::wstring> hashes;
			for (auto &p : list) {
				std::wstring nt; if (!DosToNtPath(p, nt)) { std::wcerr << L"Failed to convert to NT path: " << p << std::endl; continue; }
				unsigned long long h = ComputeNtPathHash(nt);
				wchar_t buf[32]; swprintf(buf, 32, L"%llx", h);
				hashes.push_back(buf);
			}
			ok = AppendValues(valueName, hashes);
		}
		else {
			ok = AppendValues(valueName, list);
		}
	}
	else if (_wcsicmp(option.c_str(), L"-d") == 0) {
		if (list.empty()) { PrintUsage(); return 1; }
		ok = DeleteValues(valueName, list);
	}
	else if (_wcsicmp(option.c_str(), L"-c") == 0) {
		ok = ClearValues(valueName);
	}
	else if (_wcsicmp(option.c_str(), L"-l") == 0) {
		std::vector<std::wstring> cur; if (!ReadMultiSz(HKEY_LOCAL_MACHINE, REG_PERSIST_SUBKEY, valueName, cur)) {
			std::wcout << L"(empty)" << std::endl; return 0;
		}
		for (auto &s : cur) { std::wcout << s << std::endl; }
		return 0;
	}
	else { PrintUsage(); return 1; }

	if (!ok) { std::wcerr << L"Operation failed (check privileges)\n"; return 2; }

	// Check if UMController.exe is running; if so, prompt to close it and terminate on OK.
	DWORD umcPid = 0;
	if (IsProcessRunning(L"UMController.exe", umcPid)) {
		int mb = MessageBoxW(nullptr, L"UMController is running. It must be closed to restart services. Click OK to close it now.", L"BlockList Manager", MB_OKCANCEL | MB_ICONINFORMATION | MB_SYSTEMMODAL);
		if (mb == IDCANCEL) {
			std::wcout << L"Cancelled by user. Changes written but services not restarted." << std::endl;
			return 0;
		}
		if (!TerminateProcessByPid(umcPid)) {
			std::wcerr << L"Failed to close UMController.exe automatically. Please close it manually and rerun." << std::endl;
			return 3;
		}
		Sleep(500);
	}

	// Restart UMHH.ObCallback and UserModeHookHelper services
	bool obOk = RestartService(UMHH_OB_CALLBACK_SERVICE_NAME);
	bool ctrlOk = RestartService(SERVICE_NAME);
	if (!obOk || !ctrlOk) {
		if (!obOk)
			std::wcerr << UMHH_OB_CALLBACK_SERVICE_NAME << L" failed to resstart" << std::endl;
		if (!ctrlOk)
			std::wcerr << SERVICE_NAME << L" failed to resstart" << std::endl;
		std::wcerr << L"Service restart failed. Ensure you have admin privileges." << std::endl;
		return 4;
	}

	std::wcout << L"Done. Services restarted successfully." << std::endl;
	return 0;
}
