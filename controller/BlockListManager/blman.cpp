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

static void Trim(std::wstring& s) {
	auto notspace = [](wchar_t c){ return !iswspace(c); };
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
	size_t pos = 0; for (auto& s : items) { memcpy(&buf[pos], s.c_str(), s.size()*sizeof(wchar_t)); pos += s.size(); buf[pos++] = L'\0'; }
	buf[pos++] = L'\0';
	LONG res = RegSetValueExW(key, valueName.c_str(), 0, REG_MULTI_SZ, reinterpret_cast<const BYTE*>(buf.data()), (DWORD)(buf.size()*sizeof(wchar_t)));
	return res == ERROR_SUCCESS;
}

static bool ReadMultiSz(HKEY root, const std::wstring& subKey, const std::wstring& valueName, std::vector<std::wstring>& items) {
	items.clear(); CRegKey key; if (key.Open(root, subKey.c_str(), KEY_READ) != ERROR_SUCCESS) return false;
	DWORD type = 0, size = 0; if (RegQueryValueExW(key, valueName.c_str(), nullptr, &type, nullptr, &size) != ERROR_SUCCESS || type != REG_MULTI_SZ || size == 0) return false;
	std::vector<wchar_t> buf; buf.resize(size/sizeof(wchar_t)); if (RegQueryValueExW(key, valueName.c_str(), nullptr, &type, reinterpret_cast<BYTE*>(buf.data()), &size) != ERROR_SUCCESS) return false;
	// parse
	const wchar_t* p = buf.data(); while (*p) { std::wstring s(p); items.push_back(s); p += s.size() + 1; }
	return true;
}

static bool AppendValues(const std::wstring& valueName, const std::vector<std::wstring>& toAdd) {
	std::vector<std::wstring> current; ReadMultiSz(HKEY_LOCAL_MACHINE, REG_PERSIST_SUBKEY, valueName, current);
	for (auto& s : toAdd) {
		if (std::find_if(current.begin(), current.end(), [&](const std::wstring& x){ return _wcsicmp(x.c_str(), s.c_str())==0; }) == current.end()) {
			current.push_back(s);
		}
	}
	return WriteMultiSz(HKEY_LOCAL_MACHINE, REG_PERSIST_SUBKEY, valueName, current);
}

static bool DeleteValues(const std::wstring& valueName, const std::vector<std::wstring>& toDel) {
	std::vector<std::wstring> current; if (!ReadMultiSz(HKEY_LOCAL_MACHINE, REG_PERSIST_SUBKEY, valueName, current)) return false;
	current.erase(std::remove_if(current.begin(), current.end(), [&](const std::wstring& x){
		return std::find_if(toDel.begin(), toDel.end(), [&](const std::wstring& y){ return _wcsicmp(x.c_str(), y.c_str())==0; }) != toDel.end();
	}), current.end());
	return WriteMultiSz(HKEY_LOCAL_MACHINE, REG_PERSIST_SUBKEY, valueName, current);
}

static bool ClearValues(const std::wstring& valueName) {
	CRegKey key; if (key.Create(HKEY_LOCAL_MACHINE, REG_PERSIST_SUBKEY) != ERROR_SUCCESS) return false;
	LONG res = key.DeleteValue(valueName.c_str()); return res == ERROR_SUCCESS || res == ERROR_FILE_NOT_FOUND;
}

static void PrintUsage() {
	std::wcout << L"Usage:\n"
		L"  blman process -a name1[,name2,...]   Append process names\n"
		L"  blman process -d name1[,name2,...]   Delete process names\n"
		L"  blman process -c                    Clear all process names\n"
		L"  blman process -l                    List process names\n"
		L"  blman dll     -a name1[,name2,...]   Append dll names\n"
		L"  blman dll     -d name1[,name2,...]   Delete dll names\n"
		L"  blman dll     -c                    Clear all dll names\n"
		L"  blman dll     -l                    List dll names\n";
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

static bool TerminateProcessByPid(DWORD pid) {
	if (!pid) return false; HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
	if (!h) return false; BOOL ok = TerminateProcess(h, 0); CloseHandle(h); return ok == TRUE;
}

static bool RestartService(const wchar_t* svcName) {
	SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
	if (!scm) return false;
	SC_HANDLE svc = OpenServiceW(scm, svcName, SERVICE_STOP | SERVICE_START | SERVICE_QUERY_STATUS);
	if (!svc) { CloseServiceHandle(scm); return false; }
	SERVICE_STATUS_PROCESS ssp{}; DWORD bytes = 0;
	if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &bytes)) {
		if (ssp.dwCurrentState != SERVICE_STOPPED && ssp.dwCurrentState != SERVICE_STOP_PENDING) {
			SERVICE_STATUS ss{}; ControlService(svc, SERVICE_CONTROL_STOP, &ss);
			for (int i = 0; i < 50; ++i) { Sleep(100); QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &bytes); if (ssp.dwCurrentState == SERVICE_STOPPED) break; }
		}
	}
	BOOL startOk = StartServiceW(svc, 0, nullptr);
	CloseServiceHandle(svc); CloseServiceHandle(scm);
	return startOk == TRUE;
}

int wmain(int argc, wchar_t* argv[]) {
	if (argc < 3) { PrintUsage(); return 1; }
	std::wstring category = argv[1]; Trim(category);
	std::wstring option = argv[2]; Trim(option);
	std::wstring names = (argc >= 4) ? argv[3] : L"";
	std::vector<std::wstring> list = SplitNames(names);

	std::wstring valueName;
	if (_wcsicmp(category.c_str(), L"process") == 0) valueName = REG_BLOCKED_PROCESS_NAME;
	else if (_wcsicmp(category.c_str(), L"dll") == 0) valueName = REG_BLOCKED_DLL_NAME;
	else { PrintUsage(); return 1; }

	bool ok = false;
	if (_wcsicmp(option.c_str(), L"-a") == 0) {
		if (list.empty()) { PrintUsage(); return 1; }
		ok = AppendValues(valueName, list);
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
		std::wcerr << L"Service restart failed. Ensure you have admin privileges." << std::endl;
		return 4;
	}

	std::wcout << L"Done. Services restarted successfully." << std::endl;
	return 0;

}
