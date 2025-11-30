#include "pch.h"
#include "Helper.h"
#include "ETW.h"
#include "UMController.h"
#include "RegistryStore.h"
#include "capstone/capstone.h"
#include <atomic>
#include <wchar.h>
#include <memory>
#include <mutex>
#include <vector>
#include <TlHelp32.h>
// COM/WMI headers
#include <comdef.h>
#include <Wbemidl.h>
#include <sddl.h>
#include <thread>
#include <chrono>
#include "../Shared/LogMacros.h"
#include  "../UserModeHookHelper/MacroDef.h"
#include <winsvc.h>
#include "../UserModeHookHelper/UKShared.h"
#include <psapi.h>
#include "../Shared/SharedMacroDef.h"
#include "ProcFlags.h"
#include "../ProcessHackerLib/phlib_expose.h"
#pragma comment(lib, "wbemuuid.lib")

// Simple process-wide fatal handler. Stored as an atomic pointer so it can be
// safely set from any thread during startup.
static std::atomic<Helper::FatalHandlerType> g_fatalHandler(nullptr);

// Initialize reusable buffer state
std::unique_ptr<TCHAR[]> Helper::m_sharedBuf = nullptr;
size_t Helper::m_sharedBufCap = 0;
std::mutex Helper::m_bufMutex;
// Filter instance pointer (nullable)
Filter* Helper::m_filterInstance = nullptr;
std::wstring Helper::m_SysDriverMark = L"";
DWORD Helper::m_NtCreateThreadExSyscallNum = 0;


// NOTE: WaitAndExit was removed. Call Helper::Fatal(...) at call sites.

void Helper::SetFatalHandler(FatalHandlerType handler) {
	g_fatalHandler.store(handler, std::memory_order_release);
}

// Disassemble a small buffer (usually the first bytes of an export) and
// attempt to extract the syscall number. This looks for an instruction of
// the form `mov eax, imm32` in x86-64 code and returns the imm32 value.
// Returns ULONG_MAX on failure.
static ULONG ExtractSyscallNumberFromBytes(const unsigned char buf[16]) {
	csh handle = 0;
	cs_err err = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
	if (err != CS_ERR_OK) return ULONG_MAX;

	cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);
	cs_insn *insn = NULL;
	size_t count = cs_disasm(handle, buf, 16, 0x0, 0, &insn);
	ULONG result = ULONG_MAX;
	if (count > 0) {
		for (size_t i = 0; i < count; ++i) {
			// Check for mnemonic "mov" with op_str like "eax, 0xC2"
			if (insn[i].id == X86_INS_MOV) {
				// For x86, simple string parse of op_str to find imm
				const char* op = insn[i].op_str;
				if (op) {
					// Look for pattern ", 0x" or ", " followed by digits
					const char* comma = strchr(op, ',');
					if (comma) {
						const char* imm = comma + 1;
						while (*imm == ' ') ++imm;
						// support 0xNN hex immediate
						if (imm[0] == '0' && (imm[1] == 'x' || imm[1] == 'X')) {
							unsigned long v = 0;
							if (sscanf_s(imm, "%lx", &v) == 1) {
								result = (ULONG)v;
								break;
							}
						}
						else {
							unsigned long v = 0;
							if (sscanf_s(imm, "%lu", &v) == 1) {
								result = (ULONG)v;
								break;
							}
						}
					}
				}
			}
		}
		cs_free(insn, count);
	}
	cs_close(&handle);
	return result;
}

void Helper::Fatal(const wchar_t* message) {
	// If a handler is registered, call it. Otherwise, log and return.
	auto handler = g_fatalHandler.load(std::memory_order_acquire);
	if (handler) {
		// Call the handler — it should be fast and thread-safe (e.g., post a
		// message to the UI thread). Do NOT call long-blocking operations
		// here.
		handler(message);
	}
	else {
		app.GetETW().Log(L"[UMCtrl]     Fatal: %s\n", message);
		app.GetETW().UnReg();
		exit(-1);
	}
}


DWORD64 Helper::GetNtPathHash(const UCHAR* buf, size_t byteLen) {
	const uint64_t FNV_prime = 1099511628211u;
	uint64_t hash = 14695981039346656037u;

	// Process exact number of bytes provided by the caller. This ensures
	// UTF-16LE buffers (which may contain embedded zero bytes) are hashed
	// correctly.
	const UCHAR* p = buf;
	const UCHAR* end = buf + byteLen;
	while (p < end) {
		hash ^= (uint64_t)(*p);
		hash *= FNV_prime;
		++p;
	}
	return hash;
}

// GetDosPath removed: path resolution now uses NT-paths exclusively and the
// kernel can be asked for process image NT paths via FLTCOMM_GetImagePathByPid.


std::basic_string<TCHAR> Helper::GetCurrentDirFilePath(TCHAR* append)
{
	TCHAR path[MAX_PATH];
	DWORD len = GetModuleFileName(NULL, path, MAX_PATH);
	if (len == 0 || len == MAX_PATH)
		return _T("");

	// Remove the filename to get the directory
	TCHAR* lastSlash = _tcsrchr(path, _T('\\'));
	if (lastSlash)
		*(lastSlash + 1) = _T('\0');

	// Append your custom string
	std::basic_string<TCHAR> fullPath = std::basic_string<TCHAR>(path) + append;
	return fullPath;
}

// GetFullImagePathByPID and ResolveProcessDosImagePath removed. Use NT-path
// oriented helpers instead: GetFullImageNtPathByPID and ResolveProcessNtImagePath.

bool Helper::GetFullImageNtPathByPID(DWORD pid, std::wstring& outNtPath) {
	// Try to open process and query the image name as native path
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (!hProcess) {
		return false;
	}
	bool ok = GetFullImageNtPathFromHandle(hProcess, outNtPath);
	CloseHandle(hProcess);
	return ok;
}

bool Helper::GetFullImageNtPathFromHandle(HANDLE hProcess, std::wstring& outNtPath) {
	if (!hProcess) return false;

	// Ensure we have a reasonably large shared buffer and call QueryFullProcessImageName
	// only once. We choose a large default to avoid a second call to grow the buffer.
	const size_t DEFAULT_CAP = 32768; // characters
	{
		std::lock_guard<std::mutex> lg(m_bufMutex);
		if (m_sharedBufCap < DEFAULT_CAP) {
			m_sharedBuf.reset(new TCHAR[DEFAULT_CAP]);
			m_sharedBufCap = DEFAULT_CAP;
		}
	}

	// Prepare size as input: number of TCHARs in buffer (excluding room for explicit null)
	DWORD size = (DWORD)(m_sharedBufCap - 1);
	if (!QueryFullProcessImageName(hProcess, 1, m_sharedBuf.get(), &size)) {
		return false;
	}

	// Ensure null termination and assign
	m_sharedBuf.get()[size] = (TCHAR)0;
	outNtPath.assign(m_sharedBuf.get());
	return true;
}
bool Helper::IsFileExists(TCHAR* szPath) {
	DWORD dwAttrib = GetFileAttributes(szPath);
	return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		!(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}
bool Helper::UMHH_BS_DriverCheck() {
	DeleteFileW(UM_STOP_SIGNAL_FILE_PATH);
	// Determine service name macro to use
#if defined(BS_SERVICE_NAME)
	const wchar_t* svcName = BS_SERVICE_NAME;
#else
	const wchar_t* svcName = SERVICE_NAME;
	LOG_CTRL_ETW(L"BS_SERVICE_NAME not defined; falling back to SERVICE_NAME '%s'\n", SERVICE_NAME);
#endif

	// Open SCM with rights to manage service
	SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
	if (!scm) {
		LOG_CTRL_ETW(L"UMHH_BS_DriverCheck: OpenSCManagerW failed: %lu\n", GetLastError());
		return false;
	}

	// If service exists: open with full access to stop/delete
	SC_HANDLE svc = OpenServiceW(scm, svcName, SERVICE_QUERY_STATUS | SERVICE_STOP | DELETE | SERVICE_QUERY_CONFIG);
	if (svc) {
		SERVICE_STATUS_PROCESS ssp = { 0 };
		DWORD bytes = 0;
		if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytes)) {
			if (ssp.dwCurrentState == SERVICE_RUNNING || ssp.dwCurrentState == SERVICE_START_PENDING) {
				bool ghEnabled = false; RegistryStore::ReadGlobalHookMode(ghEnabled);
				if (ghEnabled)
					return true;
				SERVICE_STATUS ss = { 0 };
				if (ControlService(svc, SERVICE_CONTROL_STOP, &ss)) {
					// wait for stopped
					const int MAX_MS = 10000; const int INTERVAL_MS = 200; int waited = 0;
					while (waited < MAX_MS) {
						if (!QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytes)) break;
						if (ssp.dwCurrentState == SERVICE_STOPPED) break;
						std::this_thread::sleep_for(std::chrono::milliseconds(INTERVAL_MS)); waited += INTERVAL_MS;
					}
				}
				else {
					LOG_CTRL_ETW(L"UMHH_BS_DriverCheck: failed to stop existing service %s : %lu\n", svcName, GetLastError());
					CloseServiceHandle(svc); CloseServiceHandle(scm); return false;
				}
			}
		}

		// Query binary path to remove file after deletion
		DWORD needed = 0; QueryServiceConfigW(svc, NULL, 0, &needed);
		std::unique_ptr<BYTE[]> buf(new BYTE[needed]);
		LPQUERY_SERVICE_CONFIGW qsc = (LPQUERY_SERVICE_CONFIGW)buf.get();
		if (QueryServiceConfigW(svc, qsc, needed, &needed)) {
			std::wstring bin = qsc->lpBinaryPathName ? qsc->lpBinaryPathName : L"";
			// delete service
			if (!DeleteService(svc)) {
				LOG_CTRL_ETW(L"UMHH_BS_DriverCheck: DeleteService failed for %s : %lu\n", svcName, GetLastError());
				CloseServiceHandle(svc); CloseServiceHandle(scm); return false;
			}
			CloseServiceHandle(svc);
			// remove binary file if it exists
			if (!bin.empty()) {
				// Expand SystemRoot macros like %SystemRoot% or \SystemRoot\
				
				wchar_t expanded[MAX_PATH];
				if (ExpandEnvironmentStringsW(bin.c_str(), expanded, _countof(expanded))) {
					DeleteFileW(expanded);
				}
				else {
					DeleteFileW(bin.c_str());
				}
			}
		}
		else {
			// Could not query, attempt delete anyway
			if (!DeleteService(svc)) {
				LOG_CTRL_ETW(L"UMHH_BS_DriverCheck: DeleteService failed (no qsc) for %s : %lu\n", svcName, GetLastError());
				CloseServiceHandle(svc); CloseServiceHandle(scm); return false;
			}
			CloseServiceHandle(svc);
		}
		// continue to recreate
	}

	DWORD err = GetLastError();
	if (svc) { /* already closed above */ }
	else if (err != ERROR_SERVICE_DOES_NOT_EXIST && err != ERROR_SERVICE_MARKED_FOR_DELETE) {
		LOG_CTRL_ETW(L"UMHH_BS_DriverCheck: OpenServiceW unexpected error: %lu\n", err);
		CloseServiceHandle(scm); return false;
	}

	// Build source and destination paths for driver file
	std::basic_string<TCHAR> drvName = std::basic_string<TCHAR>(svcName) + std::basic_string<TCHAR>(L".sys");
	std::basic_string<TCHAR> srcPath = Helper::GetCurrentDirFilePath(const_cast<TCHAR*>(drvName.c_str()));
	if (srcPath.empty()) { LOG_CTRL_ETW(L"UMHH_BS_DriverCheck: could not determine module path for %s.sys\n", svcName); CloseServiceHandle(scm); return false; }
	DWORD fa = GetFileAttributesW(srcPath.c_str()); if (fa == INVALID_FILE_ATTRIBUTES) { LOG_CTRL_ETW(L"UMHH_BS_DriverCheck: source driver not found: %s\n", srcPath.c_str()); CloseServiceHandle(scm); return false; }
	wchar_t sysDir[MAX_PATH]; if (!GetSystemDirectoryW(sysDir, _countof(sysDir))) { LOG_CTRL_ETW(L"UMHH_BS_DriverCheck: GetSystemDirectoryW failed: %lu\n", GetLastError()); CloseServiceHandle(scm); return false; }
	std::wstring dstDir = std::wstring(sysDir) + L"\\drivers\\"; std::wstring dstPath = dstDir + std::wstring(drvName.c_str());
	if (!CopyFileW(srcPath.c_str(), dstPath.c_str(), FALSE)) { LOG_CTRL_ETW(L"UMHH_BS_DriverCheck: CopyFileW failed from %s to %s : %lu\n", srcPath.c_str(), dstPath.c_str(), GetLastError()); CloseServiceHandle(scm); return false; }

	SC_HANDLE newSvc = CreateServiceW(scm, svcName, svcName, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
		SERVICE_SYSTEM_START, SERVICE_ERROR_NORMAL, dstPath.c_str(), NULL, NULL, NULL, NULL, NULL);
	if (!newSvc) { LOG_CTRL_ETW(L"UMHH_BS_DriverCheck: CreateServiceW failed: %lu\n", GetLastError()); DeleteFileW(dstPath.c_str()); CloseServiceHandle(scm); return false; }

	// Use ConfigureBootStartService to ensure registry/config is set for boot-start.
	// Query persisted GlobalHookMode first; only enable boot-start if registry requests it.
	bool ghEnabled = false; RegistryStore::ReadGlobalHookMode(ghEnabled);
	if (!ConfigureBootStartService(ghEnabled)) {
		LOG_CTRL_ETW(L"UMHH_BS_DriverCheck: ConfigureBootStartService failed for %s (requested enabled=%d)\n", svcName, (int)ghEnabled);
		// we continue, since service was created; but return false to indicate not fully configured
		CloseServiceHandle(newSvc); CloseServiceHandle(scm);
		return false;
	}

	CloseServiceHandle(newSvc); CloseServiceHandle(scm);
	LOG_CTRL_ETW(L"UMHH_BS_DriverCheck: created boot-start kernel driver %s\n", svcName);
	return true;
}
void Helper::UMHH_DriverCheck() {
	// Ensure the configured driver/service exists and is set to auto-start.
	SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
	if (!scm) {
		LOG_CTRL_ETW(L" OpenSCManagerW failed: %lu\n", GetLastError());
		return;
	}

	// Request start and status access as we may need to start the service.
	DWORD desiredAccess = SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG | SERVICE_QUERY_STATUS | SERVICE_START;
	SC_HANDLE svc = OpenServiceW(scm, SERVICE_NAME, desiredAccess);
	if (!svc) {
		DWORD err = GetLastError();
		LOG_CTRL_ETW(L"Service '%s' not found (err=%lu)\n", SERVICE_NAME, err);

		// Try to install INF named SERVICE_NAME.inf from the executable directory
		if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
			std::basic_string<TCHAR> infName = std::basic_string<TCHAR>(SERVICE_NAME) + std::basic_string<TCHAR>(L".inf");
			std::basic_string<TCHAR> infPath = Helper::GetCurrentDirFilePath(const_cast<TCHAR*>(infName.c_str()));
			if (infPath.empty()) {
				LOG_CTRL_ETW(L"Could not determine module path to locate INF\n");
				CloseServiceHandle(scm);
				return;
			}
			DWORD fa = GetFileAttributesW(infPath.c_str());
			if (fa == INVALID_FILE_ATTRIBUTES) {
				LOG_CTRL_ETW(L"INF not found at %s\n", infPath.c_str());
				CloseServiceHandle(scm);
				return;
			}

			HMODULE hNewdev = LoadLibraryW(L"newdev.dll");
			if (!hNewdev) {
				LOG_CTRL_ETW(L"Failed to load newdev.dll: %lu\n", GetLastError());
				CloseServiceHandle(scm);
				return;
			}
			typedef BOOL(WINAPI* PFN_DiInstallDriverW)(HWND, PCWSTR, DWORD, PBOOL);
			PFN_DiInstallDriverW pDiInstall = (PFN_DiInstallDriverW)GetProcAddress(hNewdev, "DiInstallDriverW");
			if (!pDiInstall) {
				LOG_CTRL_ETW(L"DiInstallDriverW not found in newdev.dll\n");
				FreeLibrary(hNewdev);
				CloseServiceHandle(scm);
				return;
			}

			BOOL needReboot = FALSE;
			BOOL installed = pDiInstall(NULL, infPath.c_str(), 0, &needReboot);
			if (!installed) {
				LOG_CTRL_ETW(L"DiInstallDriverW failed for %s: %lu\n", infPath.c_str(), GetLastError());
				FreeLibrary(hNewdev);
				CloseServiceHandle(scm);
				return;
			}
			LOG_CTRL_ETW(L"DiInstallDriverW succeeded for %s (needReboot=%d)\n", infPath.c_str(), (int)needReboot);
			FreeLibrary(hNewdev);

			// re-open the service with start/status access
			svc = OpenServiceW(scm, SERVICE_NAME, desiredAccess);
			if (!svc) {
				LOG_CTRL_ETW(L"Service still not available after install (err=%lu)\n", GetLastError());
				CloseServiceHandle(scm);
				return;
			}

			// After service creation via INF, ensure the binary path points to the
			// UserModeHookHelper.sys located next to the current executable.
			std::basic_string<TCHAR> sysName = std::basic_string<TCHAR>(SERVICE_NAME) + std::basic_string<TCHAR>(L".sys");
			std::basic_string<TCHAR> sysPath = Helper::GetCurrentDirFilePath(const_cast<TCHAR*>(sysName.c_str()));
			if (!sysPath.empty()) {
				if (!ChangeServiceConfigW(svc,
					SERVICE_NO_CHANGE, // service type
					SERVICE_DEMAND_START, // start type
					SERVICE_NO_CHANGE,
					sysPath.c_str(),   // binary path
					NULL, NULL, NULL, NULL, NULL, NULL)) {
					LOG_CTRL_ETW(L"ChangeServiceConfigW to set BinaryPathName failed: %lu (path=%s)\n", GetLastError(), sysPath.c_str());
				}
				else {
					LOG_CTRL_ETW(L"Service binary path updated to %s\n", sysPath.c_str());
				}
			}
			else {
				LOG_CTRL_ETW(L"Could not determine module path to set service binary path\n");
			}
		}
		else {
			CloseServiceHandle(scm);
			return;
		}
	}
	// Check current status and start service if not running
	SERVICE_STATUS_PROCESS ssp = { 0 };
	DWORD bytes = 0;

	// Ensure service is configured for auto-start. Query current config and
	// change to SERVICE_AUTO_START if necessary.
	{
		DWORD qNeeded = 0;
		QueryServiceConfigW(svc, NULL, 0, &qNeeded);
		if (qNeeded > 0) {
			std::unique_ptr<BYTE[]> qbuf(new BYTE[qNeeded]);
			LPQUERY_SERVICE_CONFIGW pq = (LPQUERY_SERVICE_CONFIGW)qbuf.get();
			if (QueryServiceConfigW(svc, pq, qNeeded, &qNeeded)) {
				if (pq->dwStartType != SERVICE_DEMAND_START) {
					if (!ChangeServiceConfigW(svc,
						SERVICE_NO_CHANGE, // service type
						SERVICE_AUTO_START, // start type -> change to auto
						SERVICE_DEMAND_START,
						NULL, NULL, NULL, NULL, NULL, NULL, NULL)) {
						LOG_CTRL_ETW(L"UMHH_DriverCheck: ChangeServiceConfigW to SERVICE_AUTO_START failed: %lu\n", GetLastError());
					}
					else {
						LOG_CTRL_ETW(L"UMHH_DriverCheck: service %s start type updated to SERVICE_DEMAND_START\n", SERVICE_NAME);
					}
				}
			}
			else {
				LOG_CTRL_ETW(L"UMHH_DriverCheck: QueryServiceConfigW failed: %lu\n", GetLastError());
			}
		}
	}
	if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytes)) {
		if (ssp.dwCurrentState != SERVICE_RUNNING) {
			LOG_CTRL_ETW(L"Service '%s' not running (state=%u), attempting to start\n", SERVICE_NAME, ssp.dwCurrentState);
			if (StartServiceW(svc, 0, NULL)) {
				// wait for running state with timeout
				const int MAX_MS = 10000;
				const int INTERVAL_MS = 200;
				int waited = 0;
				while (waited < MAX_MS) {
					if (!QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytes)) break;
					if (ssp.dwCurrentState == SERVICE_RUNNING) {
						LOG_CTRL_ETW(L"Service '%s' started successfully\n", SERVICE_NAME);
						break;
					}
					std::this_thread::sleep_for(std::chrono::milliseconds(INTERVAL_MS));
					waited += INTERVAL_MS;
				}
				if (ssp.dwCurrentState != SERVICE_RUNNING) {
					LOG_CTRL_ETW(L"Service '%s' did not reach RUNNING state (state=%u)\n", SERVICE_NAME, ssp.dwCurrentState);
				}
			}
			else {
				DWORD err = GetLastError();
				if (err == ERROR_SERVICE_ALREADY_RUNNING) {
					LOG_CTRL_ETW(L"Service '%s' already running\n", SERVICE_NAME);
				}
				else {
					LOG_CTRL_ETW(L"StartServiceW failed for '%s' : %lu\n", SERVICE_NAME, err);
				}
			}
		}
		else {
			LOG_CTRL_ETW(L"Service '%s' already running\n", SERVICE_NAME);
		}
	}
	else {
		LOG_CTRL_ETW(L"QueryServiceStatusEx failed: %lu\n", GetLastError());
	}

	CloseServiceHandle(svc);
	CloseServiceHandle(scm);
}
bool Helper::ResolveProcessNtImagePath(DWORD pid, Filter& filter, std::wstring& outNtPath) {
	// 1) Try to get NT path from user-mode (QueryFullProcessImageName with flag=1)
	if (GetFullImageNtPathByPID(pid, outNtPath)) return true;

	// 2) Ask kernel via filter for NT path
	std::wstring kernelPath;
	if (filter.FLTCOMM_GetImagePathByPid(pid, kernelPath)) {
		outNtPath = kernelPath;
		return true;
	}
	return false;
}

bool Helper::ResolveDosPathToNtPath(const std::wstring& dosPath, std::wstring& outNtPath) {
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

bool Helper::GetProcessCommandLineByPID(DWORD pid, std::wstring& outCmdLine) {
	// Use WMI to query Win32_Process for the CommandLine property for the PID.
	HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	bool coInit = SUCCEEDED(hr);

	IWbemLocator *pLoc = nullptr;
	IWbemServices *pSvc = nullptr;
	IEnumWbemClassObject* pEnumerator = nullptr;
	bool result = false;

	hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
		IID_IWbemLocator, (LPVOID *)&pLoc);
	if (FAILED(hr)) goto cleanup;

	hr = pLoc->ConnectServer(
		_bstr_t(L"ROOT\\CIMV2"), // namespace
		NULL, // User
		NULL, // Password
		0,    // Locale
		NULL, // SecurityFlags
		0,    // Authority
		0,    // Context
		&pSvc);

	if (FAILED(hr)) goto cleanup;

	// Set security levels on the proxy
	hr = CoSetProxyBlanket(
		pSvc,                        // the proxy to set
		RPC_C_AUTHN_WINNT,           // authentication service
		RPC_C_AUTHZ_NONE,            // authorization service
		NULL,                        // Server principal name
		RPC_C_AUTHN_LEVEL_CALL,      // authentication level
		RPC_C_IMP_LEVEL_IMPERSONATE, // impersonation level
		NULL,                        // client identity
		EOAC_NONE                    // proxy capabilities
	);
	if (FAILED(hr)) goto cleanup;

	// Query for the specific process
	wchar_t query[128];
	_snwprintf_s(query, _countof(query), _TRUNCATE, L"SELECT CommandLine FROM Win32_Process WHERE ProcessId=%u", pid);

	hr = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t(query),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);

	if (FAILED(hr)) goto cleanup;

	IWbemClassObject *pclsObj = NULL;
	ULONG uReturn = 0;
	hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
	if (uReturn == 0) goto cleanup;

	VARIANT vtProp;
	hr = pclsObj->Get(L"CommandLine", 0, &vtProp, 0, 0);
	if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR && vtProp.bstrVal != NULL) {
		outCmdLine = std::wstring(vtProp.bstrVal, SysStringLen(vtProp.bstrVal));
		result = true;
	}
	VariantClear(&vtProp);
	pclsObj->Release();

cleanup:
	if (pEnumerator) pEnumerator->Release();
	if (pSvc) pSvc->Release();
	if (pLoc) pLoc->Release();
	if (coInit) CoUninitialize();
	return result;
}
bool Helper::ResolveNtCreateThreadExSyscallNum(DWORD* sys_call_num) {
	*sys_call_num = 0;
	UCHAR out_buf[0x10] = { 0 };
	if (!ReadExportFirstBytesFromFile(L"C:\\Windows\\System32\\ntdll.dll", "NtCreateThreadEx", out_buf)) {
		LOG_CTRL_ETW(L"failed to call ReadExportFirstBytesFromFile\n");
		return false;
	}
	DWORD res = ExtractSyscallNumberFromBytes(out_buf);
	if (ULONG_MAX == res) {
		LOG_CTRL_ETW(L"failed to call ExtractSyscallNumberFromBytes\n");
		return false;
	}
	*sys_call_num = res;
	return true;
}
bool Helper::GetModuleBase(bool is64, HANDLE hProc, const wchar_t* target_module, DWORD64* base) {
	if (is64) {
		char _[MAX_PATH] = { 0 };
		ConvertWcharToChar(target_module, _, MAX_PATH);
		if (!GetModuleBaseWithPathEx(hProc, _, (PVOID*)base)) {
			LOG_CTRL_ETW(L"failed to call GetModuleBaseWithPathEx\n");
			return false;
		}
	}
	else {
		if (0 != PHLIB::GetModuleBase((PVOID)hProc, (PVOID)target_module, (PVOID)base)) {
			LOG_CTRL_ETW(L"failed to call PHLIB::GetModuleBase CPU=x86\n");
			return false;
		}
	}
	return true;
}
bool Helper::ForceInject(DWORD pid) {
	// I have an idea about foce inject, we get a process handle with 
	// PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION
	// access
	HANDLE hProc = NULL;
	if (Helper::m_filterInstance) {
		if (!Helper::m_filterInstance->FLTCOMM_GetProcessHandle(pid, &hProc)) {
			LOG_CTRL_ETW(L"failed to call FLTCOMM_GetProcessHandle\n");
			return false;
		}
	}
	else {
		Fatal(L"Helper::m_filterInstance=NULL\n");
		return false;
	}
	LOG_CTRL_ETW(L"get process handle=0x%x from kernel\n", hProc);
	
	bool is64;
	if (!IsProcess64(pid, is64)) {
		LOG_CTRL_ETW(L"failed to call IsProcess64 PID=%u\n", pid);
		CloseHandle(hProc);
		return false;
	}

	PVOID kernel32_base = NULL;
	if (is64) {
		if (!GetModuleBaseWithPathEx(hProc, is64 ? KERNEL_32_X64 : KERNEL_32_X86, &kernel32_base)) {
			LOG_CTRL_ETW(L"failed to call GetModuleBaseWithPathEx PID=%u\n", pid);
			CloseHandle(hProc);
			return false;
		}
	}
	else {
		WCHAR _[] = WIDEN(KERNEL_32_X86);
		if (0!=PHLIB::GetModuleBase((PVOID)hProc, (PVOID)_, (PVOID)&kernel32_base)) {
			LOG_CTRL_ETW(L"failed to call PHLIB::GetModuleBase PID=%u, CPU=x86\n", pid);
			CloseHandle(hProc);
			return false;
		}
	}

	DWORD LoadLibraryW_func_offset = 0;
	std::wstring dll_path = Helper::m_SysDriverMark + (is64 ? WIDEN(KERNEL_32_X64) : WIDEN(KERNEL_32_X86));
	if (!CheckExportFromFile(dll_path.c_str(), "LoadLibraryW", &LoadLibraryW_func_offset)) {
		LOG_CTRL_ETW(L"failed to call CheckExportFromFile PID=%u, dll_path=%s\n", pid, dll_path.c_str());
		CloseHandle(hProc);
		return false;
	}

	void* pLoadLibraryW = (PVOID)(ULONG_PTR)((DWORD64)kernel32_base + LoadLibraryW_func_offset);


	// this operation can be done by driver code, we only need to pass the dll path to it
	// and it should return an address back to us
	std::wstring exe = Helper::GetCurrentDirFilePath(L"");
	size_t pos = exe.find_last_of(L"/\\");
	std::wstring dir = (pos == std::wstring::npos) ? exe : exe.substr(0, pos);
	
	const wchar_t* masterName = is64 ? MASTER_X64_DLL_BASENAME : MASTER_X86_DLL_BASENAME;
	std::wstring dllnamepath = dir + L"\\" + masterName;


	// write dll path
	PVOID dll_path_addr = NULL;
	if (!Helper::m_filterInstance->FLTCOMM_WriteDllPathToTargetProcess(pid, (PVOID)dllnamepath.c_str(), &dll_path_addr)) {
		LOG_CTRL_ETW(L"failed to call FLTCOMM_WriteDllPathToTargetProcess\n");
		CloseHandle(hProc);
		return false;
	}
	LOG_CTRL_ETW(L"write dll Path=%s to target process Pid=%u memory Addr=0x%p\n", dllnamepath.c_str(), pid, dll_path_addr);
	PVOID syscall_addr = 0;
	 
	// get NtCreateThreadEx kernel function addr
	if (!Helper::m_filterInstance->FLTCOMM_GetSyscallAddr(Helper::m_NtCreateThreadExSyscallNum, &syscall_addr)) {
		LOG_CTRL_ETW(L"call FLTCOMM_GetSyscallAddr failed\n");
		goto CLEAN_UP;
	}

	HANDLE thread_handle = 0;
	if (!Helper::m_filterInstance->FLTCOMM_CreateRemoteThread(pid, pLoadLibraryW, dll_path_addr, syscall_addr, &thread_handle, NULL, hProc)) {
		LOG_CTRL_ETW(L"call FLTCOMM_CreateRemoteThread failed\n");
		goto CLEAN_UP;
	}
	CloseHandle(hProc);
	return true;

CLEAN_UP:;
	CloseHandle(hProc);
	return false;
}
bool Helper::wstrcasestr_check(const wchar_t* haystack, const wchar_t* needle) {
	if (!haystack || !needle) return false;
	if (*needle == L'\0') return true; // empty needle -> match

	for (; *haystack != L'\0'; ++haystack) {
		const wchar_t *h = haystack;
		const wchar_t *n = needle;
		while (*n != L'\0' && towlower((wint_t)*h) == towlower((wint_t)*n)) {
			++h; ++n;
		}
		if (*n == L'\0') return true; /* matched whole needle */
		if (*h == L'\0') return false; /* haystack ended */
	}
	return false;
}
bool Helper::strcasestr_check(const char *haystack, const char *needle) {
	if (!haystack || !needle) return false;
	if (*needle == '\0') return true; /* empty needle -> match */

	for (; *haystack != '\0'; ++haystack) {
		const char *h = haystack;
		const char *n = needle;
		while (*n != '\0' &&
			tolower((unsigned char)*h) == tolower((unsigned char)*n)) {
			++h; ++n;
		}
		if (*n == '\0') return true; /* matched whole needle */
		if (*h == '\0') return false; /* haystack ended */
	}
	return false;
}

// Use EnumProcessModulesEx to handle different module lists and architectures
bool Helper::GetModuleBaseWithPathEx(HANDLE hProcess, const char* mPath, PVOID* base) {
	if (!mPath || !base || !hProcess) {
		LOG_CTRL_ETW(L"GetModuleBaseWithPathEx parameter snanity check failed\n");
		return false;
}
	*base = NULL;
	

	HMODULE hMods[4096];
	DWORD cbNeeded = 0;
	wchar_t wide[MAX_PATH] = { 0 };
	// Use LIST_MODULES_ALL to be robust across WoW64 and different module visibility
	if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) {
		DWORD count = cbNeeded / sizeof(HMODULE);
		for (DWORD i = 0; i < count; ++i) {
			char szModName[MAX_PATH] = { 0 };
			if (GetModuleFileNameExA(hProcess, hMods[i], szModName, _countof(szModName))) {

				// ConvertCharToWchar(szModName, wide, MAX_PATH);
				// LOG_CTRL_ETW(L"debug: SysWOW64 module: %s\n", wide);
				if (strcasestr_check(szModName, mPath)) {
					*base = (PVOID)hMods[i];
					break;
				}
			}
		}
	}
	return (*base != NULL);
}
bool Helper::IsProcess64(DWORD pid, bool& outIs64) {
	// First attempt: if a Filter instance is available, ask the kernel
	// whether the target process is a WoW64 (32-bit) process. This is
	// authoritative and avoids user-mode permission issues when opening
	// target processes.
	if (Helper::m_filterInstance) {
		bool isWow64 = false;
		if (Helper::m_filterInstance->FLTCOMM_IsProcessWow64(pid, isWow64)) {
			outIs64 = !isWow64;
			return true;
		}
		// If the FLT IPC failed, fall back to existing user-mode logic.
	}
	// UMController is always built as x64. Simplify logic: detect WOW64.
	typedef BOOL(WINAPI *IsWow64Process2_t)(HANDLE, USHORT*, USHORT*);
	typedef BOOL(WINAPI *IsWow64Process_t)(HANDLE, PBOOL);
	static IsWow64Process2_t s_pIsWow64Process2 = nullptr;
	static IsWow64Process_t  s_pIsWow64Process = nullptr;
	static bool s_resolved = false;
	if (!s_resolved) {
		HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
		if (hK32) {
			s_pIsWow64Process2 = (IsWow64Process2_t)GetProcAddress(hK32, "IsWow64Process2");
			s_pIsWow64Process = (IsWow64Process_t)GetProcAddress(hK32, "IsWow64Process");
		}
		s_resolved = true;
	}

	HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (!h) return false;
	bool is64 = true; // assume 64-bit unless proven WOW64
	if (s_pIsWow64Process2) {
		USHORT pMachine = 0, nMachine = 0;
		if (!s_pIsWow64Process2(h, &pMachine, &nMachine)) { CloseHandle(h); return false; }
		is64 = (pMachine == 0); // pMachine != 0 => WOW64 (i.e., 32-bit process)
	}
	else if (s_pIsWow64Process) {
		BOOL wow = FALSE;
		if (!s_pIsWow64Process(h, &wow)) { CloseHandle(h); return false; }
		is64 = !wow;
	}
	CloseHandle(h);
	outIs64 = is64;
	return true;
}
void Helper::SetSysDriverMark(std::wstring sysmark){
	Helper::m_SysDriverMark = sysmark;
}
void Helper::SetNtCreateThreadExSyscallNum(DWORD num) {
	Helper::m_NtCreateThreadExSyscallNum = num;
}
void Helper::SetFilterInstance(Filter* f) {
	Helper::m_filterInstance = f;
}

bool Helper::EnableDebugPrivilege(bool enable) {
	HANDLE hToken = NULL;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		LOG_CTRL_ETW(L"EnableDebugPrivilege: OpenProcessToken failed: %lu\n", GetLastError());
		return false;
	}

	LUID luid;
	if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) {
		LOG_CTRL_ETW(L"EnableDebugPrivilege: LookupPrivilegeValueW failed: %lu\n", GetLastError());
		CloseHandle(hToken);
		return false;
	}

	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
		LOG_CTRL_ETW(L"EnableDebugPrivilege: AdjustTokenPrivileges failed: %lu\n", GetLastError());
		CloseHandle(hToken);
		return false;
	}

	DWORD err = GetLastError();
	if (err == ERROR_NOT_ALL_ASSIGNED) {
		LOG_CTRL_ETW(L"EnableDebugPrivilege: the token does not have the specified privilege\n");
		CloseHandle(hToken);
		return false;
	}

	CloseHandle(hToken);
	return true;
}
bool Helper::CreateLowPrivReqFile(wchar_t* filePath, PHANDLE outFileHandle) {
	PSECURITY_DESCRIPTOR pSD = nullptr;

	// SDDL: D: (DACL) (A;;GA;;;WD) => Allow Generic All to Everyone
	LPCWSTR sddl = L"D:(A;;GA;;;WD)";

	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
		sddl, SDDL_REVISION_1, &pSD, NULL)) {
		LOG_CTRL_ETW(L"ConvertStringSecurityDescriptorToSecurityDescriptorW failed: 0x%x\n", GetLastError());
		return false;
	}

	SECURITY_ATTRIBUTES sa = {};
	sa.nLength = sizeof(sa);
	sa.lpSecurityDescriptor = pSD;
	sa.bInheritHandle = FALSE;



	HANDLE hFile = CreateFile(filePath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		LOG_CTRL_ETW(L"IPC_SendInject: CreateFile %ws failed (%u)\n", filePath, GetLastError());
		LocalFree(pSD);

		return false;
	}
	LocalFree(pSD);
	*outFileHandle = hFile;
	return true;
}


bool Helper::IsModuleLoaded(DWORD pid, const wchar_t* baseName, bool& outPresent) {
	// if this call is to check master module, we'll use event way
	if (wcsstr(baseName, DLL_PREFIX)) {
		wchar_t event_name[100] = { 0 };
		swprintf_s(event_name, USER_MODE_MASTER_LOAD_EVENT L"%d", pid);
		HANDLE h = OpenEventW(SYNCHRONIZE, FALSE, event_name);
		DWORD err = GetLastError();
		if (!err) {
			CloseHandle(h);
			outPresent = true;
		}
		else if (err == ERROR_ACCESS_DENIED) {
			outPresent = true;
			return true;
		}
		return true;
	}


	if (!baseName || !*baseName) return false;
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	if (snap == INVALID_HANDLE_VALUE) {
		// LOG_CTRL_ETW(L"failed to call CreateToolhelp32Snapshot target PID=%u, error: 0x%x\n", pid, GetLastError());
		// Fatal(L"failed to call CreateToolhelp32Snapshot\n");
		return false;
	}
	MODULEENTRY32W me = { sizeof(me) };
	bool ok = false;
	bool present = false;
	if (Module32FirstW(snap, &me)) {
		do {
			if (_wcsicmp(me.szModule, baseName) == 0) { present = true; break; }
		} while (Module32NextW(snap, &me));
		ok = true;
	}
	CloseHandle(snap);
	if (ok) outPresent = present;
	return ok;
}

bool Helper::ConvertCharToWchar(const char* src, wchar_t* dst, size_t dstChars) {
	if (!src || !dst || dstChars == 0) return false;
	// Simple byte->word expansion: copy each input byte into the low
	// 16 bits of a wchar_t and append a null terminator. This avoids
	// calling Win32 APIs and ignores code pages as requested.
	size_t i = 0;
	for (; i + 1 < dstChars && src[i] != '\0'; ++i) {
		dst[i] = (wchar_t)(unsigned char)src[i];
	}
	if (i >= dstChars) return false; // no room for null terminator
	dst[i] = L'\0';
	return true;
}


std::wstring Helper::ToHex(ULONGLONG value) {
	if (value == 0) return L"0";
	static const wchar_t* digits = L"0123456789ABCDEF";
	std::wstring out;
	bool started = false;
	for (int nib = 15; nib >= 0; --nib) { // 16 nibbles for 64-bit
		ULONGLONG shift = (ULONGLONG)nib * 4ULL;
		unsigned v = (unsigned)((value >> shift) & 0xF);
		if (!started) {
			if (v == 0) continue;
			started = true;
		}
		out.push_back(digits[v]);
	}
	return out;
}

bool Helper::ConvertWcharToChar(const wchar_t* src, char* dst, size_t dstChars) {
	if (!src || !dst || dstChars == 0) return false;
	size_t i = 0;
	for (; i + 1 < dstChars && src[i] != L'\0'; ++i) {
		dst[i] = (char)(src[i] & 0xFF);
	}
	if (i >= dstChars) return false; // no room for null
	dst[i] = '\0';
	return true;
}
bool Helper::CheckExportFromFile(const wchar_t* dllPath, const char* exportName,DWORD* out_func_offset) {
	if (!dllPath || !exportName) {
		LOG_CTRL_ETW(L"Parameter sanity check failed\n");
		return false;
	}
	HANDLE hFile = CreateFileW(dllPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		LOG_CTRL_ETW(L"CheckExportFromFile: CreateFileW failed for %s err=%u\n", dllPath, GetLastError());
		return false;
	}

	HANDLE hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (!hMap) { CloseHandle(hFile); return false; }
	LPVOID base = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
	if (!base) { CloseHandle(hMap); CloseHandle(hFile); return false; }

	__try {
		IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
		if (dos->e_magic != IMAGE_DOS_SIGNATURE) { __leave; }

		// Point to NT headers (works for both 32- and 64-bit when cast appropriately)
		PIMAGE_NT_HEADERS pNth = (PIMAGE_NT_HEADERS)((PBYTE)base + dos->e_lfanew);
		if (pNth->Signature != IMAGE_NT_SIGNATURE) { __leave; }

		// Generic helper to convert RVA -> file offset using IMAGE_FIRST_SECTION
		auto RvaToOffsetGeneric = [&](PIMAGE_NT_HEADERS anyNth, DWORD rva) -> SIZE_T {
			PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(anyNth);
			WORD number = anyNth->FileHeader.NumberOfSections;
			for (WORD i = 0; i < number; ++i) {
				DWORD va = sections[i].VirtualAddress;
				DWORD vs = sections[i].Misc.VirtualSize ? sections[i].Misc.VirtualSize : sections[i].SizeOfRawData;
				if (rva >= va && rva < va + vs) {
					DWORD delta = rva - va;
					return (SIZE_T)sections[i].PointerToRawData + delta;
				}
			}
			return (SIZE_T)-1;
		};

		// Determine whether image is 32-bit or 64-bit by OptionalHeader.Magic
		WORD magic = pNth->OptionalHeader.Magic;
		bool is64 = false;
		if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) is64 = true;
		else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) is64 = false;
		else __leave;

		DWORD exportRva = 0;
		if (is64) {
			PIMAGE_NT_HEADERS64 nth64 = (PIMAGE_NT_HEADERS64)pNth;
			exportRva = nth64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		}
		else {
			PIMAGE_NT_HEADERS32 nth32 = (PIMAGE_NT_HEADERS32)pNth;
			exportRva = nth32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		}
		if (exportRva == 0) __leave;

		SIZE_T expOff = RvaToOffsetGeneric(pNth, exportRva);
		if (expOff == (SIZE_T)-1) __leave;
		IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)((PBYTE)base + expOff);

		DWORD* names = (DWORD*)((PBYTE)base + RvaToOffsetGeneric(pNth, exp->AddressOfNames));
		WORD* ords = (WORD*)((PBYTE)base + RvaToOffsetGeneric(pNth, exp->AddressOfNameOrdinals));
		DWORD* funcs = (DWORD*)((PBYTE)base + RvaToOffsetGeneric(pNth, exp->AddressOfFunctions));

		// Find export (ASCII comparison)
		DWORD funcRva = 0; BOOL found = FALSE;
		for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
			SIZE_T nameOff = RvaToOffsetGeneric(pNth, names[i]);
			if (nameOff == (SIZE_T)-1) continue;
			const char* name = (const char*)((PBYTE)base + nameOff);
			if (_stricmp(name, exportName) == 0) {
				WORD ord = ords[i];
				if (ord < exp->NumberOfFunctions) { funcRva = funcs[ord]; *out_func_offset = funcRva; found = TRUE; break; }
			}
		}
		if (!found) __leave;
		UnmapViewOfFile(base); CloseHandle(hMap); CloseHandle(hFile);
		base = NULL;
		hMap = NULL;
		hFile = NULL;
		return true;
	}
	__finally {
		// If not returned above, unmap/close
		if (base) { UnmapViewOfFile(base); }
		if (hMap) CloseHandle(hMap);
		if (hFile) CloseHandle(hFile);
	}
	return false;
}

// Read first 16 bytes of an export directly from DLL file on disk.
bool Helper::ReadExportFirstBytesFromFile(const wchar_t* dllPath, const char* exportName, unsigned char outBuf[16]) {
	if (!dllPath || !exportName || !outBuf) {
		LOG_CTRL_ETW(L"Parameter sanity check failed\n");
		return false;
	}

	HANDLE hFile = CreateFileW(dllPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		LOG_CTRL_ETW(L"ReadExportFirstBytesFromFile: CreateFileW failed for %s err=%u\n", dllPath, GetLastError());
		return false;
	}

	HANDLE hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (!hMap) { CloseHandle(hFile); return false; }
	LPVOID base = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
	if (!base) { CloseHandle(hMap); CloseHandle(hFile); return false; }

	__try {
		IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
		if (dos->e_magic != IMAGE_DOS_SIGNATURE) { __leave; }

		PIMAGE_NT_HEADERS pNth = (PIMAGE_NT_HEADERS)((PBYTE)base + dos->e_lfanew);
		if (pNth->Signature != IMAGE_NT_SIGNATURE) { __leave; }

		auto RvaToOffsetGeneric = [&](PIMAGE_NT_HEADERS anyNth, DWORD rva) -> SIZE_T {
			PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(anyNth);
			WORD number = anyNth->FileHeader.NumberOfSections;
			for (WORD i = 0; i < number; ++i) {
				DWORD va = sections[i].VirtualAddress;
				DWORD vs = sections[i].Misc.VirtualSize ? sections[i].Misc.VirtualSize : sections[i].SizeOfRawData;
				if (rva >= va && rva < va + vs) {
					DWORD delta = rva - va;
					return (SIZE_T)sections[i].PointerToRawData + delta;
				}
			}
			return (SIZE_T)-1;
		};

		WORD magic = pNth->OptionalHeader.Magic;
		bool is64 = false;
		if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) is64 = true;
		else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) is64 = false;
		else __leave;

		DWORD exportRva = 0;
		if (is64) {
			PIMAGE_NT_HEADERS64 nth64 = (PIMAGE_NT_HEADERS64)pNth;
			exportRva = nth64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		}
		else {
			PIMAGE_NT_HEADERS32 nth32 = (PIMAGE_NT_HEADERS32)pNth;
			exportRva = nth32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		}
		if (exportRva == 0) __leave;

		SIZE_T expOff = RvaToOffsetGeneric(pNth, exportRva);
		if (expOff == (SIZE_T)-1) __leave;
		IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)((PBYTE)base + expOff);

		DWORD* names = (DWORD*)((PBYTE)base + RvaToOffsetGeneric(pNth, exp->AddressOfNames));
		WORD* ords = (WORD*)((PBYTE)base + RvaToOffsetGeneric(pNth, exp->AddressOfNameOrdinals));
		DWORD* funcs = (DWORD*)((PBYTE)base + RvaToOffsetGeneric(pNth, exp->AddressOfFunctions));

		DWORD funcRva = 0; BOOL found = FALSE;
		for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
			SIZE_T nameOff = RvaToOffsetGeneric(pNth, names[i]);
			if (nameOff == (SIZE_T)-1) continue;
			const char* name = (const char*)((PBYTE)base + nameOff);
			if (_stricmp(name, exportName) == 0) {
				WORD ord = ords[i];
				if (ord < exp->NumberOfFunctions) { funcRva = funcs[ord]; found = TRUE; break; }
			}
		}
		if (!found) __leave;

		SIZE_T offset = RvaToOffsetGeneric(pNth, funcRva);
		if (offset == (SIZE_T)-1) __leave;
		memcpy(outBuf, (PBYTE)base + offset, 16);
		UnmapViewOfFile(base); CloseHandle(hMap); CloseHandle(hFile);
		base = NULL;
		hMap = NULL;
		hFile = NULL;
		return true;
	}
	__finally {
		// If not returned above, unmap/close
		if (base) { UnmapViewOfFile(base); }
		if (hMap) CloseHandle(hMap);
		if (hFile) CloseHandle(hFile);
	}
	return false;
}

// Helper: convert an RVA to a raw file offset for the mapped image.
// `base` is the mapped file base. `nth` may be 32- or 64-bit header pointer;
// we treat it as 64-bit for offsets since layouts are compatible for section table location.
SIZE_T Helper::RvaToOffset(void* base, IMAGE_NT_HEADERS64* nth, DWORD rva) {
	IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)((PBYTE)&nth->OptionalHeader + nth->FileHeader.SizeOfOptionalHeader);
	WORD number = nth->FileHeader.NumberOfSections;
	for (WORD i = 0; i < number; ++i) {
		DWORD va = sections[i].VirtualAddress;
		DWORD vs = sections[i].Misc.VirtualSize ? sections[i].Misc.VirtualSize : sections[i].SizeOfRawData;
		if (rva >= va && rva < va + vs) {
			DWORD delta = rva - va;
			return (SIZE_T)sections[i].PointerToRawData + delta;
		}
	}
	return (SIZE_T)-1;
}

 Filter* Helper::GetFilterInstance() {
	 return Helper::m_filterInstance;
}
// Configure/Toggle the boot-start service (UMHH.BootStart or SERVICE_NAME fallback)
bool Helper::ConfigureBootStartService(bool DesiredEnabled) {
	// disable for now, seems like I fucked up file system when using global injection
	// DesiredEnabled = FALSE;

	const wchar_t* svcName =
#if defined(BS_SERVICE_NAME)
		BS_SERVICE_NAME;
#else
		SERVICE_NAME;
#endif

	// Open SCM
	SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
	if (!scm) {
		LOG_CTRL_ETW(L"ConfigureBootStartService: OpenSCManagerW failed: %lu\n", GetLastError());
		return false;
	}

	// Compute paths
	std::basic_string<TCHAR> drvName = std::basic_string<TCHAR>(svcName) + std::basic_string<TCHAR>(L".sys");
	wchar_t sysDir[MAX_PATH]; if (!GetSystemDirectoryW(sysDir, _countof(sysDir))) { LOG_CTRL_ETW(L"ConfigureBootStartService: GetSystemDirectoryW failed: %lu\n", GetLastError()); CloseServiceHandle(scm); return false; }
	std::wstring dstDir = std::wstring(sysDir) + L"\\drivers\\"; std::wstring dstPath = dstDir + std::wstring(drvName.c_str());

	// Open service if exists
	SC_HANDLE svc = OpenServiceW(scm, svcName, SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP | SERVICE_CHANGE_CONFIG | DELETE);
	if (DesiredEnabled) {
		// Ensure driver file exists in system drivers dir. If not, try to copy from exe dir.
		DWORD fa = GetFileAttributesW(dstPath.c_str());
		if (fa == INVALID_FILE_ATTRIBUTES) {
			// try to locate next to exe
			std::basic_string<TCHAR> srcPath = Helper::GetCurrentDirFilePath(const_cast<TCHAR*>(drvName.c_str()));
			if (!srcPath.empty()) {
				CopyFileW(srcPath.c_str(), dstPath.c_str(), FALSE);
			}
		}

		if (!svc) {
			// create the service as boot-start
			SC_HANDLE newSvc = CreateServiceW(scm, svcName, svcName, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
				SERVICE_SYSTEM_START, SERVICE_ERROR_NORMAL, dstPath.c_str(), NULL, NULL, NULL, NULL, NULL);
			if (!newSvc) {
				LOG_CTRL_ETW(L"ConfigureBootStartService: CreateServiceW failed: %lu\n", GetLastError());
				CloseServiceHandle(scm);
				return false;
			}
			CloseServiceHandle(newSvc);
		}

		// Also ensure a dedicated boot-start service named 'umhh.bootstart' exists
		// and is configured as a kernel driver with System start.
		{
			const wchar_t* bootSvcName = L"umhh.bootstart";
			SC_HANDLE svcBoot = OpenServiceW(scm, bootSvcName, SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG | SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_ALL_ACCESS);
			if (!svcBoot) {
				SC_HANDLE created = CreateServiceW(scm, bootSvcName, bootSvcName, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
					SERVICE_SYSTEM_START, SERVICE_ERROR_NORMAL, dstPath.c_str(), NULL, NULL, NULL, NULL, NULL);
				if (!created) {
					LOG_CTRL_ETW(L"ConfigureBootStartService: CreateServiceW for %s failed: %lu\n", bootSvcName, GetLastError());
				}
				else {
					CloseServiceHandle(created);
					LOG_CTRL_ETW(L"ConfigureBootStartService: created boot-start service %s\n", bootSvcName);
				}
			}
			else {
				// Ensure service is configured as kernel driver and system start
				DWORD qNeeded = 0;
				QueryServiceConfigW(svcBoot, NULL, 0, &qNeeded);
				if (qNeeded > 0) {
					std::unique_ptr<BYTE[]> qbuf(new BYTE[qNeeded]);
					LPQUERY_SERVICE_CONFIGW pq = (LPQUERY_SERVICE_CONFIGW)qbuf.get();
					if (QueryServiceConfigW(svcBoot, pq, qNeeded, &qNeeded)) {
						if (pq->dwServiceType != SERVICE_KERNEL_DRIVER || pq->dwStartType != SERVICE_SYSTEM_START) {
							if (!ChangeServiceConfigW(svcBoot,
								SERVICE_KERNEL_DRIVER, // service type
								SERVICE_SYSTEM_START, // start type
								SERVICE_NO_CHANGE,
								dstPath.c_str(), NULL, NULL, NULL, NULL, NULL, NULL)) {
								LOG_CTRL_ETW(L"ConfigureBootStartService: ChangeServiceConfigW failed for %s : %lu\n", bootSvcName, GetLastError());
							}
							else {
								LOG_CTRL_ETW(L"ConfigureBootStartService: updated %s to kernel driver + SYSTEM_START\n", bootSvcName);
							}
						}
					}
				}
				CloseServiceHandle(svcBoot);
			}

			// Ensure registry ImagePath and Start=SYSTEM_START for boot service
			{
				std::wstring regPathBoot = std::wstring(L"SYSTEM\\CurrentControlSet\\Services\\") + std::wstring(L"umhh.bootstart");
				HKEY hKeyBoot = NULL; LONG rcBoot = RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPathBoot.c_str(), 0, KEY_SET_VALUE, &hKeyBoot);
				if (rcBoot == ERROR_SUCCESS) {
					std::wstring imagePathBoot = std::wstring(L"\\SystemRoot\\system32\\drivers\\") + drvName;
					RegSetValueExW(hKeyBoot, L"ImagePath", 0, REG_EXPAND_SZ, (const BYTE*)imagePathBoot.c_str(), (DWORD)((imagePathBoot.size() + 1) * sizeof(wchar_t)));
					DWORD startValBoot = SERVICE_SYSTEM_START;
					RegSetValueExW(hKeyBoot, L"Start", 0, REG_DWORD, (const BYTE*)&startValBoot, sizeof(startValBoot));
					RegCloseKey(hKeyBoot);
				}
				else {
					LOG_CTRL_ETW(L"ConfigureBootStartService: RegOpenKeyExW failed for %s : %lu\n", regPathBoot.c_str(), rcBoot);
				}
			}
		}
		// Write registry ImagePath and Start=0
		std::wstring regPath = std::wstring(L"SYSTEM\\CurrentControlSet\\Services\\") + std::wstring(svcName);
		HKEY hKey = NULL; LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, KEY_SET_VALUE, &hKey);
		if (rc == ERROR_SUCCESS) {
			std::wstring imagePath = std::wstring(L"\\SystemRoot\\system32\\drivers\\") + drvName;
			RegSetValueExW(hKey, L"ImagePath", 0, REG_EXPAND_SZ, (const BYTE*)imagePath.c_str(), (DWORD)((imagePath.size() + 1) * sizeof(wchar_t)));
			DWORD startVal = SERVICE_SYSTEM_START;
			RegSetValueExW(hKey, L"Start", 0, REG_DWORD, (const BYTE*)&startVal, sizeof(startVal));
			RegCloseKey(hKey);
		}
		else {
			LOG_CTRL_ETW(L"ConfigureBootStartService: RegOpenKeyExW failed for %s : %lu\n", regPath.c_str(), rc);
		}

		// Start service if not running


		SC_HANDLE svc2 = OpenServiceW(scm, svcName, SERVICE_QUERY_STATUS | SERVICE_START);
		if (svc2) {
			SERVICE_STATUS_PROCESS ssp = { 0 }; DWORD bytes = 0;
			if (QueryServiceStatusEx(svc2, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytes)) {
				if (ssp.dwCurrentState != SERVICE_RUNNING) {
					StartServiceW(svc2, 0, NULL);
				}
			}
			CloseServiceHandle(svc2);
		}

	}
	else {
		
		// Desired disabled: if service exists, stop it, delete the service, and
		// remove the driver file from the system drivers directory.
		if (svc) {

			SERVICE_STATUS_PROCESS ssp = { 0 }; DWORD bytes = 0;
			if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytes)) {
				if (ssp.dwCurrentState == SERVICE_RUNNING) {
					SERVICE_STATUS ss = { 0 };
					ControlService(svc, SERVICE_CONTROL_STOP, &ss);
				}
			}

			// Query binary path so we can remove the driver file after deletion
			std::wstring binPath;
			DWORD needed = 0; QueryServiceConfigW(svc, NULL, 0, &needed);
			if (needed > 0) {
				std::unique_ptr<BYTE[]> buf(new BYTE[needed]);
				LPQUERY_SERVICE_CONFIGW qsc = (LPQUERY_SERVICE_CONFIGW)buf.get();
				if (QueryServiceConfigW(svc, qsc, needed, &needed)) {
					binPath = qsc->lpBinaryPathName ? qsc->lpBinaryPathName : L"";
				}
			}

			// Attempt to delete the service
			if (!DeleteService(svc)) {
				LOG_CTRL_ETW(L"ConfigureBootStartService: DeleteService failed for %s : %lu\n", svcName, GetLastError());
			}
			else {
				LOG_CTRL_ETW(L"ConfigureBootStartService: service %s deleted\n", svcName);
			}
			CloseServiceHandle(svc);

			// Remove driver file if known
			if (!binPath.empty()) {
				wchar_t expanded[MAX_PATH];
				if (ExpandEnvironmentStringsW(binPath.c_str(), expanded, _countof(expanded))) {
					DeleteFileW(expanded);
				}
				else {
					DeleteFileW(binPath.c_str());
				}
			}
		}
	}

	if (svc) CloseServiceHandle(svc);
	CloseServiceHandle(scm);
	return true;
}



bool Helper::CopyUmhhDllsToRoot() {
	// Determine source paths located next to the running executable
	std::wstring x64Name = X64_DLL; // L"umhh.dll.x64.dll"
	std::wstring x86Name = X86_DLL; // L"umhh.dll.Win32.dll"

	// Get paths next to the current module
	std::basic_string<TCHAR> srcX64 = Helper::GetCurrentDirFilePath(const_cast<TCHAR*>(x64Name.c_str()));
	std::basic_string<TCHAR> srcX86 = Helper::GetCurrentDirFilePath(const_cast<TCHAR*>(x86Name.c_str()));

	if (srcX64.empty() && srcX86.empty()) {
		LOG_CTRL_ETW(L"CopyUmhhDllsToRoot: could not determine source paths for UMHH DLLs\n");
		return false;
	}

	// --------------------------------------------------------------
	// Get system drive dynamically (e.g., "C:\" or "D:\")
	// --------------------------------------------------------------
	WCHAR winDir[MAX_PATH] = { 0 };
	GetWindowsDirectoryW(winDir, MAX_PATH);

	std::wstring systemDrive = std::wstring(winDir, 2) + L"\\";   // "C:\" or "D:\" etc.
	// --------------------------------------------------------------

	// Build destination paths
	std::wstring dstX64 = systemDrive + x64Name;
	std::wstring dstX86 = systemDrive + x86Name;

	bool ok = true;

	if (!srcX64.empty()) {
		DWORD fa = GetFileAttributesW(srcX64.c_str());
		if (fa != INVALID_FILE_ATTRIBUTES) {
			if (!CopyFileW(srcX64.c_str(), dstX64.c_str(), FALSE)) {
				LOG_CTRL_ETW(L"CopyUmhhDllsToRoot: failed to copy %s to %s : %lu\n",
					srcX64.c_str(), dstX64.c_str(), GetLastError());
				ok = false;
			}
			else {
				LOG_CTRL_ETW(L"CopyUmhhDllsToRoot: copied %s to %s\n", srcX64.c_str(), dstX64.c_str());
			}
		}
		else {
			LOG_CTRL_ETW(L"CopyUmhhDllsToRoot: source x64 DLL not found: %s\n", srcX64.c_str());
			ok = false;
		}
	}

	if (!srcX86.empty()) {
		DWORD fa = GetFileAttributesW(srcX86.c_str());
		if (fa != INVALID_FILE_ATTRIBUTES) {
			if (!CopyFileW(srcX86.c_str(), dstX86.c_str(), FALSE)) {
				LOG_CTRL_ETW(L"CopyUmhhDllsToRoot: failed to copy %s to %s : %lu\n",
					srcX86.c_str(), dstX86.c_str(), GetLastError());
				ok = false;
			}
			else {
				LOG_CTRL_ETW(L"CopyUmhhDllsToRoot: copied %s to %s\n", srcX86.c_str(), dstX86.c_str());
			}
		}
		else {
			LOG_CTRL_ETW(L"CopyUmhhDllsToRoot: source x86 DLL not found: %s\n", srcX86.c_str());
			ok = false;
		}
	}

	return ok;
}
