#include "pch.h"
#include "Helper.h"
#include "ETW.h"
#include "UMController.h"
#include "RegistryStore.h"
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


// NOTE: WaitAndExit was removed. Call Helper::Fatal(...) at call sites.

void Helper::SetFatalHandler(FatalHandlerType handler) {
	g_fatalHandler.store(handler, std::memory_order_release);
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


std::basic_string<TCHAR> Helper::GetCurrentModulePath(TCHAR* append)
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
				} else {
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
				} else {
					DeleteFileW(bin.c_str());
				}
			}
		} else {
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
	if (svc) { /* already closed above */ } else if (err != ERROR_SERVICE_DOES_NOT_EXIST && err != ERROR_SERVICE_MARKED_FOR_DELETE) {
		LOG_CTRL_ETW(L"UMHH_BS_DriverCheck: OpenServiceW unexpected error: %lu\n", err);
		CloseServiceHandle(scm); return false;
	}

	// Build source and destination paths for driver file
	std::basic_string<TCHAR> drvName = std::basic_string<TCHAR>(svcName) + std::basic_string<TCHAR>(L".sys");
	std::basic_string<TCHAR> srcPath = Helper::GetCurrentModulePath(const_cast<TCHAR*>(drvName.c_str()));
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
			std::basic_string<TCHAR> infPath = Helper::GetCurrentModulePath(const_cast<TCHAR*>(infName.c_str()));
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
			std::basic_string<TCHAR> sysPath = Helper::GetCurrentModulePath(const_cast<TCHAR*>(sysName.c_str()));
			if (!sysPath.empty()) {
				if (!ChangeServiceConfigW(svc,
					SERVICE_NO_CHANGE, // service type
					SERVICE_AUTO_START, // start type
					SERVICE_NO_CHANGE,
					sysPath.c_str(),   // binary path
					NULL, NULL, NULL, NULL, NULL, NULL)) {
					LOG_CTRL_ETW(L"ChangeServiceConfigW to set BinaryPathName failed: %lu (path=%s)\n", GetLastError(), sysPath.c_str());
				} else {
					LOG_CTRL_ETW(L"Service binary path updated to %s\n", sysPath.c_str());
				}
			} else {
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
				if (pq->dwStartType != SERVICE_AUTO_START) {
					if (!ChangeServiceConfigW(svc,
						SERVICE_NO_CHANGE, // service type
						SERVICE_AUTO_START, // start type -> change to auto
						SERVICE_NO_CHANGE,
						NULL, NULL, NULL, NULL, NULL, NULL, NULL)) {
						LOG_CTRL_ETW(L"UMHH_DriverCheck: ChangeServiceConfigW to SERVICE_AUTO_START failed: %lu\n", GetLastError());
					} else {
						LOG_CTRL_ETW(L"UMHH_DriverCheck: service %s start type updated to SERVICE_AUTO_START\n", SERVICE_NAME);
					}
				}
			} else {
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
bool Helper::ForceInject(DWORD pid) {
	if (Helper::m_filterInstance) {
		return Helper::m_filterInstance->FLTCOMM_ForceInject(pid);
	}
	
	LOG_CTRL_ETW(L"can't perform force injection because Helper::m_filterInstance is NULL\n");
	Fatal(L"can't perform force injection because Helper::m_filterInstance is NULL\n");
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
bool Helper::GetModuleBaseWithPath(DWORD pid, char* mPath,PVOID* base) {
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (!hProcess) {
		LOG_CTRL_ETW(L"failed to open PID=%u with VM_READ access, error: 0x%x\n", pid, GetLastError());
		return false;
	}

	HMODULE hMods[1024];
	DWORD cbNeeded;
	DWORD64 kbase = 0;
	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
		for (DWORD i = 0; i < cbNeeded / sizeof(HMODULE); i++) {
			char szModName[MAX_PATH];
			GetModuleFileNameExA(hProcess, hMods[i], szModName, MAX_PATH);

			if (strcasestr_check(szModName, mPath) == 1) {
				*base = hMods[i];
				break;
			}
		}
	}
	if (*base)
		return true;
	return false;
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
bool Helper::CreateLowPrivReqFile(wchar_t* filePath,PHANDLE outFileHandle) {
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
		swprintf_s(event_name, MASTER_LOAD_EVENT L"%d", pid);
		HANDLE h = OpenEventW(EVENT_MODIFY_STATE, FALSE, L"MyTestEvent");
		if (!h)
			return false;
		DWORD err = GetLastError();
		if (err == ERROR_FILE_NOT_FOUND) {
			return false;
		}
		else {
			LOG_CTRL_ETW(L"OpenEvent failed, error = %lu\n", err);
			Fatal(L"OpenEvent failed\n");
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
			std::basic_string<TCHAR> srcPath = Helper::GetCurrentModulePath(const_cast<TCHAR*>(drvName.c_str()));
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

		// Write registry ImagePath and Start=0
		std::wstring regPath = std::wstring(L"SYSTEM\\CurrentControlSet\\Services\\") + std::wstring(svcName);
		HKEY hKey = NULL; LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, KEY_SET_VALUE, &hKey);
		if (rc == ERROR_SUCCESS) {
			std::wstring imagePath = std::wstring(L"\\SystemRoot\\system32\\drivers\\") + drvName;
			RegSetValueExW(hKey, L"ImagePath", 0, REG_EXPAND_SZ, (const BYTE*)imagePath.c_str(), (DWORD)((imagePath.size() + 1) * sizeof(wchar_t)));
			DWORD startVal = SERVICE_SYSTEM_START;
			RegSetValueExW(hKey, L"Start", 0, REG_DWORD, (const BYTE*)&startVal, sizeof(startVal));
			RegCloseKey(hKey);
		} else {
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

	} else {
		// Desired disabled: if service exists and running, stop and set Start value to SERVICE_DEMAND_START (or 3?)
		if (svc) {
			SERVICE_STATUS_PROCESS ssp = { 0 }; DWORD bytes = 0;
			if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytes)) {
				if (ssp.dwCurrentState == SERVICE_RUNNING) {
					SERVICE_STATUS ss = { 0 };
					ControlService(svc, SERVICE_CONTROL_STOP, &ss);
				}
			}

			std::wstring regPath = std::wstring(L"SYSTEM\\CurrentControlSet\\Services\\") + std::wstring(svcName);
			HKEY hKey = NULL; LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, KEY_SET_VALUE, &hKey);
			if (rc == ERROR_SUCCESS) {
				DWORD startVal = SERVICE_DEMAND_START; // set to manual/demand
				RegSetValueExW(hKey, L"Start", 0, REG_DWORD, (const BYTE*)&startVal, sizeof(startVal));
				RegCloseKey(hKey);
			} else {
				LOG_CTRL_ETW(L"ConfigureBootStartService: RegOpenKeyExW failed for %s : %lu\n", regPath.c_str(), rc);
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
	std::basic_string<TCHAR> srcX64 = Helper::GetCurrentModulePath(const_cast<TCHAR*>(x64Name.c_str()));
	std::basic_string<TCHAR> srcX86 = Helper::GetCurrentModulePath(const_cast<TCHAR*>(x86Name.c_str()));

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
