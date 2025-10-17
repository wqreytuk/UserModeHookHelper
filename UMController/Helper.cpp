#include "pch.h"
#include "Helper.h"
#include "ETW.h"
#include "UMController.h"
#include <atomic>
#include <wchar.h>
#include <memory>
#include <mutex>
#include <vector>
#include <TlHelp32.h>
// COM/WMI headers
#include <comdef.h>
#include <Wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")

// Simple process-wide fatal handler. Stored as an atomic pointer so it can be
// safely set from any thread during startup.
static std::atomic<Helper::FatalHandlerType> g_fatalHandler(nullptr);

// Initialize reusable buffer state
std::unique_ptr<TCHAR[]> Helper::m_sharedBuf = nullptr;
size_t Helper::m_sharedBufCap = 0;
std::mutex Helper::m_bufMutex;

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
	} else {
		app.GetETW().Log(L"Fatal: %s\n", message);
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

	DWORD size = 0;
	// Query required size (msdn: pass buffer length; here we call once to get length)
	QueryFullProcessImageName(hProcess, 1, NULL, &size);
	if (size == 0) {
		CloseHandle(hProcess);
		return false;
	}

	// Allocate or grow the shared buffer as needed. Protect with mutex.
	{
		std::lock_guard<std::mutex> lg(m_bufMutex);
		if (m_sharedBufCap < (size_t)(size + 1)) {
			// allocate new buffer; do not zero-initialize (new[]) as that's fine for POD
			m_sharedBuf.reset(new TCHAR[size + 1]);
			m_sharedBufCap = size + 1;
		}
	}

	// Now call again to fill buffer. Use the shared buffer pointer (no extra copy).
	if (!QueryFullProcessImageName(hProcess, 1, m_sharedBuf.get(), &size)) {
		CloseHandle(hProcess);
		return false;
	}
	CloseHandle(hProcess);

	// Construct result from buffer (ensure null termination)
	m_sharedBuf.get()[size] = (TCHAR)0;
	outNtPath.assign(m_sharedBuf.get());
	return true;
}
bool Helper::IsFileExists(TCHAR* szPath) {
	DWORD dwAttrib = GetFileAttributes(szPath);
	return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		!(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
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

bool Helper::IsProcess64(DWORD pid, bool& outIs64) {
	// UMController is always built as x64. Simplify logic: detect WOW64.
	typedef BOOL (WINAPI *IsWow64Process2_t)(HANDLE, USHORT*, USHORT*);
	typedef BOOL (WINAPI *IsWow64Process_t)(HANDLE, PBOOL);
	static IsWow64Process2_t s_pIsWow64Process2 = nullptr;
	static IsWow64Process_t  s_pIsWow64Process  = nullptr;
	static bool s_resolved = false;
	if (!s_resolved) {
		HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
		if (hK32) {
			s_pIsWow64Process2 = (IsWow64Process2_t)GetProcAddress(hK32, "IsWow64Process2");
			s_pIsWow64Process  = (IsWow64Process_t)GetProcAddress(hK32, "IsWow64Process");
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
	} else if (s_pIsWow64Process) {
		BOOL wow = FALSE;
		if (!s_pIsWow64Process(h, &wow)) { CloseHandle(h); return false; }
		is64 = !wow;
	}
	CloseHandle(h);
	outIs64 = is64;
	return true;
}

bool Helper::IsModuleLoaded(DWORD pid, const wchar_t* baseName, bool& outPresent) {
	if (!baseName || !*baseName) return false;
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	if (snap == INVALID_HANDLE_VALUE) return false;
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
