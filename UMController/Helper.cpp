#include "pch.h"
#include "Helper.h"
#include "ETW.h"
extern ETW gETW;
#include <atomic>
#include <wchar.h>
#include <memory>
#include <mutex>
#include <vector>

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
		gETW.Log(L"Fatal: %s\n", message);
		gETW.UnReg();
		exit(-1);
	}
}


DWORD64 Helper::GetNtPathHash(UCHAR* str) {
	const uint64_t FNV_prime = 1099511628211u;
	uint64_t hash = 14695981039346656037u;

	for (; *str; ++str) {
		hash ^= (unsigned char)(*str);
		hash *= FNV_prime;
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
