#include "pch.h"
#include "../../Shared/SharedMacroDef.h"
// Provide minimal NT-style macros often used in shared code so this user-
// mode translation unit doesn't require NT headers. Define them early so
// any subsequently-included headers that reference NT-style macros compile
// correctly in this user-mode component.
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((LONG)(Status)) >= 0)
#endif
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((LONG)0xC0000001)
#endif

#include <fltuser.h>
#include <string>
#include "FilterCommPort.h"
#include "../Shared/LogMacros.h"
#include "../drivers/UserModeHookHelper/MacroDef.h"
#include "ETW.h"
#include "UMController.h"
#include "Helper.h"
#include "../drivers/UserModeHookHelper/UKShared.h"
#include <memory>
#include <winerror.h>   // For HRESULT macros 
#include <cstddef>
#include <chrono>
#include "../ProcessHackerLib/phlib_expose.h"
// Use LONG to represent NT-style status values in this user-mode file to
// avoid requiring nt headers (which may not be present in all environments).

typedef LONG (NTAPI *PFN_RtlQueueWorkItem)(PVOID, PVOID, ULONG);


// Cached RtlQueueWorkItem pointer. Initialized on first use.
static PFN_RtlQueueWorkItem g_RtlQueueWorkItem = NULL;

// Cached wrapper that invokes RtlQueueWorkItem from ntdll.dll. We cache the
// function pointer on first use to avoid repeated GetProcAddress calls.
static BOOL QueueUserWorkItem(PVOID funcPtr, PVOID context, ULONG flags) {
	PFN_RtlQueueWorkItem p = g_RtlQueueWorkItem;
	if (!p) {
		HMODULE hNt = GetModuleHandleW(L"ntdll.dll");
		if (!hNt) return FALSE;
		p = (PFN_RtlQueueWorkItem)GetProcAddress(hNt, "RtlQueueWorkItem");
		if (!p) return FALSE;
		// Try to install the pointer atomically; if another thread raced, use
		// the already-installed pointer.
		PFN_RtlQueueWorkItem prev = (PFN_RtlQueueWorkItem)InterlockedCompareExchangePointer((PVOID*)&g_RtlQueueWorkItem, p, NULL);
		if (prev) p = prev;
	}
	if (!p) return FALSE;
	LONG st = (LONG)p(funcPtr, context, flags);
	return (st >= 0) ? TRUE : FALSE;
}

Filter::Filter() {
	// connect to minifilter port
	HRESULT hResult = S_OK;
	hResult = FilterConnectCommunicationPort(
		UMHHLP_PORT_NAME,
		0,
		NULL,
		0,
		NULL,
		&m_Port
	);
	if (hResult != S_OK) {
		LOG_CTRL_ETW(L"failed to call FilterConnectCommunicationPort: 0x%x\n", hResult);
		Helper::Fatal(L"FilterConnectCommunicationPort failed in Filter constructor");
	}
	else
		LOG_CTRL_ETW(L"successfully connect to minifilterport: 0x%p\n", m_Port);

	// Immediately inform kernel of our user-mode base directory where DLLs live.
	{
		// Use current module directory as the base; GetModuleFileName then strip filename
		WCHAR buf[MAX_PATH] = { 0 };
		DWORD n = GetModuleFileNameW(NULL, buf, MAX_PATH);
		if (n > 0 && n < MAX_PATH) {
			// strip to directory
			WCHAR* last = wcsrchr(buf, L'\\');
			if (last) *last = L'\0';
			// Build message
			size_t bytes = (wcslen(buf) + 1) * sizeof(WCHAR);
			size_t msgSize = sizeof(UMHH_COMMAND_MESSAGE) - 1 + bytes;
			PUMHH_COMMAND_MESSAGE msg = (PUMHH_COMMAND_MESSAGE)malloc(msgSize);
			if (msg) {
				memset(msg, 0, msgSize);
				msg->m_Cmd = CMD_SET_USER_DIR;
				memcpy(msg->m_Data, buf, bytes);
				DWORD bytesOut = 0;
				DWORD outbuffer = 0;
				HRESULT hr2 = FilterSendMessage(m_Port, msg, (DWORD)msgSize, &outbuffer, sizeof(outbuffer), &bytesOut);
				if ((hr2 != S_OK)||(outbuffer != 0)) {
					LOG_CTRL_ETW(L"FilterSendMessage(CMD_SET_USER_DIR) failed: 0x%08x\n", hr2);
				} else {
					// Also persist the user-dir into HKLM registry so the driver can read it on load.
					HKEY hKey = NULL;
					// create/open the 64-bit view so driver (64-bit) reads the same value
					LSTATUS lr = RegCreateKeyExW(HKEY_LOCAL_MACHINE,
						REG_PERSIST_SUBKEY,
						0,
						NULL,
						REG_OPTION_NON_VOLATILE,
						KEY_WRITE | KEY_WOW64_64KEY,
						NULL,
						&hKey,
						NULL);
					if (lr == ERROR_SUCCESS && hKey != NULL) {
						lr = RegSetValueExW(hKey, L"UserDir", 0, REG_SZ, (const BYTE*)buf, (DWORD)bytes);
						if (lr != ERROR_SUCCESS) {
							LOG_CTRL_ETW(L"RegSetValueExW(UserDir) failed: %u\n", lr);
						}
						RegCloseKey(hKey);
					} else {
						LOG_CTRL_ETW(L"RegCreateKeyExW for persist subkey failed: %d\n", lr);
					}
				}
				free(msg);
			}
		}
	}
	// Listener is started explicitly via StartListener
	m_StopListener = false;
	m_WorkExitEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	m_ListenerEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
}


// Notify the kernel to set global hook mode on/off
bool Filter::FLTCOMM_SetGlobalHookMode(bool enabled) {
    PUMHH_COMMAND_MESSAGE msg = (PUMHH_COMMAND_MESSAGE)malloc(sizeof(UMHH_COMMAND_MESSAGE) + sizeof(BOOLEAN));
    if (!msg) return false;
    memset(msg, 0, sizeof(UMHH_COMMAND_MESSAGE) + sizeof(BOOLEAN));
    msg->m_Cmd = CMD_SET_GLOBAL_HOOK_MODE;
    BOOLEAN val = enabled ? 1 : 0;
    memcpy(msg->m_Data, &val, sizeof(BOOLEAN));
    DWORD bytesOut = 0;
    HRESULT hr = FilterSendMessage(m_Port, msg, (DWORD)(sizeof(UMHH_COMMAND_MESSAGE) + sizeof(BOOLEAN)), NULL, 0, &bytesOut);
    free(msg);
    return hr == S_OK;
}
 
void Filter::RunListenerLoop() {
	if (m_StopListener) return;
	// Larger reply buffer to accommodate NT paths and diagnostic payloads.
	const ULONG REPLY_MAX = 32768;
	std::unique_ptr<BYTE[]> reply(new BYTE[REPLY_MAX]);

	while (!m_StopListener) {
		BYTE* buf = reply.get();

		// Use the shared m_ListenerEvent for all overlapped operations.
		if (!m_ListenerEvent) {
			LOG_CTRL_ETW(L"RunListenerLoop: m_ListenerEvent not available, aborting\n");
			break;
		}

		// Reset the listener event before issuing the overlapped call to
		// avoid immediate Wake due to previously signaled state.
		ResetEvent(m_ListenerEvent);

		OVERLAPPED ov;
		ZeroMemory(&ov, sizeof(ov));
		ov.hEvent = m_ListenerEvent;

		HRESULT hr = FilterGetMessage(m_Port, (PFILTER_MESSAGE_HEADER)buf, REPLY_MAX, &ov);
		DWORD bytesTransferred = 0;

		if (hr == S_OK) {
			// completed synchronously; get the size
			if (!GetOverlappedResult(m_Port, &ov, &bytesTransferred, FALSE)) {
				DWORD err = GetLastError();
				LOG_CTRL_ETW(L"RunListenerLoop: GetOverlappedResult(sync) failed (%u)\n", err);
				if (err == ERROR_OPERATION_ABORTED || err == ERROR_INVALID_HANDLE) break;
				continue;
			}
		} else if (hr == HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {
			// Wait for either the shared listener event (message) or worker-exit
			HANDLE waitHandles[2] = { m_ListenerEvent, m_WorkExitEvent };
			DWORD wait = WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);
			if (wait == WAIT_OBJECT_0 + 1) {
				// stop signaled - cancel pending I/O and exit
				CancelIoEx(m_Port, &ov);
				break;
			} else if (wait == WAIT_OBJECT_0) {
				// message ready
				if (!GetOverlappedResult(m_Port, &ov, &bytesTransferred, FALSE)) {
					DWORD err = GetLastError();
					LOG_CTRL_ETW(L"RunListenerLoop: GetOverlappedResult(wait) failed (%u)\n", err);
					if (err == ERROR_OPERATION_ABORTED || err == ERROR_INVALID_HANDLE) break;
					continue;
				}
			} else {
				// unexpected wait result
				continue;
			}
		} else {
			LOG_CTRL_ETW(L"FilterGetMessage failed (async): 0x%08x\n", hr);
			break;
		}

		if (bytesTransferred >= sizeof(FILTER_MESSAGE_HEADER) + UMHH_MSG_HEADER_SIZE) {
			// Interpret buffer as FILTER_MESSAGE_HEADER followed by the
			// UMHH_COMMAND_MESSAGE payload. Use bytesTransferred as the
			// authoritative size returned by GetOverlappedResult. ReplyLength
			// in the header is diagnostic-only here because some driver-side
			// messages may not populate it reliably when messages are sent
			// in quick succession.
			PFILTER_MESSAGE_HEADER fmh = (PFILTER_MESSAGE_HEADER)buf;
			size_t headerSize = sizeof(FILTER_MESSAGE_HEADER);
			size_t totalMsgBytes = bytesTransferred; // authoritative


			size_t availableAfterHeader = 0;
			if (totalMsgBytes > headerSize) availableAfterHeader = totalMsgBytes - headerSize;
			if (availableAfterHeader < UMHH_MSG_HEADER_SIZE) {
				// malformed or truncated message, ignore
				LOG_CTRL_ETW(L"RunListenerLoop: truncated message (availableAfterHeader=%u) - ignoring\n", (ULONG)availableAfterHeader);
				continue;
			}

			// UMHH payload starts immediately after the FILTER_MESSAGE_HEADER
			PUMHH_COMMAND_MESSAGE msg = (PUMHH_COMMAND_MESSAGE)(buf + headerSize);
			size_t payloadBytes = availableAfterHeader - UMHH_MSG_HEADER_SIZE;
			if (msg->m_Cmd == CMD_PROCESS_NOTIFY) {
				size_t need = sizeof(DWORD) + sizeof(BOOLEAN);
				if (payloadBytes >= need) {
					DWORD pid = 0;
					BOOLEAN create = 0;
					memcpy(&pid, msg->m_Data, sizeof(DWORD));
					memcpy(&create, msg->m_Data + sizeof(DWORD), sizeof(BOOLEAN));

					// Check if there's an optional null-terminated WCHAR process name
					const wchar_t* procName = NULL;
					size_t nameBytes = payloadBytes - need;
					if (nameBytes >= sizeof(WCHAR)) {
						// Ensure null-termination within the received buffer
						size_t wcharCount = nameBytes / sizeof(WCHAR);
						// temp pointer into msg->m_Data after pid+create
						const wchar_t* wptr = (const wchar_t*)(msg->m_Data + need);
						// Ensure the last WCHAR is NUL or else create a local copy
						if (wptr[wcharCount - 1] == L'\0') {
							procName = wptr;
						}
						else {
							// create a temporary null-terminated buffer
							std::wstring tmp(wptr, wcharCount);
							tmp.push_back(L'\0');
							// store in a static thread_local so we can pass ptr safely
							static thread_local std::wstring holder;
							holder = std::move(tmp);
							procName = holder.c_str();
						}
					}

					if (m_ProcessNotifyCb) {
					//	app.GetETW().Log(L"process notify from kernel: process %ws pid %d create %d\n", procName, pid, create);
						m_ProcessNotifyCb(pid, create, procName, m_ProcessNotifyCtx);
					}
				}
			}
			else if (msg->m_Cmd == CMD_APC_QUEUED) {
					// Payload: DWORD pid
					if (payloadBytes >= sizeof(DWORD)) {
						DWORD pid = 0;
						memcpy(&pid, msg->m_Data, sizeof(DWORD));
						// Prefer the dedicated APC-queued callback if registered. For
						// backwards compatibility fall back to the process-notify callback
						// (treated as a create notification) if no APC callback is installed.
						
						if (m_ApcQueuedCb) {
							m_ApcQueuedCb(pid, m_ApcQueuedCtx);
						} else  {
							Helper::Fatal(L"m_ApcQueuedCb is not registered\n");
						}
					}
			}
		}
		// Loop
	}
}

VOID NTAPI Filter::ListenerWorkItem(PVOID context, PVOID systemArg1, PVOID systemArg2) {
	UNREFERENCED_PARAMETER(systemArg1);
	UNREFERENCED_PARAMETER(systemArg2);
	Filter* self = static_cast<Filter*>(context);
	if (!self) return;
	self->RunListenerLoop();
	if (self->m_WorkExitEvent) SetEvent(self->m_WorkExitEvent);
}

void Filter::RegisterProcessNotifyCallback(ProcessNotifyCb cb, void* ctx) {
	m_ProcessNotifyCb = cb;
	m_ProcessNotifyCtx = ctx;
}

void Filter::UnregisterProcessNotifyCallback() {
	m_ProcessNotifyCb = NULL;
	m_ProcessNotifyCtx = NULL;
}

void Filter::RegisterApcQueuedCallback(ProcessApcQueuedCb cb, void* ctx) {
	m_ApcQueuedCb = cb;
	m_ApcQueuedCtx = ctx;
}

void Filter::UnregisterApcQueuedCallback() {
	m_ApcQueuedCb = NULL;
	m_ApcQueuedCtx = NULL;
}

void Filter::StartListener() {
	if (m_ListenerStarted) return;
	m_ListenerStarted = true;
	if (!QueueUserWorkItem(ListenerWorkItem, this, 0)) {
		Helper::Fatal(L"QueueUserWorkItem (RtlQueueWorkItem) failed in StartListener\n");
	}
	LOG_CTRL_ETW(L"user mode miniport listener queued into work item\n");
}


bool Filter::FLTCOMM_CheckHookList(const std::wstring& ntPath) {
	// Compute 64-bit FNV-1a hash over NT path bytes (UTF-16LE) and send the
	// 8-byte hash to the kernel. This preserves the original design that
	// compares a compact identifier in kernel space.
	if (ntPath.empty()) {
		Helper::Fatal(L"FLTCOMM_CheckHookList called with empty path");
		return FALSE;
	}

	// Interpret the WCHAR buffer as bytes for hashing (UTF-16LE)
	const UCHAR* bytes = reinterpret_cast<const UCHAR*>(ntPath.c_str());
	size_t bytesLen = ntPath.size() * sizeof(wchar_t);
	DWORD64 hash = Helper::GetNtPathHash(bytes, bytesLen);

	PUMHH_COMMAND_MESSAGE msg = (PUMHH_COMMAND_MESSAGE)malloc(sizeof(UMHH_COMMAND_MESSAGE) + sizeof(DWORD64));
	if (!msg) {
		Helper::Fatal(L"FLTCOMM_CheckHookList: failed to allocate message");
		return FALSE;
	}
	memset(msg, 0, sizeof(UMHH_COMMAND_MESSAGE) + sizeof(DWORD64));
	msg->m_Cmd = CMD_CHECK_HOOK_LIST;
	memcpy(msg->m_Data, &hash, sizeof(DWORD64));

	boolean isInHookList = FALSE;
	DWORD bytesOut = 0;
	HRESULT hResult = FilterSendMessage(m_Port,
		msg,
		(DWORD)(sizeof(UMHH_COMMAND_MESSAGE) + sizeof(DWORD64)),
		&isInHookList,
		sizeof(boolean),
		&bytesOut);

	if (S_OK != hResult) {
		free(msg);
		 LOG_CTRL_ETW(L"failed to call FilterSendMessage: 0x%p\n", hResult);
		 Helper::Fatal(L"FilterSendMessage failed in FLTCOMM_CheckHookList");
		return isInHookList;
	}
	free(msg);
	return isInHookList;
}
bool Filter::FLTCOMM_GetImagePathByPid(DWORD pid, std::wstring& outPath) {
	const DWORD REPLY_MAX = 32768; // bytes
	HRESULT hResult = S_OK;
	// Reuse a thread-local outgoing message buffer to avoid repeated malloc/free
	static thread_local std::unique_ptr<BYTE[]> t_msgBuf = nullptr;
	static thread_local size_t t_msgBufCap = 0;
	const size_t msgSize = sizeof(UMHH_COMMAND_MESSAGE) + sizeof(DWORD);
	if (t_msgBufCap < msgSize) {
		t_msgBuf.reset(new BYTE[msgSize]);
		t_msgBufCap = msgSize;
	}

	PUMHH_COMMAND_MESSAGE msg = (PUMHH_COMMAND_MESSAGE)t_msgBuf.get();
	memset(msg, 0, msgSize);
	msg->m_Cmd = CMD_GET_IMAGE_PATH_BY_PID;
	memcpy(msg->m_Data, &pid, sizeof(DWORD));

	// Reuse a thread-local reply buffer to avoid repeated malloc/free.
	static thread_local std::unique_ptr<BYTE[]> t_replyBuf = nullptr;
	static thread_local size_t t_replyBufCap = 0;
	if (t_replyBufCap < REPLY_MAX) {
		t_replyBuf.reset(new BYTE[REPLY_MAX]);
		t_replyBufCap = REPLY_MAX;
	}

	DWORD bytesOut = 0;
	hResult = FilterSendMessage(m_Port,
		msg,
		(DWORD)msgSize,
		t_replyBuf.get(),
		REPLY_MAX,
		&bytesOut);

	if (hResult != S_OK || bytesOut == 0) {
		// we use outbuf to store ntstatus returned by miniport messagenotify
		// because I don't know why HRESULT_FROM_NT is not work well
		// STATUS_INVALID_CID means process terminated on the way resolving ntpath
		if (*(ULONG*)t_replyBuf.get() == STATUS_INVALID_CID) {
			return false;
		}
		Helper::Fatal(L"FLTCOMM_GetImagePathByPid: FilterSendMessage failed or returned no data");
		return false;
	}

	// Ensure even byte count for WCHAR
	if (bytesOut % sizeof(WCHAR) != 0) {
		bytesOut = bytesOut - (bytesOut % sizeof(WCHAR));
	}

	WCHAR* w = (WCHAR*)t_replyBuf.get();
	// Guarantee null-termination
	size_t wcCount = bytesOut / sizeof(WCHAR);
	if (wcCount == 0) { Helper::Fatal(L"FLTCOMM_GetImagePathByPid: reply buffer empty"); return false; }
	w[wcCount - 1] = L'\0';

	if (w[0] == L'\0') {
		Helper::Fatal(L"FLTCOMM_GetImagePathByPid: reply path is empty\n");
		return false;
	}

	outPath.assign(w);
	return true;
}
bool Filter::FLTCOMM_AddHook(const std::wstring& ntPath) {
	if (ntPath.empty()) {
		Helper::Fatal(L"FLTCOMM_AddHook called with empty path");
		return false;
	}

	// Log the add-hook request for diagnostics
	LOG_CTRL_ETW(L"FLTCOMM_AddHook: request path=%s\n", ntPath.c_str());

	// Compute hash
	const UCHAR* bytes = reinterpret_cast<const UCHAR*>(ntPath.c_str());
	size_t bytesLen = ntPath.size() * sizeof(wchar_t);
	DWORD64 hash = Helper::GetNtPathHash(bytes, bytesLen);

	// Build message: ULONGLONG hash followed by null-terminated WCHAR path
	size_t pathBytes = (ntPath.size() + 1) * sizeof(WCHAR);
	size_t msgSize = (sizeof(UMHH_COMMAND_MESSAGE) - 1) + sizeof(ULONGLONG) + pathBytes;
	PUMHH_COMMAND_MESSAGE msg = (PUMHH_COMMAND_MESSAGE)malloc(msgSize);
	if (!msg) {
		Helper::Fatal(L"FLTCOMM_AddHook: failed to allocate message");
		return false;
	}
	memset(msg, 0, msgSize);
	msg->m_Cmd = CMD_ADD_HOOK;
	memcpy(msg->m_Data, &hash, sizeof(ULONGLONG));
	memcpy((BYTE*)msg->m_Data + sizeof(ULONGLONG), ntPath.c_str(), pathBytes);

	LONG st = (LONG)0xC0000001; // fallback non-success value
	DWORD bytesOut = 0;
	HRESULT hResult = FilterSendMessage(m_Port,
		msg,
		(DWORD)msgSize,
		&st,
		sizeof(LONG),
		&bytesOut);
	free(msg);
	if (hResult == S_OK && st >= 0) {
		LOG_CTRL_ETW(L"FLTCOMM_AddHook: succeeded path=%s hash=0x%I64x\n", ntPath.c_str(), hash);
		SetLastError(ERROR_SUCCESS);
		return true;
	}
	// Any failure here is considered fatal for the app
	LOG_CTRL_ETW(L"FLTCOMM_AddHook: failed path=%s\n", ntPath.c_str());
	SetLastError(21); // ERROR_NOT_READY as sentinel for fatal
	Helper::Fatal(L"FLTCOMM_AddHook: kernel or IPC failure while adding hook");
	return false;
}

bool Filter::FLTCOMM_GetHookSection(HANDLE& outHandle) {
	outHandle = NULL;
	PUMHH_COMMAND_MESSAGE msg = (PUMHH_COMMAND_MESSAGE)malloc(sizeof(UMHH_COMMAND_MESSAGE));
	if (!msg) return false;
	memset(msg, 0, sizeof(UMHH_COMMAND_MESSAGE));
	msg->m_Cmd = CMD_GET_HOOK_SECTION;

	// Reply buffer to receive duplicated HANDLE (size depends on architecture)
	SIZE_T replySize = sizeof(HANDLE);
	std::unique_ptr<BYTE[]> reply(new BYTE[replySize]);
	DWORD bytesOut = 0;
	HRESULT hr = FilterSendMessage(m_Port, msg, (DWORD)sizeof(UMHH_COMMAND_MESSAGE), reply.get(), (DWORD)replySize, &bytesOut);
	free(msg);
	if (hr != S_OK || bytesOut < (DWORD)replySize) return false;

	// Copy handle value out
	HANDLE h = NULL;
	RtlCopyMemory(&h, reply.get(), sizeof(HANDLE));
	if (!h) return false;
	outHandle = h;
	return true;
}

bool Filter::FLTCOMM_MapHookSectionToSet(std::unordered_set<unsigned long long>& outSet) {
	HANDLE hSec = NULL;
	if (!FLTCOMM_GetHookSection(hSec)) return false;

	// Map view readonly
	LPVOID view = MapViewOfFile(hSec, FILE_MAP_READ, 0, 0, 0);
	if (!view) {
		CloseHandle(hSec);
		return false;
	}

	unsigned char* ptr = (unsigned char*)view;
	// Validate header: at least 12 bytes
	if (!ptr) { UnmapViewOfFile(view); CloseHandle(hSec); return false; }
	ULONG version = *(ULONG*)(ptr);
	ULONG count = *(ULONG*)(ptr + 4);
	// reserved at ptr+8
	if (version != 1) { UnmapViewOfFile(view); CloseHandle(hSec); return false; }

	SIZE_T expected = 12 + (SIZE_T)count * sizeof(unsigned long long);
	// We don't have explicit size of mapping; rely on reasonable bounds (avoid crash)
	// but assume driver created mapping sized exactly to expected.

	for (ULONG i = 0; i < count; ++i) {
		unsigned long long h = *(unsigned long long*)(ptr + 12 + i * sizeof(unsigned long long));
		outSet.insert(h);
	}

	UnmapViewOfFile(view);
	CloseHandle(hSec);
	return true;
}
bool Filter::FLTCOMM_IsProcessWow64(DWORD pid, bool& outIsWow64) {
	// I'll give up requesting kernel for this info, copied some code from process hacker project
	BOOLEAN IsWow64 = FALSE;
	ULONG status = (ULONG)(ULONG_PTR)PHLIB::PhGetProcessIsWow64((void*)(ULONG_PTR)pid,
		(void*)(ULONG_PTR)&IsWow64);
	if (0 != status) {
		LOG_CTRL_ETW(L"failed to call PHLIB::PhGetProcessIsWow64, Pid=%u Status=0x%x\n", pid, status);
		return false;
	}
	outIsWow64 = IsWow64;
	
	return true;
}

bool Filter::FLTCOMM_IsProtectedProcess(DWORD pid, bool& outIsProtected) {
	const size_t msgSize = (sizeof(UMHH_COMMAND_MESSAGE) - 1) + sizeof(DWORD);
	PUMHH_COMMAND_MESSAGE msg = (PUMHH_COMMAND_MESSAGE)malloc(msgSize);
	if (!msg) return false;
	memset(msg, 0, msgSize);
	msg->m_Cmd = CMD_IS_PROTECTED_PROCESS;
	memcpy(msg->m_Data, &pid, sizeof(DWORD));

	struct PROT_REPLY { BOOLEAN isProtected; UCHAR pad[3]; } replyBuf;
	memset(&replyBuf, 0, sizeof(replyBuf));
	DWORD bytesOut = 0;
	HRESULT hr = FilterSendMessage(m_Port, msg, (DWORD)msgSize, &replyBuf, (DWORD)sizeof(replyBuf), &bytesOut);
	free(msg);

	if (hr != S_OK) {
		LOG_CTRL_ETW(L"FLTCOMM_IsProtectedProcess: FilterSendMessage failed hr=0x%08x pid=%u\n", hr, pid);
		return false;
	}
	if (bytesOut == 0) return false;
	outIsProtected = (replyBuf.isProtected ? true : false);
	return true;
}

bool Filter::FLTCOMM_GetProcessHandle(DWORD pid, HANDLE* outHandle) {
	*outHandle = NULL;
	HANDLE hDuplicate = NULL;
	// Attempt to use cached handle keyed by {pid, creationTime}
	// We need creation time to build the key; if we have a cached entry for this pid with any creation time,
	// validate it by querying creation time and use it.
	for (auto it = m_handleCache.begin(); it != m_handleCache.end(); ++it) {
		if (it->first.pid == pid) {
			HANDLE h = it->second;
			ULONGLONG ct = 0;
			if (h && QueryCreationTime(h, ct)) {
				if (ct == it->first.creationTime) {
					BOOL ok = DuplicateHandle(
						GetCurrentProcess(), // source process
						h,           // your original handle
						GetCurrentProcess(), // target process (same process)
						&hDuplicate,         // receives duplicate
						0,                   // same access
						FALSE,               // not inheritable
						DUPLICATE_SAME_ACCESS
					);
					if (!ok) {
						// LOG_CTRL_ETW(L"DuplicateHandle failed; trying kernel duplication\n");
						HANDLE hDupKernel = NULL;
						if (!FLTCOMM_DuplicateHandleKernel(h, &hDupKernel)) {
							LOG_CTRL_ETW(L"Kernel duplicate failed, Pid=%d\n",pid);
							return false;
						}
						hDuplicate = hDupKernel;
					}
					*outHandle = hDuplicate;
					return true;
				}
			}
		}
	}
	const size_t msgSize = (sizeof(UMHH_COMMAND_MESSAGE) - 1) + sizeof(DWORD);
	PUMHH_COMMAND_MESSAGE msg = (PUMHH_COMMAND_MESSAGE)malloc(msgSize);
	if (!msg) return false;
	memset(msg, 0, msgSize);
	msg->m_Cmd = CMD_GET_PROCESS_HANDLE;
	memcpy(msg->m_Data, &pid, sizeof(DWORD));

	// Protocol: driver returns an 8-byte handle value regardless of client arch.
	// Read 8 bytes and cast down safely on x86.
	const SIZE_T replySize = 8; // fixed-width handle field
	std::unique_ptr<BYTE[]> reply(new BYTE[replySize]);
	DWORD bytesOut = 0;
	HRESULT hr = FilterSendMessage(m_Port, msg, (DWORD)msgSize, reply.get(), (DWORD)replySize, &bytesOut);
	free(msg);
	if (hr != S_OK || bytesOut != (DWORD)replySize) {
		LOG_CTRL_ETW(L"FLTCOMM_GetProcessHandle: FilterSendMessage hr=0x%x bytesOut=%u (expected %u)\n", hr, bytesOut, (unsigned)replySize);
		return false;
	}
	unsigned long long h64 = 0;
	memcpy(&h64, reply.get(), replySize);
	if (h64 == 0) return false;
	HANDLE hProc = (HANDLE)(ULONG_PTR)h64;
	// Compute creation time key and cache
	ULONGLONG ct = 0;
	if (QueryCreationTime(hProc, ct)) {
		ProcKey key{ pid, ct };
		m_handleCache.insert({ key, hProc });
	}
	// we can not return this handle to caller, because caller will close it, cause cache ineffect
	// we should duplicate a new handle to user
	BOOL ok = DuplicateHandle(
		GetCurrentProcess(), // source process
		hProc,           // your original handle
		GetCurrentProcess(), // target process (same process)
		&hDuplicate,         // receives duplicate
		0,                   // same access
		FALSE,               // not inheritable
		DUPLICATE_SAME_ACCESS
	);
	if (!ok) {
		// LOG_CTRL_ETW(L"DuplicateHandle failed; trying kernel duplication\n");
		HANDLE hDupKernel = NULL;
		if (!FLTCOMM_DuplicateHandleKernel(hProc, &hDupKernel)) {
			LOG_CTRL_ETW(L"Kernel duplicate failed\n");
			return false;
		}
		hDuplicate = hDupKernel;
	}
	*outHandle = hDuplicate;
	return true;
}

bool Filter::FLTCOMM_DuplicateHandleKernel(HANDLE sourceHandle, HANDLE* outDuplicated)
{
	if (!outDuplicated) return false;
	*outDuplicated = NULL;
	const size_t msgSize = (sizeof(UMHH_COMMAND_MESSAGE) - 1) + sizeof(HANDLE);
	PUMHH_COMMAND_MESSAGE msg = (PUMHH_COMMAND_MESSAGE)malloc(msgSize);
	if (!msg) return false;
	memset(msg, 0, msgSize);
	msg->m_Cmd = CMD_DUPLICATE_HANDLE_KERNEL;
	memcpy(msg->m_Data, &sourceHandle, sizeof(HANDLE));

	SIZE_T replySize = sizeof(HANDLE);
	std::unique_ptr<BYTE[]> reply(new BYTE[replySize]);
	DWORD bytesOut = 0;
	HRESULT hr = FilterSendMessage(m_Port, msg, (DWORD)msgSize, reply.get(), (DWORD)replySize, &bytesOut);
	free(msg);
	if (hr != S_OK || bytesOut < (DWORD)replySize) {
		return false;
	}
	HANDLE h = NULL; RtlCopyMemory(&h, reply.get(), sizeof(HANDLE));
	if (!h) return false;
	*outDuplicated = h;
	return true;
}

bool Filter::FLTCOMM_ReadKernelMemory(_In_ LPVOID target_addr, _Out_ LPVOID buffer, _In_ size_t size) {
	if (!target_addr || !buffer || size == 0 || size > UMHH_KERNEL_RW_MAX_TRANSFER) {
		return false;
	}
	// 1. Map kernel memory to user
	UMHH_MAP_KERNEL_TO_USER_REQUEST req = {};
	req.KernelVa = (ULONGLONG)(ULONG_PTR)target_addr;
	req.Length = (ULONG)size;
	req.CacheType = 1; // MmCached

	const size_t msgSize = UMHH_MSG_HEADER_SIZE + sizeof(req);
	std::unique_ptr<BYTE[]> msgBuf(new BYTE[msgSize]);
	if (!msgBuf) return false;
	memset(msgBuf.get(), 0, msgSize);
	PUMHH_COMMAND_MESSAGE msg = (PUMHH_COMMAND_MESSAGE)msgBuf.get();
	msg->m_Cmd = CMD_MAP_KERNEL_TO_USER;
	memcpy(msg->m_Data, &req, sizeof(req));

	UMHH_MAP_KERNEL_TO_USER_REPLY reply = {};
	DWORD bytesOut = 0;
	HRESULT hr = FilterSendMessage(m_Port,
		msg,
		(DWORD)msgSize,
		&reply,
		(DWORD)sizeof(reply),
		&bytesOut);
	if (hr != S_OK || bytesOut != sizeof(reply) || !reply.UserVa) {
		LOG_CTRL_ETW(L"FLTCOMM_ReadKernelMemory: map failed hr=0x%08x\n", hr);
		return false;
	}

	// 2. Copy from mapped user VA
	memcpy(buffer, (void*)(ULONG_PTR)reply.UserVa, size);

	// 3. Free the mapping
	UMHH_FREE_MDL_REQUEST freeReq = {};
	freeReq.UserVa = reply.UserVa;
	freeReq.Mdl = reply.Mdl;
	size_t freeMsgSize = UMHH_MSG_HEADER_SIZE + sizeof(freeReq);
	std::unique_ptr<BYTE[]> freeMsgBuf(new BYTE[freeMsgSize]);
	if (!freeMsgBuf) return false;
	memset(freeMsgBuf.get(), 0, freeMsgSize);
	PUMHH_COMMAND_MESSAGE freeMsg = (PUMHH_COMMAND_MESSAGE)freeMsgBuf.get();
	freeMsg->m_Cmd = CMD_FREE_MDL;
	memcpy(freeMsg->m_Data, &freeReq, sizeof(freeReq));
	DWORD freeBytesOut = 0;
	NTSTATUS freeStatus = STATUS_UNSUCCESSFUL;
	hr = FilterSendMessage(m_Port,
		freeMsg,
		(DWORD)freeMsgSize,
		&freeStatus,
		(DWORD)sizeof(freeStatus),
		&freeBytesOut);
	if (hr != S_OK || !NT_SUCCESS(freeStatus)) {
		LOG_CTRL_ETW(L"FLTCOMM_ReadKernelMemory: free_mdl failed hr=0x%08x status=0x%08x\n", hr, freeStatus);
		return false;
	}
	return true;
}

bool Filter::FLTCOMM_WriteKernelMemory(_In_ LPVOID target_addr, _Out_ LPVOID buffer, _In_ size_t size) {
	if (!target_addr || !buffer || size == 0 || size > UMHH_KERNEL_RW_MAX_TRANSFER) {
		return false;
	}
	// 1. Map kernel memory to user
	UMHH_MAP_KERNEL_TO_USER_REQUEST req = {};
	req.KernelVa = (ULONGLONG)(ULONG_PTR)target_addr;
	req.Length = (ULONG)size;
	req.CacheType = 1; // MmCached

	const size_t msgSize = UMHH_MSG_HEADER_SIZE + sizeof(req);
	std::unique_ptr<BYTE[]> msgBuf(new BYTE[msgSize]);
	if (!msgBuf) return false;
	memset(msgBuf.get(), 0, msgSize);
	PUMHH_COMMAND_MESSAGE msg = (PUMHH_COMMAND_MESSAGE)msgBuf.get();
	msg->m_Cmd = CMD_MAP_KERNEL_TO_USER;
	memcpy(msg->m_Data, &req, sizeof(req));

	UMHH_MAP_KERNEL_TO_USER_REPLY reply = {};
	DWORD bytesOut = 0;
	HRESULT hr = FilterSendMessage(m_Port,
		msg,
		(DWORD)msgSize,
		&reply,
		(DWORD)sizeof(reply),
		&bytesOut);
	if (hr != S_OK || bytesOut != sizeof(reply) || !reply.UserVa) {
		LOG_CTRL_ETW(L"FLTCOMM_WriteKernelMemory: map failed hr=0x%08x\n", hr);
		return false;
	}

	// 2. Copy to mapped user VA
	memcpy((void*)(ULONG_PTR)reply.UserVa, buffer, size);

	// 3. Free the mapping
	UMHH_FREE_MDL_REQUEST freeReq = {};
	freeReq.UserVa = reply.UserVa;
	freeReq.Mdl = reply.Mdl;
	size_t freeMsgSize = UMHH_MSG_HEADER_SIZE + sizeof(freeReq);
	std::unique_ptr<BYTE[]> freeMsgBuf(new BYTE[freeMsgSize]);
	if (!freeMsgBuf) return false;
	memset(freeMsgBuf.get(), 0, freeMsgSize);
	PUMHH_COMMAND_MESSAGE freeMsg = (PUMHH_COMMAND_MESSAGE)freeMsgBuf.get();
	freeMsg->m_Cmd = CMD_FREE_MDL;
	memcpy(freeMsg->m_Data, &freeReq, sizeof(freeReq));
	DWORD freeBytesOut = 0;
	NTSTATUS freeStatus = STATUS_UNSUCCESSFUL;
	hr = FilterSendMessage(m_Port,
		freeMsg,
		(DWORD)freeMsgSize,
		&freeStatus,
		(DWORD)sizeof(freeStatus),
		&freeBytesOut);
	if (hr != S_OK || !NT_SUCCESS(freeStatus)) {
		LOG_CTRL_ETW(L"FLTCOMM_WriteKernelMemory: free_mdl failed hr=0x%08x status=0x%08x\n", hr, freeStatus);
		return false;
	}
	return true;
}

bool Filter::QueryCreationTime(HANDLE hProc, ULONGLONG& outCreationTime) {
	outCreationTime = 0;
	if (!hProc) return false;
	FILETIME ftCreate = {0}, ftExit = {0}, ftKernel = {0}, ftUser = {0};
	if (!GetProcessTimes(hProc, &ftCreate, &ftExit, &ftKernel, &ftUser)) {
		return false;
	}
	ULARGE_INTEGER uli;
	uli.LowPart = ftCreate.dwLowDateTime;
	uli.HighPart = ftCreate.dwHighDateTime;
	outCreationTime = uli.QuadPart;
	return true;
}

bool Filter::FLTCOMM_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) {
	if (!hProcess || !lpBaseAddress || !lpBuffer || nSize == 0) return false;
	// Build payload: [DWORD pid][PVOID base][SIZE_T size][bytes...]
	DWORD pid = GetProcessId(hProcess);
	const SIZE_T payloadFixed = sizeof(DWORD) + sizeof(PVOID) + sizeof(SIZE_T);
	const SIZE_T msgSize = UMHH_MSG_HEADER_SIZE + payloadFixed + nSize;
	std::unique_ptr<BYTE[]> msgBuf(new BYTE[msgSize]);
	if (!msgBuf) return false;
	memset(msgBuf.get(), 0, msgSize);
	PUMHH_COMMAND_MESSAGE msg = (PUMHH_COMMAND_MESSAGE)msgBuf.get();
	msg->m_Cmd = CMD_WRITE_PROCESS_MEMORY;
	SIZE_T off = 0;
	memcpy(msg->m_Data + off, &pid, sizeof(DWORD)); off += sizeof(DWORD);
	PVOID base = lpBaseAddress; memcpy(msg->m_Data + off, &base, sizeof(PVOID)); off += sizeof(PVOID);
	SIZE_T sizeField = nSize; memcpy(msg->m_Data + off, &sizeField, sizeof(SIZE_T)); off += sizeof(SIZE_T);
	memcpy(msg->m_Data + off, lpBuffer, nSize);

	NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
	DWORD bytesOut = 0;
	HRESULT hr = FilterSendMessage(m_Port, msg, (DWORD)msgSize, &ntstatus, (DWORD)sizeof(ntstatus), &bytesOut);
	if (hr != S_OK || bytesOut != sizeof(ntstatus)) {
		LOG_CTRL_ETW(L"FLTCOMM_WriteProcessMemory: FilterSendMessage hr=0x%x bytesOut=%u\n", hr, bytesOut);
		return false;
	}
	if (!NT_SUCCESS(ntstatus)) {
		LOG_CTRL_ETW(L"FLTCOMM_WriteProcessMemory: driver returned NTSTATUS=0x%08x\n", ntstatus);
		return false;
	}
	if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = nSize;
	return true;
}

	// The implementation of FLTCOMM_ElevateToPpl has been removed as it used deprecated CMD_ELEVATE_TO_PPL.
	// void Filter::FLTCOMM_ElevateToPpl(DWORD pid) {
	//     // Implementation removed
	// }

bool Filter::FLTCOMM_UnprotectPpl(DWORD pid) {
	const size_t msgSize = (sizeof(UMHH_COMMAND_MESSAGE) - 1) + sizeof(DWORD);
	PUMHH_COMMAND_MESSAGE msg = (PUMHH_COMMAND_MESSAGE)malloc(msgSize);
	if (!msg) return false;
	memset(msg, 0, msgSize);
	msg->m_Cmd = CMD_UNPROTECT_PPL;
	memcpy(msg->m_Data, &pid, sizeof(DWORD));
	DWORD bytesOut = 0;
	LONG ntstatus = STATUS_UNSUCCESSFUL;
	HRESULT hr = FilterSendMessage(m_Port, msg, (DWORD)msgSize, &ntstatus, (DWORD)sizeof(ntstatus), &bytesOut);
	free(msg);
	if (hr != S_OK) return false;
	return (bytesOut == sizeof(ntstatus)) ? NT_SUCCESS(ntstatus) : true;
}

bool Filter::FLTCOMM_RecoverPpl(DWORD pid, DWORD protValue) {
	const size_t msgSize = (sizeof(UMHH_COMMAND_MESSAGE) - 1) + sizeof(DWORD) + sizeof(DWORD);
	PUMHH_COMMAND_MESSAGE msg = (PUMHH_COMMAND_MESSAGE)malloc(msgSize);
	if (!msg) return false;
	memset(msg, 0, msgSize);
	msg->m_Cmd = CMD_RECOVER_PPL;
	size_t off = 0;
	memcpy(msg->m_Data + off, &pid, sizeof(DWORD)); off += sizeof(DWORD);
	memcpy(msg->m_Data + off, &protValue, sizeof(DWORD));
	DWORD bytesOut = 0; LONG ntstatus = STATUS_UNSUCCESSFUL;
	HRESULT hr = FilterSendMessage(m_Port, msg, (DWORD)msgSize, &ntstatus, (DWORD)sizeof(ntstatus), &bytesOut);
	free(msg);
	if (hr != S_OK) return false;
	return (bytesOut == sizeof(ntstatus)) ? NT_SUCCESS(ntstatus) : true;
}

bool Filter::FLTCOMM_QueryPplProtection(DWORD pid, DWORD& outProt) {
	outProt = 0;
	const size_t msgSize = (sizeof(UMHH_COMMAND_MESSAGE) - 1) + sizeof(DWORD);
	PUMHH_COMMAND_MESSAGE msg = (PUMHH_COMMAND_MESSAGE)malloc(msgSize);
	if (!msg) return false;
	memset(msg, 0, msgSize);
	msg->m_Cmd = CMD_QUERY_PPL_PROTECTION;
	memcpy(msg->m_Data, &pid, sizeof(DWORD));
	DWORD bytesOut = 0;
	DWORD replyProt = 0;
	HRESULT hr = FilterSendMessage(m_Port, msg, (DWORD)msgSize, &replyProt, (DWORD)sizeof(replyProt), &bytesOut);
	free(msg);
	if (hr != S_OK || bytesOut != sizeof(replyProt)) return false;
	outProt = replyProt;
	return true;
}

bool Filter::FLTCOMM_CreateRemoteThread(DWORD pid, PVOID startRoutine, PVOID parameter, PVOID ntCreateThreadExAddr,
	PVOID extra, HANDLE* outThreadHandle, HANDLE callerHandle) {
	// Build message: DWORD pid + pointer-sized startRoutine + pointer-sized parameter + pointer ntCreateThreadExAddr + pointer extra + optional HANDLE
	size_t msgSize = (sizeof(UMHH_COMMAND_MESSAGE) - 1) + sizeof(DWORD) + sizeof(PVOID) + sizeof(PVOID) + sizeof(PVOID) + sizeof(PVOID);
	msgSize += sizeof(HANDLE);
	PUMHH_COMMAND_MESSAGE msg = (PUMHH_COMMAND_MESSAGE)malloc(msgSize);
	if (!msg) return false;
	memset(msg, 0, msgSize);
	msg->m_Cmd = CMD_CREATE_REMOTE_THREAD;
	size_t off = 0;
	memcpy(msg->m_Data + off, &pid, sizeof(DWORD)); off += sizeof(DWORD);
	memcpy(msg->m_Data + off, &startRoutine, sizeof(PVOID)); off += sizeof(PVOID);
	memcpy(msg->m_Data + off, &parameter, sizeof(PVOID)); off += sizeof(PVOID);
	memcpy(msg->m_Data + off, &ntCreateThreadExAddr, sizeof(PVOID)); off += sizeof(PVOID);
	memcpy(msg->m_Data + off, &extra, sizeof(PVOID)); off += sizeof(PVOID);

	memcpy(msg->m_Data + off, &callerHandle, sizeof(HANDLE)); off += sizeof(HANDLE);


	SIZE_T replySize = outThreadHandle ? sizeof(HANDLE) : 0;
	std::unique_ptr<BYTE[]> reply;
	if (replySize) reply.reset(new BYTE[replySize]);
	DWORD bytesOut = 0;
	HRESULT hr = FilterSendMessage(m_Port, msg, (DWORD)msgSize, replySize ? reply.get() : NULL, (DWORD)replySize, &bytesOut);
	free(msg);
	if (hr != S_OK) return false;
	if (outThreadHandle) {
		if (bytesOut < (DWORD)sizeof(HANDLE)) return false;
		HANDLE h = NULL; RtlCopyMemory(&h, reply.get(), sizeof(HANDLE));
		*outThreadHandle = h;
	}
	return true;
}

bool Filter::FLTCOMM_GetSyscallAddr(ULONG syscallNumber, PVOID* outAddr) {
	if (!outAddr) return false;
	size_t msgSize = (sizeof(UMHH_COMMAND_MESSAGE) - 1) + sizeof(ULONG);
	PUMHH_COMMAND_MESSAGE msg = (PUMHH_COMMAND_MESSAGE)malloc(msgSize);
	if (!msg) return false;
	memset(msg, 0, msgSize);
	msg->m_Cmd = CMD_GET_SYSCALL_ADDR;
	memcpy(msg->m_Data, &syscallNumber, sizeof(ULONG));

	SIZE_T replySize = sizeof(PVOID);
	std::unique_ptr<BYTE[]> reply(new BYTE[replySize]);
	DWORD bytesOut = 0;
	HRESULT hr = FilterSendMessage(m_Port, msg, (DWORD)msgSize, reply.get(), (DWORD)replySize, &bytesOut);
	free(msg);
	if (hr != S_OK || bytesOut < (DWORD)replySize) return false;
	PVOID addr = NULL; RtlCopyMemory(&addr, reply.get(), sizeof(PVOID));
	*outAddr = addr;
	return true;
}
bool Filter::FLTCOMM_WriteDllPathToTargetProcess(DWORD pid, PVOID userWideStringPtr, PVOID* outValue) {
	if (!outValue) return false;
	size_t msgSize = (sizeof(UMHH_COMMAND_MESSAGE) - 1) + sizeof(DWORD) + sizeof(PVOID);
	PUMHH_COMMAND_MESSAGE msg = (PUMHH_COMMAND_MESSAGE)malloc(msgSize);
	if (!msg) return false;
	memset(msg, 0, msgSize);
	msg->m_Cmd = CMD_WRITE_DLL_PATH;
	size_t off = 0;
	memcpy(msg->m_Data + off, &pid, sizeof(DWORD)); off += sizeof(DWORD);
	memcpy(msg->m_Data + off, &userWideStringPtr, sizeof(PVOID)); off += sizeof(PVOID);

	SIZE_T replySize = sizeof(PVOID);
	std::unique_ptr<BYTE[]> reply(new BYTE[replySize]);
	DWORD bytesOut = 0;
	HRESULT hr = FilterSendMessage(m_Port, msg, (DWORD)msgSize, reply.get(), (DWORD)replySize, &bytesOut);
	free(msg);
	if (hr != S_OK || bytesOut < (DWORD)replySize) return false;
	PVOID v = NULL; RtlCopyMemory(&v, reply.get(), sizeof(PVOID));
	*outValue = v;
	return true;
}

bool Filter::FLTCOMM_RegisterObCallback(bool registerFlag) {
	// Ob callback registration has moved into a separate component (UMHH.ObCallback).
	// This user-mode function no longer talks to the kernel. To (re)register the
	// callback, restart the `UMHH.ObCallback` service which hosts the registration.
	UNREFERENCED_PARAMETER(registerFlag);
	return false;
}

bool Filter::FLTCOMM_RemoveHookByHash(ULONGLONG hash) {
	LOG_CTRL_ETW(L"FLTCOMM_RemoveHookByHash: request hash=0x%I64x\n", hash);
	size_t msgSize = sizeof(UMHH_COMMAND_MESSAGE) + sizeof(ULONGLONG) - 1;
	PUMHH_COMMAND_MESSAGE msg = (PUMHH_COMMAND_MESSAGE)malloc(msgSize);
	if (!msg) {
		Helper::Fatal(L"FLTCOMM_RemoveHookByHash: failed to allocate message");
		return false;
	}
	memset(msg, 0, msgSize);
	msg->m_Cmd = CMD_REMOVE_HOOK;
	memcpy(msg->m_Data, &hash, sizeof(ULONGLONG));

	BOOLEAN removed = FALSE;
	DWORD bytesOut = 0;
	HRESULT hResult = FilterSendMessage(m_Port,
		msg,
		(DWORD)msgSize,
		&removed,
		sizeof(BOOLEAN),
		&bytesOut);
	free(msg);
	if (hResult == S_OK && removed == TRUE) {
		LOG_CTRL_ETW(L"FLTCOMM_RemoveHookByHash: succeeded hash=0x%I64x\n", hash);
		SetLastError(ERROR_SUCCESS);
		return true;
	}
	// Any failure is fatal in user-mode policy
	LOG_CTRL_ETW(L"FLTCOMM_RemoveHookByHash: failed hash=0x%I64x\n", hash);
	return false;
}

// Request kernel to enumerate hook NT paths. Returns true on success and
// fills out vector with NT paths (empty list if none). Caller should handle
// large lists by providing a sufficiently large buffer; here we use a
// reasonably large static buffer for simplicity.
bool Filter::FLTCOMM_EnumHookPaths(std::vector<std::wstring>& outPaths) {
	const DWORD REPLY_MAX = 32768;
	std::unique_ptr<BYTE[]> reply(new BYTE[REPLY_MAX]);
	PUMHH_COMMAND_MESSAGE msg = (PUMHH_COMMAND_MESSAGE)malloc(sizeof(UMHH_COMMAND_MESSAGE));
	if (!msg) return false;
	memset(msg, 0, sizeof(UMHH_COMMAND_MESSAGE));
	msg->m_Cmd = CMD_ENUM_HOOKS;

	DWORD bytesOut = 0;
	HRESULT hr = FilterSendMessage(m_Port, msg, (DWORD)sizeof(UMHH_COMMAND_MESSAGE), reply.get(), REPLY_MAX, &bytesOut);
	free(msg);
	if (hr != S_OK || bytesOut == 0) return false;

	// Parse concatenated null-terminated WCHAR strings
	size_t wcCount = bytesOut / sizeof(WCHAR);
	WCHAR* w = (WCHAR*)reply.get();
	size_t i = 0;
	while (i < wcCount) {
		if (w[i] == L'\0') { ++i; continue; }
		std::wstring s(&w[i]);
		outPaths.push_back(s);
		i += s.size() + 1;
	}
	return true;
}

Filter::~Filter() {
	// Signal the listener to stop and wait for worker to exit.
	m_StopListener = true;
	if (m_Port != INVALID_HANDLE_VALUE) {
		// Cancel any pending overlapped FilterGetMessage calls on this handle.
		CancelIoEx(m_Port, NULL);
	}
	if (m_WorkExitEvent) {
		// Wait a short time for the worker to exit; if it doesn't, continue
		// with cleanup to avoid hangs during shutdown.
		WaitForSingleObject(m_WorkExitEvent, 2000);
	}
	if (m_WorkExitEvent) { CloseHandle(m_WorkExitEvent); m_WorkExitEvent = NULL; }
	if (m_ListenerEvent) { CloseHandle(m_ListenerEvent); m_ListenerEvent = NULL; }
	if (m_Port && m_Port != INVALID_HANDLE_VALUE) {
		CloseHandle(m_Port);
		m_Port = INVALID_HANDLE_VALUE;
	}
}

