#include "pch.h"
#include <fltuser.h>
#include <string>
#include "FilterCommPort.h"
#include "../UserModeHookHelper/MacroDef.h"
#include "ETW.h"
#include "UMController.h"
#include "Helper.h"
#include "../UserModeHookHelper/UKShared.h"
#include <memory>
#include <winerror.h>   // For HRESULT macros 


// Provide minimal NTSTATUS/NT_SUCCESS definitions for user-mode build
#ifndef NTSTATUS
typedef long NTSTATUS;
#endif
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// use app-owned ETW instance

Filter::~Filter() {
	// disconnect from minifilter port
	if (m_Port != INVALID_HANDLE_VALUE) {
		CloseHandle(m_Port);  // Disconnects from minifilter
		m_Port = INVALID_HANDLE_VALUE;
	}
	else {
		app.GetETW().Log(L"disconnected from minifilterport\n");
	}
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
		app.GetETW().Log(L"failed to call FilterConnectCommunicationPort: 0x%x\n", hResult);
		Helper::Fatal(L"FilterConnectCommunicationPort failed in Filter constructor");
	}
	else
		app.GetETW().Log(L"successfully connect to minifilterport: 0x%p\n", m_Port);
}


boolean Filter::FLTCOMM_CheckHookList(const std::wstring& ntPath) {
	// Compute 64-bit FNV-1a hash over NT path bytes (UTF-16LE) and send the
	// 8-byte hash to the kernel. This preserves the original design that
	// compares a compact identifier in kernel space.
	if (ntPath.empty()) {
		Helper::Fatal(L"FLTCOMM_CheckHookList called with empty path");
		return FALSE;
	}

	// Interpret the WCHAR buffer as bytes for hashing (UTF-16LE)
	const UCHAR* bytes = reinterpret_cast<const UCHAR*>(ntPath.c_str());
	DWORD64 hash = Helper::GetNtPathHash(const_cast<UCHAR*>(bytes));

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
		app.GetETW().Log(L"failed to call FilterSendMessage: 0x%p\n", hResult);
		Helper::Fatal(L"FilterSendMessage failed in FLTCOMM_CheckHookList");
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
		if (hResult == HRESULT_FROM_WIN32(ERROR_NOT_FOUND)) {
			app.GetETW().Log(L"process terminated on the fly, can not get ntpath\n");
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

	// Compute hash
	const UCHAR* bytes = reinterpret_cast<const UCHAR*>(ntPath.c_str());
	DWORD64 hash = Helper::GetNtPathHash(const_cast<UCHAR*>(bytes));

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

	NTSTATUS st = STATUS_UNSUCCESSFUL;
	DWORD bytesOut = 0;
	HRESULT hResult = FilterSendMessage(m_Port,
		msg,
		(DWORD)msgSize,
		&st,
		sizeof(NTSTATUS),
		&bytesOut);
	free(msg);
	if (hResult == S_OK && NT_SUCCESS(st)) {
		SetLastError(ERROR_SUCCESS);
		return true;
	}
	// Any failure here is considered fatal for the app
	SetLastError(21); // ERROR_NOT_READY as sentinel for fatal
	Helper::Fatal(L"FLTCOMM_AddHook: kernel or IPC failure while adding hook");
	return false;
}

bool Filter::FLTCOMM_RemoveHookByHash(ULONGLONG hash) {
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
		SetLastError(ERROR_SUCCESS);
		return true;
	}
	// Any failure is fatal in user-mode policy
	SetLastError(21); // ERROR_NOT_READY as sentinel for fatal
	Helper::Fatal(L"FLTCOMM_RemoveHookByHash: kernel or IPC failure while removing hook");
	return false;
}