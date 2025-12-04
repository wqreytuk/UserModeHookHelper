
#include <Windows.h>
#include <stdio.h>
#include <evntprov.h>
#include <fltuser.h>
#include "../UserModeHookHelper/MacroDef.h"
#include "../UserModeHookHelper/UKShared.h"
#include <memory>

static const GUID ProviderGUID =
{ 0x3da12c0, 0x27c2, 0x4d75, { 0x95, 0x3a, 0x2c, 0x4e, 0x66, 0xa3, 0x74, 0x64 } };
REGHANDLE g_ProviderHandle;
void Log(_In_ PCWSTR Format, ...);


bool FLTCOMM_GetProcessHandle(HANDLE m_Port, DWORD pid, HANDLE* outHandle);
bool FLTCOMM_CreateRemoteThread(HANDLE m_Port, DWORD pid, PVOID startRoutine, PVOID parameter, PVOID ntCreateThreadExAddr,
	PVOID extra, HANDLE* outThreadHandle, HANDLE callerHandle);
int main(int argc, char* argv[]) {
	// register ETW

	ULONG status = EventRegister(&ProviderGUID,
		NULL,
		NULL,
		&g_ProviderHandle);
	if (0 != status) {
		MessageBoxA(NULL, "Failed to register ETW", "Suicide", MB_ICONERROR);
		exit(-1);
	}

	// parse parameter

	// DWORD, DWORD64, DWORD64, DWORD64
	// eThread(pid, pLoadLibraryW, dll_path_addr, syscall_addr, &
	if (argc != 5) {
		MessageBoxA(NULL, "malformed cmdline parameter", "Suicide", MB_ICONERROR);
		exit(-1);
	}
	DWORD pid = atoi(argv[1]);
	DWORD64 pLoadLibraryW = (DWORD64)strtoull(argv[2], nullptr, 10);
	DWORD64 dll_path_addr = (DWORD64)strtoull(argv[3], nullptr, 10);
	DWORD64 syscall_addr = (DWORD64)strtoull(argv[4], nullptr, 10);

	// connect to minifilter port
	HRESULT hResult = S_OK;
	HANDLE m_Port = INVALID_HANDLE_VALUE;
	hResult = FilterConnectCommunicationPort(
		UMHHLP_PORT_NAME,
		0,
		NULL,
		0,
		NULL,
		&m_Port
	);
	if (hResult != S_OK) {
		Log(L"failed to call FilterConnectCommunicationPort: 0x%x\n", hResult);
		MessageBoxA(NULL, "FilterConnectCommunicationPort failed in Filter constructor", "Suicide", MB_ICONERROR);
		exit(-1);
	}
	else
		Log(L"successfully connect to minifilterport: 0x%p\n", m_Port);


	// get process handle
	HANDLE hProc = NULL;
	if (!FLTCOMM_GetProcessHandle(m_Port,pid, &hProc)) {
		Log(L"failed to call FLTCOMM_GetProcessHandle\n");
		MessageBoxA(NULL, "FLTCOMM_GetProcessHandle failed", "Suicide", MB_ICONERROR);
		exit(-1);
	}

	// create remote thread
	// bool FLTCOMM_CreateRemoteThread(HANDLE m_Port,DWORD pid, PVOID startRoutine, PVOID parameter, PVOID ntCreateThreadExAddr,
	// PVOID extra, HANDLE* outThreadHandle, HANDLE callerHandle) {
	HANDLE thread_handle = 0;
	if (!FLTCOMM_CreateRemoteThread(m_Port, pid, (PVOID)pLoadLibraryW, (PVOID)dll_path_addr, 
		(PVOID)syscall_addr, &thread_handle, NULL, hProc)) {
		Log(L"failed to call FLTCOMM_CreateRemoteThread\n");
		MessageBoxA(NULL, "FLTCOMM_CreateRemoteThread failed", "Suicide", MB_ICONERROR);
		exit(-1);
	}
	Log(L"I'm going commit suicide\n");
	exit(-1);
	return 0;
}

bool FLTCOMM_GetProcessHandle(HANDLE m_Port,DWORD pid, HANDLE* outHandle) {
	*outHandle = NULL;
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
		Log(L"FLTCOMM_GetProcessHandle: FilterSendMessage hr=0x%x bytesOut=%u (expected %u)\n", hr, bytesOut, (unsigned)replySize);
		return false;
	}
	unsigned long long h64 = 0;
	memcpy(&h64, reply.get(), replySize);
	if (h64 == 0) return false;
	*outHandle = (HANDLE)(ULONG_PTR)h64;
	return true;
}

bool FLTCOMM_CreateRemoteThread(HANDLE m_Port,DWORD pid, PVOID startRoutine, PVOID parameter, PVOID ntCreateThreadExAddr,
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

void Log(_In_ PCWSTR Format, ...) {
	WCHAR Buffer[1024];
	va_list args;
	va_start(args, Format);
	_vsnwprintf_s(Buffer, RTL_NUMBER_OF(Buffer) - 1, Format, args);
	va_end(args);
	Buffer[RTL_NUMBER_OF(Buffer) - 1] = L'\0';

	WCHAR Prefixed[1100];
	_snwprintf_s(Prefixed, RTL_NUMBER_OF(Prefixed) - 1, L"[SUICIDE]    %s", Buffer);
	Prefixed[RTL_NUMBER_OF(Prefixed) - 1] = L'\0';
	if (g_ProviderHandle)
		EventWriteString(g_ProviderHandle, 0, 0, Prefixed);
	else
		// fall back to debugger output
		OutputDebugStringW(Prefixed);
}