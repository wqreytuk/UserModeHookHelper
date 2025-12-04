// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <stdio.h>  
#include <evntprov.h>
#include <fltuser.h>
#include <memory>
#include "../UserModeHookHelper/MacroDef.h"
#include "../UserModeHookHelper/UKShared.h"

static const GUID ProviderGUID =
{ 0x3da12c0, 0x27c2, 0x4d75, { 0x95, 0x3a, 0x2c, 0x4e, 0x66, 0xa3, 0x74, 0x64 } };
REGHANDLE g_ProviderHandle;

bool FLTCOMM_GetProcessHandle(HANDLE m_Port, DWORD pid, HANDLE* outHandle);
void Log(_In_ PCWSTR Format, ...) {
	WCHAR Buffer[1024];
	va_list args;
	va_start(args, Format);
	_vsnwprintf_s(Buffer, RTL_NUMBER_OF(Buffer) - 1, Format, args);
	va_end(args);
	Buffer[RTL_NUMBER_OF(Buffer) - 1] = L'\0';

	WCHAR Prefixed[1100];
	_snwprintf_s(Prefixed, RTL_NUMBER_OF(Prefixed) - 1, L"[HookCode]   %s", Buffer);
	Prefixed[RTL_NUMBER_OF(Prefixed) - 1] = L'\0';
	EventWriteString(g_ProviderHandle, 0, 0, Prefixed);
}

extern "C" __declspec(dllexport) VOID HookCodeWin32(ULONG esp) {
	if (!esp) {
		Log(L"Fatal Error, RSP==NULL\n");
		return;
	}
	// original_esp can be used to access original parameter
	ULONG original_esp = esp + 0x20;

	// original rigster value and location
	ULONG ebp = *(PULONG)((UCHAR*)(ULONG_PTR)esp + 0x0);
	ULONG edi = *(PULONG)((UCHAR*)(ULONG_PTR)esp + 0x4);
	ULONG esi = *(PULONG)((UCHAR*)(ULONG_PTR)esp + 0x8);
	ULONG edx = *(PULONG)((UCHAR*)(ULONG_PTR)esp + 0xC);
	ULONG ecx = *(PULONG)((UCHAR*)(ULONG_PTR)esp + 0x10);
	ULONG ebx = *(PULONG)((UCHAR*)(ULONG_PTR)esp + 0x14);
	ULONG eax = *(PULONG)((UCHAR*)(ULONG_PTR)esp + 0x18);


	// WRITE YOUR CODE HERE

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
		return;
	}
	else
		Log(L"successfully connect to minifilterport: 0x%p\n", m_Port);


	// get process handle
	// pid is save in ebp+8
	DWORD pid = *(DWORD*)((ULONG_PTR)ebp + 8);
	HANDLE hProc = NULL;
	if (!FLTCOMM_GetProcessHandle(m_Port, pid, &hProc)) {
		CloseHandle(m_Port);
		Log(L"failed to call FLTCOMM_GetProcessHandle\n");
		return;
	}
	// after successfully get high access handle, modify original eax value with it
	*(PULONG)((UCHAR*)(ULONG_PTR)esp + 0x18) = (ULONG)(ULONG_PTR)hProc;
	Log(L"process handle is replaced with 0x%x\n", hProc);
	CloseHandle(m_Port);
	// HOOK CODE END


	return;
}
extern "C" __declspec(dllexport) VOID HookCodeX64(PVOID rcx, PVOID rdx, PVOID r8, PVOID r9, PVOID rsp) {
	if (!rsp) {
		Log(L"Fatal Error, RSP==NULL\n");
		return;
	}

	PVOID original_rsp = (PVOID)((DWORD64)rsp + 0x80);

	// original rigster value and location
	PVOID r15 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)rsp + 0x0);
	PVOID r14 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)rsp + 0x8);
	PVOID r13 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)rsp + 0x10);
	PVOID r12 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)rsp + 0x18);
	PVOID r11 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)rsp + 0x20);
	PVOID r10 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)rsp + 0x28);
	PVOID rbp = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)rsp + 0x40);
	PVOID rdi = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)rsp + 0x48);
	PVOID rsi = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)rsp + 0x50);
	PVOID rbx = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)rsp + 0x68);
	PVOID rax = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)rsp + 0x70);


	// WRITE YOUR CODE HERE
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
		return;
	}
	else
		Log(L"successfully connect to minifilterport: 0x%p\n", m_Port);


	// get process handle
	// pid is save in r11-0x48, r11 is original_rsp+0x68
	DWORD pid =(DWORD) *(DWORD64*)((ULONG_PTR)original_rsp + 0x68-0x48);
	HANDLE hProc = NULL;
	if (!FLTCOMM_GetProcessHandle(m_Port, pid, &hProc)) {
		CloseHandle(m_Port);
		Log(L"failed to call FLTCOMM_GetProcessHandle\n");
		return;
	}
	// after successfully get high access handle, modify original rax value with it
	*(DWORD64*)((UCHAR*)rsp + 0x70) = (DWORD64)(ULONG_PTR)hProc;
	Log(L"process handle is replaced with 0x%x\n", hProc);
	CloseHandle(m_Port);

	// HOOK CODE END


	return;
}

VOID EntryCode() {
	ULONG status = EventRegister(&ProviderGUID,
		NULL,
		NULL,
		&g_ProviderHandle);
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		EntryCode();
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}



bool FLTCOMM_GetProcessHandle(HANDLE m_Port, DWORD pid, HANDLE* outHandle) {
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
