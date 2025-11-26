// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <stdio.h>  

#include <evntprov.h>
static const GUID ProviderGUID =
{ 0x3da12c0, 0x27c2, 0x4d75, { 0x95, 0x3a, 0x2c, 0x4e, 0x66, 0xa3, 0x74, 0x64 } };
REGHANDLE g_ProviderHandle;

void Log(_In_ PCWSTR Format, ...) {
	WCHAR Buffer[1024];
	va_list args;
	va_start(args, Format);
	_vsnwprintf_s(Buffer, RTL_NUMBER_OF(Buffer) - 1, Format, args);
	va_end(args);
	Buffer[RTL_NUMBER_OF(Buffer) - 1] = L'\0';

	WCHAR Prefixed[1100];
	_snwprintf_s(Prefixed, RTL_NUMBER_OF(Prefixed) - 1, L"[HookCode]  %s", Buffer);
	Prefixed[RTL_NUMBER_OF(Prefixed) - 1] = L'\0';
	EventWriteString(g_ProviderHandle, 0, 0, Prefixed);
}

extern "C" __declspec(dllexport) VOID HookCodeWin32() {
	return;
}
extern "C" __declspec(dllexport) VOID HookCodeX64(PVOID rcx, PVOID rdx, PVOID r8, PVOID r9, PVOID rsp) {
	PVOID r15 = (PVOID)*(DWORD64*)((UCHAR*)rsp + 0x0);
	PVOID r14 = (PVOID)*(DWORD64*)((UCHAR*)rsp + 0x8);
	PVOID r13 = (PVOID)*(DWORD64*)((UCHAR*)rsp + 0x10);
	PVOID r12 = (PVOID)*(DWORD64*)((UCHAR*)rsp + 0x18);
	PVOID r11 = (PVOID)*(DWORD64*)((UCHAR*)rsp + 0x20);
	PVOID r10 = (PVOID)*(DWORD64*)((UCHAR*)rsp + 0x28);
	PVOID rbp = (PVOID)*(DWORD64*)((UCHAR*)rsp + 0x40);
	PVOID rdi = (PVOID)*(DWORD64*)((UCHAR*)rsp + 0x48);
	PVOID rsi = (PVOID)*(DWORD64*)((UCHAR*)rsp + 0x50);
	PVOID rbx = (PVOID)*(DWORD64*)((UCHAR*)rsp + 0x68);
	PVOID rax = (PVOID)*(DWORD64*)((UCHAR*)rsp + 0x70);

	if (!rsp) {
		Log(L"Fatal Error, RSP==NULL\n");
		return;
	}

	// WRITE YOUR CODE HERE

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

