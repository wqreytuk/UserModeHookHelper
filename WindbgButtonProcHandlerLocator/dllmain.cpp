// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <stdio.h>  
#include <evntprov.h>
#include <tlhelp32.h>
#include <string>

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
	Log(L"CreateFileW opening: %s\n", *(DWORD*)((ULONG_PTR)original_esp + 0x4));
	// HOOK CODE END


	return;
}

std::wstring GetModuleNameFromAddress(void* address)
{
	DWORD pid = GetCurrentProcessId();

	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	if (snap == INVALID_HANDLE_VALUE)
		return L"";

	MODULEENTRY32W me32{};
	me32.dwSize = sizeof(me32);

	if (Module32FirstW(snap, &me32)) {
		do {
			BYTE* base = me32.modBaseAddr;
			DWORD size = me32.modBaseSize;

			if ((BYTE*)address >= base && (BYTE*)address < base + size) {
				CloseHandle(snap);
				return me32.szModule;   // wide module name
			}
		} while (Module32NextW(snap, &me32));
	}

	CloseHandle(snap);
	return L"";
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
	// this hanler addr should be inside windbg?
	if (0x00007FF7898B9110 == (DWORD64)rax)
		return;
	PVOID moduleBase = 0;
	std::wstring owning = GetModuleNameFromAddress(rax);
	if (!owning.empty()) {
		// exclude code within COMCTL32 / MSFTEDIT module
		if (owning.find(L"COMCTL32.dll") == std::wstring::npos)
			if (owning.find(L"MSFTEDIT.DLL") == std::wstring::npos)
				Log(L"proc handler Addr=0x%p, Module=%s\n", rax, owning.c_str());
	}
	else {
		Log(L"proc handler Addr=0x%p, no module info\n", rax);
	}
	// HOOK CODE END


	return;
}

extern "C" __declspec(dllexport) VOID WindbgMSGHooK1(PVOID rcx, PVOID rdx, PVOID r8, PVOID r9, PVOID rsp) {
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
	// r14d is msg id
	Log(L"MSG id: 0x%x\n", r14);
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

