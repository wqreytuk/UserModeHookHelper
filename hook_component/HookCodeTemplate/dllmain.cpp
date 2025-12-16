// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <stdio.h>  

#include <evntprov.h>
#include "../HookCodeLib/HookCodeLib.h"
static const GUID ProviderGUID =
{ 0x3da12c0, 0x27c2, 0x4d75, { 0x95, 0x3a, 0x2c, 0x4e, 0x66, 0xa3, 0x74, 0x64 } };
REGHANDLE g_ProviderHandle;
#define DebugBreak() __debugbreak();
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
void DLog(_In_ PCWSTR Format, ...) {
	WCHAR Buffer[1024];
	va_list args;
	va_start(args, Format);
	_vsnwprintf_s(Buffer, RTL_NUMBER_OF(Buffer) - 1, Format, args);
	va_end(args);
	Buffer[RTL_NUMBER_OF(Buffer) - 1] = L'\0';

	WCHAR Prefixed[1100];
	_snwprintf_s(Prefixed, RTL_NUMBER_OF(Prefixed) - 1, L"[HookCode]   %s", Buffer);
	Prefixed[RTL_NUMBER_OF(Prefixed) - 1] = L'\0';
	OutputDebugString(Prefixed);
}
class HookServicesAdapter : public IHookServices {
	 VOID HKLog(const wchar_t* fmt, ...) override{
		 WCHAR Buffer[1024];
		 va_list args;
		 va_start(args, fmt);
		 _vsnwprintf_s(Buffer, RTL_NUMBER_OF(Buffer) - 1, fmt, args);
		 va_end(args);
		 Buffer[RTL_NUMBER_OF(Buffer) - 1] = L'\0';

		 WCHAR Prefixed[1100];
		 _snwprintf_s(Prefixed, RTL_NUMBER_OF(Prefixed) - 1, L"[HCLib]      %s", Buffer);
		 Prefixed[RTL_NUMBER_OF(Prefixed) - 1] = L'\0';
		 EventWriteString(g_ProviderHandle, 0, 0, Prefixed);
	}
};
static HookServicesAdapter g_HookServices; // singleton adapter instance
#define PROLOGX64(rsp)                                                         \
    if (!(rsp)) {                                                            \
        Log(L"Fatal Error, RSP==NULL\n");                                    \
        return;                                                              \
    }                                                                        \
    PVOID original_rsp = (PVOID)((DWORD64)(rsp) + 0x80);                     \
    PVOID r15 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x0);          \
    PVOID r14 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x8);          \
    PVOID r13 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x10);         \
    PVOID r12 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x18);         \
    PVOID r11 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x20);         \
    PVOID r10 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x28);         \
    PVOID rbp = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x40);         \
    PVOID rdi = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x48);         \
    PVOID rsi = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x50);         \
    PVOID rbx = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x68);         \
    PVOID rax = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x70);

#define PROLOGWin32(esp)                                                       \
    if (!(esp)) {                                                            \
        Log(L"Fatal Error, RSP==NULL\n");                                    \
        return;                                                              \
    }                                                                        \
                                                                             \
    /* original_esp can be used to access original parameters */             \
    ULONG original_esp = (esp) + 0x20;                                       \
                                                                             \
    /* original register values saved on stack */                             \
    ULONG ebp = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x0);                   \
    ULONG edi = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x4);                   \
    ULONG esi = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x8);                   \
    ULONG edx = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0xC);                   \
    ULONG ecx = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x10);                  \
    ULONG ebx = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x14);                  \
    ULONG eax = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x18);
extern "C" __declspec(dllexport) VOID HookCodeWin32(ULONG esp) {
	PROLOGWin32(esp);

	// WRITE YOUR CODE HERE
	Log(L"CreateFileW opening: %s\n", *(DWORD*)((ULONG_PTR)original_esp + 0x4));
	// HOOK CODE END


	return;
}
extern "C" __declspec(dllexport) VOID HookCodeX64(PVOID rcx, PVOID rdx, PVOID r8, PVOID r9, PVOID rsp) {
	PROLOGX64(rsp);


	// WRITE YOUR CODE HERE
	Log(L"CreateFileW opening: %s\n", rcx);
	// HOOK CODE END


	return;
}

VOID EntryCode() {
	ULONG status = EventRegister(&ProviderGUID,
		NULL,
		NULL,
		&g_ProviderHandle);
	// set HookCodeLib interface
	HookCode::SetHookServices(&g_HookServices);
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

