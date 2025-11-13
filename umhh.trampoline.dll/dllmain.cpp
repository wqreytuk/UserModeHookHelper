// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <stdio.h>
BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

 
// NOTE: For brevity in this patch, functions 011..100 for both stages follow the identical body pattern.
// If you require the literal expanded code for 011..100, I can append them in a subsequent patch.
// ---- Explicit expansion for trampoline_stage_[1|2]_num_011 .. num_100 ----
#define TRAMP_BODY(num,stage) \
	printf("trampoline_stage_" stage "_num_" #num "\n"); \
	printf("%d\n", abcd); printf("%d\n", a2bcd); printf("%d\n", abc2d); (param); __int64 a2; __int64 a3; (a2); (a3); \
	const __int64 *a4 = 0; const wchar_t *a5 = 0; const wchar_t *v5; unsigned __int64 v6; __int64 v8; __int64 v9; unsigned __int64 v10; va_list va; (va); \
	v5 = a5; v6 = 0xFFFFFFFFFFFFFFFFui64; v8 = 0xEi64; if (a5) { if (*a5) { v10 = 0xFFFFFFFFFFFFFFFFui64; do ++v10; while (a5[v10]); v9 = 2 * v10 + 2; } else { v9 = 0xEi64; } } else { v9 = 0xAi64; } \
	if (a5) { if (!*a5) v5 = L"<NULL>"; } else { v5 = L"NULL"; } if (a4) { if (*a4) { do ++v6; while (a4[v6]); v8 = 2 * v6 + 2; } } else { v8 = 0xAi64; } \
	if (a4) { if (!*a4) a4 = (__int64*)(__int64)1234567; } else { a4 = (__int64*)(__int64)1234567; } \
	printf("APCTEST - DispatchRead() called."); printf("APCTEST - DispatchRead() called."); printf("APCTEST - DispatchRead() called."); printf("APCTEST - DispatchRead() called."); printf("APCTEST - DispatchRead() called."); \
	printf("APCTEST - DispatchRead() called."); printf("APCTEST - DispatchRead() called."); printf("APCTEST - DispatchRead() called."); printf("APCTEST - DispatchRead() called."); printf("APCTEST - DispatchRead() called."); \
	printf("APCTEST - DispatchRead() called."); printf("APCTEST - DispatchRead() called."); printf("APCTEST - DispatchRead() called."); printf("APCTEST - DispatchRead() called."); printf("APCTEST - DispatchRead() called."); \
	printf("APCTEST - DispatchRead() called."); printf("APCTEST - DispatchRead() called."); printf("APCTEST - DispatchRead() called."); printf("APCTEST - DispatchRead() called."); printf("APCTEST - DispatchRead() called."); \
	printf("APCTEST - DispatchRead() called."); printf("APCTEST - DispatchRead() called."); printf("APCTEST - DispatchRead() called."); printf("APCTEST - DispatchRead() called."); printf("APCTEST - DispatchRead() called."); \
	printf("APCTEST - DispatchRead() called."); printf("APCTEST - DispatchRead() called."); printf("APCTEST - DispatchRead() called."); printf("APCTEST - DispatchRead() called."); printf("APCTEST - DispatchRead() called."); \
	printf("APCTEST - DispatchRead() called."); printf("APCTEST - DispatchRead() called."); printf("APCTEST - DispatchRead() called."); printf("APCTEST - DispatchRead() called.");

#define DECL_PAIR(num) \
extern "C" __declspec(dllexport) VOID trampoline_stage_1_num_##num (INT param, int abcd, int a2bcd, int abc2d) { TRAMP_BODY(num,"1") } \
extern "C" __declspec(dllexport) VOID trampoline_stage_2_num_##num (INT param, int abcd, int a2bcd, int abc2d) { TRAMP_BODY(num,"2") }

DECL_PAIR(001)
DECL_PAIR(002)
DECL_PAIR(003)
DECL_PAIR(004)
DECL_PAIR(005)
DECL_PAIR(006)
DECL_PAIR(007)
DECL_PAIR(008)
DECL_PAIR(009)
DECL_PAIR(010)
DECL_PAIR(011)
DECL_PAIR(012)
DECL_PAIR(013)
DECL_PAIR(014)
DECL_PAIR(015)
DECL_PAIR(016)
DECL_PAIR(017)
DECL_PAIR(018)
DECL_PAIR(019)
DECL_PAIR(020)
DECL_PAIR(021)
DECL_PAIR(022)
DECL_PAIR(023)
DECL_PAIR(024)
DECL_PAIR(025)
DECL_PAIR(026)
DECL_PAIR(027)
DECL_PAIR(028)
DECL_PAIR(029)
DECL_PAIR(030)
DECL_PAIR(031)
DECL_PAIR(032)
DECL_PAIR(033)
DECL_PAIR(034)
DECL_PAIR(035)
DECL_PAIR(036)
DECL_PAIR(037)
DECL_PAIR(038)
DECL_PAIR(039)
DECL_PAIR(040)
DECL_PAIR(041)
DECL_PAIR(042)
DECL_PAIR(043)
DECL_PAIR(044)
DECL_PAIR(045)
DECL_PAIR(046)
DECL_PAIR(047)
DECL_PAIR(048)
DECL_PAIR(049)
DECL_PAIR(050)
DECL_PAIR(051)
DECL_PAIR(052)
DECL_PAIR(053)
DECL_PAIR(054)
DECL_PAIR(055)
DECL_PAIR(056)
DECL_PAIR(057)
DECL_PAIR(058)
DECL_PAIR(059)
DECL_PAIR(060)
DECL_PAIR(061)
DECL_PAIR(062)
DECL_PAIR(063)
DECL_PAIR(064)
DECL_PAIR(065)
DECL_PAIR(066)
DECL_PAIR(067)
DECL_PAIR(068)
DECL_PAIR(069)
DECL_PAIR(070)
DECL_PAIR(071)
DECL_PAIR(072)
DECL_PAIR(073)
DECL_PAIR(074)
DECL_PAIR(075)
DECL_PAIR(076)
DECL_PAIR(077)
DECL_PAIR(078)
DECL_PAIR(079)
DECL_PAIR(080)
DECL_PAIR(081)
DECL_PAIR(082)
DECL_PAIR(083)
DECL_PAIR(084)
DECL_PAIR(085)
DECL_PAIR(086)
DECL_PAIR(087)
DECL_PAIR(088)
DECL_PAIR(089)
DECL_PAIR(090)
DECL_PAIR(091)
DECL_PAIR(092)
DECL_PAIR(093)
DECL_PAIR(094)
DECL_PAIR(095)
DECL_PAIR(096)
DECL_PAIR(097)
DECL_PAIR(098)
DECL_PAIR(099)
DECL_PAIR(100)

#undef DECL_PAIR
#undef TRAMP_BODY