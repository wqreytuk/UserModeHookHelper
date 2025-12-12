#pragma once
#include <ntdll.h>
#include <phnt/ntldr.h>
#include <phnt/ntpsapi.h>
#include "../Shared/HookServices.h"
#include "../Shared/SharedMacroDef.h"

#define NTSTATUS LONG
#define PTR_ADD_OFFSET(Pointer, Offset) ((PVOID)((ULONG_PTR)(Pointer) + (ULONG_PTR)(Offset)))
#define WINDOWS_ANCIENT 0
#define WINDOWS_XP 51
#define WINDOWS_SERVER_2003 52
#define WINDOWS_VISTA 60
#define WINDOWS_7 61
#define WINDOWS_8 62
#define WINDOWS_8_1 63
#define WINDOWS_10 100
#define WINDOWS_NEW MAXLONG
#define PH_ENUM_PROCESS_MODULES_TRY_MAPPED_FILE_NAME 2
#define PH_ENUM_PROCESS_MODULES_LIMIT 0x800
namespace PHLIB {

	typedef struct _PH_MODULE_NODE {
		LDR_DATA_TABLE_ENTRY Entry;
		struct _PH_MODULE_NODE* Next;
	} PH_MODULE_NODE, *PPH_MODULE_NODE;


	// Enumerate modules and return a newly-allocated singly-linked list
	// of PH_MODULE_NODE structures (caller is responsible for freeing).
	NTSTATUS PhpEnumProcessModules(
		_In_ DWORD pid, wchar_t* target_module, unsigned long long* ModuleBase
	); 
	NTSTATUS PhBuildModuleListInteranl(
		_In_ DWORD pid, _Out_ PPH_MODULE_LIST_NODE* OutHead
	);
	NTSTATUS PhpEnumProcessModulesX64(
		_In_ HANDLE ProcessHandle, wchar_t *target_module, unsigned long long* ModuleBase);
	NTSTATUS PhpEnumProcessModulesWin32(
			_In_ HANDLE ProcessHandle, wchar_t *target_module, unsigned long long* ModuleBase);
	// Build a linked list of modules (base + size + full path) for a WOW64 process.
	// Caller owns the list and must free each node's Path and the node itself.
	NTSTATUS PhBuildModuleListWin32(
		_In_ HANDLE ProcessHandle,
		_Out_ PPH_MODULE_LIST_NODE* OutHead
	);
	NTSTATUS PhBuildModuleListX64(
		_In_ HANDLE ProcessHandle,
		_Out_ PPH_MODULE_LIST_NODE* OutHead);

	NTSTATUS
		PhGetProcessBasicInformation(
			_In_ HANDLE ProcessHandle,
			_Out_ PPROCESS_BASIC_INFORMATION BasicInformation
		);
	// Logging integration: allow host to provide IHookServices for logging
	NTSTATUS
		PhGetProcessIsWow64Internal(
			_In_ DWORD pid,
			_Out_ PBOOLEAN IsWow64
		);
	void SetHookServicesInternal(IHookServices* services);
	void PHLog(const wchar_t* fmt, ...);
	NTSTATUS IsProcessWow64Internal(
		_In_ HANDLE hProc,
		_Out_ PBOOLEAN IsWow64);
	NTSTATUS PhGetProcessMappedFileName(
		_In_ HANDLE ProcessHandle,
		_In_ PVOID BaseAddress,
		_Out_ PUNICODE_STRING* FileName
	);
	NTSTATUS PhReadVirtualMemory(
		_In_ HANDLE ProcessHandle,
		_In_ PVOID BaseAddress,
		_Out_writes_bytes_(BufferSize) PVOID Buffer,
		_In_ SIZE_T BufferSize,
		_Out_opt_ PSIZE_T NumberOfBytesRead
	);

	VOID PhInitializeWindowsVersion(
		VOID
	);

}