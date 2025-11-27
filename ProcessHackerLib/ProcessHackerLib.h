#pragma once
#include <ntdll.h>
#include <phnt/ntldr.h>
#include <phnt/ntpsapi.h>
namespace PHLIB {
#define NTSTATUS LONG
#define NT_SUCCESS(x) (0==x)
	typedef BOOLEAN(NTAPI *PPHP_ENUM_PROCESS_MODULES_CALLBACK)(
		_In_ HANDLE ProcessHandle,
		_In_ PLDR_DATA_TABLE_ENTRY Entry,
		_In_ PVOID AddressOfEntry,
		_In_opt_ PVOID Context1,
		_In_opt_ PVOID Context2
		);
	NTSTATUS PhpEnumProcessModules(
		_In_ HANDLE ProcessHandle,
		_In_ PPHP_ENUM_PROCESS_MODULES_CALLBACK Callback,
		_In_opt_ PVOID Context1,
		_In_opt_ PVOID Context2
	);

	NTSTATUS PhReadVirtualMemory(
		_In_ HANDLE ProcessHandle,
		_In_ PVOID BaseAddress,
		_Out_writes_bytes_(BufferSize) PVOID Buffer,
		_In_ SIZE_T BufferSize,
		_Out_opt_ PSIZE_T NumberOfBytesRead
	);
}