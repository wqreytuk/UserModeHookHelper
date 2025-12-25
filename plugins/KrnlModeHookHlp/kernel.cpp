#include "Kernel.h"
#include <winternl.h>
#include "MacroDef.h"
#include "KmhhCtx.h"
#include "Log.h"


#pragma comment(lib, "ntdll.lib")

// Minimal definitions (not exposed in standard headers)
typedef struct _SYSTEM_MODULE_ENTRY {
	PVOID  Reserved1;
	PVOID  Reserved2;
	PVOID  ImageBase;
	ULONG  ImageSize;
	ULONG  Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	CHAR   FullPathName[256];
} SYSTEM_MODULE_ENTRY, *PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG NumberOfModules;
	SYSTEM_MODULE_ENTRY Modules[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;


namespace KRNL {

	BOOLEAN ReadPrimitive(_In_ LPVOID target_addr, _Out_ LPVOID buffer, _In_ size_t size) {
		if (!KmhhCtx_GetHookServices()) {
			KMHHLog(L"failed to call KmhhCtx_GetHookServices\n");
			return FALSE;
		}
		return KmhhCtx_GetHookServices()->ReadPrimitive(target_addr, buffer, size);
	}

	BOOLEAN WritePrimitive(_In_ LPVOID target_addr, _In_ LPVOID buffer, _In_ size_t size) {
		if (!KmhhCtx_GetHookServices()) {
			KMHHLog(L"failed to call KmhhCtx_GetHookServices\n");
			return FALSE;
		}
		return KmhhCtx_GetHookServices()->WritePrimitive(target_addr, buffer, size);
	}

	DWORD GetDriverBase(
		_In_ PCSTR DriverName,
		_Out_ PVOID* DriverBaseAddress
	)
	{
		NTSTATUS status;
		ULONG bufferSize = 0;
		PVOID buffer = NULL;

		*DriverBaseAddress = NULL;

		// Query required size
		status = NtQuerySystemInformation(
			(SYSTEM_INFORMATION_CLASS)SystemModuleInformation,
			NULL,
			0,
			&bufferSize
		);

		if (status != STATUS_INFO_LENGTH_MISMATCH)
			return status;

		buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufferSize);
		if (!buffer)
			return STATUS_INSUFFICIENT_RESOURCES;

		status = NtQuerySystemInformation(
			(SYSTEM_INFORMATION_CLASS)SystemModuleInformation,
			buffer,
			bufferSize,
			&bufferSize
		);

		if (0 != status) {
			HeapFree(GetProcessHeap(), 0, buffer);
			return status;
		}

		PSYSTEM_MODULE_INFORMATION pInfo =
			(PSYSTEM_MODULE_INFORMATION)buffer;

		for (ULONG i = 0; i < pInfo->NumberOfModules; i++) {
			PSYSTEM_MODULE_ENTRY pEntry = &pInfo->Modules[i];

			if (_stricmp(
				pEntry->FullPathName + pEntry->OffsetToFileName,
				DriverName
			) == 0)
			{
				*DriverBaseAddress = pEntry->ImageBase;
				break;
			}
		}

		HeapFree(GetProcessHeap(), 0, buffer);
		return (*DriverBaseAddress) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
	}
}