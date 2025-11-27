// ProcessHackerLib.cpp : 定义静态库的函数。
//

#include "pch.h"
#include "framework.h"
#include "ProcessHackerLib.h"
namespace PHLIB {

	FORCEINLINE
		NTSTATUS
		PhGetProcessBasicInformation(
			_In_ HANDLE ProcessHandle,
			_Out_ PPROCESS_BASIC_INFORMATION BasicInformation
		)
	{
		return NtQueryInformationProcess(
			ProcessHandle,
			ProcessBasicInformation,
			BasicInformation,
			sizeof(PROCESS_BASIC_INFORMATION),
			NULL
		);
	}
	NTSTATUS PhReadVirtualMemory(
		_In_ HANDLE ProcessHandle,
		_In_ PVOID BaseAddress,
		_Out_writes_bytes_(BufferSize) PVOID Buffer,
		_In_ SIZE_T BufferSize,
		_Out_opt_ PSIZE_T NumberOfBytesRead
	)
	{
		NTSTATUS status;

		// KphReadVirtualMemory is much slower than
		// NtReadVirtualMemory, so we'll stick to
		// the using the original system call whenever possible.

		status = NtReadVirtualMemory(
			ProcessHandle,
			BaseAddress,
			Buffer,
			BufferSize,
			NumberOfBytesRead
		);


		return status;
	}
	NTSTATUS PhpEnumProcessModules(
		_In_ HANDLE ProcessHandle,
		_In_ PPHP_ENUM_PROCESS_MODULES_CALLBACK Callback,
		_In_opt_ PVOID Context1,
		_In_opt_ PVOID Context2
	)
	{
		NTSTATUS status;
		PROCESS_BASIC_INFORMATION basicInfo;
		PPEB_LDR_DATA ldr;
		PEB_LDR_DATA pebLdrData;
		PLIST_ENTRY startLink;
		PLIST_ENTRY currentLink;
		ULONG dataTableEntrySize;
		LDR_DATA_TABLE_ENTRY currentEntry;
		ULONG i;

		// Get the PEB address.
		status = PhGetProcessBasicInformation(ProcessHandle, &basicInfo);

		if (!NT_SUCCESS(status))
			return status;

		// Read the address of the loader data.
		status = PhReadVirtualMemory(
			ProcessHandle,
			PTR_ADD_OFFSET(basicInfo.PebBaseAddress, FIELD_OFFSET(PEB, Ldr)),
			&ldr,
			sizeof(PVOID),
			NULL
		);

		if (!NT_SUCCESS(status))
			return status;

		// Read the loader data.
		status = PhReadVirtualMemory(
			ProcessHandle,
			ldr,
			&pebLdrData,
			sizeof(PEB_LDR_DATA),
			NULL
		);

		if (!NT_SUCCESS(status))
			return status;

		if (!pebLdrData.Initialized)
			return STATUS_UNSUCCESSFUL;

		if (WindowsVersion >= WINDOWS_8)
			dataTableEntrySize = LDR_DATA_TABLE_ENTRY_SIZE_WIN8;
		else if (WindowsVersion >= WINDOWS_7)
			dataTableEntrySize = LDR_DATA_TABLE_ENTRY_SIZE_WIN7;
		else
			dataTableEntrySize = LDR_DATA_TABLE_ENTRY_SIZE_WINXP;

		// Traverse the linked list (in load order).

		i = 0;
		startLink = PTR_ADD_OFFSET(ldr, FIELD_OFFSET(PEB_LDR_DATA, InLoadOrderModuleList));
		currentLink = pebLdrData.InLoadOrderModuleList.Flink;

		while (
			currentLink != startLink &&
			i <= PH_ENUM_PROCESS_MODULES_LIMIT
			)
		{
			PVOID addressOfEntry;

			addressOfEntry = CONTAINING_RECORD(currentLink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			status = PhReadVirtualMemory(
				ProcessHandle,
				addressOfEntry,
				&currentEntry,
				dataTableEntrySize,
				NULL
			);

			if (!NT_SUCCESS(status))
				return status;

			// Make sure the entry is valid.
			if (currentEntry.DllBase)
			{
				// Execute the callback.
				if (!Callback(
					ProcessHandle,
					&currentEntry,
					addressOfEntry,
					Context1,
					Context2
				))
					break;
			}

			currentLink = currentEntry.InLoadOrderLinks.Flink;
			i++;
		}

		return status;
	}
}
