// ProcessHackerLib.cpp : 定义静态库的函数。
//

#include "pch.h"
#include "framework.h"
#include "ProcessHackerLib.h"
#include <stdio.h> 
#include <phnt/ntrtl.h>
#include <phnt/ntmmapi.h>
#include <phnt/ntpebteb.h>
#include <malloc.h>
namespace PHLIB {
	static ULONG WindowsVersion = 0;
	// Forward-declare the shared IHookServices (defined in Shared/HookServices.h)

	static IHookServices* g_hookServices = nullptr;

	void SetHookServicesInternal(IHookServices* services) {
		g_hookServices = services;
	}
	inline bool wstrcasestr_check(const wchar_t* haystack, const wchar_t* needle) {
		if (!haystack || !needle) return false;
		if (*needle == L'\0') return true; // empty needle -> match

		for (; *haystack != L'\0'; ++haystack) {
			const wchar_t *h = haystack;
			const wchar_t *n = needle;
			while (*n != L'\0' && towlower((wint_t)*h) == towlower((wint_t)*n)) {
				++h; ++n;
			}
			if (*n == L'\0') return true; /* matched whole needle */
			if (*h == L'\0') return false; /* haystack ended */
		}
		return false;
	}
#define PHLog(...) \
    do { \
        if (g_hookServices) { \
            g_hookServices->LogPhlib(__VA_ARGS__); \
        } \
    } while (0)
	NTSTATUS
		PhGetProcessIsWow64Internal(
			_In_ DWORD pid,
			_Out_ PBOOLEAN IsWow64
		)
	{
		NTSTATUS status;
		ULONG_PTR wow64;
		if (!g_hookServices) {
			PHLog(L"g_hookServices NULL\n");
			return STATUS_UNSUCCESSFUL;
		}
		HANDLE ProcessHandle = NULL;
		ProcessHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
		if (!ProcessHandle) {
			if (!g_hookServices->GetHighAccessProcHandle(pid, &ProcessHandle)) {
				PHLog(L"failed to call GetHighAccessProcHandle\n");
				return STATUS_UNSUCCESSFUL;
			}
		}
		status = NtQueryInformationProcess(
			ProcessHandle,
			ProcessWow64Information,
			&wow64,
			sizeof(ULONG_PTR),
			NULL
		);

		if (NT_SUCCESS(status))
		{
			*IsWow64 = !!wow64;
		}
		CloseHandle(ProcessHandle);
		return status;
	}
	NTSTATUS IsProcessWow64Internal(
		_In_ HANDLE hProc,
		_Out_ PBOOLEAN IsWow64){
		ULONG_PTR wow64;
		NTSTATUS status = NtQueryInformationProcess(
			hProc,
			ProcessWow64Information,
			&wow64,
			sizeof(ULONG_PTR),
			NULL
		);

		if (NT_SUCCESS(status))
		{
			*IsWow64 = !!wow64;
		}
		return status;
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
		if (!NT_SUCCESS(status)) {
			PHLog(L"failed to call NtReadVirtualMemory, Status=0x%x\n", status);
		}

		return status;
	}
	
	VOID PhInitializeWindowsVersion(
		VOID
	)
	{
		RTL_OSVERSIONINFOEXW versionInfo;
		ULONG majorVersion;
		ULONG minorVersion;

		versionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW);

		if (!NT_SUCCESS(RtlGetVersion(&versionInfo)))
		{
			//PhShowWarning(
			//    NULL,
			//    L"Unable to determine the Windows version. "
			//    L"Some functionality may not work as expected."
			//    );
			WindowsVersion = WINDOWS_NEW;
			return;
		}


		majorVersion = versionInfo.dwMajorVersion;
		minorVersion = versionInfo.dwMinorVersion;

		if (majorVersion == 5 && minorVersion < 1 || majorVersion < 5)
		{
			WindowsVersion = WINDOWS_ANCIENT;
		}
		/* Windows XP */
		else if (majorVersion == 5 && minorVersion == 1)
		{
			WindowsVersion = WINDOWS_XP;
		}
		/* Windows Server 2003 */
		else if (majorVersion == 5 && minorVersion == 2)
		{
			WindowsVersion = WINDOWS_SERVER_2003;
		}
		/* Windows Vista, Windows Server 2008 */
		else if (majorVersion == 6 && minorVersion == 0)
		{
			WindowsVersion = WINDOWS_VISTA;
		}
		/* Windows 7, Windows Server 2008 R2 */
		else if (majorVersion == 6 && minorVersion == 1)
		{
			WindowsVersion = WINDOWS_7;
		}
		/* Windows 8 */
		else if (majorVersion == 6 && minorVersion == 2)
		{
			WindowsVersion = WINDOWS_8;
		}
		/* Windows 8.1 */
		else if (majorVersion == 6 && minorVersion == 3)
		{
			WindowsVersion = WINDOWS_8_1;
		}
		/* Windows 10 */
		else if (majorVersion == 10 && minorVersion == 0)
		{
			WindowsVersion = WINDOWS_10;
		}
		else if (majorVersion == 10 && minorVersion > 0 || majorVersion > 10)
		{
			WindowsVersion = WINDOWS_NEW;
		}
	}


	BOOLEAN NTAPI PhpEnumProcessModules32Callback(
		_In_ HANDLE ProcessHandle,
		_In_ PLDR_DATA_TABLE_ENTRY32 EntryRaw, wchar_t* module_path
	)
	{
		PUNICODE_STRING mappedFileName;
		NTSTATUS st = PhGetProcessMappedFileName(ProcessHandle, (PVOID)(ULONG_PTR)EntryRaw->DllBase, &mappedFileName);
		if (st != 0) {
			PHLog(L"failed to call PhpEnumProcessModules32Callback, Status=0x%x\n", st);
			return false;
		}
		memcpy(module_path, mappedFileName->Buffer, mappedFileName->Length);
		return true;
	}
	BOOLEAN NTAPI PhpEnumProcessModules64Callback(
		_In_ HANDLE ProcessHandle,
		_In_ PLDR_DATA_TABLE_ENTRY EntryRaw, wchar_t* module_path
	)
	{
		PUNICODE_STRING mappedFileName;
		NTSTATUS st = PhGetProcessMappedFileName(ProcessHandle, (PVOID)(ULONG_PTR)EntryRaw->DllBase, &mappedFileName);
		if (st != 0) {
			PHLog(L"failed to call PhpEnumProcessModules64Callback, Status=0x%x\n", st);
			return false;
		}
		memcpy(module_path, mappedFileName->Buffer, mappedFileName->Length);
		return true;
	}
	
	FORCEINLINE
		NTSTATUS
		PhGetProcessPeb32(
			_In_ HANDLE ProcessHandle,
			_Out_ PVOID *Peb32
		)
	{
		NTSTATUS status;
		ULONG_PTR wow64;

		status = NtQueryInformationProcess(
			ProcessHandle,
			ProcessWow64Information,
			&wow64,
			sizeof(ULONG_PTR),
			NULL
		);

		if (NT_SUCCESS(status))
		{
			*Peb32 = (PVOID)wow64;
		}

		return status;
	}
	NTSTATUS PhBuildModuleListInteranl(
		_In_ DWORD pid, _Out_ PPH_MODULE_LIST_NODE* OutHead
	) {
		if (!g_hookServices) {
			PHLog(L"g_hookServices NULL\n");
			return STATUS_UNSUCCESSFUL;
		}
		bool is64 = false;
		if (!g_hookServices->IsProcess64(pid, is64)) {
			PHLog(L"failed to call IsProcess64\n");
			return STATUS_UNSUCCESSFUL;
		}
		HANDLE hProc = NULL;
		hProc = OpenProcess(
			PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
			FALSE,
			pid
		);
		if (!hProc)
			if (!g_hookServices->GetHighAccessProcHandle(pid, &hProc)) {
				PHLog(L"failed to call GetHighAccessProcHandle\n");
				return STATUS_UNSUCCESSFUL;
			}
		NTSTATUS st = is64 ? PhBuildModuleListX64(hProc, OutHead)
			: PhBuildModuleListWin32(hProc, OutHead);
		CloseHandle(hProc);
		return st;
	}
	NTSTATUS PhpEnumProcessModules(
		DWORD pid, WCHAR* target_module, unsigned long long* ModuleBase
	) {
		if (!g_hookServices) {
			PHLog(L"g_hookServices NULL\n");
			return STATUS_UNSUCCESSFUL;
		}
		bool is64 = false;
		if (!g_hookServices->IsProcess64(pid, is64)) {
			PHLog(L"failed to call IsProcess64\n");
			return STATUS_UNSUCCESSFUL;
		}
		HANDLE hProc = NULL;
		hProc = OpenProcess(
			PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
			FALSE,
			pid
		);
		if (!hProc)
			if (!g_hookServices->GetHighAccessProcHandle(pid, &hProc)) {
				PHLog(L"failed to call GetHighAccessProcHandle\n");
				return STATUS_UNSUCCESSFUL;
			}
		NTSTATUS st = is64 ? PhpEnumProcessModulesX64(hProc, target_module, ModuleBase)
			: PhpEnumProcessModulesWin32(hProc, target_module, ModuleBase);
		CloseHandle(hProc);
		return st;
	}
	NTSTATUS PhpEnumProcessModulesWin32(
		_In_ HANDLE ProcessHandle, wchar_t *target_module, DWORD64* ModuleBase
	) {
		NTSTATUS status;
		PPEB32 peb;
		ULONG ldr; // PEB_LDR_DATA32 *32
		PEB_LDR_DATA32 pebLdrData;
		ULONG startLink; // LIST_ENTRY32 *32
		ULONG currentLink; // LIST_ENTRY32 *32
		ULONG dataTableEntrySize;
		LDR_DATA_TABLE_ENTRY32 currentEntry;
		ULONG i;

		PhInitializeWindowsVersion();

		// Get the 32-bit PEB address.
		status = PhGetProcessPeb32(ProcessHandle, (PVOID*)&peb);

		if (!NT_SUCCESS(status))
			return status;

		if (!peb)
			return STATUS_NOT_SUPPORTED; // not a WOW64 process

			// Read the address of the loader data.
		status = PhReadVirtualMemory(
			ProcessHandle,
			PTR_ADD_OFFSET(peb, FIELD_OFFSET(PEB32, Ldr)),
			&ldr,
			sizeof(ULONG),
			NULL
		);

		if (!NT_SUCCESS(status))
			return status;

		// Read the loader data.
		status = PhReadVirtualMemory(
			ProcessHandle,
			UlongToPtr(ldr),
			&pebLdrData,
			sizeof(PEB_LDR_DATA32),
			NULL
		);

		if (!NT_SUCCESS(status))
			return status;

		if (!pebLdrData.Initialized)
			return STATUS_UNSUCCESSFUL;

		if (WindowsVersion >= WINDOWS_8)
			dataTableEntrySize = LDR_DATA_TABLE_ENTRY_SIZE_WIN8_32;
		else if (WindowsVersion >= WINDOWS_7)
			dataTableEntrySize = LDR_DATA_TABLE_ENTRY_SIZE_WIN7_32;
		else
			dataTableEntrySize = LDR_DATA_TABLE_ENTRY_SIZE_WINXP_32;

		// Traverse the linked list (in load order).

		i = 0;
		startLink = (ULONG)(ldr + FIELD_OFFSET(PEB_LDR_DATA32, InLoadOrderModuleList));
		currentLink = pebLdrData.InLoadOrderModuleList.Flink;

		while (
			currentLink != startLink &&
			i <= PH_ENUM_PROCESS_MODULES_LIMIT
			)
		{
			ULONG addressOfEntry;

			addressOfEntry = PtrToUlong(CONTAINING_RECORD(UlongToPtr(currentLink), LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks));
			status = PhReadVirtualMemory(
				ProcessHandle,
				UlongToPtr(addressOfEntry),
				&currentEntry,
				dataTableEntrySize,
				NULL
			);

			if (!NT_SUCCESS(status))
				return status;

			// Make sure the entry is valid.
			if (currentEntry.DllBase)
			{
				WCHAR mode_path[MAX_PATH] = { 0 };
				// Execute the callback.
				if (!PhpEnumProcessModules32Callback(
					ProcessHandle,
					&currentEntry,
					mode_path
				)) {
					PHLog(L"failed to call PhpEnumProcessModules32Callback\n");
					break;
				}
				if (wstrcasestr_check(mode_path, target_module)) {
					*ModuleBase = currentEntry.DllBase;
					PHLog(L"target module Path=%s Base=0x%p\n", mode_path, *ModuleBase);
					break;
				}
			}

			currentLink = currentEntry.InLoadOrderLinks.Flink;
			i++;
		}

		return status;
	}

	// I need to expose this function, so HookCodeLib can reuse it
	NTSTATUS PhpEnumProcessModulesX64(
		_In_ HANDLE ProcessHandle, wchar_t *target_module, DWORD64* ModuleBase
	) {
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
		startLink = (PLIST_ENTRY)PTR_ADD_OFFSET(ldr, FIELD_OFFSET(PEB_LDR_DATA, InLoadOrderModuleList));
		currentLink = pebLdrData.InLoadOrderModuleList.Flink;

		PPH_MODULE_LIST_NODE head = NULL;
		PPH_MODULE_LIST_NODE tail = NULL;

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
				wchar_t mode_path[MAX_PATH] = { 0 };
				// Execute the callback.
				if (!PhpEnumProcessModules64Callback(
					ProcessHandle,
					&currentEntry,
					mode_path
				)) {
					PHLog(L"failed to call PhpEnumProcessModules64Callback\n");
					break;
				}
				if (wstrcasestr_check(mode_path, target_module)) {
					*ModuleBase = (DWORD64)(ULONG_PTR)currentEntry.DllBase;
					PHLog(L"target module Path=%s Base=0x%p\n", mode_path, *ModuleBase);
					break;
				}
			}
			currentLink = currentEntry.InLoadOrderLinks.Flink;
			i++;
		}
		return status;
	}

	NTSTATUS PhBuildModuleListWin32(
		_In_ HANDLE ProcessHandle,
		_Out_ PPH_MODULE_LIST_NODE* OutHead
	) {
		if (OutHead) *OutHead = NULL;
		NTSTATUS status;
		PPEB32 peb = NULL;
		ULONG ldr = 0;
		PEB_LDR_DATA32 pebLdrData;
		ULONG startLink = 0;
		ULONG currentLink = 0;
		ULONG dataTableEntrySize = 0;
		LDR_DATA_TABLE_ENTRY32 currentEntry;
		ULONG i = 0;

		PhInitializeWindowsVersion();
		status = PhGetProcessPeb32(ProcessHandle, (PVOID*)&peb);
		if (!NT_SUCCESS(status)) return status;
		if (!peb) return STATUS_NOT_SUPPORTED;

		status = PhReadVirtualMemory(ProcessHandle, PTR_ADD_OFFSET(peb, FIELD_OFFSET(PEB32, Ldr)), &ldr, sizeof(ULONG), NULL);
		if (!NT_SUCCESS(status)) return status;
		status = PhReadVirtualMemory(ProcessHandle, UlongToPtr(ldr), &pebLdrData, sizeof(PEB_LDR_DATA32), NULL);
		if (!NT_SUCCESS(status)) return status;
		if (!pebLdrData.Initialized) return STATUS_UNSUCCESSFUL;

		if (WindowsVersion >= WINDOWS_8)
			dataTableEntrySize = LDR_DATA_TABLE_ENTRY_SIZE_WIN8_32;
		else if (WindowsVersion >= WINDOWS_7)
			dataTableEntrySize = LDR_DATA_TABLE_ENTRY_SIZE_WIN7_32;
		else
			dataTableEntrySize = LDR_DATA_TABLE_ENTRY_SIZE_WINXP_32;

		startLink = (ULONG)(ldr + FIELD_OFFSET(PEB_LDR_DATA32, InLoadOrderModuleList));
		currentLink = pebLdrData.InLoadOrderModuleList.Flink;

		PPH_MODULE_LIST_NODE head = NULL;
		PPH_MODULE_LIST_NODE tail = NULL;

		while (currentLink != startLink && i <= PH_ENUM_PROCESS_MODULES_LIMIT) {
			ULONG addressOfEntry = PtrToUlong(CONTAINING_RECORD(UlongToPtr(currentLink), LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks));
			status = PhReadVirtualMemory(ProcessHandle, UlongToPtr(addressOfEntry), &currentEntry, dataTableEntrySize, NULL);
			if (!NT_SUCCESS(status)) break;
			if (currentEntry.DllBase) {
				PUNICODE_STRING mappedFileName = NULL;
				NTSTATUS st = PhGetProcessMappedFileName(ProcessHandle, (PVOID)(ULONG_PTR)currentEntry.DllBase, &mappedFileName);
				if (NT_SUCCESS(st) && mappedFileName && mappedFileName->Buffer && mappedFileName->Length > 0) {
					SIZE_T wcharLen = mappedFileName->Length / sizeof(WCHAR);
					SIZE_T bytes = (wcharLen + 1) * sizeof(WCHAR);
					PPH_MODULE_LIST_NODE node = (PPH_MODULE_LIST_NODE)malloc(sizeof(PH_MODULE_LIST_NODE));
					if (node) {
						RtlZeroMemory(node, sizeof(PH_MODULE_LIST_NODE));
						node->Base = (void*)(ULONG_PTR)currentEntry.DllBase;
						node->Size = currentEntry.SizeOfImage; // populate SizeOfImage if available
						node->Path = (PWSTR)malloc(bytes);
						if (node->Path) {
							RtlCopyMemory(node->Path, mappedFileName->Buffer, mappedFileName->Length);
							node->Path[wcharLen] = L'\0';
							// append to list
							node->Next = NULL;
							if (!head) head = node; else tail->Next = node;
							tail = node;
						}
						else {
							free(node);
						}
					}
				}
				if (mappedFileName) free(mappedFileName);
			}
			currentLink = currentEntry.InLoadOrderLinks.Flink;
			i++;
		}

		if (OutHead) *OutHead = head;
		return STATUS_SUCCESS;
	}

	
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

	NTSTATUS PhBuildModuleListX64(
		_In_ HANDLE ProcessHandle,
		_Out_ PPH_MODULE_LIST_NODE* OutHead
	) {
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
		startLink = (PLIST_ENTRY)PTR_ADD_OFFSET(ldr, FIELD_OFFSET(PEB_LDR_DATA, InLoadOrderModuleList));
		currentLink = pebLdrData.InLoadOrderModuleList.Flink;

		PPH_MODULE_LIST_NODE head = NULL;
		PPH_MODULE_LIST_NODE tail = NULL;

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
				PUNICODE_STRING mappedFileName = NULL;
				NTSTATUS st = PhGetProcessMappedFileName(ProcessHandle, (PVOID)(ULONG_PTR)currentEntry.DllBase, &mappedFileName);
				if (NT_SUCCESS(st) && mappedFileName && mappedFileName->Buffer && mappedFileName->Length > 0) {
					SIZE_T wcharLen = mappedFileName->Length / sizeof(WCHAR);
					SIZE_T bytes = (wcharLen + 1) * sizeof(WCHAR);
					PPH_MODULE_LIST_NODE node = (PPH_MODULE_LIST_NODE)malloc(sizeof(PH_MODULE_LIST_NODE));
					if (node) {
						RtlZeroMemory(node, sizeof(PH_MODULE_LIST_NODE));
						node->Base = (void*)(ULONG_PTR)currentEntry.DllBase;
						node->Size = currentEntry.SizeOfImage; // populate SizeOfImage if available
						node->Path = (PWSTR)malloc(bytes);
						if (node->Path) {
							RtlCopyMemory(node->Path, mappedFileName->Buffer, mappedFileName->Length);
							node->Path[wcharLen] = L'\0';
							// append to list
							node->Next = NULL;
							if (!head) head = node; else tail->Next = node;
							tail = node;
						}
						else {
							free(node);
						}
					}
				}
				if (mappedFileName) free(mappedFileName);
			}
			currentLink = currentEntry.InLoadOrderLinks.Flink;
			i++;
		}
		if (OutHead) *OutHead = head;
		return STATUS_SUCCESS;
	}


	NTSTATUS PhGetProcessMappedFileName(
		_In_ HANDLE ProcessHandle,
		_In_ PVOID BaseAddress,
		_Out_ PUNICODE_STRING* FileName
	)
	{
		NTSTATUS status;
		PVOID buffer;
		SIZE_T bufferSize;
		SIZE_T returnLength;

		bufferSize = 0x100;
		buffer = malloc(bufferSize);

		status = NtQueryVirtualMemory(
			ProcessHandle,
			BaseAddress,
			MemoryMappedFilenameInformation,
			buffer,
			bufferSize,
			&returnLength
		);

		if (status == STATUS_BUFFER_OVERFLOW)
		{
			free(buffer);
			bufferSize = returnLength;
			buffer = malloc(bufferSize);

			status = NtQueryVirtualMemory(
				ProcessHandle,
				BaseAddress,
				MemoryMappedFilenameInformation,
				buffer,
				bufferSize,
				&returnLength
			);
		}

		if (!NT_SUCCESS(status))
		{
			free(buffer);
			return status;
		}

		*FileName = (PUNICODE_STRING)buffer;

		return status;
	}
}
