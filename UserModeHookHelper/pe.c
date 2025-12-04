#include "PE.h"
#include "mini.h"
#include "Trace.h"
#include "DriverCtx.h"
#include <ntifs.h>
// Some WDK versions may not declare PsGetProcessWow64Process; forward declare it.
extern PVOID PsGetProcessWow64Process(IN PEPROCESS Process);
// Unified PE_GetExport implementation
PVOID PE_GetExport(IN PVOID ImageBase, IN PCHAR NativeName)
{
    if (!ImageBase || !NativeName) return NULL;

    // Quick sanity: check DOS header
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)ImageBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    if (pDos->e_lfanew == 0) return NULL;

    // Try to interpret as 32-bit image first
    __try {
        PIMAGE_NT_HEADERS32 pNt32 = (PIMAGE_NT_HEADERS32)((PCHAR)ImageBase + pDos->e_lfanew);
        if (pNt32->Signature == IMAGE_NT_SIGNATURE && pNt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            ULONG imageSize = pNt32->OptionalHeader.SizeOfImage;
            ULONG exportRVA = pNt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            ULONG exportSize = pNt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
            if (exportRVA == 0 || exportRVA >= imageSize || exportSize == 0) return NULL;

            PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((PCHAR)ImageBase + exportRVA);
            if (!pExport) return NULL;

            // Validate table RVAs
            if (pExport->AddressOfFunctions >= imageSize || pExport->AddressOfNames >= imageSize || pExport->AddressOfNameOrdinals >= imageSize)
                return NULL;

            PULONG AddressOfFunctions = (PULONG)((PCHAR)ImageBase + pExport->AddressOfFunctions);
            PULONG AddressOfNames = (PULONG)((PCHAR)ImageBase + pExport->AddressOfNames);
            PUSHORT AddressOfNameOrdinals = (PUSHORT)((PCHAR)ImageBase + pExport->AddressOfNameOrdinals);

            for (ULONG i = 0; i < pExport->NumberOfNames; ++i) {
                ULONG nameRVA = AddressOfNames[i];
                if (nameRVA == 0 || nameRVA >= imageSize) continue;
                PCHAR name = (PCHAR)ImageBase + nameRVA;
                if (!name) continue;
                if (strcmp(name, NativeName) != 0) continue;

                USHORT ord = AddressOfNameOrdinals[i];
                if ((ULONG)ord >= pExport->NumberOfFunctions) return NULL;
                ULONG funcRVA = AddressOfFunctions[ord];
                if (funcRVA == 0 || funcRVA >= imageSize) return NULL;

                // detect forwarded export (points into export dir)
                if (funcRVA >= exportRVA && funcRVA < exportRVA + exportSize) return NULL;

                PVOID funcPtr = (PCHAR)ImageBase + funcRVA;
                if (!funcPtr) return NULL;

                // pNativeSize support removed; callers only need the function pointer.

                return funcPtr;
            }

            return NULL;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // fall through to try the generic path
    }

    // Generic path (works for 64-bit images) using Rtl helpers
        // Manual generic path (64-bit image parsing without Rtl helpers)
        PIMAGE_NT_HEADERS64 pNt64 = (PIMAGE_NT_HEADERS64)((PCHAR)ImageBase + pDos->e_lfanew);
        if (pNt64->Signature != IMAGE_NT_SIGNATURE) return NULL;
        if (pNt64->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return NULL;

        ULONG imageSize64 = (ULONG)pNt64->OptionalHeader.SizeOfImage;
        ULONG exportRVA64 = pNt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        ULONG exportSize64 = pNt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        if (exportRVA64 == 0 || exportRVA64 >= imageSize64 || exportSize64 == 0) return NULL;

        if (exportRVA64 + sizeof(IMAGE_EXPORT_DIRECTORY) > imageSize64) return NULL;
        PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((PCHAR)ImageBase + exportRVA64);

        // Validate tables fit inside image
        if (pExport->AddressOfFunctions >= imageSize64 || pExport->AddressOfNames >= imageSize64 || pExport->AddressOfNameOrdinals >= imageSize64)
            return NULL;

        PULONG AddressOfFunctions = (PULONG)((PCHAR)ImageBase + pExport->AddressOfFunctions);
        PULONG AddressOfNames = (PULONG)((PCHAR)ImageBase + pExport->AddressOfNames);
        PUSHORT AddressOfNameOrdinals = (PUSHORT)((PCHAR)ImageBase + pExport->AddressOfNameOrdinals);

        for (ULONG i = 0; i < pExport->NumberOfNames; ++i) {
            ULONG nameRVA = AddressOfNames[i];
            if (nameRVA == 0 || nameRVA >= imageSize64) continue;

            // Safe string compare bounded by image size
            PCHAR namePtr = (PCHAR)ImageBase + nameRVA;
            ULONG maxLen = imageSize64 - nameRVA;
            BOOLEAN eq = TRUE;
            for (ULONG k = 0; k < maxLen; ++k) {
                CHAR c = namePtr[k];
                if (c == '\0') { break; }
                if (c != NativeName[k]) { eq = FALSE; break; }
            }
            if (!eq) continue;
            // ensure NativeName ended as well
            if (strlen(NativeName) >= maxLen) continue; // NativeName too long to be inside image

            USHORT ord = AddressOfNameOrdinals[i];
            if ((ULONG)ord >= pExport->NumberOfFunctions) return NULL;
            ULONG funcRVA = AddressOfFunctions[ord];
            if (funcRVA == 0 || funcRVA >= imageSize64) return NULL;

            // Detect forwarded export (points into export dir)
            if (funcRVA >= exportRVA64 && funcRVA < exportRVA64 + exportSize64) return NULL;

            PVOID funcPtr = (PCHAR)ImageBase + funcRVA;
            if (!funcPtr) return NULL;

            return funcPtr;
        }

    return NULL;
}

ULONG PE_MiArbitraryCodeBlockedOffsetAndBitpos(ACG_MitigationOffPos* acg) {
	// DbgBreakPoint();
	if (!acg) {
		Log(L"required parameter pos can not be NULL\n");
		return 0;
	} 

	PVOID ntkrnl_base = 0;
	PE_GetDriverBase("ntoskrnl.exe", &ntkrnl_base);
	if (!ntkrnl_base) {
		Log(L"failed to call PE_GetDriverBase\n");
		return 0;
	}
	PVOID fn_NtMapViewOfSection_addr = 0;
	fn_NtMapViewOfSection_addr = PE_GetExport(ntkrnl_base, "NtMapViewOfSection");
	if (!fn_NtMapViewOfSection_addr) {
		Log(L"failed to get export function NtMapViewOfSection address\n");
		return 0;
	}

	// begin search
	INT32 Limit = 4096;

	// Increase that address until you hit "0x8b 0xd8"
	// which is asm code mov ebx, eax
	// this pattern only appears after nt!MiMapViewOfSection being called
	for (int i = 0; i < Limit; i++) {		      
		if (*(PUINT8)((ULONG_PTR)fn_NtMapViewOfSection_addr + i) == 0x8b
			&& *(PUINT8)((ULONG_PTR)fn_NtMapViewOfSection_addr + i + 1) == 0xd8)
		{
			// next instruction rip + offset
			DWORD64 MiMapViewOfSection = (DWORD64)(ULONG_PTR)fn_NtMapViewOfSection_addr + i +
				(DWORD64)(ULONG_PTR)(INT64)(INT32)(*(DWORD*)(DWORD64)((ULONG_PTR)fn_NtMapViewOfSection_addr + i - 0x5 + 1));
			// now search from MiMapViewOfSection until get 0x8b 0xf8, which is  asm code mov edi, eax
			// then search back to check if there is two mov qword ptr instruction whit a 0x20 back search limit
			for ( i = 0; i < Limit; i++) {
				if (*(PUINT8)((ULONG_PTR)MiMapViewOfSection + i) == 0x8b
					&& *(PUINT8)((ULONG_PTR)MiMapViewOfSection + i + 1) == 0xf8) {
				// back search to match certain pattern
					if (*(PUINT8)((ULONG_PTR)MiMapViewOfSection + i - 5 - 5 - 5) == 0x48
						&& * (PUINT8)((ULONG_PTR)MiMapViewOfSection + i - 5 - 5 - 5 + 1) == 0x89) {
						if (*(PUINT8)((ULONG_PTR)MiMapViewOfSection + i - 5 - 5 - 5+5) == 0x48
							&& * (PUINT8)((ULONG_PTR)MiMapViewOfSection + i - 5 - 5 - 5 +5+ 1) == 0x89) {
							DWORD64 call_ins_addr = (ULONG_PTR)MiMapViewOfSection + i - 5;
							DWORD64 nex_ins_addr = call_ins_addr + 5;
							DWORD64 MiMapViewOfImageSection = nex_ins_addr +
								(DWORD64)(ULONG_PTR)(INT64)(INT32)(*(DWORD*)(DWORD64)((ULONG_PTR)call_ins_addr + 1));
							for ( i = 0; i < Limit; i++) {
								if (*(PUINT8)((ULONG_PTR)MiMapViewOfImageSection + i) == 0x85
									&& *(PUINT8)((ULONG_PTR)MiMapViewOfImageSection + i + 1) == 0xc0) {
									if (*(PUINT8)((ULONG_PTR)MiMapViewOfImageSection + i - 5) == 0xe8
										&& *(PUINT8)((ULONG_PTR)MiMapViewOfImageSection + i - 5-5) == 0x49) {
										call_ins_addr = MiMapViewOfImageSection+i - 5;
										nex_ins_addr = MiMapViewOfImageSection+i;
										DWORD64 MiArbitraryCodeBlocked = nex_ins_addr +
											(DWORD64)(ULONG_PTR)(INT64)(INT32)(*(DWORD*)(DWORD64)((ULONG_PTR)call_ins_addr + 1));
										for ( i = 0; i < Limit; i++) {
											if (*(PUINT8)((ULONG_PTR)MiArbitraryCodeBlocked + i) == 0xf
												&& *(PUINT8)((ULONG_PTR)MiArbitraryCodeBlocked + i + 1) == 0xba
												&& *(PUINT8)((ULONG_PTR)MiArbitraryCodeBlocked + i + 2) == 0xe2) {
												acg->acg_pos = *(PUINT8)((ULONG_PTR)MiArbitraryCodeBlocked + i + 3);
												acg->mitigation= *(DWORD*)((ULONG_PTR)MiArbitraryCodeBlocked + i - 4);
												// continue search to get AuditDisableDynamicCode bit position
												DWORD64 ACG_POS = (DWORD64)(ULONG_PTR)MiArbitraryCodeBlocked + i+4;
												for (i = 0; i < Limit; i++) {
													if (*(PUINT8)((ULONG_PTR)ACG_POS + i) == 0xf
														&& *(PUINT8)((ULONG_PTR)ACG_POS + i + 1) == 0xba
														&& *(PUINT8)((ULONG_PTR)ACG_POS + i + 2) == 0xe2) {
														acg->acg_audit_pos = *(PUINT8)((ULONG_PTR)ACG_POS + i + 3);
														return acg->mitigation;
													}
												}
											}
										}
									}
								}
							}
						}
					
					}
				
				}
			}
		}
	}
	return 0;
}
PULONGLONG PE_GetSSDT()
{
    // Decide path based on OS version persisted in driver context.
    // Windows 11 (Major=10, Build>=22000) uses the KiSystemServiceUser walk;
    // older builds use legacy pattern directly from KiSystemCall64.
    DRIVERCTX_OSVER ver = DriverCtx_GetOsVersion();
    BOOLEAN isWin11 = (ver.Major == 10 && ver.Build >= 22000);
    if (isWin11) {
		ULONGLONG  KiSystemCall64 = __readmsr(0xC0000082);	// Get the address of nt!KeSystemCall64
		ULONGLONG  KiSystemServiceRepeat = 0;
		DWORD64 KiSystemServiceUser = 0;
		INT32 Limit = 4096;

		for (int i = 0; i < Limit; i++) {		        // Increase that address until you hit "0x4c/0x8d/0x15"
			if (*(PUINT8)((ULONG_PTR)KiSystemCall64 + i) == 0x65
				&& *(PUINT8)((ULONG_PTR)KiSystemCall64 + i + 1) == 0xC6
				&& *(PUINT8)((ULONG_PTR)KiSystemCall64 + i + 2) == 0x4
				&& *(PUINT8)((ULONG_PTR)KiSystemCall64 + i + 3) == 0x25)
			{
				KiSystemCall64 = KiSystemCall64 + i;
				KiSystemServiceUser = KiSystemCall64 + 4 + 4 + 1 + 1 + 4 +
					// sign extend
					(DWORD64)(ULONG_PTR)(INT64)((INT32)(*(DWORD*)((ULONG_PTR)KiSystemCall64 + 4 + 4 + 1 + 1))); 
				for ( i = 0; i < Limit; i++) {		        // Increase that address until you hit "0x4c/0x8d/0x15"
					if (*(PUINT8)((ULONG_PTR)KiSystemServiceUser + i) == 0x4C
						&& *(PUINT8)((ULONG_PTR)KiSystemServiceUser + i + 1) == 0x8D
						&& *(PUINT8)((ULONG_PTR)KiSystemServiceUser + i + 2) == 0x15)
					{
						KiSystemServiceRepeat = KiSystemServiceUser + i;
						// Convert relative address to absolute address
						return (PULONGLONG)(*(PINT32)((ULONG_PTR)KiSystemServiceRepeat + 3) + (ULONG_PTR)KiSystemServiceRepeat + 7);

					}
				}
			}
		}

	}
	else {
		ULONGLONG  KiSystemCall64 = __readmsr(0xC0000082);	// Get the address of nt!KeSystemCall64
		ULONGLONG  KiSystemServiceRepeat = 0;
		INT32 Limit = 4096;

		for (int i = 0; i < Limit; i++) {		        // Increase that address until you hit "0x4c/0x8d/0x15"
			if (*(PUINT8)((ULONG_PTR)KiSystemCall64 + i) == 0x4C
				&& *(PUINT8)((ULONG_PTR)KiSystemCall64 + i + 1) == 0x8D
				&& *(PUINT8)((ULONG_PTR)KiSystemCall64 + i + 2) == 0x15)
			{
				KiSystemServiceRepeat = KiSystemCall64 + i;
				DbgPrint("KiSystemCall64           %p \r\n", KiSystemCall64);
				DbgPrint("KiSystemServiceRepeat    %p \r\n", KiSystemServiceRepeat);

				// Convert relative address to absolute address
				return (PULONGLONG)(*(PINT32)((ULONG_PTR)KiSystemServiceRepeat + 3) + (ULONG_PTR)KiSystemServiceRepeat + 7);
			}
		}
	}

	return 0;
}
// Return TRUE if the provided PEPROCESS corresponds to a 32-bit (WoW64)
// process running under WoW64. Returns FALSE on error or if the process is 64-bit.
// Note: this function does not take or drop a reference on Process.
BOOLEAN PE_IsProcessX86(IN PEPROCESS Process)
{
	if (!Process) {
		Log(L"you can not pass Process parameter as NULL\n");
		MiniUnload(0);
		return FALSE;
	}

    // PsGetProcessWow64Process returns the WoW64 context pointer if present.
    PVOID wow64 = PsGetProcessWow64Process(Process);
    return (wow64 != NULL) ? TRUE : FALSE;
}



// Structure to hold module information entry
typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG NumberOfModules;
	SYSTEM_MODULE_INFORMATION_ENTRY Modules[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

FORCEINLINE const char* stristr(const char* haystack, const char* needle) {
	if (!haystack || !needle) return NULL;

	size_t needleLen = 0;
	while (needle[needleLen]) ++needleLen;
	if (needleLen == 0) return haystack;

	for (; *haystack; ++haystack) {
		size_t i = 0;
		while (i < needleLen && tolower(haystack[i]) == tolower(needle[i])) {
			++i;
		}
		if (i == needleLen) return haystack;
	}

	return NULL;
}
#define SystemModuleInformation 11
NTSTATUS ZwQuerySystemInformation(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);
NTSTATUS PE_GetDriverBase(
	PCSTR DriverName,
	PVOID* DriverBaseAddress
)
{
	NTSTATUS status;
	ULONG bufferSize = 0;
	PVOID buffer = NULL;

	// Query the size of the buffer needed
	status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &bufferSize);
	if (status != STATUS_INFO_LENGTH_MISMATCH) {
		return status;
	}

	// Allocate memory for the system module information
	buffer = ExAllocatePoolWithTag(NonPagedPool, bufferSize, 'modL');
	if (buffer == NULL) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// Query the system module information
	status = ZwQuerySystemInformation(SystemModuleInformation, buffer, bufferSize, &bufferSize);
	if (!NT_SUCCESS(status)) {
		ExFreePool(buffer);
		return status;
	}

	PSYSTEM_MODULE_INFORMATION pSystemModuleInfo = (PSYSTEM_MODULE_INFORMATION)buffer;
	for (ULONG i = 0; i < pSystemModuleInfo->NumberOfModules; i++) {
		PSYSTEM_MODULE_INFORMATION_ENTRY pModuleEntry = &pSystemModuleInfo->Modules[i];

		if (stristr((PCSTR)pModuleEntry->FullPathName, DriverName)) {
			*DriverBaseAddress = pModuleEntry->ImageBase;
			break;
		}
	}

	ExFreePool(buffer);
	return status;
}
