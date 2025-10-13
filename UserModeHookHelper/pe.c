#include "pe.h"
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


// Return TRUE if the provided PEPROCESS corresponds to a 32-bit (WoW64)
// process running under WoW64. Returns FALSE on error or if the process is 64-bit.
// Note: this function does not take or drop a reference on Process.
BOOLEAN PE_IsProcessX86(IN PEPROCESS Process)
{
    if (!Process) return FALSE;

    // PsGetProcessWow64Process returns the WoW64 context pointer if present.
    PVOID wow64 = PsGetProcessWow64Process(Process);
    return (wow64 != NULL) ? TRUE : FALSE;
}
