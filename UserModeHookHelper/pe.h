#ifndef PE_H
#define PE_H
#include "Common.h"
#include <ntimage.h>

// PE helpers: safely query mapped PE images in kernel space.
//
// Preconditions:
// - ImageBase must be a valid, mapped image base address in kernel virtual
//   address space (the memory where the PE file is mapped as an image).
// - NativeName must be a NUL-terminated ASCII export name (e.g., "LdrLoadDll").
//
// Behavior:
// - Returns a pointer to the exported function implementation inside the
//   mapped image, or NULL if the export is not found or is a forwarded export.
// - Forwarded exports are NOT resolved; in that case the function returns NULL.

// Returns the address of the exported function implementation inside the
// mapped image, or NULL if the export is not found or is a forwarded export.
// PE_GetExport returns the address of the exported function inside the image
// matching 'NativeName'. Returns NULL if not found or if the export is a
// forwarded export. The caller is responsible for ensuring ImageBase points
// to a valid mapped image in memory.
PVOID PE_GetExport(IN PVOID ImageBase, IN PCHAR NativeName);

// PE_IsProcessX86
// - Returns TRUE if the provided PEPROCESS corresponds to a 32-bit (WoW64)
//   process. Returns FALSE if the process is 64-bit or on error.
// - Caller must pass a valid referenced or non-referenced PEPROCESS. This
//   function does not take or drop references; callers that pass an
//   unreferenced PEPROCESS must ensure it remains valid for the call.
BOOLEAN PE_IsProcessX86(IN PEPROCESS Process);
PULONGLONG PE_GetSSDT();
NTSTATUS PE_GetDriverBase(
	PCSTR DriverName,
	PVOID* DriverBaseAddress
); 
// Wrapper kept for compatibility; PE_GetExport auto-detects 32/64 images.
// PE_GetExport auto-detects 32/64 images; PE_GetExport32 removed.

#endif // PE_H
