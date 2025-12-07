#ifndef KERNELOFFSETS_H
#define KERNELOFFSETS_H

#include "Common.h"
#include "DriverCtx.h"

typedef struct _EPROCESS_OFFSETS {
	ULONG ProtectionOffset;
	ULONG SectionSignatureLevelOffset;	
	struct _ACG_MitigationOffPos {
		ULONG mitigation_offset;
		UCHAR acg_pos;
		UCHAR acg_audit_pos;
	}ACG_MitigationOffPos;
} EPROCESS_OFFSETS, *PEPROCESS_OFFSETS;
typedef struct _EPROCESS_ORI_VALUE {
	UCHAR  ProtectionValue;
	UCHAR SectionSignatureLevelValue;
} EPROCESS_ORI_VALUE, *PEPROCESS_ORI_VALUE;

// Returns TRUE and fills offsets when found based on OS version.
// Uses YAML files under "\??\C:\Users\x\Pictures\1\.vs\1" that encode
// kernel structure offsets for Win10/Win11.
BOOLEAN KO_GetEprocessOffsets(PEPROCESS_OFFSETS Offsets);

#endif
