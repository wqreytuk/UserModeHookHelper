#include "KernelOffsets.h"
// Exact per-build offsets table (generated); no ranges.
typedef struct _BUILD_OFFSETS {
	ULONG Build;
	ULONG Prot;
	ULONG SecSig;
	// add an inner structure for MitigationFlag and ACG
	struct __ACG_MitigationOffPos {
		ULONG mitigation_offset;
		UCHAR acg_pos;
		UCHAR acg_audit_pos;
	}_ACG_MitigationOffPos;
} BUILD_OFFSETS;

// This file can be auto-generated from version offset sources.
static const BUILD_OFFSETS g_BuildOffsets[] = {
    {10240, 0x6AA, 0x6A9,{0,0,0}},
    {10586, 0x6B1, 0x6B0,{0,0,0}},
    {14393, 0x6C2, 0x6C1,{0,0,0}},
    {15063, 0x6CA, 0x6C9,{0,0,0}},
    {16299, 0x6Ca, 0x6C9,{0x828,0x8,0xb}},
    {17134, 0x6Ca, 0x6C9,{0,0,0}},
    {17763, 0x6Ca, 0x6C9,{0,0,0}},
    {18362, 0x6FA, 0x6F9,{0,0,0}},
    {19041, 0x87A, 0x879,{0,0,0}},
    {19042, 0x87A, 0x879,{0,0,0}},
    {19043, 0x87A, 0x879,{0,0,0}},
    {19044, 0x87A, 0x879,{0,0,0}},
    {19045, 0x87A, 0x879,{0,0,0}},
    {20348, 0x87A, 0x879,{0,0,0}},
    {22000, 0x87A, 0x879,{0,0,0}},
    {22621, 0x87A, 0x879,{0,0,0}},
    {22631, 0x87A, 0x879,{0,0,0}},
    {26100, 0x5FA, 0x5F9,{0,0,0}},
    {26200, 0x5FA, 0x5F9,{0,0,0}},
};

static int FindOffsetsExact(ULONG build, const BUILD_OFFSETS* table, int count)
{
    for (int i = 0; i < count; ++i) {
		if (table[i].Build == build) { return i; }
    }
    return -1;
}

BOOLEAN KO_GetEprocessOffsets(PEPROCESS_OFFSETS Offsets)
{
    if (!Offsets) return FALSE;
    DRIVERCTX_OSVER ver = DriverCtx_GetOsVersion();
  
	int ok = FindOffsetsExact(ver.Build, g_BuildOffsets, RTL_NUMBER_OF(g_BuildOffsets));
    if (ok<0) return FALSE;
    Offsets->ProtectionOffset = g_BuildOffsets[ok].Prot;
    Offsets->SectionSignatureLevelOffset = g_BuildOffsets[ok].SecSig;
	Offsets->ACG_MitigationOffPos.mitigation_offset = g_BuildOffsets[ok]._ACG_MitigationOffPos.mitigation_offset;
	Offsets->ACG_MitigationOffPos.acg_pos = g_BuildOffsets[ok]._ACG_MitigationOffPos.acg_pos;
	Offsets->ACG_MitigationOffPos.acg_audit_pos = g_BuildOffsets[ok]._ACG_MitigationOffPos.acg_audit_pos;
    return TRUE;
}
