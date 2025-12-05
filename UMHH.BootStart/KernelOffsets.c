#include "KernelOffsets.h"
// Exact per-build offsets table (generated); no ranges.
typedef struct _BUILD_OFFSETS { ULONG Build; ULONG Prot; ULONG SecSig; } BUILD_OFFSETS;

// This file can be auto-generated from version offset sources.
static const BUILD_OFFSETS g_BuildOffsets[] = {
    {10240, 0x6AA, 0x6A9},
    {10586, 0x6B1, 0x6B0},
    {14393, 0x6C2, 0x6C1},
    {15063, 0x6CA, 0x6C9},
    {16299, 0x6C9, 0x6C8},
    {17134, 0x6C9, 0x6C8},
    {17763, 0x6C9, 0x6C8},
    {18362, 0x6FA, 0x6F9},
    {19041, 0x87A, 0x879},
    {19042, 0x87A, 0x879},
    {19043, 0x87A, 0x879},
    {19044, 0x87A, 0x879},
    {19045, 0x87A, 0x879},
    {20348, 0x87A, 0x879},
    {22000, 0x87A, 0x879},
    {22621, 0x87A, 0x879},
    {22631, 0x87A, 0x879},
    {26100, 0x5FA, 0x5F9},
    {26200, 0x5FA, 0x5F9},
};

static BOOLEAN FindOffsetsExact(ULONG build, const BUILD_OFFSETS* table, SIZE_T count, ULONG* prot, ULONG* secsig)
{
    for (SIZE_T i = 0; i < count; ++i) {
        if (table[i].Build == build) { *prot = table[i].Prot; *secsig = table[i].SecSig; return TRUE; }
    }
    return FALSE;
}

BOOLEAN KO_GetEprocessOffsets(PEPROCESS_OFFSETS Offsets)
{
    if (!Offsets) return FALSE;
    DRIVERCTX_OSVER ver = DriverCtx_GetOsVersion();
    ULONG prot = 0, secsig = 0; BOOLEAN ok = FALSE;
    ok = FindOffsetsExact(ver.Build, g_BuildOffsets, RTL_NUMBER_OF(g_BuildOffsets), &prot, &secsig);
    if (!ok) return FALSE;
    Offsets->ProtectionOffset = prot;
    Offsets->SectionSignatureLevelOffset = secsig;
    return TRUE;
}
