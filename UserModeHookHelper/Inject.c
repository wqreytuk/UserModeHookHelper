#include "Inject.h"
#include "Trace.h"
#include "HookList.h"
#include "PE.h"
#include "DriverCtx.h"
#include "StrLib.h"
#include "UKShared.h"
#include "FltCommPort.h"

BOOLEAN
KeInsertQueueApc(
	IN  PKAPC Apc,
	IN  PVOID SystemArgument1,
	IN  PVOID SystemArgument2,
	IN  KPRIORITY Increment
);

typedef enum _KAPC_ENVIRONMENT {
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
} KAPC_ENVIRONMENT;
/*
klif!InjpThunkX86:
fffff800`46b76010 83ec08          sub     esp,8
fffff800`46b76013 0fb7442414      movzx   eax,word ptr [rsp+14h]
fffff800`46b76018 66890424        mov     word ptr [rsp],ax
fffff800`46b7601c 6689442402      mov     word ptr [rsp+2],ax
fffff800`46b76021 8b442410        mov     eax,dword ptr [rsp+10h]
fffff800`46b76025 89442404        mov     dword ptr [rsp+4],eax
fffff800`46b76029 8d442414        lea     eax,[rsp+14h]
fffff800`46b7602d 50              push    rax
fffff800`46b7602e 8d442404        lea     eax,[rsp+4]
fffff800`46b76032 50              push    rax
fffff800`46b76033 6a00            push    0
fffff800`46b76035 6a00            push    0
fffff800`46b76037 ff54241c        call    qword ptr [rsp+1Ch]
fffff800`46b7603b 83c408          add     esp,8
fffff800`46b7603e c20c00          ret     0Ch
*/

UCHAR InjpThunkX86[] = {              //
  0x83, 0xec, 0x08,                   // sub    esp,0x8
  0x0f, 0xb7, 0x44, 0x24, 0x14,       // movzx  eax,[esp + 0x14]
  0x66, 0x89, 0x04, 0x24,             // mov    [esp],ax
  0x66, 0x89, 0x44, 0x24, 0x02,       // mov    [esp + 0x2],ax
  0x8b, 0x44, 0x24, 0x10,             // mov    eax,[esp + 0x10]
  0x89, 0x44, 0x24, 0x04,             // mov    [esp + 0x4],eax
  0x8d, 0x44, 0x24, 0x14,             // lea    eax,[esp + 0x14]
  0x50,                               // push   eax
  0x8d, 0x44, 0x24, 0x04,             // lea    eax,[esp + 0x4]
  0x50,                               // push   eax
  0x6a, 0x00,                         // push   0x0
  0x6a, 0x00,                         // push   0x0
  0xff, 0x54, 0x24, 0x1c,             // call   [esp + 0x1c]
  0x83, 0xc4, 0x08,                   // add    esp,0x8
  0xc2, 0x0c, 0x00,                   // ret    0xc
};                                    //
/*
klif!InjpThunkX64:
fffff800`46b76048 4883ec38        sub     rsp,38h
fffff800`46b7604c 4889c8          mov     rax,rcx
fffff800`46b7604f 664489442420    mov     word ptr [rsp+20h],r8w
fffff800`46b76055 664489442422    mov     word ptr [rsp+22h],r8w
fffff800`46b7605b 4c8d4c2440      lea     r9,[rsp+40h]
fffff800`46b76060 4889542428      mov     qword ptr [rsp+28h],rdx
fffff800`46b76065 4c8d442420      lea     r8,[rsp+20h]
fffff800`46b7606a 31d2            xor     edx,edx
fffff800`46b7606c 31c9            xor     ecx,ecx
fffff800`46b7606e ffd0            call    rax
fffff800`46b76070 4883c438        add     rsp,38h
fffff800`46b76074 c20000          ret     0

*/
UCHAR InjpThunkX64[] = {              //
  0x48, 0x83, 0xec, 0x38,             // sub    rsp,0x38
  0x48, 0x89, 0xc8,                   // mov    rax,rcx
  0x66, 0x44, 0x89, 0x44, 0x24, 0x20, // mov    [rsp+0x20],r8w
  0x66, 0x44, 0x89, 0x44, 0x24, 0x22, // mov    [rsp+0x22],r8w
  0x4c, 0x8d, 0x4c, 0x24, 0x40,       // lea    r9,[rsp+0x40]
  0x48, 0x89, 0x54, 0x24, 0x28,       // mov    [rsp+0x28],rdx
  0x4c, 0x8d, 0x44, 0x24, 0x20,       // lea    r8,[rsp+0x20]
  0x31, 0xd2,                         // xor    edx,edx
  0x31, 0xc9,                         // xor    ecx,ecx
  0xff, 0xd0,                         // call   rax
  0x48, 0x83, 0xc4, 0x38,             // add    rsp,0x38
  0xc2, 0x00, 0x00,                   // ret    0x0
};

typedef struct _INJ_THUNK
{
	PVOID           Buffer;
	USHORT          Length;
} INJ_THUNK, *PINJ_THUNK;


// Pending-inject list: holds referenced PEPROCESS pointers for processes
// that need DLL injection when ntdll.dll is loaded.
typedef struct _PENDING_INJECT {
    LIST_ENTRY ListEntry;
    PEPROCESS Process; // referenced
} PENDING_INJECT, *PPENDING_INJECT;

static LIST_ENTRY s_PendingInjectList;
static KSPIN_LOCK s_PendingInjectLock;
static INJ_THUNK       InjThunk[2] = {
  { InjpThunkX86,   sizeof(InjpThunkX86)   },
  { InjpThunkX64,   sizeof(InjpThunkX64)   }
};

// Simple FNV-1a 64-bit over UTF-16LE bytes
static ULONGLONG ComputeNtPathHash(PUNICODE_STRING Path)
{	
    if (!Path || !Path->Buffer || Path->Length == 0) return 0;
    const ULONGLONG FNV_offset = 14695981039346656037ULL;
    const ULONGLONG FNV_prime = 1099511628211ULL;
    ULONGLONG hash = FNV_offset;
    // iterate over bytes of the UNICODE string (UTF-16LE)
    USHORT byteLen = Path->Length; // length in bytes
    PUCHAR bytes = (PUCHAR)Path->Buffer;
    for (USHORT i = 0; i < byteLen; ++i) {
        hash ^= (ULONGLONG)bytes[i];
        hash *= FNV_prime;
    }
    return hash;
}

static BOOLEAN PendingInject_Exists_Internal(PEPROCESS Process)
{
    BOOLEAN found = FALSE;
    KIRQL oldIrql;
    KeAcquireSpinLock(&s_PendingInjectLock, &oldIrql);
    PLIST_ENTRY e = s_PendingInjectList.Flink;
    while (e != &s_PendingInjectList) {
        PPENDING_INJECT p = CONTAINING_RECORD(e, PENDING_INJECT, ListEntry);
        if (p->Process == Process) { found = TRUE; break; }
        e = e->Flink;
    }
    KeReleaseSpinLock(&s_PendingInjectLock, oldIrql);
    return found;
}

static VOID PendingInject_Add_Internal(PEPROCESS Process)
{
    if (PendingInject_Exists_Internal(Process)) return;
    PPENDING_INJECT p = ExAllocatePoolWithTag(NonPagedPool, sizeof(PENDING_INJECT), 'gInP');
    if (!p) return;
    RtlZeroMemory(p, sizeof(*p));
    // take a reference to the process object
    ObReferenceObject(Process);
    p->Process = Process;
    KIRQL oldIrql;
    KeAcquireSpinLock(&s_PendingInjectLock, &oldIrql);
    InsertTailList(&s_PendingInjectList, &p->ListEntry);
    KeReleaseSpinLock(&s_PendingInjectLock, oldIrql);
}

// this function is actually not used, because Process is removed in PendingInject_PopForInject
static VOID PendingInject_Remove_Internal(PEPROCESS Process)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&s_PendingInjectLock, &oldIrql);
    PLIST_ENTRY e = s_PendingInjectList.Flink;
    while (e != &s_PendingInjectList) {
        PPENDING_INJECT p = CONTAINING_RECORD(e, PENDING_INJECT, ListEntry);
        e = e->Flink; // advance first since we may remove
        if (p->Process == Process) {
            RemoveEntryList(&p->ListEntry);
            // drop the reference we took when adding
            ObDereferenceObject(p->Process);
            ExFreePoolWithTag(p, 'gInP');
            break;
        }
    }
    KeReleaseSpinLock(&s_PendingInjectLock, oldIrql);
}

// Simple case-insensitive check whether a UNICODE_STRING ends with "ntdll.dll"
static BOOLEAN ImageNameIsNtdll_Internal(PUNICODE_STRING ImageName)
{
	if (!ImageName || !ImageName->Buffer || ImageName->Length == 0) return FALSE;
	// find last backslash
	USHORT chars = ImageName->Length / sizeof(WCHAR);
	PWCHAR buf = ImageName->Buffer;
	PWCHAR last = buf + chars - 1;
	// walk backward to component start
	while (last >= buf && *last != L'\\' && *last != L'/') --last;
	PWCHAR comp = (last >= buf && (*last == L'\\' || *last == L'/')) ? (last + 1) : buf;
	// compare comp to L"ntdll.dll" case-insensitive
	static const WCHAR target[] = L"ntdll.dll";
	SIZE_T need = (wcslen(target)) * sizeof(WCHAR);
	USHORT compBytes = (USHORT)((buf + chars - comp) * sizeof(WCHAR));
	if (compBytes != need) {
		if ((buf + chars - comp) * sizeof(WCHAR) < need) return FALSE;
	}
	UNICODE_STRING usComp;
	usComp.Buffer = comp;
	usComp.Length = (USHORT)((buf + chars - comp) * sizeof(WCHAR));
	usComp.MaximumLength = usComp.Length;
	UNICODE_STRING usTarget;
	RtlInitUnicodeString(&usTarget, target);
	if (RtlCompareUnicodeString(&usComp, &usTarget, TRUE) == 0) return TRUE;
	return FALSE;
}



// Placeholder injection function to be implemented later
NTSTATUS Inject_Perform(PEPROCESS Process, PIMAGE_INFO ImageInfo)
{
	NTSTATUS status = STATUS_SUCCESS;

	// Validate parameters
	if (!ImageInfo || !ImageInfo->ImageBase) {
		return STATUS_INVALID_PARAMETER;
	}

	PVOID dllBase = ImageInfo->ImageBase;
	PVOID ldrFuncAddr = PE_GetExport(dllBase, "LdrLoadDll");
	if (!ldrFuncAddr) {
		Log(L"failed to get LdrLoadDll from ntdll base: 0x%p\n", dllBase);
		return STATUS_UNSUCCESSFUL;
	}

	OBJECT_ATTRIBUTES   ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes,
		NULL,
		OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	// resource tracking - initialize early so CLEAN_UP can safely release
	HANDLE SectionHandle = NULL;
	PVOID SectionMemoryAddress = NULL;
	PKAPC Apc = NULL;
	BOOLEAN Inserted = FALSE;
	SIZE_T SectionSize = PAGE_SIZE;
	LARGE_INTEGER MaximumSize;
	MaximumSize.QuadPart = SectionSize;

	status = ZwCreateSection(&SectionHandle,
		GENERIC_READ | GENERIC_WRITE,
		&ObjectAttributes,
		&MaximumSize,
		PAGE_EXECUTE_READWRITE,
		SEC_COMMIT,
		NULL);
	if (!NT_SUCCESS(status)) {
		Log(L"failed to call ZwCreateSection from Inject_Perform: 0x%x\n", status);
		goto CLEAN_UP;
	}

	status = ZwMapViewOfSection(SectionHandle,
		ZwCurrentProcess(),
		&SectionMemoryAddress,
		0,
		SectionSize,
		NULL,
		&SectionSize,
		ViewUnmap,
		0,
		PAGE_READWRITE);
	if (!NT_SUCCESS(status)) {
		Log(L"failed to call ZwMapViewOfSection from Inject_Perform: 0x%x\n", status);
		goto CLEAN_UP;
	}

	BOOLEAN x64 = !PE_IsProcessX86(Process);
	PVOID ApcRoutineAddress = SectionMemoryAddress;
	// 0 for x86, 1 for x64
	RtlCopyMemory(ApcRoutineAddress,
		InjThunk[x64].Buffer,
		InjThunk[x64].Length);

	PWCHAR DllPath = (PWCHAR)((PUCHAR)SectionMemoryAddress + InjThunk[x64].Length);
	WCHAR dllPath[MAX_PATH] = { 0 };
	SL_ConcatWideString(DriverCtx_GetUserDir(), L"\\", dllPath, MAX_PATH);
	SL_ConcatWideString(dllPath, x64 ? X64_DLL : X86_DLL, dllPath, MAX_PATH);
	// copy wide string including terminating NUL
	RtlCopyMemory(DllPath, dllPath, (wcslen(dllPath) + 1) * sizeof(WCHAR));
	Log(L"to be injected dll path: %ws\n", dllPath);

	// remap to get execution privilege
	status = ZwUnmapViewOfSection(ZwCurrentProcess(), SectionMemoryAddress);
	if (!NT_SUCCESS(status)) {
		Log(L"failed to call ZwUnmapViewOfSection from Inject_Perform: 0x%x\n", status);
		goto CLEAN_UP;
	}
	SectionMemoryAddress = NULL;
	status = ZwMapViewOfSection(SectionHandle,
		ZwCurrentProcess(),
		&SectionMemoryAddress,
		0,
		PAGE_SIZE,
		NULL,
		&SectionSize,
		ViewUnmap,
		0,
		PAGE_EXECUTE_READ);
	if (!NT_SUCCESS(status)) {
		Log(L"failed to remap from Inject_Perform: 0x%x\n", status);
		goto CLEAN_UP;
	}

	ApcRoutineAddress = SectionMemoryAddress;
	DllPath = (PWCHAR)((PUCHAR)SectionMemoryAddress + InjThunk[x64].Length);

	PVOID ApcContext = ldrFuncAddr;
	PVOID ApcArgument1 = (PVOID)DllPath;
	PVOID ApcArgument2 = (PVOID)wcslen(dllPath);

	PKNORMAL_ROUTINE ApcRoutine = (PKNORMAL_ROUTINE)(ULONG_PTR)ApcRoutineAddress;
	KPROCESSOR_MODE ApcMode = UserMode;
	PKNORMAL_ROUTINE NormalRoutine = ApcRoutine;
	PVOID NormalContext = ApcContext;
	PVOID SystemArgument1 = ApcArgument1;
	PVOID SystemArgument2 = ApcArgument2;

	Apc = ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(KAPC), tag_apc);
	if (!Apc)
	{
		Log(L"failed to call ExAllocatePoolWithTag, aborting\n");
		status = STATUS_NO_MEMORY;
		goto CLEAN_UP;
	}

	KeInitializeApc((PVOID)Apc,
		(PVOID)PsGetCurrentThread(),
		(PVOID)OriginalApcEnvironment,
		(PVOID)&Inject_ApcKernelRoutine,
		(PVOID)NULL,
		(PVOID)NormalRoutine,
		ApcMode,
		(PVOID)NormalContext);

	Inserted = KeInsertQueueApc(Apc,
		SystemArgument1,
		SystemArgument2,
		0);

	// Notify user-mode that we queued an APC for this process so the user-mode
	// controller can start a short-lived checker (e.g. 10s) to detect when the
	// master DLL is loaded and update the process hook-state accordingly.
	// This uses Comm_BroadcastProcessNotify which is safe to call from here.
	{
		ULONG notified = 0;
		DWORD pid = (DWORD)(ULONG_PTR)PsGetProcessId(Process);
		NTSTATUS st = Comm_BroadcastApcQueued(pid, &notified);
		Log(L"Inject: broadcast apc queued notify for pid %u result 0x%08x notified=%u\n", pid, st, notified);
	}

CLEAN_UP:

	// If we allocated an APC but didn't successfully queue it, free it now.
	if (Apc && !Inserted) {
		Log(L"failed to call KeInsertQueueApc\n");
		status = STATUS_UNSUCCESSFUL;
		ExFreePoolWithTag(Apc, tag_apc);
		Apc = NULL;
	}

	// Unmap any mapped view in our process
	if (SectionMemoryAddress) {
		(VOID)ZwUnmapViewOfSection(ZwCurrentProcess(), SectionMemoryAddress);
		SectionMemoryAddress = NULL;
	}

	// Close section handle if created
	if (SectionHandle) {
		ZwClose(SectionHandle);
		SectionHandle = NULL;
	}

	return status;
}

NTSTATUS Inject_Init(VOID)
{
    InitializeListHead(&s_PendingInjectList);
    KeInitializeSpinLock(&s_PendingInjectLock);
    return STATUS_SUCCESS;
}

VOID Inject_Uninit(VOID)
{
    // Free any remaining entries
    KIRQL oldIrql;
    KeAcquireSpinLock(&s_PendingInjectLock, &oldIrql);
    PLIST_ENTRY e = s_PendingInjectList.Flink;
    while (e != &s_PendingInjectList) {
        PPENDING_INJECT p = CONTAINING_RECORD(e, PENDING_INJECT, ListEntry);
        e = e->Flink;
        RemoveEntryList(&p->ListEntry);
        // drop reference taken when added
        ObDereferenceObject(p->Process);
        ExFreePoolWithTag(p, 'gInP');
    }
    InitializeListHead(&s_PendingInjectList);
    KeReleaseSpinLock(&s_PendingInjectLock, oldIrql);
}

// Atomically remove and return the PEPROCESS to inject for the supplied process
// If a pending entry existed, returns the referenced PEPROCESS (caller must
// ObDereferenceObject it when done). Returns NULL if no pending entry.
PEPROCESS PendingInject_PopForInject(PEPROCESS Process)
{
    PEPROCESS ret = NULL;
    KIRQL oldIrql;
    KeAcquireSpinLock(&s_PendingInjectLock, &oldIrql);
    PLIST_ENTRY e = s_PendingInjectList.Flink;
    while (e != &s_PendingInjectList) {
        PPENDING_INJECT p = CONTAINING_RECORD(e, PENDING_INJECT, ListEntry);
        e = e->Flink; // advance first
        if (p->Process == Process) {
            RemoveEntryList(&p->ListEntry);
            // return the process (the stored entry has a reference); transfer ownership
            ret = p->Process;
            ExFreePoolWithTag(p, 'gInP');
            break;
        }
    }
    KeReleaseSpinLock(&s_PendingInjectLock, oldIrql);
    return ret;
}

VOID Inject_CheckAndQueue(PUNICODE_STRING ImageName, PEPROCESS Process)
{
    if (!ImageName || !ImageName->Buffer || ImageName->Length == 0) return;
    ULONGLONG hash = ComputeNtPathHash(ImageName);
    if (hash != 0 && HookList_ContainsHash(hash)) {
        PendingInject_Add_Internal(Process);
        Log(L"Process queued for injection (from broadcast)\n");
    }
}

// Pending list accessors were removed; external code should use Inject_CheckAndQueue
// and let Inject_OnImageLoad perform atomic pop + inject.

VOID Inject_OnImageLoad(PUNICODE_STRING FullImageName, PEPROCESS Process, PIMAGE_INFO ImageInfo)
{
	if (!FullImageName || FullImageName->Length == 0) return;
	if (ImageNameIsNtdll_Internal(FullImageName)) {
		// Atomically take the pending entry for this process if present so
		// only one thread performs injection.
		PEPROCESS procToInject = PendingInject_PopForInject(Process);
		if (procToInject) {
			Log(L"ntdll.dll loaded in process: performing injection\n");
			Inject_Perform(procToInject, ImageInfo);
			// we received a referenced PEPROCESS from the pop; drop it now
			ObDereferenceObject(procToInject);
		}
	}
}

VOID
NTAPI
Inject_ApcKernelRoutine(
	_In_ PKAPC Apc,
	_Inout_ PKNORMAL_ROUTINE* NormalRoutine,
	_Inout_ PVOID* NormalContext,
	_Inout_ PVOID* SystemArgument1,
	_Inout_ PVOID* SystemArgument2
)
{
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	//
	// Common kernel routine for both user-mode and
	// kernel-mode APCs queued by the InjpQueueApc
	// function.  Just release the memory of the APC
	// structure and return back.
	//

	ExFreePoolWithTag(Apc, tag_apc);
}