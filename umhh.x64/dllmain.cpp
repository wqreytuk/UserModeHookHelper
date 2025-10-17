
#define _ARM_WINAPI_PARTITION_DESKTOP_SDK_AVAILABLE 1


//
// Include NTDLL-related headers.
//
#define NTDLL_NO_INLINE_INIT_STRING
#include <ntdll.h>
#include "../UMController/IPC.h"
#include "../UMController/ETW.h"

#define PAGE_SIZE 0x1000
#if defined(_M_IX86)
#  define ARCH_A          "x86"
#  define ARCH_W         L"x86"
#elif defined(_M_AMD64)
#  define ARCH_A          "x64"
#  define ARCH_W         L"x64"
#elif defined(_M_ARM)
#  define ARCH_A          "ARM32"
#  define ARCH_W         L"ARM32"
#elif defined(_M_ARM64)
#  define ARCH_A          "ARM64"
#  define ARCH_W         L"ARM64"
#else
#  error Unknown architecture
#endif
#define WIDEN2(x) L##x
#define WIDEN(x) WIDEN2(x)
#define WFILE WIDEN(__FILE__)

// size_t strlen(const char * str)
// {
//   const char *s;
//   for (s = str; *s; ++s) {}
//   return(s - str);
// }

//
// Include support for ETW logging.
// Note that following functions are mocked, because they're
// located in advapi32.dll.  Fortunatelly, advapi32.dll simply
// redirects calls to these functions to the ntdll.dll.
//

// Map Event* symbols to the standard ETW APIs provided by evntprov.h
#define EventActivityIdControl  EventActivityIdControl
#define EventEnabled            EventEnabled
#define EventProviderEnabled    EventProviderEnabled
#define EventRegister           EventRegister
#define EventSetInformation     EventSetInformation
#define EventUnregister         EventUnregister
#define EventWrite              EventWrite
#define EventWriteEndScenario   EventWriteEndScenario
#define EventWriteEx            EventWriteEx
#define EventWriteStartScenario EventWriteStartScenario
#define EventWriteString        EventWriteString
#define EventWriteTransfer      EventWriteTransfer

#include <evntprov.h>

#include "../UMController/ETW.h"

#include <stdarg.h>

//
// Include Detours.
//


// This is necessary for x86 builds because of SEH,
// which is used by Detours.  Look at loadcfg.c file
// in Visual Studio's CRT source codes for the original
// implementation.
//

#if defined(_M_IX86) || defined(_X86_)

EXTERN_C PVOID __safe_se_handler_table[]; /* base of safe handler entry table */
EXTERN_C BYTE  __safe_se_handler_count;   /* absolute symbol whose address is
											 the count of table entries */
EXTERN_C
CONST
DECLSPEC_SELECTANY
IMAGE_LOAD_CONFIG_DIRECTORY
_load_config_used = {
	sizeof(_load_config_used),
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	(SIZE_T)__safe_se_handler_table,
	(SIZE_T)&__safe_se_handler_count,
};

#endif

//
// Unfortunatelly sprintf-like functions are not exposed
// by ntdll.lib, which we're linking against.  We have to
// load them dynamically.
//

typedef int(__cdecl * _snwprintf_fn_t)(
	wchar_t *buffer,
	size_t count,
	const wchar_t *format,
	...
	);

// vsnwprintf signature and function pointer (we'll resolve at runtime)
typedef int(__cdecl * _vsnwprintf_fn_t)(
	wchar_t *buffer,
	size_t count,
	const wchar_t *format,
	va_list args
	);

static _snwprintf_fn_t _snwprintf = NULL;
static _vsnwprintf_fn_t _vsnwprintf = NULL;
//
// ETW provider GUID and global provider handle.
//

//
// GUID:
//   {a4b4ba50-a667-43f5-919b-1e52a6d69bd5}
//
 
REGHANDLE ProviderHandle = 0;

//
// Hooking functions and prototypes.
//



// Removed unused detour hook functions and helper thread routine to reduce dead code.

NTSTATUS
NTAPI
EnableDetours(
	VOID
)
{
	// DetourTransactionBegin();
	// {
	//     OrigNtQuerySystemInformation = NtQuerySystemInformation;
	//     DetourAttach((PVOID*)&OrigNtQuerySystemInformation, HookNtQuerySystemInformation);
	// 
	//     OrigNtCreateThreadEx = NtCreateThreadEx;
	//     DetourAttach((PVOID*)&OrigNtCreateThreadEx, HookNtCreateThreadEx);
	// }
	// DetourTransactionCommit();

	return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
DisableDetours(
	VOID
)
{
	// DetourTransactionBegin();
	// {
	// 	DetourDetach((PVOID*)&OrigNtQuerySystemInformation, HookNtQuerySystemInformation);
	// 	DetourDetach((PVOID*)&OrigNtCreateThreadEx, HookNtCreateThreadEx);
	// }
	// DetourTransactionCommit();

	return STATUS_SUCCESS;
}
typedef NTSTATUS(NTAPI *PNtDeleteFile)(
	POBJECT_ATTRIBUTES ObjectAttributes
	);
typedef NTSTATUS(NTAPI *PFN_LdrLoadDll)(
	PWSTR               PathToFile OPTIONAL, // Usually NULL for system search
	PULONG              Flags OPTIONAL,      // Normally 0
	PUNICODE_STRING     ModuleFileName,      // DLL name
	PHANDLE             ModuleHandle         // out: handle to loaded module
	);
typedef NTSTATUS(NTAPI *PFN_NtDelayExecution)(
	BOOLEAN Alertable,        // TRUE = APCs can wake the thread
	PLARGE_INTEGER Interval   // Relative (negative) or absolute (positive) time in 100-ns units
	);
// Minimal typedefs in case winternl.h not present
typedef NTSTATUS(NTAPI *PFN_NtOpenFile)(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	ULONG              ShareAccess,
	ULONG              OpenOptions
	);
typedef ULONG(NTAPI *PRtlGetCurrentProcessId)(void);

typedef NTSTATUS(NTAPI *PFN_NtReadFile)(
	HANDLE            FileHandle,
	HANDLE            Event OPTIONAL,
	PIO_APC_ROUTINE   ApcRoutine OPTIONAL,
	PVOID             ApcContext OPTIONAL,
	PIO_STATUS_BLOCK  IoStatusBlock,
	PVOID             Buffer,
	ULONG             Length,
	PLARGE_INTEGER    ByteOffset OPTIONAL,
	PULONG            Key OPTIONAL
	);




typedef NTSTATUS(NTAPI *PNtCreateEvent)(
	PHANDLE EventHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	EVENT_TYPE EventType,
	BOOLEAN InitialState
	);

typedef NTSTATUS(NTAPI *PNtOpenEvent)(
	PHANDLE EventHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes
	);

typedef NTSTATUS(NTAPI *PNtSetEvent)(
	HANDLE EventHandle,
	PLONG PreviousState OPTIONAL
	);

typedef NTSTATUS(NTAPI *PNtWaitForSingleObject)(
	HANDLE Handle,
	BOOLEAN Alertable,
	PLARGE_INTEGER Timeout OPTIONAL
	);

// Native section/map function pointers (NT APIs)
typedef NTSTATUS(NTAPI *PFN_NtCreateSection)(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, PLARGE_INTEGER MaximumSize OPTIONAL, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle OPTIONAL);
typedef NTSTATUS(NTAPI *PFN_NtMapViewOfSection)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, ULONG InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
typedef NTSTATUS(NTAPI *PFN_NtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);

typedef NTSTATUS(NTAPI *PFN_NtClose)(HANDLE Handle);
static NTSTATUS ReadBytesFromFileNt(
	_In_z_ PCWSTR dosPath,
	_Out_writes_bytes_(BufferLen) PVOID Buffer,
	_In_ ULONG BufferLen,
	_Out_opt_ PULONG BytesRead
)
{


	UNICODE_STRING NtdllPath;
	RtlInitUnicodeString(&NtdllPath, (PWSTR)L"ntdll.dll");

	ANSI_STRING RoutineName;
	RtlInitAnsiString(&RoutineName, (PSTR)"ntOpenFile");
	PFN_NtOpenFile pNtOpenFile = 0;
	PFN_NtReadFile pNtReadFile = 0;
	PFN_NtClose pNtClose = 0;
	PFN_NtDelayExecution pNtDelay = 0;
	HANDLE NtdllHandle;
	LdrGetDllHandle(NULL, 0, &NtdllPath, &NtdllHandle);
	LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtOpenFile);
	RtlInitAnsiString(&RoutineName, (PSTR)"NtReadFile");
	LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtReadFile);
	RtlInitAnsiString(&RoutineName, (PSTR)"NtClose");
	LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtClose);
	RtlInitAnsiString(&RoutineName, (PSTR)"NtClose");
	LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtClose);
	RtlInitAnsiString(&RoutineName, (PSTR)"NtDelayExecution");
	LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtDelay);



	if (!pNtOpenFile || !pNtReadFile || !pNtClose)
		return STATUS_ENTRYPOINT_NOT_FOUND;

	UNICODE_STRING uPath;
	RtlInitUnicodeString(&uPath, dosPath);

	OBJECT_ATTRIBUTES objAttr;
	InitializeObjectAttributes(&objAttr, &uPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

	IO_STATUS_BLOCK iosb;
	HANDLE hFile = NULL;

	// Open for read attributes + read data
	NTSTATUS status = pNtOpenFile(
		&hFile,
		GENERIC_READ | SYNCHRONIZE,
		&objAttr,
		&iosb,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE
	);

	if (!NT_SUCCESS(status)) return status;

	// Read from beginning. Since opened synchronous, ByteOffset NULL is fine.
	status = pNtReadFile(
		hFile,
		NULL,
		NULL,
		NULL,
		&iosb,
		Buffer,
		BufferLen,
		NULL,   // read from current file pointer (start)
		NULL
	);

	if (BytesRead && NT_SUCCESS(status)) {
		*BytesRead = (ULONG)iosb.Information;
	}

	pNtClose(hFile);
	return status;
}
// Read a 32-bit unsigned integer from start of file
BOOL ReadUint32FromFile(_In_z_ PCWSTR path, _Out_ UINT32 *out)
{
	if (!path || !out) return FALSE;
	UINT32 val = 0;
	ULONG bytesRead = 0;
	NTSTATUS st = ReadBytesFromFileNt(path, &val, sizeof(val), &bytesRead);
	if (!NT_SUCCESS(st) || bytesRead < sizeof(val)) return FALSE;
	*out = val;
	return TRUE;
}

// Read a 64-bit unsigned integer from start of file
BOOL ReadUint64FromFile(_In_z_ PCWSTR path, _Out_ UINT64 *out)
{
	if (!path || !out) return FALSE;
	UINT64 val = 0;
	ULONG bytesRead = 0;
	NTSTATUS st = ReadBytesFromFileNt(path, &val, sizeof(val), &bytesRead);
	if (!NT_SUCCESS(st) || bytesRead < sizeof(val)) return FALSE;
	*out = val;
	return TRUE;
}
PFN_NtOpenFile pNtOpenFile = 0;
PFN_NtReadFile pNtReadFile = 0;
PFN_NtClose pNtClose = 0;
PFN_NtDelayExecution pNtDelay = 0;
PFN_LdrLoadDll pLdrLoadDll = 0;
PNtDeleteFile pNtDeleteFile = 0;
PRtlGetCurrentProcessId pRtlGetCurrentProcessId = 0;

// Returns TRUE if file exists (NT view), FALSE otherwise.

BOOL FileExistsViaNtOpenFile(const wchar_t *ntPath);
int ReadFileParsePidAndDllPath(WCHAR* patbuf, char* dllPath);

PNtCreateEvent                 pNtCreateEvent = 0;
PNtOpenEvent                   pNtOpenEvent = 0;
PNtSetEvent                    pNtSetEvent = 0;
PNtWaitForSingleObject         pNtWaitForSingleObject = 0;


#include <ntdef.h>

VOID ConcatPidToPath(PWCHAR outBuffer, USHORT bufferLenInWchars, HANDLE pid)
{
	// Base path
	const WCHAR basePath[] = L"\\??\\C:\\users\\public\\signal.bin.";

	USHORT i = 0;
	// Copy base path
	while (basePath[i] && i < bufferLenInWchars - 1) {
		outBuffer[i] = basePath[i];
		i++;
	}

	// Append pid as decimal digits
	DWORD64 tmp =(DWORD64)(PVOID)pid;
	WCHAR digits[10];  // max 32-bit decimal digits
	int d = 0;

	if (tmp == 0) {
		digits[d++] = L'0';
	}
	else {
		while (tmp != 0 && d < 10) {
			digits[d++] = (WCHAR)(L'0' + (tmp % 10));
			tmp /= 10;
		}
	}

	// digits are reversed, copy in reverse order
	for (int j = d - 1; j >= 0 && i < bufferLenInWchars - 1; j--) {
		outBuffer[i++] = digits[j];
	}

	outBuffer[i] = L'\0';  // null terminate
}

VOID EtwLog(_In_ PCWSTR Format, ...)
{
	WCHAR Buffer[1024];
	va_list args;

	va_start(args, Format);
	_vsnwprintf(Buffer, RTL_NUMBER_OF(Buffer) - 1, Format, args);
	va_end(args);

	Buffer[RTL_NUMBER_OF(Buffer) - 1] = L'\0'; // ensure null-termination

	EventWriteString(ProviderHandle, 0, 0, Buffer);
}
// mainn


NTSTATUS mycode(_In_ PVOID ThreadParameter) {
	DbgBreakPoint();





	UNICODE_STRING NtdllPath;
	RtlInitUnicodeString(&NtdllPath, (PWSTR)L"ntdll.dll");

	ANSI_STRING RoutineName;
	RtlInitAnsiString(&RoutineName, (PSTR)"NtOpenFile");

	HANDLE NtdllHandle;
	LdrGetDllHandle(NULL, 0, &NtdllPath, &NtdllHandle);
	LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtOpenFile);
	RtlInitAnsiString(&RoutineName, (PSTR)"NtReadFile");
	LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtReadFile);
	RtlInitAnsiString(&RoutineName, (PSTR)"NtClose");
	LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtClose);
	RtlInitAnsiString(&RoutineName, (PSTR)"NtDelayExecution");
	LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtDelay);
	RtlInitAnsiString(&RoutineName, (PSTR)"LdrLoadDll");
	LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pLdrLoadDll);
	RtlInitAnsiString(&RoutineName, (PSTR)"NtDeleteFile");
	LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtDeleteFile);



	RtlInitAnsiString(&RoutineName, (PSTR)"NtCreateEvent");
	LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtCreateEvent);
	RtlInitAnsiString(&RoutineName, (PSTR)"NtOpenEvent");
	LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtOpenEvent);
	RtlInitAnsiString(&RoutineName, (PSTR)"NtSetEvent");
	LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtSetEvent);
	RtlInitAnsiString(&RoutineName, (PSTR)"NtWaitForSingleObject");
	LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtWaitForSingleObject);

	// Resolve section/map NT API pointers
	PFN_NtCreateSection pNtCreateSection = NULL;
	PFN_NtMapViewOfSection pNtMapViewOfSection = NULL;
	PFN_NtUnmapViewOfSection pNtUnmapViewOfSection = NULL;
	RtlInitAnsiString(&RoutineName, (PSTR)"NtCreateSection");
	LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtCreateSection);
	RtlInitAnsiString(&RoutineName, (PSTR)"NtMapViewOfSection");
	LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtMapViewOfSection);
	RtlInitAnsiString(&RoutineName, (PSTR)"NtUnmapViewOfSection");
	LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&pNtUnmapViewOfSection);




	// Create native named section and event for IPC
	WCHAR sectionName[128];
	WCHAR eventName[128];
	HANDLE curPid = NtCurrentProcessId();
	_snwprintf(sectionName, RTL_NUMBER_OF(sectionName), DLL_IPC_SECTION_FMT, (ULONG)(ULONG_PTR)curPid);
	_snwprintf(eventName, RTL_NUMBER_OF(eventName), DLL_IPC_EVENT_FMT, (ULONG)(ULONG_PTR)curPid);

	

	UNICODE_STRING usSection;
	UNICODE_STRING usEvent;
	RtlInitUnicodeString(&usSection, sectionName);
	RtlInitUnicodeString(&usEvent, eventName);

	OBJECT_ATTRIBUTES secAttr;
	InitializeObjectAttributes(&secAttr, &usSection, OBJ_CASE_INSENSITIVE | OBJ_OPENIF, NULL, NULL);
	EtwLog(L"NtCreateSection with name: %s\n", sectionName);
	HANDLE hSection = NULL;
	SIZE_T viewSize = 4096;
	if (pNtCreateSection) {
		NTSTATUS st = pNtCreateSection(&hSection, SECTION_ALL_ACCESS, &secAttr, (PLARGE_INTEGER)&viewSize, PAGE_READWRITE, SEC_COMMIT, NULL);
		if (!NT_SUCCESS(st)) {
			//EtwLog(L"NtCreateSection failed: 0x%08x\n", st);
			hSection = NULL;
		}
	}

	PVOID baseAddress = NULL;
	if (hSection && pNtMapViewOfSection) {
#define VIEW_SHARE 1
		NTSTATUS st = pNtMapViewOfSection(hSection, NtCurrentProcess(), &baseAddress, 0, PAGE_SIZE, NULL, &viewSize, VIEW_SHARE, 0, PAGE_READWRITE);
		if (!NT_SUCCESS(st)) {
			//EtwLog(L"NtMapViewOfSection failed: 0x%08x\n", st);
			baseAddress = NULL;
		}
	}

	// Create or open event
	HANDLE hEvent = NULL;
	EtwLog(L"NtCreateEvent with name: %s\n", eventName);
	if (pNtCreateEvent) {
		OBJECT_ATTRIBUTES evAttr;
		InitializeObjectAttributes(&evAttr, &usEvent, OBJ_CASE_INSENSITIVE | OBJ_OPENIF, NULL, NULL);
		NTSTATUS st = pNtCreateEvent(&hEvent, EVENT_ALL_ACCESS, &evAttr, NotificationEvent, FALSE);
		if (!NT_SUCCESS(st)) {
			EtwLog(L"NtCreateEvent failed: 0x%08x\n", st);
			hEvent = NULL;
		}
	}

	WCHAR pathBuf[64];

	ConcatPidToPath(pathBuf, sizeof(pathBuf) / sizeof(WCHAR), NtCurrentProcessId());

	// Server loop: wait on event, read WCHAR path from section, load, zero buffer
	for (;;) {
		if (!hEvent) {
			EtwLog(L"%s(%d) - unexpected (!hEvent)\n", WFILE, __LINE__);
			LARGE_INTEGER li;
			li.QuadPart = -(LONGLONG)1000 * 10000LL;
			pNtDelay((BOOLEAN)0, &li);
			continue;
		}

		pNtWaitForSingleObject(hEvent, FALSE, NULL);

		EtwLog(L"current process is signaled to inject a dll\n");
		char dllPath[256] = { 0 };
		int pid = ReadFileParsePidAndDllPath(pathBuf, dllPath);
		EtwLog(L"get to be injected dll path: %S\n", dllPath);
		{

			UNICODE_STRING uPath;
			OBJECT_ATTRIBUTES oa;
			RtlInitUnicodeString(&uPath, pathBuf);
			InitializeObjectAttributes(&oa, &uPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

			NTSTATUS status = pNtDeleteFile(&oa);
		}
		// 当前进程就是将要被注入dll的目标进程
		UNICODE_STRING str;
		WCHAR buffer[260];
		{
			PUNICODE_STRING ustr = &str;
			USHORT i = 0;
			char* src = dllPath;
			while (src[i] && (i * sizeof(WCHAR) + sizeof(WCHAR)) <= 256) {
				buffer[i] = (WCHAR)(unsigned char)src[i]; // simple widening
				i++;
			}
			buffer[i] = L'\0';

			ustr->Buffer = buffer;
			ustr->Length = i * sizeof(WCHAR);
			ustr->MaximumLength = (i + 1) * sizeof(WCHAR);

			EtwLog(L"wide char dll path character count: %d\n", i);// unicode string for t obe injected dll path : %wZ\n", ustr);// dllPath);
			EtwLog(L"constructed unicode string for to be injected dll path: %wZ\n", ustr);// dllPath);

			pLdrLoadDll(0, 0, ustr, (PHANDLE)dllPath);
		}

	}


	return 0;

}
// endd

int ReadFileParsePidAndDllPath(WCHAR* patbuf, char* dllPath) {


	UNICODE_STRING ustr;
	RtlInitUnicodeString(&ustr, patbuf);

	OBJECT_ATTRIBUTES objAttr;
	InitializeObjectAttributes(&objAttr, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);

	IO_STATUS_BLOCK iosb;
	HANDLE hFile = NULL;

	// DesiredAccess: FILE_READ_ATTRIBUTES is enough to check existence.
	// OpenOptions: FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT
	NTSTATUS status = pNtOpenFile(&hFile,
		FILE_READ_ATTRIBUTES | SYNCHRONIZE | FILE_ALL_ACCESS,
		&objAttr,
		&iosb,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);

	if (status != 0) {

		// 打开文件失败
		return -1;
	}
	IO_STATUS_BLOCK isb = { 0 };
	char fileContextBuffer[256] = { 0 };
	if (0 != pNtReadFile(hFile, 0, 0, 0, &isb, fileContextBuffer, 256, 0, 0)) {
		// 读取失败
		pNtClose(hFile);
		return -2;
	}
	ULONG_PTR actualBufferLen = isb.Information;
	DWORD pid = 0;
	for (size_t i = 0; i < actualBufferLen; i++)
	{
		if (fileContextBuffer[i] != '$') {
			*((UCHAR*)(&pid) + i) = fileContextBuffer[i];
		}
		else {
			for (size_t j = i + 1; j < actualBufferLen; j++)
			{
				if (fileContextBuffer[j] != '$')
					dllPath[j - i - 1] = fileContextBuffer[j];
				else
					goto endloop;
			}
		}
	}
endloop:
	int ret = *(DWORD*)(&pid);
	pNtClose(hFile);
	return ret;
}

// Returns TRUE if file exists (NT view), FALSE otherwise.
BOOL FileExistsViaNtOpenFile(const wchar_t *ntPath)
{
	if (!ntPath) return FALSE;

	UNICODE_STRING ustr;
	RtlInitUnicodeString(&ustr, ntPath);

	OBJECT_ATTRIBUTES objAttr;
	InitializeObjectAttributes(&objAttr, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);

	IO_STATUS_BLOCK iosb;
	HANDLE hFile = NULL;

	// DesiredAccess: FILE_READ_ATTRIBUTES is enough to check existence.
	// OpenOptions: FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT
	NTSTATUS status = pNtOpenFile(&hFile,
		FILE_READ_ATTRIBUTES | SYNCHRONIZE,
		&objAttr,
		&iosb,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);


	if (NT_SUCCESS(status)) {
		// file open succeeded => exists
		pNtClose(hFile);
		return TRUE;
	}
	// if you want to check specific reasons:
	// if (status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND) -> not exists
	return FALSE;
}

NTSTATUS
NTAPI
OnProcessAttach(
	_In_ PVOID ModuleHandle
)
{


	ANSI_STRING RoutineName;
	RtlInitAnsiString(&RoutineName, (PSTR)"_snwprintf");

	UNICODE_STRING NtdllPath;
	RtlInitUnicodeString(&NtdllPath, (PWSTR)L"ntdll.dll");

	HANDLE NtdllHandle;
	LdrGetDllHandle(NULL, 0, &NtdllPath, &NtdllHandle);
	LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&_snwprintf);



	RtlInitAnsiString(&RoutineName, (PSTR)"_vsnwprintf");
	LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&_vsnwprintf);


	EventRegister(&ProviderGUID,
		NULL,
		NULL,
		&ProviderHandle);
	// mycode();
	RtlCreateUserThread(NtCurrentProcess(),
		NULL,
		FALSE,
		0,
		0,
		0,
		(PUSER_THREAD_START_ROUTINE)&mycode,
		NULL,
		NULL,
		NULL);

	return 0; // Early exit: remaining legacy code removed as unreachable
}

NTSTATUS
NTAPI
OnProcessDetach(
	_In_ HANDLE ModuleHandle
)
{
	//
	// Unhook all functions.
	//

	if (ProviderHandle) {
		EventUnregister(ProviderHandle);
		ProviderHandle = 0;
	}

	return 0;
}

EXTERN_C
BOOL
NTAPI
NtDllMain(
	_In_ HANDLE ModuleHandle,
	_In_ ULONG Reason,
	_In_ LPVOID Reserved
)
{
	switch (Reason)
	{
	case DLL_PROCESS_ATTACH: 
		OnProcessAttach(ModuleHandle);
		break;

	case DLL_PROCESS_DETACH:
		OnProcessDetach(ModuleHandle);
		break;

	case DLL_THREAD_ATTACH:

		break;

	case DLL_THREAD_DETACH:

		break;
	}

	return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:

		// Sleep(60000);
	 //  __debugbreak();
		OnProcessAttach(hModule);
		break;

	case DLL_PROCESS_DETACH:
		OnProcessDetach(hModule);
		break;

	case DLL_THREAD_ATTACH:

		break;

	case DLL_THREAD_DETACH:

		break;
	}

	return TRUE;
}
