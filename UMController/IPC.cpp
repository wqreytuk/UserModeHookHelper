#include "pch.h"
// IPC implementation for UMController — uses native ntdll APIs only.
#include "IPC.h"
#include <windows.h>
#include <wchar.h>
#include <string.h>
#include "UMController.h" // for app.GetETW()

// Helper to format named object name into buffer
static void FormatObjectName(PWCHAR out, size_t outCount, PCWSTR fmt, DWORD pid)
{
    // Use swprintf_s for simplicity (UMController is user-mode)
    swprintf_s(out, outCount, fmt, (unsigned)pid);
}

BOOL IPC_SendInject(DWORD pid, PCWSTR dllPath)
{
    if (!dllPath || pid == 0) return FALSE;

    WCHAR sectionName[128];
    WCHAR eventName[128];
    FormatObjectName(sectionName, sizeof(sectionName)/sizeof(sectionName[0]), IPC_SECTION_FMT, pid);
    FormatObjectName(eventName, sizeof(eventName)/sizeof(eventName[0]), IPC_EVENT_FMT, pid);

    // Use Win32 named file-mapping and event APIs — simpler and allowed in UMController
    const SIZE_T viewSize = 4096;

    app.GetETW().Log(L"IPC_SendInject: pid=%u dll=%s\n", pid, dllPath);
    app.GetETW().Log(L"IPC_SendInject: section='%s' event='%s'\n", sectionName, eventName);

    // Create or open a named file mapping (backed by paging file)
    HANDLE hMap = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, (DWORD)viewSize, sectionName);
    if (!hMap) {
        app.GetETW().Log(L"IPC_SendInject: CreateFileMappingW failed (%u)\n", GetLastError());
        return FALSE;
    }

    LPVOID baseAddress = MapViewOfFile(hMap, FILE_MAP_WRITE, 0, 0, viewSize);
    if (!baseAddress) {
        app.GetETW().Log(L"IPC_SendInject: MapViewOfFile failed (%u)\n", GetLastError());
        CloseHandle(hMap);
        return FALSE;
    }

    // Write the DLL path as WCHAR, ensure it fits
    size_t maxChars = viewSize / sizeof(WCHAR);
    size_t needed = wcslen(dllPath) + 1;
    if (needed > maxChars) {
        app.GetETW().Log(L"IPC_SendInject: dll path too long (%u chars)\n", (unsigned)needed);
        UnmapViewOfFile(baseAddress);
        CloseHandle(hMap);
        return FALSE;
    }

    ZeroMemory(baseAddress, viewSize);
    memcpy(baseAddress, dllPath, needed * sizeof(WCHAR));

    // Create or open the named event and signal it
    HANDLE hEvent = CreateEventW(NULL, FALSE, FALSE, eventName);
    if (!hEvent) {
        app.GetETW().Log(L"IPC_SendInject: CreateEventW failed (%u)\n", GetLastError());
        UnmapViewOfFile(baseAddress);
        CloseHandle(hMap);
        return FALSE;
    }

    BOOL b = SetEvent(hEvent);
    if (b) app.GetETW().Log(L"IPC_SendInject: SetEvent succeeded\n");
    else app.GetETW().Log(L"IPC_SendInject: SetEvent failed (%u)\n", GetLastError());

    // Cleanup
    UnmapViewOfFile(baseAddress);
    CloseHandle(hMap);
    CloseHandle(hEvent);

    return b == TRUE;
}
