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
    WCHAR eventName[128];
    // The injected DLL's in-process helper expects the per-pid file under
    // C:\Users\Public\signal.bin.<pid> (NT view: \??\C:\users\public\signal.bin.<pid>)
    // and expects the event in the BaseNamedObjects namespace with the
    // format DLL_IPC_EVENT_FMT. Construct these and write the file contents
    // in the layout the helper reads: [4-byte little-endian pid] '$' [ascii dllPath] '$'.

    // Build event name using DLL format so it matches the dll's created event
    FormatObjectName(eventName, sizeof(eventName)/sizeof(eventName[0]), IPC_EVENT_FMT, pid);

    app.GetETW().Log(L"IPC_SendInject: pid=%u dll=%s\n", pid, dllPath);
    app.GetETW().Log(L"IPC_SendInject: event='%s'\n", eventName);

    // Build signal filename in Win32 form
    WCHAR signalPath[MAX_PATH];
	FormatObjectName(signalPath, RTL_NUMBER_OF(signalPath), USER_IPC_SIGNAL_FILE_FMT, (unsigned)pid);

    // Convert wide DLL path to ANSI bytes because the injector widens bytes back
    // to WCHAR on the target process side.
    int asciiLen = WideCharToMultiByte(CP_ACP, 0, dllPath, -1, NULL, 0, NULL, NULL);
    if (asciiLen <= 0) {
        app.GetETW().Log(L"IPC_SendInject: WideCharToMultiByte failed\n");
        return FALSE;
    }
    char* asciiBuf = new char[asciiLen];
    WideCharToMultiByte(CP_ACP, 0, dllPath, -1, asciiBuf, asciiLen, NULL, NULL);
	// delete signal file first
	DeleteFile(signalPath);
    // Prepare payload: 4 bytes pid (little endian), '$', dll bytes (no null), '$'
    // We'll write as binary file.
    HANDLE hFile = CreateFile(signalPath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        app.GetETW().Log(L"IPC_SendInject: CreateFileW failed (%u)\n", GetLastError());
        return FALSE;
    }

    DWORD written = 0;
    // write pid as 4 bytes little-endian
    DWORD pidValue = pid;
    if (!WriteFile(hFile, &pidValue, sizeof(pidValue), &written, NULL) || written != sizeof(pidValue)) {
        app.GetETW().Log(L"IPC_SendInject: WriteFile(pid) failed (%u)\n", GetLastError());
        CloseHandle(hFile);
        return FALSE;
    }
    // write marker '$'
    char marker = '$';
    if (!WriteFile(hFile, &marker, 1, &written, NULL) || written != 1) {
        app.GetETW().Log(L"IPC_SendInject: WriteFile(marker1) failed (%u)\n", GetLastError());
        CloseHandle(hFile);
        return FALSE;
    }
    // write ascii dll path (without terminating null)
    size_t dllBytes = (size_t)(asciiLen - 1); // exclude null
    if (dllBytes > 0) {
        if (!WriteFile(hFile, asciiBuf, (DWORD)dllBytes, &written, NULL) || written != dllBytes) {
            app.GetETW().Log(L"IPC_SendInject: WriteFile(dllPath) failed (%u)\n", GetLastError());
            CloseHandle(hFile);
            return FALSE;
        }
    }
    // write trailing marker '$'
    if (!WriteFile(hFile, &marker, 1, &written, NULL) || written != 1) {
        app.GetETW().Log(L"IPC_SendInject: WriteFile(marker2) failed (%u)\n", GetLastError());
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);

    // Signal event in BaseNamedObjects namespace
    HANDLE hEvent = CreateEventW(NULL, FALSE, FALSE, eventName);
    if (!hEvent) {
        app.GetETW().Log(L"IPC_SendInject: CreateEventW failed (%u)\n", GetLastError());
        return FALSE;
    }

    BOOL b = SetEvent(hEvent);
    if (b) app.GetETW().Log(L"IPC_SendInject: SetEvent succeeded\n");
    else app.GetETW().Log(L"IPC_SendInject: SetEvent failed (%u)\n", GetLastError());

    CloseHandle(hEvent);
    delete[] asciiBuf;
    return b == TRUE;
}
