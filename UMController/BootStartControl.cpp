#include "BootStartControl.h"
#include <windows.h>
#include <iostream>

static HANDLE OpenUmhhDevice()
{
    HANDLE h = CreateFileW(UMHH_DOSLINK_NAME_USER, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    return h;
}

bool BS_SendSuspendInjectQueue(bool suspend)
{
    HANDLE h = OpenUmhhDevice();
    if (h == INVALID_HANDLE_VALUE) return false;
    UMHH_INJECT_QUEUE_STATE s = { suspend ? 1u : 0u };
    DWORD returned = 0;
    BOOL ok = DeviceIoControl(h, IOCTL_UMHH_SET_INJECT_QUEUE_STATE, &s, sizeof(s), NULL, 0, &returned, NULL);
    CloseHandle(h);
    return ok == TRUE;
}
