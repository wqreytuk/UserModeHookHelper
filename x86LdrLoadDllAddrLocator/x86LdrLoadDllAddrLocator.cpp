#include <Windows.h>
#include <stdio.h>
#include "../Shared/SharedMacroDef.h"
int main()
{
	DeleteFile(LOCATOR_IPC_FILE_PATH);
	FILE* fp = NULL;
	_wfopen_s(&fp, LOCATOR_IPC_FILE_PATH, L"w");
	if (fp) {
		// if both x64 and x86n dll is loaded, GetModuleHandle will
		// always return the one that match our current architecture
		HMODULE x86_nt_base = GetModuleHandle(L"kernel32.dll");
		if (x86_nt_base) {
			DWORD ldr_load_dll_func_addr = (DWORD)GetProcAddress(x86_nt_base, "LoadLibraryW");
			if (ldr_load_dll_func_addr) {
				fwrite(&ldr_load_dll_func_addr, sizeof(DWORD), 1, fp);
				fclose(fp);
				HANDLE hEvent = OpenEvent(EVENT_MODIFY_STATE, FALSE, LOCATOR_SIGNAL_EVENT);
				if (hEvent) {
					SetEvent(hEvent);
					CloseHandle(hEvent);
				}
				return 0;
			}
		}
		fclose(fp);
	}
	return 0;
}