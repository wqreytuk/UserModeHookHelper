#pragma once
#include <Windows.h>
namespace KRNL {
	BOOLEAN ReadPrimitive(_In_ LPVOID target_addr, _Out_ LPVOID buffer, _In_ size_t size);
	BOOLEAN WritePrimitive(_In_ LPVOID target_addr, _In_ LPVOID buffer, _In_ size_t size);
	NTSTATUS GetDriverBase(
		_In_ PCSTR DriverName,
		_Out_ PVOID* DriverBaseAddress
	);

}