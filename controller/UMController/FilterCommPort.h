#ifndef FILTERCOMMPORT_H
#define FILTERCOMMPORT_H
// Flag used in WM_APP_UPDATE_PROCESS wParam to indicate a process CREATE event
#define PROCESS_NOTIFY_CREATE_FLAG 0x80000000u

#include <vector>
#include <string>
#include <unordered_set>
#include <Windows.h>
#include <unordered_map>

class Filter
{
public:
	Filter();
	// Start the asynchronous listener worker. Separated from constructor so
	// caller can choose when to start listening (e.g., after UI is populated).
	void StartListener();
	// Check whether the NT image path is in the kernel hook list. The path is
	// passed as an NT-style wide string.
	bool FLTCOMM_CheckHookList(const std::wstring& ntPath);
	// Ask kernel for image path (NT or DOS) of the given PID. Returns true
	// and fills outPath on success.
	bool FLTCOMM_GetImagePathByPid(DWORD pid, std::wstring& outPath);
	// Request kernel to enumerate hook NT paths. Returns true on success and
	// fills out vector with NT paths (empty list if none).
	bool FLTCOMM_EnumHookPaths(std::vector<std::wstring>& outPaths);
	// (Path resolution moved to Helper::ResolveDosPathToNtPath)
	// Add or remove hook entries in kernel (NT path is passed as UTF-16LE)
	bool FLTCOMM_AddHook(const std::wstring& ntPath);
	bool FLTCOMM_RemoveHookByHash(ULONGLONG hash);
	~Filter();
	// Register a callback that will be invoked when the kernel sends
	// a CMD_PROCESS_NOTIFY message. The callback receives the PID, a
	// create flag, and a UTF-16 process name (may be NULL). The context
	// pointer is passed back to the callback (can be used for HWND).
	typedef void(__cdecl *ProcessNotifyCb)(DWORD pid, BOOLEAN create, const wchar_t* name, void* ctx);
	void RegisterProcessNotifyCallback(ProcessNotifyCb cb, void* ctx);
	void UnregisterProcessNotifyCallback();

	// Register a callback invoked when the kernel sends a CMD_APC_QUEUED
	// notification. The callback receives the PID and the ctx pointer.
	typedef void(__cdecl *ProcessApcQueuedCb)(DWORD pid, void* ctx);
	void RegisterApcQueuedCallback(ProcessApcQueuedCb cb, void* ctx);
	void UnregisterApcQueuedCallback();

	// New: request the kernel duplicate the hook-list section into this
	// process and return the handle. Returns true on success and sets outHandle.
	bool FLTCOMM_GetHookSection(HANDLE& outHandle);
	// Map the provided section handle into this process and populate the
	// provided unordered_set with the 64-bit hashes. Returns true on success.
	bool FLTCOMM_MapHookSectionToSet(std::unordered_set<unsigned long long>& outSet);
	// Request kernel to determine if a PID is a WoW64 (32-bit) process. Returns
	// true on success and sets outIsWow64 accordingly.
	bool FLTCOMM_IsProcessWow64(DWORD pid, bool& outIsWow64);
	// Request kernel to determine if a PID is a Protected Process (PP/PP-Lite).
	// Returns true on success and sets outIsProtected accordingly.
	bool FLTCOMM_IsProtectedProcess(DWORD pid, bool& outIsProtected);
	bool FLTCOMM_SetGlobalHookMode(bool enabled);
	// Request kernel to duplicate a process handle for a given PID into this
	// process. Returns true on success and sets outHandle to the duplicated
	// handle (caller must CloseHandle when done). Requires caller privileges.
	bool FLTCOMM_GetProcessHandle(DWORD pid, HANDLE* outHandle);

	bool FLTCOMM_DuplicateHandleKernel(HANDLE sourceHandle, HANDLE* outDuplicated);
	// Write memory into target process using an existing handle
	bool FLTCOMM_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
	// Request kernel to elevate a process to PPL protection (driver-defined semantics).
	// Request kernel to remove PPL protection from a process (driver-defined semantics).
	bool FLTCOMM_UnprotectPpl(DWORD pid);
	// Recover PPL by setting Protection to a saved original value.
	bool FLTCOMM_RecoverPpl(DWORD pid, DWORD protValue);
	// Query current PPL Protection value (driver returns EPROCESS->Protection byte/ULONG)
	bool FLTCOMM_QueryPplProtection(DWORD pid, DWORD& outProt);
	// Ask kernel to log a simple hello-world message for diagnostics. 
	// Request kernel to create a remote thread in target process. Payload: DWORD pid, PVOID startRoutine, PVOID parameter.
	// If outThreadHandle != NULL, kernel will return a duplicated HANDLE (valid in this process) in reply buffer.
	// Optional: if callerHandle != NULL the caller-supplied HANDLE (from this process) will be sent so
	// the driver can use/validate it instead of opening the target by PID. The callerHandle is only
	// meaningful when it refers to the same target process PID and must have appropriate access rights.
	bool FLTCOMM_CreateRemoteThread(DWORD pid, PVOID startRoutine, PVOID parameter, PVOID ntCreateThreadExAddr,
		PVOID extra, HANDLE* outThreadHandle, HANDLE callerHandle);
	// Request kernel to resolve syscall number to kernel function address.
	// Payload: ULONG syscallNumber. On success returns TRUE and sets outAddr.
	bool FLTCOMM_GetSyscallAddr(ULONG syscallNumber, PVOID* outAddr);
	// Request driver to write a DLL path pointer into target process.
	// Payload: DWORD pid; PVOID userWideStringPtr
	// Reply: PVOID returned in reply buffer (placeholder NULL until implemented).
	bool FLTCOMM_WriteDllPathToTargetProcess(DWORD pid, PVOID userWideStringPtr, PVOID* outValue);
    // Request driver to register/unregister an Ob callback. Payload: BOOLEAN registerFlag (1=register,0=unregister)
    // Returns true on success.
    bool FLTCOMM_RegisterObCallback(bool registerFlag);
private:
	HANDLE m_Port = INVALID_HANDLE_VALUE;
	// listener state for async messages
	HANDLE m_WorkExitEvent = NULL; // signaled when queued worker exits
	volatile bool m_StopListener = false;
	volatile bool m_ListenerStarted = false;
    HANDLE m_ListenerEvent = NULL; // event used with OVERLAPPED FilterGetMessage
	ProcessNotifyCb m_ProcessNotifyCb = NULL;
	void* m_ProcessNotifyCtx = NULL;

	// APC queued callback and context
	ProcessApcQueuedCb m_ApcQueuedCb = NULL;
	void* m_ApcQueuedCtx = NULL;
	void RunListenerLoop();
	static VOID NTAPI ListenerWorkItem(PVOID context, PVOID systemArg1, PVOID systemArg2);

	struct ProcKey {
		DWORD pid;
		ULONGLONG creationTime; // FILETIME as 64-bit
	};
	struct ProcKeyHash {
		size_t operator()(const ProcKey& k) const noexcept {
			return ((size_t)k.pid * 1315423911u) ^ (size_t)k.creationTime;
		}
	};
	struct ProcKeyEq {
		bool operator()(const ProcKey& a, const ProcKey& b) const noexcept {
			return a.pid == b.pid && a.creationTime == b.creationTime;
		}
	};
	std::unordered_map<ProcKey, HANDLE, ProcKeyHash, ProcKeyEq> m_handleCache;
	static bool QueryCreationTime(HANDLE hProc, ULONGLONG& outCreationTime);
};
#endif
