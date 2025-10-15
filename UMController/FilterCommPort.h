#ifndef FILTERCOMMPORT_H
#define FILTERCOMMPORT_H
// Flag used in WM_APP_UPDATE_PROCESS wParam to indicate a process CREATE event
#define PROCESS_NOTIFY_CREATE_FLAG 0x80000000u
class Filter
{
public:
	Filter();
	// Start the asynchronous listener worker. Separated from constructor so
	// caller can choose when to start listening (e.g., after UI is populated).
	void StartListener();
	// Check whether the NT image path is in the kernel hook list. The path is
	// passed as an NT-style wide string.
	boolean FLTCOMM_CheckHookList(const std::wstring& ntPath);
	// Ask kernel for image path (NT or DOS) of the given PID. Returns true
	// and fills outPath on success.
	bool FLTCOMM_GetImagePathByPid(DWORD pid, std::wstring& outPath);
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
};
#endif