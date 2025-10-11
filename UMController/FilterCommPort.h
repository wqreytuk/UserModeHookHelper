#ifndef FILTERCOMMPORT_H
#define FILTERCOMMPORT_H
// Flag used in WM_APP_UPDATE_PROCESS wParam to indicate a process CREATE event
#define PROCESS_NOTIFY_CREATE_FLAG 0x80000000u
class Filter
{
public:
	Filter();
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
	// a CMD_PROCESS_NOTIFY message. The context pointer will be passed
	// back to the callback and may be used to carry a HWND for posting.
	typedef void(__cdecl *ProcessNotifyCb)(DWORD pid, BOOLEAN create, void* ctx);
	void RegisterProcessNotifyCallback(ProcessNotifyCb cb, void* ctx);
	void UnregisterProcessNotifyCallback();

private:
	HANDLE m_Port = INVALID_HANDLE_VALUE;
	// listener state for async messages
	HANDLE m_WorkExitEvent = NULL; // signaled when queued worker exits
	volatile bool m_StopListener = false;
	ProcessNotifyCb m_ProcessNotifyCb = NULL;
	void* m_ProcessNotifyCtx = NULL;
	void RunListenerLoop();
	static VOID NTAPI ListenerWorkItem(PVOID context, PVOID systemArg1, PVOID systemArg2);
};
#endif