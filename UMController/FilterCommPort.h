#ifndef FILTERCOMMPORT_H
#define FILTERCOMMPORT_H
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

private:
	HANDLE m_Port = INVALID_HANDLE_VALUE;
};
#endif