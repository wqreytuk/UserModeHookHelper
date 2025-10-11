#ifndef ETW_H
#define ETW_H
#include <evntprov.h>
static const GUID ProviderGUID =
{ 0x3da12c0, 0x27c2, 0x4d75, { 0x95, 0x3a, 0x2c, 0x4e, 0x66, 0xa3, 0x74, 0x64 } };

#define SIGNALEVENTNAME _T("9527")
// Named event used by EtwTracer to signal the parent process that the
// tracer has successfully started and is ready to receive events.
#define ETW_TRACER_READY_EVENT _T("UMHH_ETW_TRACER_READY_9527")

class ETW {
public:
	~ETW();
	ETW();
	// register etw event
	void Reg();
	void Log(_In_ PCWSTR Format, ...);
	void UnReg();
	void StartTracer();
private:
	REGHANDLE m_ProviderHandle;
	HANDLE m_Event;
};
#endif