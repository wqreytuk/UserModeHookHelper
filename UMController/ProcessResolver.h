// ProcessResolver.h - encapsulate process image resolution and hook checks
#pragma once
#include <vector>
#include <Windows.h>

class Filter;
class CUMControllerDlg;

namespace ProcessResolver {
    // Start background resolver for a list of PIDs (used by LoadProcessList)
    void StartLoaderResolver(CUMControllerDlg* dlg, const std::vector<DWORD>& pids, Filter* filter);

    // Start single-PID resolver (used for create notifications)
    void StartSingleResolver(CUMControllerDlg* dlg, DWORD pid, Filter* filter);

    // Start a short-lived checker invoked after the kernel queues an APC into
    // a target process. This polls for up to 10s to detect whether the
    // master DLL has been loaded and then updates ProcessManager/UI.
    void StartCreateChecker(HWND hwnd, DWORD pid);
}
