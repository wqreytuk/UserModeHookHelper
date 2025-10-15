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
}
