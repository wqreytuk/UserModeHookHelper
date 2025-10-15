// HookActions.h - extracted handlers for context menu and hook actions
#pragma once
#include <Windows.h>
#include <string>

class CUMControllerDlg;
class Filter;
class CListCtrl;

namespace HookActions {
    void HandleNMRClick(CUMControllerDlg* dlg, CListCtrl* list, NMHDR* pNMHDR, LRESULT* pResult);
    void HandleAddHook(CUMControllerDlg* dlg, Filter* filter, CListCtrl* list, int nItem, DWORD pid);
    void HandleRemoveHook(CUMControllerDlg* dlg, Filter* filter, CListCtrl* list, int nItem, DWORD pid);
    void HandleInjectDll(CUMControllerDlg* dlg, Filter* filter, CListCtrl* list, int nItem, DWORD pid);
}
