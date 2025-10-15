#include "pch.h"
#include "HookActions.h"
#include "UMControllerDlg.h"
#include "Helper.h"
#include "FilterCommPort.h"
#include "ProcessManager.h"
#include "UIHelpers.h"
#include "IPC.h"
#include <commdlg.h>
#include "Resource.h"
#include "UMController.h"

using namespace HookActions;

void HookActions::HandleNMRClick(CUMControllerDlg* dlg, CListCtrl* list, NMHDR* pNMHDR, LRESULT* pResult) {
    UNREFERENCED_PARAMETER(pNMHDR);
    int nItem = list->GetNextItem(-1, LVNI_SELECTED);
    if (nItem == -1) return;

    PROC_ITEMDATA packed = (PROC_ITEMDATA)list->GetItemData(nItem);
    DWORD pid = PID_FROM_ITEMDATA(packed);
    ProcessEntry item;
    int idx = -1;
    if (!PM_GetEntryCopyByPid(pid, item, &idx)) return;

    CMenu menu;
    menu.CreatePopupMenu();
    menu.AppendMenu(MF_STRING, ID_MENU_ADD_HOOK, L"Add to Hook List");
    menu.AppendMenu(MF_STRING, ID_MENU_REMOVE_HOOK, L"Remove from Hook List");
    menu.AppendMenu(MF_STRING, ID_MENU_INJECT_DLL, L"Inject DLL");

    DWORD flags = FLAGS_FROM_ITEMDATA(packed);
    bool inHook = (flags & PF_IN_HOOK_LIST) != 0;
    bool dllLoaded = (flags & PF_MASTER_DLL_LOADED) != 0;
    menu.EnableMenuItem(ID_MENU_ADD_HOOK, inHook ? MF_GRAYED : MF_ENABLED);
    menu.EnableMenuItem(ID_MENU_REMOVE_HOOK, inHook ? MF_ENABLED : MF_GRAYED);
    menu.EnableMenuItem(ID_MENU_INJECT_DLL, dllLoaded ? MF_ENABLED : MF_GRAYED);

    CPoint point;
    GetCursorPos(&point);
    menu.TrackPopupMenu(TPM_RIGHTBUTTON, point.x, point.y, dlg);

    if (pResult) *pResult = 0;
}

void HookActions::HandleAddHook(CUMControllerDlg* dlg, Filter* filter, CListCtrl* list, int nItem, DWORD pid) {
    UNREFERENCED_PARAMETER(dlg);
    PROC_ITEMDATA packed = (PROC_ITEMDATA)list->GetItemData(nItem);

    std::wstring ntPath;
    if (!Helper::ResolveProcessNtImagePath(pid, *filter, ntPath)) {
        app.GetETW().Log(L"OnAddHook: failed to resolve NT path for pid %u\n", pid);
        MessageBox(NULL, L"Failed to resolve process image path. The process may have exited.", L"Add Hook", MB_OK | MB_ICONERROR);
        return;
    }

    app.GetETW().Log(L"OnAddHook: adding hook for pid %u ntpath=%s\n", pid, ntPath.c_str());

    bool ok = filter->FLTCOMM_AddHook(ntPath);
    if (!ok) {
        app.GetETW().Log(L"OnAddHook: FLTCOMM_AddHook failed for %s\n", ntPath.c_str());
        MessageBox(NULL, L"Failed to add hook entry in kernel.", L"Add Hook", MB_OK | MB_ICONERROR);
        return;
    }

    PM_UpdateEntryFields(pid, ntPath, true, L"");

    bool is64 = false; Helper::IsProcess64(pid, is64);
    bool dllLoaded = false; Helper::IsModuleLoaded(pid, is64 ? MASTER_X64_DLL_BASENAME : MASTER_X86_DLL_BASENAME, dllLoaded);
    DWORD flags = PF_IN_HOOK_LIST;
    if (dllLoaded) flags |= PF_MASTER_DLL_LOADED;
    if (is64) flags |= PF_IS_64BIT;
    PROC_ITEMDATA newPacked = MAKE_ITEMDATA(pid, flags);
    list->SetItemData(nItem, (DWORD_PTR)newPacked);
    list->SetItemText(nItem, 2, FormatHookColumn(newPacked, true).c_str());

    MessageBox(NULL, L"Process added to hook list.", L"Add Hook", MB_OK | MB_ICONINFORMATION);
}

void HookActions::HandleRemoveHook(CUMControllerDlg* dlg, Filter* filter, CListCtrl* list, int nItem, DWORD pid) {
    UNREFERENCED_PARAMETER(dlg);
    std::wstring ntPath;
    if (!Helper::ResolveProcessNtImagePath(pid, *filter, ntPath)) {
        app.GetETW().Log(L"OnRemoveHook: failed to resolve NT path for pid %u\n", pid);
        MessageBox(NULL, L"Failed to resolve process image path. The process may have exited.", L"Remove Hook", MB_OK | MB_ICONERROR);
        return;
    }

    const UCHAR* bytes = reinterpret_cast<const UCHAR*>(ntPath.c_str());
    size_t bytesLen = ntPath.size() * sizeof(wchar_t);
    ULONGLONG hash = (ULONGLONG)Helper::GetNtPathHash(bytes, bytesLen);

    app.GetETW().Log(L"OnRemoveHook: removing hook for pid %u ntpath=%s hash=0x%I64x\n", pid, ntPath.c_str(), hash);

    bool ok = filter->FLTCOMM_RemoveHookByHash(hash);
    if (!ok) {
        app.GetETW().Log(L"OnRemoveHook: FLTCOMM_RemoveHookByHash failed for hash=0x%I64x\n", hash);
        MessageBox(NULL, L"Failed to remove hook from kernel.", L"Remove Hook", MB_OK | MB_ICONERROR);
        return;
    }

    PM_UpdateEntryFields(pid, ntPath, false, L"");

    bool is64 = false; Helper::IsProcess64(pid, is64);
    bool dllLoaded = false; Helper::IsModuleLoaded(pid, is64 ? MASTER_X64_DLL_BASENAME : MASTER_X86_DLL_BASENAME, dllLoaded);
    DWORD flags = 0;
    if (dllLoaded) flags |= PF_MASTER_DLL_LOADED;
    if (is64) flags |= PF_IS_64BIT;
    PROC_ITEMDATA newPacked = MAKE_ITEMDATA(pid, flags);
    list->SetItemData(nItem, (DWORD_PTR)newPacked);
    list->SetItemText(nItem, 2, FormatHookColumn(newPacked, false).c_str());

    MessageBox(NULL, L"Process removed from hook list.", L"Remove Hook", MB_OK | MB_ICONINFORMATION);
}

void HookActions::HandleInjectDll(CUMControllerDlg* dlg, Filter* filter, CListCtrl* list, int nItem, DWORD pid) {
    UNREFERENCED_PARAMETER(dlg);
    wchar_t szFile[MAX_PATH] = {0};
    OPENFILENAME ofn = {0};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = L"DLL Files\0*.dll\0All Files\0*.*\0";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    ofn.lpstrTitle = L"Select DLL to inject";

    if (!GetOpenFileName(&ofn)) return;

    BOOL ok = IPC_SendInject(pid, szFile);
    if (ok) {
        app.GetETW().Log(L"IPC_SendInject succeeded for pid %u dll %s\n", pid, szFile);
        MessageBox(NULL, L"Injection request sent.", L"Inject DLL", MB_OK | MB_ICONINFORMATION);
    } else {
        app.GetETW().Log(L"IPC_SendInject failed for pid %u dll %s\n", pid, szFile);
        MessageBox(NULL, L"Failed to send injection request.", L"Inject DLL", MB_OK | MB_ICONERROR);
    }
}
