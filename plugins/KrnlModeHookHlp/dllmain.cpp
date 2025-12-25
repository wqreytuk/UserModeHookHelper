// dllmain.cpp : Plugin entry for KrnlModeHookHlp.

#include "pch.h"
#include <vector>
#include <string>
#include <CommCtrl.h>
#include "resource.h"
#include "HookServices.h"
#include "KmhhCtx.h"

#pragma comment(lib, "comctl32.lib")

namespace {
    struct HookEntry {
        int id;
        const wchar_t* address;
        const wchar_t* target;
        const wchar_t* state;
    };

    struct KmhhCreateContext {
        HWND parent = nullptr;
        IHookServices* services = nullptr;
    };

    HINSTANCE g_hInstance = nullptr;
    HWND g_hDialog = nullptr;
    IHookServices* g_services = nullptr;

    void EnsureCommonControls() {
        static bool initialized = false;
        if (initialized) return;
        INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_LISTVIEW_CLASSES };
        InitCommonControlsEx(&icc);
        initialized = true;
    }

    void CenterRelativeToParent(HWND hwnd, HWND parent) {
        if (!IsWindow(hwnd)) return;
        RECT rcDlg{}; GetWindowRect(hwnd, &rcDlg);
        int dlgW = rcDlg.right - rcDlg.left;
        int dlgH = rcDlg.bottom - rcDlg.top;
        HMONITOR monitor = MonitorFromWindow(parent && IsWindow(parent) ? parent : hwnd, MONITOR_DEFAULTTONEAREST);
        MONITORINFO mi{ sizeof(mi) };
        if (!GetMonitorInfoW(monitor, &mi)) {
            SystemParametersInfoW(SPI_GETWORKAREA, 0, &mi.rcWork, 0);
        }
        RECT work = mi.rcWork;
        int x = work.left + ((work.right - work.left) - dlgW) / 2;
        int y = work.top + ((work.bottom - work.top) - dlgH) / 2;
        MoveWindow(hwnd, x, y, dlgW, dlgH, FALSE);
    }

    void SetupHookListColumns(HWND list) {
        ListView_SetExtendedListViewStyleEx(list, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES,
            LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
        LVCOLUMNW col{}; col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        col.pszText = const_cast<LPWSTR>(L"Hook ID"); col.cx = 70; col.iSubItem = 0;
        ListView_InsertColumn(list, 0, &col);
        col.pszText = const_cast<LPWSTR>(L"Address"); col.cx = 120; col.iSubItem = 1;
        ListView_InsertColumn(list, 1, &col);
        col.pszText = const_cast<LPWSTR>(L"Target"); col.cx = 150; col.iSubItem = 2;
        ListView_InsertColumn(list, 2, &col);
        col.pszText = const_cast<LPWSTR>(L"State"); col.cx = 80; col.iSubItem = 3;
        ListView_InsertColumn(list, 3, &col);
    }

    void PopulateSampleHooks(HWND list) {
        ListView_DeleteAllItems(list);
        const HookEntry demo[] = {
            { 1, L"nt!NtCreateFile+0x20", L"kmhhhook.sys!HookCreateFile", L"Active" },
            { 2, L"nt!NtQuerySystemInformation+0x8E", L"kmhhhook.sys!HookQueryInfo", L"Pending" },
            { 3, L"dxgkrnl!DxgkSubmitCommand", L"gpu_guard.sys!InterceptSubmit", L"Disabled" }
        };
        for (const auto& entry : demo) {
            LVITEMW item{};
            item.mask = LVIF_TEXT;
            std::wstring idText = std::to_wstring(entry.id);
            item.pszText = const_cast<LPWSTR>(idText.c_str());
            int row = ListView_InsertItem(list, &item);
            ListView_SetItemText(list, row, 1, const_cast<LPWSTR>(entry.address));
            ListView_SetItemText(list, row, 2, const_cast<LPWSTR>(entry.target));
            ListView_SetItemText(list, row, 3, const_cast<LPWSTR>(entry.state));
        }
    }

    void HandleApplySequence(HWND hwnd) {
        // Placeholder logic until real kernel hook application is implemented.
        MessageBoxW(hwnd,
            L"Kernel hook sequence application is not yet implemented."
            L"\nUse this entry point to load and apply your .hookseq plan to kernel hooks.",
            L"Kernel Mode Hook Helper",
            MB_ICONINFORMATION);
    }

    INT_PTR CALLBACK KmhhDialogProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) {
        switch (msg) {
        case WM_INITDIALOG:
        {
            auto* ctx = reinterpret_cast<KmhhCreateContext*>(lParam);
            g_services = ctx ? ctx->services : nullptr;
            HWND hList = GetDlgItem(hDlg, IDC_KMHH_LIST_HOOKS);
            SetupHookListColumns(hList);
            PopulateSampleHooks(hList);
            CenterRelativeToParent(hDlg, ctx ? ctx->parent : nullptr);
            return TRUE;
        }
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
            case IDC_KMHH_BTN_APPLY_SEQ:
                HandleApplySequence(hDlg);
                return TRUE;
            case IDCANCEL:
                DestroyWindow(hDlg);
                return TRUE;
            default:
                break;
            }
            break;
        case WM_CLOSE:
            DestroyWindow(hDlg);
            return TRUE;
        case WM_DESTROY:
            if (g_hDialog == hDlg) g_hDialog = nullptr;
            return TRUE;
        }
        return FALSE;
    }
}

extern "C" __declspec(dllexport) void PluginMain(HWND parentHwnd, IHookServices* services) {
	KmhhCtx_SetHookServices(services);
    EnsureCommonControls();
    if (g_hDialog && IsWindow(g_hDialog)) {
        ShowWindow(g_hDialog, SW_SHOWNORMAL);
        SetForegroundWindow(g_hDialog);
        return;
    }
    KmhhCreateContext ctx{ parentHwnd, services };
    HWND dlg = CreateDialogParamW(g_hInstance, MAKEINTRESOURCEW(IDD_KMHH_DIALOG), parentHwnd, KmhhDialogProc, reinterpret_cast<LPARAM>(&ctx));
    if (!dlg) {
        MessageBoxW(parentHwnd,
            L"Failed to create Kernel Mode Hook Helper dialog.",
            L"KrnlModeHookHlp",
            MB_ICONERROR);
        return;
    }
    g_hDialog = dlg;
    ShowWindow(dlg, SW_SHOWNORMAL);
    UpdateWindow(dlg);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        g_hInstance = hModule;
    }
    else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
        g_hDialog = nullptr;
        g_services = nullptr;
    }
    return TRUE;
}

