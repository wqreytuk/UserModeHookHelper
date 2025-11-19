#include "pch.h"
#include "PidInput.h"
#include <string>

// Implementation: Create a simple modal dialog using CreateDialog/DialogBox
// We'll register a dialog class dynamically and use a simple window as dialog.

struct PidDlgCtx {
	HWND owner;
	HWND hwndDlg;
	HWND hwndEdit;
	DWORD pid;
	BOOL ok;
};

static LRESULT CALLBACK PidDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
	PidDlgCtx* ctx = (PidDlgCtx*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
	switch (msg) {
	case WM_CREATE: {
		ctx = (PidDlgCtx*)((LPCREATESTRUCT)lParam)->lpCreateParams;
		SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)ctx);
		ctx->hwndDlg = hWnd;
		// Create static text
		CreateWindowW(L"STATIC", L"Enter target PID:", WS_VISIBLE | WS_CHILD, 10, 10, 200, 20, hWnd, NULL, NULL, NULL);
		ctx->hwndEdit = CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_NUMBER, 10, 35, 200, 22, hWnd, NULL, NULL, NULL);
		CreateWindowW(L"BUTTON", L"OK", WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON, 40, 70, 70, 24, hWnd, (HMENU)1, NULL, NULL);
		CreateWindowW(L"BUTTON", L"Cancel", WS_VISIBLE | WS_CHILD, 130, 70, 70, 24, hWnd, (HMENU)2, NULL, NULL);
		SendMessageW(ctx->hwndEdit, EM_SETLIMITTEXT, 10, 0);
		SetFocus(ctx->hwndEdit);
		return 0;
	}
	case WM_COMMAND: {
		int id = LOWORD(wParam);
		if (id == 1) { // OK
			wchar_t buf[64] = { 0 };
			GetWindowTextW(ctx->hwndEdit, buf, _countof(buf));
			if (buf[0] != L'\0') {
				DWORD v = (DWORD)wcstoul(buf, NULL, 10);
				if (v != 0) {
					ctx->pid = v;
					ctx->ok = TRUE;
					EndDialog(hWnd, 1);
					return 0;
				}
			}
			MessageBoxW(hWnd, L"Please enter a valid PID (non-zero).", L"Invalid PID", MB_OK | MB_ICONWARNING);
		}
		else if (id == 2) { // Cancel
			ctx->ok = FALSE;
			EndDialog(hWnd, 0);
		}
		return 0;
	}
	case WM_CLOSE:
		EndDialog(hWnd, 0);
		return 0;
	}
	return DefWindowProc(hWnd, msg, wParam, lParam);
}

BOOL ShowPidInputDialog(HWND owner, DWORD* outPid) {
	if (!outPid) return FALSE;
	const wchar_t* clsName = L"UMHH_PidInputClass";
	WNDCLASSEXW wc = { 0 };
	wc.cbSize = sizeof(wc);
	wc.lpfnWndProc = DefWindowProcW;
	wc.hInstance = GetModuleHandle(NULL);
	wc.lpszClassName = clsName;
	// Register a temporary class if not exists
	RegisterClassExW(&wc);

	// Create dialog window using DialogBoxParam with a custom dialog proc via CreateDialogIndirect is complex; simpler: create a modal window and run a message loop.
	// We'll use DialogBoxParam with a small template built at runtime using CreateDialogIndirectParam requires template; to keep simple, use CreateDialogParam with a dummy resource ID won't work. Instead, use CreateWindow and a modal loop.

	PidDlgCtx ctx = { 0 };
	ctx.owner = owner;
	ctx.pid = 0;
	ctx.ok = FALSE;

	HWND hDlg = CreateWindowExW(WS_EX_DLGMODALFRAME, clsName, L"Enter PID", WS_POPUP | WS_CAPTION | WS_SYSMENU, CW_USEDEFAULT, CW_USEDEFAULT, 240, 140, owner, NULL, GetModuleHandle(NULL), &ctx);
	if (!hDlg) return FALSE;

	// Subclass our window to use PidDlgProc by setting GWLP_WNDPROC
	SetWindowLongPtrW(hDlg, GWLP_USERDATA, (LONG_PTR)&ctx);
	WNDPROC orig = (WNDPROC)SetWindowLongPtrW(hDlg, GWLP_WNDPROC, (LONG_PTR)PidDlgProc);

	// Center over owner
	if (owner) {
		RECT rcOwner; GetWindowRect(owner, &rcOwner);
		RECT rc; GetWindowRect(hDlg, &rc);
		int w = rc.right - rc.left; int h = rc.bottom - rc.top;
		int x = rcOwner.left + ((rcOwner.right - rcOwner.left) - w) / 2;
		int y = rcOwner.top + ((rcOwner.bottom - rcOwner.top) - h) / 2;
		SetWindowPos(hDlg, NULL, x, y, 0, 0, SWP_NOZORDER | SWP_NOSIZE);
	}

	ShowWindow(hDlg, SW_SHOW);
	// Modal message loop
	MSG msg;
	BOOL done = FALSE;
	while (!done) {
		if (!GetMessageW(&msg, NULL, 0, 0)) break;
		if (IsDialogMessage(hDlg, &msg)) {
			// processed
		}
		else {
			TranslateMessage(&msg);
			DispatchMessageW(&msg);
		}
		// If our dialog was destroyed, exit
		if (!IsWindow(hDlg)) break;
	}

	if (ctx.ok) {
		*outPid = ctx.pid;
		return TRUE;
	}
	return FALSE;
}
