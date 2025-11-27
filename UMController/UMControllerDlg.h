
// UMControllerDlg.h : header file
//

#pragma once
#include <vector>
#include <string>
#include <algorithm>
#include <tlhelp32.h>
#include "FilterCommPort.h"
#include <unordered_map>
#include <thread>
#include <unordered_set>
#include "ProcessManager.h"
#include <functional>

// CUMControllerDlg dialog
class CUMControllerDlg : public CDialogEx
{
	// Construction
public:
	virtual BOOL PreCreateWindow(CREATESTRUCT& cs);
	CUMControllerDlg(CWnd* pParent = nullptr);	// standard constructor

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_UMCONTROLLER_DIALOG };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation

protected:
	HICON m_hIcon;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	virtual BOOL PreTranslateMessage(MSG* pMsg);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg void OnAddHook();
	afx_msg void OnRemoveHook();
	afx_msg void OnInjectDll();
	afx_msg void OnAddExecutableToHookList();
	afx_msg void OnRemoveExecutablesFromHookList();
	afx_msg void OnClearEtwLog();
	afx_msg void OnOpenEtwLog();
	// Help menu handlers
	afx_msg void OnHelpAbout();
	DECLARE_MESSAGE_MAP()
public:
	void LoadProcessList();
	void FilterProcessList(const std::wstring& filter);

	// Query whether Global Hook Mode is enabled (persisted toggle)
	bool IsGlobalHookModeEnabled() const { return m_globalHookMode; }


	afx_msg void OnEnChangeEditSearch();
	afx_msg void OnNMRClickListProc(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnLvnColumnclickListProc(NMHDR *pNMHDR, LRESULT *pResult);
    afx_msg LRESULT OnUpdateProcess(WPARAM wParam, LPARAM lParam);
	afx_msg void OnNMDblclkListProc(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnMarkEarlyBreak();
	afx_msg void OnUnmarkEarlyBreak();
	afx_msg void OnForceInject();
	afx_msg void OnDestroy();
    afx_msg LRESULT OnHookDlgDestroyed(WPARAM wParam, LPARAM lParam);
	afx_msg void OnSize(UINT nType, int cx, int cy);
	// Removed obsolete OnTimer; enumeration-only mode no longer uses it.
	afx_msg void OnToggleGlobalHookMode();
	afx_msg LRESULT OnApplyGlobalHookMenu(WPARAM wParam, LPARAM lParam);
    
private: 
	Filter m_Filter;
	CListCtrl m_ProcListCtrl;
	std::wstring m_CurrentFilterString;
	CProgressCtrl m_StartupProgress;
	DWORD m_NtCreateThreadExSyscallNum;
	CStatic m_StartupPct;
	CMenu m_Menu;
	HMODULE m_hHookUiDll = NULL; // dynamic HookUI DLL handle
	typedef BOOL (WINAPI *PFN_ShowHookDialog)(HWND, DWORD, const wchar_t*, struct IHookServices*);
	PFN_ShowHookDialog m_pfnShowHookDialog = nullptr; // resolved factory
	bool CheckHookList(const std::wstring& imagePath);
    afx_msg LRESULT OnFatalMessage(WPARAM wParam, LPARAM lParam);
	// Periodic rescan state
	HANDLE m_RescanEvent = NULL;
	std::thread m_RescanThread;
	unsigned m_RescanIntervalMs = 30000; // default 30s
	// Sorting state
	int m_SortColumn = 0;
	bool m_SortAscending = true;
	static int CALLBACK ProcListCompareFunc(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort);

	// Startup progress state (snapshot-based)
	bool m_StartupInProgress = false;
	size_t m_TotalStartupPids = 0; // total processes enumerated in initial snapshot
	// Session composite key cache (PID + creation time)
	struct ProcKey {
		DWORD pid{};
		FILETIME createTime{}; // 64-bit value via High/Low
	};
	struct ProcKeyHash {
		size_t operator()(ProcKey const& k) const noexcept {
			// Mix pid and creation time into 64 bits then fold
			unsigned long long ct = (((unsigned long long)k.createTime.dwHighDateTime) << 32) | k.createTime.dwLowDateTime;
			unsigned long long h = ct ^ (unsigned long long)k.pid * 0x9E3779B185EBCA87ULL;
			// final avalanche
			h ^= (h >> 33); h *= 0xff51afd7ed558ccdULL; h ^= (h >> 33); h *= 0xc4ceb9fe1a85ec53ULL; h ^= (h >> 33);
			return (size_t)h;
		}
	};
	struct ProcKeyEq {
		bool operator()(ProcKey const& a, ProcKey const& b) const noexcept {
			return a.pid == b.pid && a.createTime.dwLowDateTime == b.createTime.dwLowDateTime && a.createTime.dwHighDateTime == b.createTime.dwHighDateTime;
		}
	};
	std::unordered_map<ProcKey, std::wstring, ProcKeyHash, ProcKeyEq> m_SessionNtPathCache; // composite key -> NT path
	// Persistent NT path registry cache (hash=NT path) loaded at startup & pruned on completion.
	// Composite registry cache loaded at startup (PID+FILETIME -> NT path)
	std::unordered_map<ProcKey, std::wstring, ProcKeyHash, ProcKeyEq> m_CompositeRegistryCache;
	std::vector<std::tuple<DWORD,DWORD,DWORD,std::wstring>> m_PersistSnapshotEntries; // for writing back
	bool m_BackgroundPersistStarted = false; // background thread launched
	bool m_CachePersisted = false; // composite cache written this session
	// persisted toggle
	bool m_globalHookMode = false;
	// Master DLL scanner guard: ensure scanner started only once
	bool m_MasterDllScannerStarted = false;

	// Cached Early Break marks (lowercased NT paths) to avoid registry hits
	std::unordered_set<std::wstring> m_EarlyBreakSet;
	// Cached forced marks (PID:HIGH:LOW) compacted into 64-bit keys
	std::unordered_set<unsigned long long> m_ForcedSet;

	// Plugin system
	CMenu m_PluginsSubMenu; // submenu showing discovered plugins
	std::unordered_map<int, std::wstring> m_PluginMap; // cmd id -> dll full path
	std::unordered_map<int, HMODULE> m_PluginHandles; // loaded plugin handles
	void ScanAndPopulatePlugins();
	void UnloadAllPlugins();
	afx_msg void OnPluginCommand(UINT nID);
	afx_msg void OnPluginRefresh();
	afx_msg void OnPluginUnloadAll();
	void FinishStartupIfDone(); // persistence only (no UI)
	void CompleteStartupUI(); // UI enable/hide after enumeration completes
	LRESULT OnPostEnumCleanup(WPARAM, LPARAM);
	// Inline resolution now performed in LoadProcessList.
};