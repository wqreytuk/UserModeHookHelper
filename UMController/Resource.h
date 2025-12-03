//{{NO_DEPENDENCIES}}
// Microsoft Visual C++ generated include file.
// Used by UMController.rc
//
#define IDM_ABOUTBOX                    0x0010
#define IDD_ABOUTBOX                    100
#define IDS_ABOUTBOX                    101
#define IDD_UMCONTROLLER_DIALOG         102
#define IDR_MAINFRAME                   128
#define IDR_MAIN_MENU                   130
#define IDC_LIST_PROC                   1004
#define IDC_EDIT1                       1005
#define IDC_EDIT_SEARCH                 1005

#define ID_MENU_ADD_HOOK       40001
#define ID_MENU_REMOVE_HOOK    40002
#define ID_MENU_INJECT_DLL     40003
// Force Inject context menu (invokes Helper::ForceInject when allowed)
#define ID_MENU_FORCE_INJECT   40010
// Early-break marking context menu
#define ID_MENU_MARK_EARLY_BREAK 40008
#define ID_MENU_UNMARK_EARLY_BREAK 40009
// Context-menu remove (single selected process) — separate from Tools->Remove
#define ID_MENU_REMOVE_HOOK_SINGLE 40005
// Add from executable via Tools menu (distinct from context-menu add-by-process)
#define ID_MENU_ADD_EXE        40004
// Clear ETW log via Tools menu
#define ID_MENU_CLEAR_ETW       40006
#define ID_MENU_OPEN_ETW_LOG     40007
// Extra menu command
#define ID_MENU_EXTRA_ENABLE_GLOBAL_HOOK_MODE 40020
#define ID_MENU_EXTRA_SELFDEFENSE       40022
#define ID_TOOLS_ADD_WHITELIST         40031
#define ID_TOOLS_REMOVE_WHITELIST      40032
// Plugin menu base (reserve a small range for plugin items)
#define ID_MENU_PLUGINS_BASE   41000
#define ID_MENU_PLUGINS        41001
// Plugin control commands
#define ID_MENU_PLUGIN_REFRESH 41050
#define ID_MENU_PLUGIN_UNLOAD_ALL 41051
// Menu resource for dialog Tools menu
#define IDR_TOOLS_MENU         129
#define IDD_REMOVE_HOOK_DLG    140
#define IDD_HOOK_PROC_DLG       141
// Whitelist removal dialog and controls
#define IDD_REMOVE_WHITELIST_DLG 142
#define IDC_LIST_WHITELIST       1022

#define IDC_BTN_HOOK            1006
// Hook dialog new controls
#define IDC_LIST_MODULES         1010
#define IDC_EDIT_OFFSET          1011
#define IDC_EDIT_DIRECT          1012
#define IDC_STATIC_MODULE        1013
#define IDC_STATIC_OFFSET        1014
#define IDC_STATIC_DIRECT        1015
#define IDC_BTN_APPLY_HOOK       1016
#define IDC_PROGRESS_STARTUP      1017
#define IDC_STATIC_STARTUP_PCT     1018
#define IDC_STATIC_HINT           1019


// About dialog hyperlink control
#define IDC_SYSLINK_SITE          1020

// Next default values for new objects
// 
#ifdef APSTUDIO_INVOKED
#ifndef APSTUDIO_READONLY_SYMBOLS
#define _APS_NEXT_RESOURCE_VALUE        146
#define _APS_NEXT_COMMAND_VALUE         32772
#define _APS_NEXT_CONTROL_VALUE         1023
#define _APS_NEXT_SYMED_VALUE           101
#endif
#endif
