#define UNICODE

#include <windows.h>
#include <wchar.h>

#include "setup.h"

UCHAR StackFrameHeader[] = {0x8B, 0xFF, 0x55, 0x8B, 0xEC};

int WINAPI WinMain (
    HINSTANCE hInstance,	// handle to current instance
    HINSTANCE hPrevInstance,	// handle to previous instance
    LPSTR lpCmdLine,	// pointer to command line
    int nCmdShow 	// show state of window
   )
{
    return Startup();
}

int
Startup (
    void
)
{
    if (!CheckOS())
    {
        MessageBox(NULL, L"Sorry, but the current version of Windows is not supported by this software.", L"NT Locale Emulator Revolution Beta Setup", MB_OK | MB_ICONSTOP);
        
        return -1;
    }
    
    switch (MessageBox(NULL, L"Welcome to the NT locale Emulator Revolution Setup Wizard\n\nThe current version of NTLER is 0.6 beta.\nBefore you install the software, make sure you have read the guide carefully.\nPress Yes button to install NTLER,\nor No to uninstall it.", L"NT Locale Emulator Revolution Beta Setup", MB_YESNOCANCEL))
    {
        case IDYES:
        
            if (Install())
            {
                MessageBox(NULL, L"An error was occurred.", L"NT Locale Emulator Revolution Beta Setup", MB_OK | MB_ICONSTOP);
                
                Uninstall(TRUE);
            }
            
            break;
            
        case IDNO:
        
            return Uninstall(FALSE);
    }
    
    return 0;
}

BOOLEAN
CheckOS (
    void
)
{
    BOOL wow64;
    WINAPI_IsWow64Process IsWow64Process;
    OSVERSIONINFOEX_ osver;
    DWORD vernum;
    
    osver.dwOSVersionInfoSize = sizeof(osver);
    
    GetVersionEx((LPOSVERSIONINFO)&osver);
    
    vernum = (osver.dwMajorVersion << 16) + osver.dwMinorVersion | (osver.wProductType == VER_NT_WORKSTATION ? 0 : 0x80000000);
    
    if (vernum != VER_WINXP && vernum != VER_WIN2K3 && vernum != VER_WIN7)
        return FALSE;
    
    IsWow64Process = (WINAPI_IsWow64Process)GetProcAddress(GetModuleHandle(L"kernel32"), "IsWow64Process");
    
    if (!IsWow64Process)
        return FALSE;
    
    if (!IsWow64Process(GetCurrentProcess(), &wow64))
        return FALSE;
    
    if (wow64)
        return FALSE;
    
    if (!CheckStackFrame(IsWow64Process))
        return FALSE;
    
    return TRUE;
}

int
ForceCopy (
    PWSTR ToPath,
    PWSTR FromPath
)
{
    TCHAR path[MAX_PATH];
    
    if (CopyFile(FromPath, ToPath, FALSE))
        return ERROR_SUCCESS;
    
    if (GetLastError() == ERROR_FILE_NOT_FOUND)
        return ERROR_FILE_NOT_FOUND;
    
    wcscpy(path, ToPath);
    wcscat(path, L"_deleting");
    
    if (!MoveFile(ToPath, path))
        return GetLastError();
    
    if (!MoveFileEx(path, NULL, MOVEFILE_DELAY_UNTIL_REBOOT))
        return GetLastError();
    
    if (CopyFile(FromPath, ToPath, FALSE))
        return ERROR_SUCCESS;
    
    return GetLastError();
}

int
UpdateRegistry (
    HKEY MainKey
)
{
    int retval;
    DWORD version = 20005;
    LPTSTR pFileNamePart;
    TCHAR cAppDir[MAX_PATH];
    TCHAR cSysDir[MAX_PATH];
    
    GetModuleFileName(NULL, cSysDir, MAX_PATH);
    
    GetFullPathName(cSysDir, MAX_PATH, cAppDir, &pFileNamePart);
    
    *pFileNamePart = 0;
    
    retval = RegSetValueEx(MainKey,
                           L"Version",
                           0,
                           REG_DWORD,
                           (const LPBYTE)&version,
                           sizeof(DWORD));
    
    if (retval)
        return retval;
    
    retval = RegSetValueEx(MainKey,
                           L"Location",
                           0,
                           REG_SZ,
                           (const LPBYTE)cAppDir,
                           (wcslen(cAppDir) + 1) * sizeof(WCHAR));
    
    return retval;
}

int
Update (
    int Version,
    HKEY MainKey
)
{
    int retval;
    LPTSTR pFileNamePart;
    TCHAR cAppDir[MAX_PATH];
    TCHAR cSysDir[MAX_PATH];
    TCHAR cSrcPath[MAX_PATH];
    TCHAR cDestPath[MAX_PATH];

    GetModuleFileName(NULL, cSysDir, MAX_PATH);
    
    GetFullPathName(cSysDir, MAX_PATH, cAppDir, &pFileNamePart);
    
    *pFileNamePart = 0;
    
    GetSystemDirectory(cSysDir, MAX_PATH);
    
    wcscpy(cDestPath, cSysDir);
    wcscat(cDestPath, L"\\");
    wcscat(cDestPath, L"NTLEA_UsrModHlpDll_x86.dll");
    
    wcscpy(cSrcPath, cAppDir);
    wcscat(cSrcPath, L"NTLEA_UsrModHlpDll_x86.dll");
    
    retval = ForceCopy(cDestPath, cSrcPath);
    
    if (retval)
        return retval;
    
    retval = UpdateRegistry(MainKey);
    
    MessageBox(NULL, L"The update has been completed, reboot is required to take effect.", L"NT Locale Emulator Revolution Beta Setup", MB_OK);
    
    return retval;
}

int
Install (
    void
)
{
    int retval;
    HKEY key, mainkey;
    DWORD exitcode, version, datasize;
    LPTSTR pFileNamePart;
    STARTUPINFO startinfo;
    PROCESS_INFORMATION procinfo;
    TCHAR cAppDir[MAX_PATH];
    TCHAR cSysDir[MAX_PATH];
    TCHAR cSrcPath[MAX_PATH];
    TCHAR cDestPath[MAX_PATH];
    
    retval = RegCreateKeyEx(HKEY_LOCAL_MACHINE,
                            L"System\\CurrentControlSet\\Control\\NTLEA",
                            0,
                            NULL,
                            REG_OPTION_NON_VOLATILE,
                            KEY_ALL_ACCESS,
                            NULL,
                            &mainkey,
                            NULL);
    
    if (retval)
        return retval;
    
    datasize = sizeof(DWORD);
    
    retval = RegQueryValueEx(mainkey,
                             L"Version",
                             NULL,
                             NULL,
                             (LPBYTE)&version,
                             &datasize);
    
    if (retval == ERROR_SUCCESS)
    {
        if (version == 99999)
        {
            return Update(version, mainkey);
        }
        else
        {
            MessageBox(NULL, L"You have already installed NTLER in your system.", L"NT Locale Emulator Revolution Beta Setup", MB_OK);
        }
        
        return 0;
    }
    
    GetModuleFileName(NULL, cSysDir, MAX_PATH);
    
    GetFullPathName(cSysDir, MAX_PATH, cAppDir, &pFileNamePart);
    
    *pFileNamePart = 0;
    
    GetSystemDirectory(cSysDir, MAX_PATH);
    
    wcscpy(cSrcPath, cSysDir);
    wcscat(cDestPath, L"\\");
    wcscat(cSrcPath, L"ntoskrnl.exe");
    
    wcscpy(cSrcPath, cAppDir);
    wcscat(cSrcPath, L"NTLEA_UsrModHlpDll_x86.dll");
    
    wcscpy(cDestPath, cSysDir);
    wcscat(cDestPath, L"\\");
    wcscat(cDestPath, L"NTLEA_UsrModHlpDll_x86.dll");
    
    retval = CopyFile(cSrcPath, cDestPath, FALSE);
    
    if (!retval)
        return GetLastError();
    
    wcscpy(cSrcPath, cAppDir);
    wcscat(cSrcPath, L"NTLEA_BootCfgDrv_x86.sys");
    
    wcscpy(cDestPath, cSysDir);
    wcscat(cDestPath, L"\\Drivers\\");
    wcscat(cDestPath, L"NTLEA_BootCfgDrv_x86.sys");
    
    retval = CopyFile(cSrcPath, cDestPath, FALSE);
    
    if (!retval)
        return GetLastError();
    
    retval = InstallService(L"NTLEA_BootCfgDrv", cDestPath, L"Base", 1, 0);
    
    if (retval)
        return retval;
    
    wcscpy(cSrcPath, cAppDir);
    wcscat(cSrcPath, L"NTLEA_MulLocEmuDrv_x86.sys");
    
    wcscpy(cDestPath, cSysDir);
    wcscat(cDestPath, L"\\Drivers\\");
    wcscat(cDestPath, L"NTLEA_MulLocEmuDrv_x86.sys");
    
    retval = CopyFile(cSrcPath, cDestPath, FALSE);
    
    if (!retval)
        return GetLastError();
    
    retval = InstallService(L"NTLEA_MulLocEmuDrv", cDestPath, L"Base", 1, 1);
    
    if (retval)
        return retval;
    
    wcscpy(cDestPath, cAppDir);
    wcscat(cDestPath, L"NtleaDaemon.exe");
    
    retval = RegCreateKeyEx(HKEY_LOCAL_MACHINE,
                            L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                            0,
                            NULL,
                            REG_OPTION_NON_VOLATILE,
                            KEY_SET_VALUE,
                            NULL,
                            &key,
                            NULL);
    
    if (retval)
        return retval;
    
    retval = RegSetValueEx(key,
                           L"NTLER Daemon",
                           0,
                           REG_SZ,
                           (const LPBYTE)&cDestPath[0],
                           (wcslen(cDestPath) + 1) * sizeof(WCHAR));
    
    if (retval)
        return retval;
    
    wcscpy(cSrcPath, cAppDir);
    wcscat(cSrcPath, L"NTLEA_Menu.dll");
    
    wsprintf(cDestPath, L"regasm \"%s\" /codebase", cSrcPath);
    
    startinfo.cb = sizeof(STARTUPINFO);
    
    GetStartupInfo(&startinfo);
    
    if (!CreateProcess(NULL,
                       cDestPath,
                       NULL,
                       NULL,
                       FALSE,
                       0,
                       NULL,
                       NULL,
                       &startinfo,
                       &procinfo))
        return GetLastError();
    
    WaitForSingleObject(procinfo.hProcess, INFINITE);
    
    GetExitCodeProcess(procinfo.hProcess, &exitcode);
    
    if (exitcode)
        return exitcode;
    
    retval = UpdateRegistry(mainkey);
    
    if (retval)
        return retval;
    
    MessageBox(NULL, L"The installation has been completed, reboot is required to take effect.", L"NT Locale Emulator Revolution Beta Setup", MB_OK);
    
    return 0;
}

int
Uninstall (
    BOOLEAN Silent
)
{
    HKEY key;
    LPTSTR pFileNamePart;
    STARTUPINFO startinfo;
    PROCESS_INFORMATION procinfo;
    TCHAR cAppDir[MAX_PATH];
    TCHAR cSysDir[MAX_PATH];
    TCHAR cSrcPath[MAX_PATH];
    TCHAR cDestPath[MAX_PATH];
    
    GetModuleFileName(NULL, cSysDir, MAX_PATH);
    
    GetFullPathName(cSysDir, MAX_PATH, cAppDir, &pFileNamePart);
    
    *pFileNamePart = 0;
    
    GetSystemDirectory(cSysDir, MAX_PATH);
    
    wcscpy(cDestPath, cSysDir);
    wcscat(cDestPath, L"\\");
    wcscat(cDestPath, L"NTLEA_UsrModHlpDll_x86.dll");
    
    MoveFileEx(cDestPath, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
    
    wcscpy(cDestPath, cSysDir);
    wcscat(cDestPath, L"\\Drivers\\");
    wcscat(cDestPath, L"NTLEA_BootCfgDrv_x86.sys");
    
    MoveFileEx(cDestPath, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
    
    UninstallService(L"NTLEA_BootCfgDrv");
    
    wcscpy(cDestPath, cSysDir);
    wcscat(cDestPath, L"\\Drivers\\");
    wcscat(cDestPath, L"NTLEA_MulLocEmuDrv_x86.sys");
    
    MoveFileEx(cDestPath, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
    
    UninstallService(L"NTLEA_MulLocEmuDrv");
    
    if (RegCreateKeyEx(HKEY_LOCAL_MACHINE,
                       L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                       0,
                       NULL,
                       REG_OPTION_NON_VOLATILE,
                       KEY_SET_VALUE,
                       NULL,
                       &key,
                       NULL) == ERROR_SUCCESS)
    {
        RegDeleteValue(key, L"NTLER Daemon");
    }
    
    RegDeleteKey(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\NTLEA");
    
    if (!Silent)
    {
        wcscpy(cSrcPath, cAppDir);
        wcscat(cSrcPath, L"NTLEA_Menu.dll");
        
        wsprintf(cDestPath, L"regasm \"%s\" /unregister", cSrcPath);
        
        startinfo.cb = sizeof(STARTUPINFO);
        
        GetStartupInfo(&startinfo);
        
        CreateProcess(NULL,
                      cDestPath,
                      NULL,
                      NULL,
                      FALSE,
                      0,
                      NULL,
                      NULL,
                      &startinfo,
                      &procinfo);
        
        MessageBox(NULL, L"The uninstallation has been completed, reboot is required to take effect.", L"NT Locale Emulator Revolution Beta Setup", MB_OK);
    }
    
    return 0;
}

int
UninstallService (
    LPTSTR pszServiceName
)
{
    int retval;
    SC_HANDLE hService, hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    
    if (!hSCM)
        return GetLastError();
    
    hService = OpenService(hSCM,
                           pszServiceName,
                           SERVICE_ALL_ACCESS);
    
    if (!hService)
        return GetLastError();
    
    retval = DeleteService(hService);
    
    CloseServiceHandle(hService);
    
    CloseServiceHandle(hSCM);
    
    return retval;
}

DWORD
InstallService (
    LPTSTR pszServiceName,
    LPTSTR pszFilePath,
    LPTSTR pszGroup,
    DWORD dwType,
    DWORD dwStart
)
{
    SC_HANDLE hService, hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    
    if (!hSCM)
        return GetLastError();
    
    hService = CreateService(hSCM,
                             pszServiceName,
                             NULL,
                             SERVICE_ALL_ACCESS,
                             dwType,
                             dwStart,
                             0,
                             pszFilePath,
                             pszGroup,
                             NULL,
                             NULL,
                             NULL,
                             NULL);
    
    if (!hService)
        return GetLastError();
    
    CloseServiceHandle(hService);
    
    CloseServiceHandle(hSCM);
    
    return ERROR_SUCCESS;
}

BOOLEAN
CheckStackFrame (
    PVOID RoutineEntry
)
{
    SIZE_T i;
    
    for (i = 0 ; i < sizeof(StackFrameHeader) ; i++)
    {
        if (((PUCHAR)RoutineEntry)[i] != StackFrameHeader[i])
            return FALSE;
    }
    
    return TRUE;
};