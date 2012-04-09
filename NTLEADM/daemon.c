#define UNICODE

#include <windows.h>
#include <wchar.h>

#include "daemon.h"


FILE_LIST File2 = {
    NULL,
    LOCATION_DRIVERS,
    FILE_2
};

FILE_LIST File1 = {
    &File2,
    LOCATION_DRIVERS,
    FILE_1
};

FILE_LIST File0 = {
    &File1,
    LOCATION_SYSTEM32,
    FILE_0
};

SERVICE_LIST Service1 = {
    NULL,
    SERVICE_1
};

SERVICE_LIST Service0 = {
    &Service1,
    SERVICE_0
};


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
    int error;
    PFILE_LIST FileList = &File0;
    PSERVICE_LIST ServiceList = &Service1;  // Service0
    DWORD status;
    LPTSTR buf;
    TCHAR text[1024];
    
    CreateMutex(NULL, FALSE, GLOBAL_MUTEX_NAME);
    
    if (GetLastError())
        return 0;
    
    error = CheckFile(&FileList);
    
    if (error)
    {
        if (error == ERROR_ACCESS_DENIED)
            return 0;
        
        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                      NULL,
                      error,
                      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                      (LPTSTR)&buf,
                      0,
                      NULL);
        
        wsprintf(text, ERROR_FORMAT, ERROR_FILE, FileList->FileName, buf);
        
        MessageBox(NULL, text, ERROR_TITLE, MB_OK | MB_ICONSTOP);
        
        return -1;
    }
    
    error = CheckService(&ServiceList, &status);
    
    if (error)
    {
        if (error == ERROR_ACCESS_DENIED)
            return 0;
        
        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                      NULL,
                      error,
                      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                      (LPTSTR)&buf,
                      0,
                      NULL);
        
        wsprintf(text, ERROR_FORMAT, ERROR_SERVICE, ServiceList->ServiceName, buf);
        
        MessageBox(NULL, text, ERROR_TITLE, MB_OK | MB_ICONSTOP);
        
        return -1;
    }
    
    if (status != SERVICE_RUNNING)
    {
        wsprintf(text, ERROR_FORMAT, ERROR_SERVICE, ServiceList->ServiceName, ERROR_SERVICE_STOPPED);
        
        MessageBox(NULL, text, ERROR_TITLE, MB_OK | MB_ICONSTOP);
        
        return -1;
    }
    
    return 0;
}

int
CheckFile (
    PFILE_LIST *FileList
)
{
    PFILE_LIST list = *FileList;
    ULONG i, c;
    TCHAR path[MAX_PATH];
    
    while (list)
    {
        switch (list->Location)
        {
            case LOCATION_MAIN:
            
                GetModuleFileName(NULL, path, MAX_PATH);
                
                for (i = 0 ;; i++)
                {
                    if (path[i] == '\\' || path[i] == '/')
                        c = i;
                    else if (path[i] == 0)
                        break;
                }
                
                path[c] = 0;
            
                break;
            
            case LOCATION_SYSTEM32:
            
                GetSystemDirectory(path, MAX_PATH);
                
                break;
            
            case LOCATION_DRIVERS:
            
                GetSystemDirectory(path, MAX_PATH);
                
                lstrcat(path, L"\\Drivers");
                
                break;
        }
        
        lstrcat(path, L"\\");
        lstrcat(path, list->FileName);
        
        if (GetFileAttributes(path) == 0xFFFFFFFF)
            return GetLastError();
        
        list = list->Next;
        
        *FileList = list;
    }
    
    return ERROR_SUCCESS;
}

int
CheckService (
    PSERVICE_LIST *ServiceList,
    DWORD *ServiceStatus
)
{
    PSERVICE_LIST list = *ServiceList;
    SC_HANDLE service, scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    LPQUERY_SERVICE_CONFIG config = NULL;
    DWORD bytes;
    SERVICE_STATUS status;
    
    if (!scm)
        return GetLastError();
    
    while (list)
    {
        service = OpenService(scm, list->ServiceName, SERVICE_ALL_ACCESS);
        
        if (!service)
            return GetLastError();
        
        if (!QueryServiceStatus(service, &status))
            return GetLastError();
        
        *ServiceStatus = status.dwCurrentState;
        
        if (*ServiceStatus != SERVICE_RUNNING)
        {
            QueryServiceConfig(service, config, 0, &bytes);
            
            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
            {
                config = (LPQUERY_SERVICE_CONFIG)LocalAlloc(LMEM_FIXED, bytes);
                
                if (QueryServiceConfig(service, config, bytes, &bytes))
                {
                    if (config->dwStartType == SERVICE_DISABLED)
                    {
                        ChangeServiceConfig(service,
                                            SERVICE_NO_CHANGE,
                                            SERVICE_SYSTEM_START,
                                            SERVICE_NO_CHANGE,
                                            NULL,
                                            NULL,
                                            NULL,
                                            NULL,
                                            NULL,
                                            NULL,
                                            NULL);
                    }
                }
            }
            
            break;
        }
        
        CloseServiceHandle(service);
        
        list = list->Next;
        
        *ServiceList = list;
    }
    
    return ERROR_SUCCESS;
}