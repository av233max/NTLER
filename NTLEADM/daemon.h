#define    GLOBAL_MUTEX_NAME   L"NTLEA_GlobalMutex"

#define    FILE_0         L"NTLEA_UsrModHlpDll_x86.dll"

#define    FILE_1         L"NTLEA_BootCfgDrv_x86.sys"

#define    FILE_2         L"NTLEA_MulLocEmuDrv_x86.sys"

#define    SERVICE_0      L"NTLEA_BootCfgDrv"

#define    SERVICE_1      L"NTLEA_MulLocEmuDrv"

#define    ERROR_FILE     L"file"

#define    ERROR_SERVICE  L"service"

#define    ERROR_FORMAT   L"An error has occurred while accessing the %s :\n%s\n\nDescription:\n%s\nTo solve this issue, uninstall NTLEA and reboot the system, then reinstall it please."

#define    ERROR_TITLE    L"NT Locale Emulator Revolution"

#define    ERROR_SERVICE_STOPPED   L"The service does not start correctly.\n"

enum
{

    LOCATION_MAIN,
    LOCATION_SYSTEM32,
    LOCATION_DRIVERS
    
};


typedef struct _FILE_LIST
{

    struct _FILE_LIST *Next;
    int     Location;
    LPTSTR  FileName;

} FILE_LIST, *PFILE_LIST;

typedef struct _SERVICE_LIST
{

    struct _SERVICE_LIST *Next;
    LPTSTR  ServiceName;

} SERVICE_LIST, *PSERVICE_LIST;

int
Startup (
    void
);

int
CheckFile (
    PFILE_LIST *FileList
);

int
CheckService (
    PSERVICE_LIST *ServiceList,
    DWORD *ServiceStatus
);