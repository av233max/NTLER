#include <windows.h>
#include <winreg.h>
#include <ntstatus.h>
#include <wchar.h>

#include "lpcdef.h"

#pragma comment(linker, "/nodefaultlib:msvcrt.lib")
#pragma comment(linker, "/opt:NOWIN98")
#pragma comment(linker, "/entry:main")
#pragma comment(lib, "ntdll.lib")

#define    MUVAL          __declspec(dllexport)
#define    MUAPI          __declspec(dllexport) __stdcall

#define    MU_DEVNAME_HOST_CONTROL       L"\\Device\\NTLEA_KernelHCI"

#define    IOCTL_MARK_CALLING_THREAD     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x01, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define    IOCTL_CLEAR_THREAD_RECORD     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x02, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define    IOCTL_GET_LEB_BASE            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x03, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define    IOCTL_SUBSTITUTE_TO_FACENAME  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x04, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define    IOCTL_GET_PATH_BINDING_LEB    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x05, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define    IOCTL_ADD_APPCONFIG           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x06, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define    IOCTL_ENUM_APPCONFIG          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x07, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define    IOCTL_REMOVE_APPCONFIG        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x08, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define    IOCTL_QUERY_LEB               CTL_CODE(FILE_DEVICE_UNKNOWN, 0x09, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define    IOCTL_QUERY_APPCONFIG         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x10, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack (push)
#pragma pack (1)

typedef struct _MU_NLS_PARAMETER
{

    LCID     LocaleId;
    ULONG    AnsiCodePage;
    ULONG    OemCodePage;  // ushort in fact
    
} MU_NLS_PARAMETER, *PMU_NLS_PARAMETER;

typedef struct _MU_LOADER_ENVIRONMENT
{

    MU_NLS_PARAMETER NlsParam;
    ULONG    EnhancedOptions;
    ULONG    TimeZone;
    WCHAR    SubstituteFont[LF_FACESIZE];
    
} MU_LOADER_ENVIRONMENT, *PMU_LOADER_ENVIRONMENT;

typedef struct _MU_APPLICATION_CONFIGURATION
{

    MU_LOADER_ENVIRONMENT Leb;
    UCHAR    UserStorageLength;
    UCHAR    UserStorage[1];
    WCHAR    AppFilePath[1];  // length limited to MAX_PATH, including terminating null character
    
} MU_APPLICATION_CONFIGURATION, *PMU_APPLICATION_CONFIGURATION;

typedef struct _MU_CTLOUT_GET_LEB_BASE
{

    PMU_LOADER_ENVIRONMENT Base;

} MU_CTLOUT_GET_LEB_BASE, *PMU_CTLOUT_GET_LEB_BASE;

typedef struct _MU_CTLIN_ADD_APPCONFIG
{

    MU_APPLICATION_CONFIGURATION AppConfig;
    
} MU_CTLIN_ADD_APPCONFIG, *PMU_CTLIN_ADD_APPCONFIG;

typedef struct _MU_APPLICATION_CONFIGURATION_WITH_KEY
{

    ULONG    Key;
    MU_APPLICATION_CONFIGURATION AppConfig;

} MU_APPLICATION_CONFIGURATION_WITH_KEY, *PMU_APPLICATION_CONFIGURATION_WITH_KEY;

typedef struct _MU_CTLOUT_ENUM_APPCONFIG
{

    ULONG    RequiredBufferSize;
    MU_APPLICATION_CONFIGURATION_WITH_KEY AppConfigWithKey[1];
    
} MU_CTLOUT_ENUM_APPCONFIG, *PMU_CTLOUT_ENUM_APPCONFIG;

typedef struct _MU_CTLIN_QUERY_APPCONFIG
{

    WCHAR    FilePath[1];
    
} MU_CTLIN_QUERY_APPCONFIG, *PMU_CTLIN_QUERY_APPCONFIG;

typedef struct _MU_CTLOUT_QUERY_APPCONFIG
{

    ULONG    RequiredBufferSize;
    MU_APPLICATION_CONFIGURATION_WITH_KEY AppConfigWithKey;

} MU_CTLOUT_QUERY_APPCONFIG, *PMU_CTLOUT_QUERY_APPCONFIG;

#pragma pack (pop)

HANDLE
MUAPI
MuOpenControlDevice (
    void
);

BOOLEAN
MUAPI
MuSyncSendControl (
    HANDLE DeviceHandle,
    ULONG ControlCode,
    PVOID InBuffer,
    ULONG InBufferSize,
    PVOID OutBuffer,
    ULONG OutBufferSize,
    PULONG ReturnSize
);

PMU_LOADER_ENVIRONMENT
MUAPI
MuQueryLebBase (
    HANDLE DeviceHandle
);

BOOLEAN
MUAPI
MuAddAppConfig (
    HANDLE DeviceHandle,
    PMU_APPLICATION_CONFIGURATION AppConfig
);

ULONG
MUAPI
MuEnumAppConfig (
    HANDLE DeviceHandle,
    PMU_CTLOUT_ENUM_APPCONFIG EnumConfig,
    ULONG BufferSize
);

BOOLEAN
MUAPI
MuRemoveAppConfig (
    HANDLE DeviceHandle,
    ULONG Key
);

ULONG
MUAPI
MuQueryAppConfig (
    HANDLE DeviceHandle,
    PMU_CTLIN_QUERY_APPCONFIG QueryConfigInput,
    PMU_CTLOUT_QUERY_APPCONFIG QueryConfigOutput,
    ULONG OutputBufferSize
);

BOOLEAN
MUAPI
MuCloseControlDevice (
    HANDLE DeviceHandle
);