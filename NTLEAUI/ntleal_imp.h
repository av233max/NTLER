#ifndef _INC_MULIB
#define _INC_MULIB

#ifdef __cplusplus
extern "C" {
#endif

#pragma comment(lib, "NTLEA_LdrLibDll_x86.lib")

#define    MU_DATABASE_ALIGN(x)          ((x) & ~3)
#define    MU_DATABASE_CARRY_ALIGN(x)    (((x) + 3) & ~3)  // round up to 4 bytes alignment

#define    MU_OPTION_CHANGE_UI_LANG_ID   (1 << 0)
#define    MU_OPTION_MAP_SPECIAL_FOLDERS (1 << 1)
#define    MU_OPTION_SPECIFY_FONT        (1 << 2)
#define    MU_OPTION_LOCK_TIMEZONE       (1 << 3)

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

#define MUAPI __declspec(dllimport) __stdcall

HANDLE
MUAPI
MuOpenControlDevice (
    void
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

BOOLEAN
MUAPI
MuRemoveAppConfig (
    HANDLE DeviceHandle,
    ULONG Key
);

BOOLEAN
MUAPI
MuCloseControlDevice (
    HANDLE DeviceHandle
);

ULONG
MUAPI
MuEnumAppConfig (
    HANDLE DeviceHandle,
    PMU_CTLOUT_ENUM_APPCONFIG EnumConfig,
    ULONG BufferSize
);

ULONG
MUAPI
MuQueryAppConfig (
    HANDLE DeviceHandle,
    PMU_CTLIN_QUERY_APPCONFIG QueryConfigInput,
    PMU_CTLOUT_QUERY_APPCONFIG QueryConfigOutput,
    ULONG OutputBufferSize
);

#ifdef __cplusplus
}
#endif
#endif