#define UNICODE

#include <windows.h>
#include <wingdi.h>
#include <winreg.h>
#include <ntstatus.h>
#include <wchar.h>

#include "lpcdef.h"

#pragma comment(linker, "/nodefaultlib:msvcrt.lib")
#pragma comment(linker, "/base:0x0F800000")
#pragma comment(linker, "/opt:NOWIN98")
#pragma comment(linker, "/entry:main")
#pragma comment(lib, "ntdll.lib")

#define    MUVAL          __declspec(dllexport)
#define    MUAPI          __declspec(dllexport) __stdcall

#define    FN_WINMM       L"winmm.dll"
#define    FN_MMDEVAPI    L"mmdevapi.dll"

#define    MN_KERNEL32    L"kernel32"

#define    MU_FILENAME_KERNEL32_DLL        L"kernel32.dll"
#define    MU_FILENAME_GDI32_DLL           L"gdi32.dll"
#define    MU_FILENAME_SHELL32_DLL         L"shell32.dll"
#define    MU_FILENAME_USER32_DLL          L"user32.dll"

#define    REGPATH_PREFIX                  L"\\Registry\\Machine\\"
#define    REGPATH_AUDIO_ENDPOINTS         L"Software\\Microsoft\\Windows\\CurrentVersion\\MMDevices\\Audio"
#define    REGPATH_PROPERTY_STORE          L"\\Properties"
#define    REGPATH_BACKSLASH               L"\\"

#define    PN_GET_CURRENT_PROCESS_ID       "GetCurrentProcessId"
#define    PN_PROCESS_ID_TO_SESSION_ID     "ProcessIdToSessionId"

#define    FMT_AUDIO_DEVICE_HARDWARE_ID         L"NPAUDIO"
#define    LEN_AUDIO_DEVICE_HARDWARE_ID         ((sizeof(FMT_AUDIO_DEVICE_HARDWARE_ID) - 1) / sizeof(WCHAR))
#define    LEN_AUDIO_DEVICE_HARDWARE_FULL_ID    (LEN_AUDIO_DEVICE_HARDWARE_ID + 2)

#define    MU_MAX_CONCURRENT_SESSIONS      40

#define    MU_DEVNAME_HOST_CONTROL         L"\\Device\\NTLEA_KernelHCI"

#define    MU_AUDIO_DEVICE_NAME            L"\\Device\\MultiuserAudio"

#define    DFN_RENDER                      L"Render"
#define    DFN_CAPTURE                     L"Capture"
#define    DFN_REMOTE_RENDER               L"RemoteRender"
#define    DFN_REMOTE_CAPTURE              L"RemoteCapture"

#define    FRF_GET_RENDER                  1
#define    FRF_GET_CAPTURE                 1 << 1
#define    FRF_GET_REMOTE_RENDER           1 << 2
#define    FRF_FILTER_NP_DEVICES           1 << 3
#define    FRF_SELECT_NP_DEVICE            1 << 4

#define    FMT_AUDIO_DEVICE_REGISTRY_GUID  L"{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}"
#define    LEN_AUDIO_DEVICE_REGISTRY_GUID  ((sizeof(FMT_AUDIO_DEVICE_REGISTRY_GUID) - 1) / sizeof(WCHAR))

#define    STRING_PROPERTY_DEVICE_ID_GUID  L"{83da6326-97a6-4088-9453-a1923f573b29},3"

#define    MU_MAX_DEVICE_INSTANCE          100

#define    MAX_DATA_FLOW                   4

#define    MU_OPTION_CHANGE_UI_LANG_ID   (1 << 0)
#define    MU_OPTION_MAP_SPECIAL_FOLDERS (1 << 1)
#define    MU_OPTION_SPECIFY_FONT        (1 << 2)
#define    MU_OPTION_LOCK_TIMEZONE       (1 << 3)

#define    IOCTL_GET_NODE_ID             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x05, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define    IOCTL_MARK_CALLING_THREAD     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x01, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define    IOCTL_CLEAR_THREAD_RECORD     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x02, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define    IOCTL_GET_LEB_BASE            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x03, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define    IOCTL_SUBSTITUTE_TO_FACENAME  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x04, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define    IOCTL_GET_PATH_BINDING_LEB    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x05, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define    IOCTL_ADD_APPCONFIG           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x06, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define    IOCTL_ENUM_APPCONFIG          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x07, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define    IOCTL_REMOVE_APPCONFIG        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x08, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define    IOCTL_QUERY_LEB               CTL_CODE(FILE_DEVICE_UNKNOWN, 0x09, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define    IOCTL_CREATE_SYMBOLIC_LINK    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define    IOCTL_QUERY_APPCONFIG         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x10, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MU_IMPERSONATION_PATH_GUID       L"{8BD92939-58B8-414A-82CE-5254192C8D3C}"

#define GLOBAL_NAMESPACE                 L"\\??\\"

#define PASSING_DRIVE_LETTER             L"x:"  // one character extra for backslash

#define MU_STRING_FORMAT_GUID_PATH       L"%s%08d"

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

typedef struct _MU_CTLIN_MARK_CALLING_THREAD
{

    MU_LOADER_ENVIRONMENT Leb;

} MU_CTLIN_MARK_CALLING_THREAD, *PCTLIN_MARK_CALLING_THREAD;

typedef struct _MU_CTLIN_QUERY_LEB
{

    WCHAR    FilePath[1];
    
} MU_CTLIN_QUERY_LEB, *PMU_CTLIN_QUERY_LEB;

typedef struct _MU_CTLOUT_QUERY_LEB
{

    MU_LOADER_ENVIRONMENT Leb;
    
} MU_CTLOUT_QUERY_LEB, *PMU_CTLOUT_QUERY_LEB;

#pragma pack (pop)

typedef struct _MU_VERIFY_BLOCK
{
	
    ULONG    Offset;
    UCHAR    Length;
    UCHAR    Bytes[0];
    
} MU_VERIFY_BLOCK, *PMU_VERIFY_BLOCK;

typedef struct _MU_MODIFY_BLOCK
{

    ULONG    Offset;
    UCHAR    Length;
    UCHAR    Bytes[0];

} MU_MODIFY_BLOCK, *PMU_MODIFY_BLOCK;

typedef struct _MU_HOOK_BLOCK
{

    ULONG    Offset;
    PVOID    **OriginalAddress;
    PVOID    *HookAddress;
    
} MU_HOOK_BLOCK, *PMU_HOOK_BLOCK;

typedef struct _MU_AUDIT_BLOCK
{

    ULONG               NumCodeBlocks;
    PMU_VERIFY_BLOCK    VerifyBlock;
    
    union
    {
        PMU_MODIFY_BLOCK    ModifyBlock;
        PMU_HOOK_BLOCK      HookBlock;
    };

} MU_AUDIT_BLOCK, *PMU_AUDIT_BLOCK;

typedef struct _MU_AUDIT_PARAMETER
{

    PWSTR              FileName;
    ULONG              ImageSize;
    ULONG              NumAuBlocks;
    PMU_AUDIT_BLOCK    AuditBlock;

} MU_AUDIT_PARAMETER, *PMU_AUDIT_PARAMETER;

typedef struct _NTDLL_IMAGE_INFO
{

    ULONG Unknown[6];
    PVOID ImageStart;
    PVOID ImageEntry;
    ULONG ImageSize;
    UNICODE_STRING ImageFullPathName;
    UNICODE_STRING ImageFileName;

} NTDLL_IMAGE_INFO, *PNTDLL_IMAGE_INFO;

typedef struct _WINMM_DEVICE_INFO
{

    ULONG Unknown[3];
    WCHAR DevicePath[0];

} WINMM_DEVICE_INFO, *PWINMM_DEVICE_INFO;

typedef struct _WINMM_PNP_INFO
{

    ULONG InfoSize;
    ULONG Unknown[2];
    ULONG AudioNodes;
    ULONG Unknown2[2];
    WINMM_DEVICE_INFO DeviceInfo;
    
} WINMM_PNP_INFO, *PWINMM_PNP_INFO;

typedef struct _MU_REG_KEY_INFO
{

    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG NameLength;
    WCHAR KeyName[LEN_AUDIO_DEVICE_REGISTRY_GUID];
    
} MU_REG_KEY_INFO, *PMU_REG_KEY_INFO;

typedef struct _MU_REG_VALUE_INFO
{

    ULONG TitleIndex;
    ULONG Type;
    ULONG DataLength;
    UCHAR Data[MAX_PATH];
    
} MU_REG_VALUE_INFO, *PMU_REG_VALUE_INFO;

typedef struct _MU_DEVICE_STRING_GUID
{

    WCHAR GuidString[LEN_AUDIO_DEVICE_REGISTRY_GUID + 1];
    
} MU_DEVICE_STRING_GUID, *PMU_DEVICE_STRING_GUID;

typedef struct _MU_DEVICE_GUID_TABLE
{

    ULONG StructSize;
    ULONG DeviceCount;
    MU_DEVICE_STRING_GUID Guids[MU_MAX_DEVICE_INSTANCE];

} MU_DEVICE_GUID_TABLE, *PMU_DEVICE_GUID_TABLE;

typedef NTSTATUS (__stdcall *PLDRP_WALK_IMPORT_DESCRIPTOR) (
    PVOID Unknown,
    PNTDLL_IMAGE_INFO ImageInfo
);

NTSTATUS
MUAPI
MuHelperHook0 (
    PVOID Unknown,
    PNTDLL_IMAGE_INFO ImageInfo
);

void
MuHookSystemRoutines (
    PVOID ImageBase,
    ULONG ImageSize,
    PUNICODE_STRING ImageFileName,
    PMU_AUDIT_PARAMETER AuditParam,
    ULONG NumFilesToPatch,
    POSVERSIONINFOW OsVersion
);

void
MuWriteProtectedAddress (
    PVOID Destination,
    PVOID Source,
    ULONG Length,
    BOOLEAN FlushCode
);

void
MuHookAddress (
    PVOID Destination,
    ULONG Value
);

int
WINAPI
MuHookMmGetPnpInfo (
    PULONG InfoSize,
    PWINMM_PNP_INFO *PnpInfo
);

HANDLE
MuOpenControlDevice (
    void
);

BOOLEAN
MuSyncSendControl (
    HANDLE DeviceHandle,
    ULONG ControlCode,
    PVOID InBuffer,
    ULONG InBufferSize,
    PVOID OutBuffer,
    ULONG OutBufferSize,
    PULONG ReturnSize
);

LONG
WINAPI
MuHookMmRegOpen (
    HKEY hKey,
    LPWSTR lpSubKey,
    DWORD ulOptions,
    REGSAM samDesired,
    PHKEY phkResult
);

PVOID
IATHookRoutineByName (
	PVOID pImageBase,
	PCSTR pRoutineName,
	PVOID pRedirectRoutine
);

LONG
WINAPI
MuHookMmEnumEndpointOpenRoot (
    HKEY hKey,
    LPWSTR lpSubKey,
    DWORD ulOptions,
    REGSAM samDesired,
    PHKEY phkResult
);

BOOLEAN
MuMakeDeviceName (
    PWSTR DeviceName,
    PULONG NameLength
);

LONG
WINAPI
MuHookMmEnumEndpointEnumSub (
    HKEY hKey,
    DWORD dwIndex,
    LPTSTR lpName,
    LPDWORD lpcName,
    LPDWORD lpReserved,
    LPTSTR lpClass,
    LPDWORD lpcClass,
    PFILETIME lpftLastWriteTime
);

LONG
WINAPI
MuHookMmEnumEndpointCloseRoot (
    HKEY hKey
);

LONG
WINAPI
MuHookMmEnumEndpointOpenSub (
    HKEY hKey,
    LPWSTR lpSubKey,
    DWORD ulOptions,
    REGSAM samDesired,
    PHKEY phkResult
);

#define    WriteAddressUlong    MuHookAddress

typedef int (__stdcall *PWINMM_GET_PNPINFO) (
    PULONG InfoSize,
    PWINMM_PNP_INFO *PnpInfo
);


typedef BOOL (__stdcall *PPROCESS_ID_TO_SESSION_ID) (
    DWORD ProcessId,
    PDWORD SessionId
);

typedef DWORD (__stdcall *PGET_CURRENT_PROCESS_ID) (
    void
);

typedef LONG (__stdcall *PREG_OPEN_KEY_EX_W) (
    HKEY hKey,
    LPWSTR lpSubKey,
    DWORD ulOptions,
    REGSAM samDesired,
    PHKEY phkResult
    );
    
typedef LONG (__stdcall *PREG_QUERY_VALUE_W) (
    HKEY hKey,
    LPWSTR lpSubKey,
    LPWSTR lpValue,
    PLONG   lpcbValue
    );
    
typedef LONG (__stdcall *PREG_ENUM_KEY_EX_W) (
    HKEY hKey,
    DWORD dwIndex,
    LPWSTR lpName,
    LPDWORD lpcbName,
    LPDWORD lpReserved,
    LPWSTR lpClass,
    LPDWORD lpcbClass,
    PFILETIME lpftLastWriteTime
    );
    
typedef LONG (__stdcall *PREG_CLOSE_KEY) (
    HKEY hKey
    );
    
typedef HANDLE (WINAPI *PGDI32_FONT_CREATE) (
    PLOGFONT LogFont,
    PVOID Unknown0,
    PVOID Unknown1,
    PVOID Unknown2,
    PVOID Unknown3
    );
    
typedef HGDIOBJ (WINAPI *PGDI32_SELECT_OBJECT) (
    HDC hdc,
    HGDIOBJ hgdiobj
    );

typedef NTSTATUS (NTAPI *PNT_CREATE_PROCESS_EX) (
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    ULONG Flags,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    ULONG JobMemberLevel
    );
    
NTSTATUS
NTAPI
MuStubHookCreateProcessEx_XP (
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    ULONG Flags,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    ULONG JobMemberLevel
);

NTSTATUS
NTAPI
MuStubHookCreateProcessEx_2K3 (
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    ULONG Flags,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    ULONG JobMemberLevel
);

HRESULT
NTAPI
MuStubGetFolderPathW (
    HWND hwndOwner,
    int nFolder,
    HANDLE hToken,
    DWORD dwFlags,
    LPTSTR pszPath
);

HRESULT
WINAPI
MuGetFolderPathW (
    HWND hwndOwner,
    int nFolder,
    HANDLE hToken,
    DWORD dwFlags,
    LPTSTR pszPath
);

NTSTATUS
NTAPI
MuHookCreateProcessEx (
    PCWSTR ImageFilePath,
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    ULONG Flags,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    ULONG JobMemberLevel
);

NTSTATUS
MUAPI
MuWalkImportDescriptor (
    PVOID Unknown,
    PNTDLL_IMAGE_INFO ImageInfo
);

NTSTATUS
MUAPI
MuProcessStaticImports (
    PNTDLL_IMAGE_INFO ImageInfo,
    PVOID Unknown
);

void
MuProcessUserModeHook (
    PNTDLL_IMAGE_INFO ImageInfo
);

#define MM_MAX_NUMAXES 16

typedef struct tagDESIGNVECTOR {
  DWORD dvReserved;
  DWORD dvNumAxes;
  LONG  dvValues[MM_MAX_NUMAXES];
}DESIGNVECTOR, *PDESIGNVECTOR;

typedef struct _ENUMLOGFONTEXDV
{

    ENUMLOGFONTEX elfEnumLogfontEx;
    DESIGNVECTOR  elfDesignVector;

} ENUMLOGFONTEXDV, *PENUMLOGFONTEXDV;

HFONT
WINAPI
MuCreateFontIndirectExW (
    PENUMLOGFONTEXDV penumlfex
);

HDC
WINAPI
MuCreateCompatibleDC (
    HDC hdc
);

HDC
WINAPI
MuStubCreateCompatibleDC (
    HDC hdc
);

HFONT
WINAPI
MuStubCreateFontIndirectExW (
    PENUMLOGFONTEXDV penumlfex
);

HANDLE
__stdcall
MuGdiHfontCreate (
    PLOGFONT LogFont,
    PVOID Unknown0,
    PVOID Unknown1,
    PVOID Unknown2,
    PVOID Unknown3
);

PVOID
MuInlineHook (
    PVOID OriginalProcedure,
    PVOID RedirectAddress
);

LCID
WINAPI
MuGetUserDefaultLCID (
    void
);

BOOLEAN
MuCheckRoutineStackFrame (
    PVOID RoutineEntry
);

PVOID
EATLookupRoutineEntryByName (
	PVOID pImageBase,
	PCSTR pRoutineName
);

int
NTAPI
MuStubGetTextFaceAliasW_NT5 (
    HDC hdc,
    int nCount,
    LPTSTR lpFaceName
);

int
NTAPI
MuCopyFaceName (
    LPWSTR ToStr,
    LPWSTR FromStr
);