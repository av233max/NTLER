#define INITGUID

#include <guiddef.h>

#include "imgdef.h"
#include "ntintdef.h"

#define    MU_POOL_TAG                   'DCUM'

#define    MASK_PASS                     0

#define    VER_WIN2K                     0x00050000
#define    VER_WINXP                     0x00050001
#define    VER_WIN2K3                    0x80050002
#define    VER_VISTA                     0x00060000
#define    VER_WIN2K8                    0x80060000
#define    VER_WIN2K8R2                  0x80060001
#define    VER_WIN7                      0x00060001

#define    LARGE_PAGE_SIZE               0x400000
#define    MAX_PATH                      260
#define    DISK_SECTOR_SIZE              0x200

#define    MU_MAX_INDEX_LENGTH           (16 + 1)

#define    MU_GENERIC_BLOCK_SIZE         16

#define    MUALIGN                       DECLSPEC_ALIGN(MU_GENERIC_BLOCK_SIZE)

#define    MU_DATABASE_VERSION           20004

#define    MU_TINY_DATABASE_NAME         L"NTLEA_KrnlTdbBin_All.dat"

#define    MU_DEVNAME_HOST_CONTROL       L"\\Device\\NTLEA_KernelHCI"

#define    MU_EVENTNAME_BOOTSYNC         L"\\NTLEA_BootSyncEvent"

#define    MU_ROOTDIR_SYSTEM32           L"\\SystemRoot\\system32\\"

#define    MU_ERROR_TEXT_FORMAT          L"P:%d S:%08x"
#define    MU_DEBUG_INFO_FORMAT          L"%d"

#define    MU_FILENAME_HELPER_DLL        L"NTLEA_UsrModHlpDll_x86.dll"
#define    MU_FILENAME_NTSYSTEM_DLL      "ntdll.dll"

#define    MU_REGPATH_NTLEA_DEBUG_ROOT   L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\NTLEA"

#define    MU_REGPATH_CODEPAGE           L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nls\\CodePage"
#define    MU_REGPATH_LANGUAGE           L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nls\\Language"
#define    MU_REGVAL_ACP                 L"ACP"
#define    MU_REGVAL_OEMCP               L"OEMCP"
#define    MU_REGVAL_DEFAULT             L"Default"
#define    MU_REGVAL_LAST_ERROR          L"LastError"
#define    MU_REGVAL_INFORMATION         L"Information"

#define    MU_STRING_FORMAT_CODEPAGE     L"%d"
#define    MU_STRING_FORMAT_LOCALE_ID    L"%04x"
#define    MU_STRING_FORMAT_GUID_PATH    L"%08d"

#define    MU_HELPER_LDR_HOOK_NAME       "_MuWalkImportDescriptor@8"
#define    MU_HELPER_LDR_ENV_NAME        "MuLoaderEnvironment"

#define    MU_IMPERSONATION_PATH_GUID    L"{8BD92939-58B8-414A-82CE-5254192C8D3C}"

#define    GLOBAL_NAMESPACE              L"\\??\\"

#define    PASSING_DRIVE_LETTER          L"x:"  // one character extra for backslash

#define    GLOBAL_NAMESPACE_SIZE         (sizeof(GLOBAL_NAMESPACE) - sizeof(WCHAR))

#define    MU_HELPER_LDR_HOOK_OFFSET     0x1010
#define    MU_HELPER_LDR_ORG_OFFSET      0x1042

#define    STATE_UNLOCKED                0
#define    STATE_WRITE_PENDING           (1 << 0)

#define    LF_FACESIZE                   32

#define    MU_OPTION_CHANGE_UI_LANG_ID   (1 << 0)
#define    MU_OPTION_MAP_SPECIAL_FOLDERS (1 << 1)
#define    MU_OPTION_SPECIFY_FONT        (1 << 2)
#define    MU_OPTION_LOCK_TIMEZONE       (1 << 3)

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

#define    MU_DATABASE_ALIGN(x)          ((x) & ~3)
#define    MU_DATABASE_CARRY_ALIGN(x)    (((x) + 3) & ~3)  // round up to 4 bytes alignment

#define    OFFSET_OF(type, member)       (SIZE_T)(&((type *)0)->member)

enum
{

    NTKERNEL_PAE0_MP0 = 0,
    NTKERNEL_PAE1_MP0,
    NTKERNEL_PAE0_MP1,
    NTKERNEL_PAE1_MP1, 
    TOTAL_NTKERNEL_VERSIONS
    
};

enum
{

    ENTRY_LOCALE_CONFIGURATION,
    ENTRY_APPLICATION_CONFIGURATION,
    TOTAL_DATABASE_ENTRIES
    
};

enum
{

    PHASE_CREATE_DEVICE,
    PHASE_CHECK_OS_VERSION,
    PHASE_LOAD_DATABASE,
    PHASE_INIT_KERNEL_HOOK,
    PHASE_SET_NOTIFY,
    PHASE_INIT_HELPER
    
};

enum
{

    OP_MODIFY,
    OP_HOOK_CALL,
    OP_REPLACE_CALL,
    OP_INLINE_JUMP,
    OP_LOCATE_ENTRY

};

#pragma pack (push)
#pragma pack (1)

typedef struct _MU_VERIFY_DATA
{

    struct _MU_VERIFY_DATA *Next;
    ULONG   Length;
    PUCHAR  VerifyCode;
    PUCHAR  VerifyMask;
    ULONG   OffsetToFix;

} MU_VERIFY_DATA, *PMU_VERIFY_DATA;

typedef struct _MU_NLS_SOURCE
{

    PVOID    TableSection;
    ULONG    AnsiTableOffset;
    ULONG    OemTableOffset;
    ULONG    LangTableOffset;
    
} MU_NLS_SOURCE, *PMU_NLS_SOURCE;

typedef struct _MU_DLL_ENTRY
{

    PVOID    MuOrgWalkImportDescriptor;
    PVOID    MuHookWalkImportDescriptor;
    PVOID    MuLoaderEnvironment;

} MU_DLL_ENTRY, *PMU_DLL_ENTRY;

typedef struct _MU_VERIFY_BLOCK
{

    ULONG    Offset;
    UCHAR    Length;
    UCHAR    Bytes[0];

} MU_VERIFY_BLOCK, *PMU_VERIFY_BLOCK;

typedef struct _MU_PUBLIC_BLOCK
{

    ULONG    Offset;
    UCHAR    OperationType;

} MU_PUBLIC_BLOCK, *PMU_PUBLIC_BLOCK;

typedef struct _MU_MODIFY_BLOCK
{

    ULONG    Offset;
    UCHAR    OperationType;
    UCHAR    Length;
    UCHAR    Bytes[0];

} MU_MODIFY_BLOCK, *PMU_MODIFY_BLOCK;

typedef struct _MU_REPLACE_CALL_BLOCK  // offset points to a "call xxxxxxxx" instruction
{

    ULONG    Offset;
    ULONG    OperationType;
    PVOID    *OriginalCall;
    PVOID    *RedirectCall;
    
} MU_REPLACE_CALL_BLOCK, *PMU_REPLACE_CALL_BLOCK;

typedef struct _MU_HOOK_CALL_BLOCK  // offset points to a "call xxxxxxxx" instruction
{

    ULONG    Offset;
    ULONG    OperationType;
    PVOID    *OriginalAddress;
    PVOID    RedirectAddress;
    
} MU_HOOK_CALL_BLOCK, *PMU_HOOK_CALL_BLOCK;

typedef struct _MU_INLINE_JUMP_BLOCK  // offset points to a function entry which should be hooked by inline jump
{

    ULONG    Offset;
    ULONG    OperationType;
    PVOID    *OriginalAddress;
    PVOID    RedirectAddress;
    
} MU_INLINE_JUMP_BLOCK, *PMU_INLINE_JUMP_BLOCK;

typedef struct _MU_LOCATE_ENTRY_BLOCK  // offset points to a function entry which should be located
{

    ULONG    Offset;
    ULONG    OperationType;
    PVOID    *EntryAddress;

} MU_LOCATE_ENTRY_BLOCK, *PMU_LOCATE_ENTRY_BLOCK;

typedef struct _MU_AUDIT_BLOCK
{

    ULONG               NumCodeBlocks;
    PMU_VERIFY_BLOCK    VerifyBlock;
    
    union
    {
        PMU_PUBLIC_BLOCK       PublicBlock;
        PMU_MODIFY_BLOCK       ModifyBlock;
        PMU_HOOK_CALL_BLOCK    HookCallBlock;
        PMU_REPLACE_CALL_BLOCK ReplaceCallBlock;
        PMU_INLINE_JUMP_BLOCK  InlineJumpBlock;
        PMU_LOCATE_ENTRY_BLOCK LocateEntryBlock;
    };

} MU_AUDIT_BLOCK, *PMU_AUDIT_BLOCK;

typedef struct _MU_NTKERNEL_HOOK_DATA
{

    ULONG              NumBuildVersions;
    PMU_AUDIT_BLOCK    AuditBlock[TOTAL_NTKERNEL_VERSIONS];

} MU_NTKERNEL_HOOK_DATA, *PMU_NTKERNEL_HOOK_DATA;

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

typedef struct _MU_TEMPORARY_THREAD_RECORD
{

    struct _MU_TEMPORARY_THREAD_RECORD *Next;
    PETHREAD   ThreadObject;
    BOOLEAN    LockContext;
    UCHAR      Alignment[3];
    MU_LOADER_ENVIRONMENT Leb;
    
} MU_TEMPORARY_THREAD_RECORD, *PMU_TEMPORARY_THREAD_RECORD;

typedef struct _MU_NLS_SOURCE_DESCRIPTOR
{

    struct _MU_NLS_SOURCE_DESCRIPTOR *Next;
    MU_NLS_PARAMETER NlsParam;
    MU_NLS_SOURCE CustomNlsSource;

} MU_NLS_SOURCE_DESCRIPTOR, *PMU_NLS_SOURCE_DESCRIPTOR;

typedef struct _MU_PROCESS_CONTEXT
{

    struct _MU_PROCESS_CONTEXT *Next;
    PEPROCESS  ProcessObject;
    ULONG      RefCount;
    ULONG      EnhancedOptions;
    PMU_NLS_SOURCE_DESCRIPTOR Nsd;
    NLSTABLEINFO CustomNlsTableInfo;
    
} MU_PROCESS_CONTEXT, *PMU_PROCESS_CONTEXT;

typedef struct _MU_USER_OA_CONTEXT
{

    OBJECT_ATTRIBUTES ObjAttr;
    WCHAR    NameBuffer[1];

} MU_USER_OA_CONTEXT, *PMU_USER_OA_CONTEXT;

typedef struct _MU_DATABASE_DATASET_INFO
{

    ULONG    NextChunkOffset;
    USHORT   ChunkSize;
    USHORT   DataSize;
    UCHAR    Data[1];
    
} MU_DATABASE_DATASET_INFO, *PMU_DATABASE_DATASET_INFO;

typedef struct _MU_DATABASE_DATASET_INFO_IN_MEMORY
{

    struct _MU_DATABASE_DATASET_INFO_IN_MEMORY *Next;
    ULONG    CurrentChunkOffset;
    ULONG    NextChunkOffset;
    USHORT   ChunkSize;
    USHORT   DataSize;
    UCHAR    Data[1];
    
} MU_DATABASE_DATASET_INFO_IN_MEMORY, *PMU_DATABASE_DATASET_INFO_IN_MEMORY;


typedef struct _MU_DATABASE_LOOKASIDE_LIST
{

    ULONG    NextChunkOffset;
    USHORT   ChunkSize;
    USHORT   DataSize;
    
} MU_DATABASE_LOOKASIDE_LIST, *PMU_DATABASE_LOOKASIDE_LIST;

typedef struct _MU_DATABASE_LOOKASIDE_LIST_IN_MEMORY
{

    struct _MU_DATABASE_LOOKASIDE_LIST_IN_MEMORY *Next;
    ULONG    CurrentChunkOffset;
    ULONG    NextChunkOffset;
    USHORT   ChunkSize;
    USHORT   DataSize;
    
} MU_DATABASE_LOOKASIDE_LIST_IN_MEMORY, *PMU_DATABASE_LOOKASIDE_LIST_IN_MEMORY;

typedef struct _MU_DATABASE_ENTRY_CATALOG
{

    ULONG    FirstEntryOffset;
    
} MU_DATABASE_ENTRY_CATALOG, *PMU_DATABASE_ENTRY_CATALOG;

/* cache the whole database instead of caching partial data

typedef struct _MU_DATABASE_CACHE_BUFFER
{

    UCHAR    Bytes[DISK_SECTOR_SIZE];
    
} MU_DATABASE_CACHE_BUFFER, *PMU_DATABASE_CACHE_BUFFER;

typedef struct _MU_DATABASE_CACHE_ENTRY
{

    ULONG    BufferCommit;
    PMU_DATABASE_CACHE_BUFFER CacheBuffers[MU_MAX_DATABASE_CACHE_BUFFER];
    ULONG    CacheOffset;

} MU_DATABASE_CACHE_ENTRY, *PMU_DATABASE_CACHE_ENTRY;

#define    MU_MAX_DATABASE_CACHE_BUFFER  100
*/

typedef struct _MU_DATABASE_HEADER
{

    GUID     KnownGuid;
    ULONG    Version;
    GUID     PrivateGuid;
    UCHAR    State;
    UCHAR    EntryCount;
    USHORT   Alignment;
    MU_DATABASE_ENTRY_CATALOG Lookaside;
    MU_DATABASE_ENTRY_CATALOG Entries[1];
    
} MU_DATABASE_HEADER, *PMU_DATABASE_HEADER;

#define    MU_MIN_DATABASE_SIZE     sizeof(MU_DATABASE_HEADER)
#define    MU_MAX_DATABASE_SIZE     0x800000
#define    MU_MAX_LIST_ENTRY_SIZE   0xA00000
#define    MU_MAX_DATASET_SIZE      0xFF00

typedef struct _MU_DATABASE_OBJECT
{

    KMUTEX  AccessMutex;
    HANDLE  FileHandle;
    ULONG   FileSize;
    ULONG   BytesAllocated;
    UCHAR   EntryCount;
    UCHAR   Alignment[3];
    PMU_DATABASE_LOOKASIDE_LIST_IN_MEMORY LookasideList;
    PMU_DATABASE_DATASET_INFO_IN_MEMORY EntryList[1];

} MU_DATABASE_OBJECT, *PMU_DATABASE_OBJECT;

typedef struct _MU_PATH_MAPPING_RECORD
{

    struct _MU_PATH_MAPPING_RECORD *Next;
    WCHAR    Path[1];

} MU_PATH_MAPPING_RECORD, *PMU_PATH_MAPPING_RECORD;

typedef struct _MU_GLOBAL_DATA
{

    KSPIN_LOCK                   GlobalLock;
    KSPIN_LOCK                   ThreadRecordLock;
    KSPIN_LOCK                   ProcessContextLock;
    FAST_MUTEX                   ImpersonationPathMutex;
    FAST_MUTEX                   UserStorageMutex;
    KMUTEX                       NsdLibraryMutex;
    PVOID                        DllSection;
    PVOID                        DllImageBase;
    ULONG                        DllImageSize;
    ULONG                        MappedPathCount;
    PMU_PATH_MAPPING_RECORD      PathMappingRecord;
    PMU_TEMPORARY_THREAD_RECORD  TempThreadRecord;
    PMU_PROCESS_CONTEXT          ProcessContext;
    PMU_NLS_SOURCE_DESCRIPTOR    NsdLibrary;
    PMU_DATABASE_OBJECT          DatabaseObject;
    MU_DLL_ENTRY                 DllEntries;
    MU_NLS_SOURCE                SystemNlsSource;
    NLSTABLEINFO                 SystemNlsTableInfo;

} MU_GLOBAL_DATA, *PMU_GLOBAL_DATA;

typedef struct _MU_SUBSITUTES_META_DATA
{

    PWCHAR   SubstituteName;
    PWCHAR   RealFaceName;

} MU_SUBSITUTES_META_DATA, *PMU_SUBSITUTES_META_DATA;

typedef struct _MU_LOCALE_SUBSITUTES_DESCRIPTOR
{

    LCID    LocaleId;
    ULONG   NumMetaData;
    PMU_SUBSITUTES_META_DATA MetaData;
    
} MU_LOCALE_SUBSITUTES_DESCRIPTOR, *PMU_LOCALE_SUBSITUTES_DESCRIPTOR;

typedef struct _MU_CTLOUT_GET_LEB_BASE
{

    PMU_LOADER_ENVIRONMENT Base;

} MU_CTLOUT_GET_LEB_BASE, *PMU_CTLOUT_GET_LEB_BASE;

typedef struct _MU_CTLIN_MARK_CALLING_THREAD
{

    MU_LOADER_ENVIRONMENT Leb;

} MU_CTLIN_MARK_CALLING_THREAD, *PMU_CTLIN_MARK_CALLING_THREAD;

typedef struct _MU_CTLIN_SUBSTITUTE_TO_FACE_NAME
{

    WCHAR   FaceName[LF_FACESIZE];

} MU_CTLIN_SUBSTITUTE_TO_FACE_NAME, *PMU_CTLIN_SUBSTITUTE_TO_FACE_NAME;

typedef struct _MU_CTLOUT_SUBSTITUTE_TO_FACE_NAME
{

    WCHAR   FaceName[LF_FACESIZE];

} MU_CTLOUT_SUBSTITUTE_TO_FACE_NAME, *PMU_CTLOUT_SUBSTITUTE_TO_FACE_NAME;

typedef struct _MU_SUBSTITUTE_TO_FACE_NAME_CONTEXT
{

    LCID    LocaleId;
    PMU_CTLIN_SUBSTITUTE_TO_FACE_NAME InputBuffer;
    PMU_CTLOUT_SUBSTITUTE_TO_FACE_NAME OutputBuffer;

} MU_SUBSTITUTE_TO_FACE_NAME_CONTEXT, *PMU_SUBSTITUTE_TO_FACE_NAME_CONTEXT;

typedef struct _MU_FONT_SUBSTITUTE_DESCRIPTOR
{

    WCHAR   SubstituteName[LF_FACESIZE];
    WCHAR   RealFaceName[LF_FACESIZE];

} MU_FONT_SUBSTITUTE_DESCRIPTOR, *PMU_FONT_SUBSTITUTE_DESCRIPTOR;

typedef struct _MU_LOCALE_CONFIGURATION
{

    LCID    LocaleId;
    ULONG   NumSubstitutes;
    WCHAR   DefaultFont[LF_FACESIZE];
    MU_FONT_SUBSTITUTE_DESCRIPTOR Fsd[1];

} MU_LOCALE_CONFIGURATION, *PMU_LOCALE_CONFIGURATION;

typedef struct _MU_APPLICATION_CONFIGURATION
{

    MU_LOADER_ENVIRONMENT Leb;
    UCHAR    UserStorageLength;
    UCHAR    UserStorage[1];
    WCHAR    AppFilePath[1];  // length limited to MAX_PATH, including terminating null character
    
} MU_APPLICATION_CONFIGURATION, *PMU_APPLICATION_CONFIGURATION;

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

typedef struct _MU_ENUM_APPCONFIG_CONTEXT
{

    ULONG BufferSize;
    ULONG BytesWritten;
    PMU_CTLOUT_ENUM_APPCONFIG OutputBuffer;
    
} MU_ENUM_APPCONFIG_CONTEXT, *PMU_ENUM_APPCONFIG_CONTEXT;

typedef struct _MU_CTLIN_QUERY_LEB
{

    WCHAR    FilePath[1];
    
} MU_CTLIN_QUERY_LEB, *PMU_CTLIN_QUERY_LEB;

typedef struct _MU_CTLOUT_QUERY_LEB
{

    MU_LOADER_ENVIRONMENT Leb;
    
} MU_CTLOUT_QUERY_LEB, *PMU_CTLOUT_QUERY_LEB;

typedef struct _MU_CTLIN_REMOVE_APPCONFIG
{

    ULONG    Key;
    
} MU_CTLIN_REMOVE_APPCONFIG, *PMU_CTLIN_REMOVE_APPCONFIG;

typedef struct _MU_CTLIN_QUERY_APPCONFIG
{

    WCHAR    FilePath[1];
    
} MU_CTLIN_QUERY_APPCONFIG, *PMU_CTLIN_QUERY_APPCONFIG;

typedef struct _MU_CTLOUT_QUERY_APPCONFIG
{

    ULONG    RequiredBufferSize;
    MU_APPLICATION_CONFIGURATION_WITH_KEY AppConfigWithKey;

} MU_CTLOUT_QUERY_APPCONFIG, *PMU_CTLOUT_QUERY_APPCONFIG;

typedef struct _MU_QUERY_APPCONFIG_CONTEXT
{

    ULONG    OutputBufferSize;
    ULONG    BytesWritten;
    PMU_CTLIN_QUERY_APPCONFIG InputBuffer;
    PMU_CTLOUT_QUERY_APPCONFIG OutputBuffer;
    
} MU_QUERY_APPCONFIG_CONTEXT, *PMU_QUERY_APPCONFIG_CONTEXT;

typedef struct _MU_CTLIN_CREATE_SYMBOLIC_LINK
{

    WCHAR    FolderPath[1];

} MU_CTLIN_CREATE_SYMBOLIC_LINK, *PMU_CTLIN_CREATE_SYMBOLIC_LINK;

typedef struct _MU_CTLOUT_CREATE_SYMBOLIC_LINK
{

    ULONG    ImpersonationPathId;

} MU_CTLOUT_CREATE_SYMBOLIC_LINK, *PMU_CTLOUT_CREATE_SYMBOLIC_LINK;

#pragma pack (pop)

typedef void (NTAPI *NTUNEXPPROC_RtlInitNlsTables) (
    IN PUSHORT AnsiNlsBase,
    IN PUSHORT OemNlsBase,
    IN PUSHORT LanguageNlsBase,
    OUT PNLSTABLEINFO TableInfo
);

typedef NTSTATUS (NTAPI *NTUNEXPPROC_MmCreatePeb) (
    PEPROCESS TargetProcess,
    PINITIAL_PEB InitialPeb,
    PPEB *Base
);

typedef NTSTATUS (NTAPI *NTUNEXPPROC_MmCreateTeb) (
    PEPROCESS TargetProcess,
    PINITIAL_TEB InitialTeb,
    PCLIENT_ID ClientId,
    PTEB *Base
);

typedef LCID (NTAPI *NTUNEXPPROC_MmGetSessionLocaleId) (
    void
);

typedef NTSTATUS (NTAPI *NTUNEXPPROC_NtQueryDefaultLocale) (
    BOOLEAN UserProfile,
    PLCID DefaultLocaleId
);

typedef NTSTATUS (NTAPI *NTUNEXPPROC_NtQueryDefaultUILanguage) (
    LANGID *LangId
);

typedef NTSTATUS (NTAPI *NTUNEXPPROC_NtQueryInstallUILanguage) (
    LANGID *LangId
);

typedef NTSTATUS (NTAPI *NTPROC_NtCreateFile) (
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
);

typedef NTSTATUS (NTAPI *NTPROC_NtOpenFile) (
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess,
    ULONG OpenOptions
);

typedef BOOLEAN (*MU_DATABASE_ENUM_DATASET_PROC) (
    PMU_DATABASE_DATASET_INFO_IN_MEMORY Dataset,
    PVOID CallerContext,
    PNTSTATUS FinalStatus
);

NTSTATUS
DriverEntry (
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
);

NTSTATUS
MuDispatchCreateClose (
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
);

NTSTATUS
MuDispatchPower (
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
);

NTSTATUS
MuDispatchDeviceControl (
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
);

VOID
MuCreateProcessNotify (
    HANDLE ParentId,
    HANDLE ProcessId,
    BOOLEAN Create
);

NTSTATUS
MuInitializeKernelHook (
    PMU_GLOBAL_DATA GlobalData
);

PVOID
MuPagedAlloc (
    SIZE_T Bytes
);

PVOID
MuAlloc (
    SIZE_T Bytes
);

void
MuFree (
    PVOID Pointer
);

NTSTATUS
MuQueryRegistryValue (
    PCWSTR DirName,
    PCWSTR ValueName,
    PKEY_VALUE_PARTIAL_INFORMATION *ValueInfo
);

NTSTATUS
MuLoadSystemDefaultNlsTables (
    PMU_GLOBAL_DATA GlobalData
);

NTSTATUS
MuQueryNlsFileIndex (
    PCWSTR DirName,
    PCWSTR ValueName,
    PWSTR FileIndex
);

NTSTATUS
MuLoadNlsTableIntoContiguousBuffer (
    PCWSTR AnsiFileIndex,
    PCWSTR OemFileIndex,
    PCWSTR LangFileIndex,
    PMU_NLS_SOURCE NlsSource
);

NTSTATUS
MuQueryRegistryStringValue (
    PCWSTR DirName,
    PCWSTR ValueName,
    PWSTR Buffer,
    ULONG LengthInChar
);

NTSTATUS
MuReadFileInSystemFolder (
    PCWSTR FileName,
    PVOID *Buffer,
    PULONG DataLength,
    ULONG LengthLimit
);

NTSTATUS
MuGetNtKernelImageInfo (
    PVOID *ImageBase,
    PULONG ImageSize
);

BOOLEAN
MuHookKernel (
    PVOID KernelBase,
    ULONG KernelSize
);

BOOLEAN
MuLocateUnexportedSystemRoutines (
    PVOID KernelBase,
    ULONG KernelSize
);

void
MuWriteMemoryDword (
    PVOID Dest,
    ULONG Value
);

void
MuWriteMemory (
    PVOID Dest,
    PVOID Data,
    ULONG NumberOfBytes
);

NTSTATUS
MuMultiByteToUnicodeN (
    PWCH UnicodeString,
    ULONG MaxBytesInUnicodeString,
    PULONG BytesInUnicodeString,
    PCH MultiByteString,
    ULONG BytesInMultiByteString
);

NTSTATUS
MuUnicodeToMultiByteN (
    PCH MultiByteString,
    ULONG MaxBytesInMultiByteString,
    PULONG BytesInMultiByteString,
    PWCH UnicodeString,
    ULONG BytesInUnicodeString
);

NTSTATUS
MuOemToUnicodeN (
    PWCH UnicodeString,
    ULONG MaxBytesInUnicodeString,
    PULONG BytesInUnicodeString,
    PCH MultiByteString,
    ULONG BytesInMultiByteString
);

NTSTATUS
MuUnicodeToOemN (
    PCH MultiByteString,
    ULONG MaxBytesInMultiByteString,
    PULONG BytesInMultiByteString,
    PWCH UnicodeString,
    ULONG BytesInUnicodeString
);

NTSTATUS
MuUpcaseUnicodeToMultiByteN (
    PCH MultiByteString,
    ULONG MaxBytesInMultiByteString,
    PULONG BytesInMultiByteString,
    PWCH UnicodeString,
    ULONG BytesInUnicodeString
);

NTSTATUS
MuUpcaseUnicodeToOemN (
    PCH MultiByteString,
    ULONG MaxBytesInMultiByteString,
    PULONG BytesInMultiByteString,
    PWCH UnicodeString,
    ULONG BytesInUnicodeString
);

NTSTATUS
MuMultiByteToUnicodeSize (
    PULONG BytesInUnicodeString,
    PCH MultiByteString,
    ULONG BytesInMultiByteString
);

NTSTATUS
MuUnicodeToMultiByteSize (
    PULONG BytesInMultiByteString,
    PWCH UnicodeString,
    ULONG BytesInUnicodeString
);

void
MuGetDefaultCodePage(
    PUSHORT AnsiCodePage,
    PUSHORT OemCodePage
);

NTSTATUS
MuQueryDefaultUILanguage (
    LANGID *DefaultUILanguageId
);

NTSTATUS
MuQueryInstallUILanguage (
    LANGID *InstallUILanguageId
);

PMU_GLOBAL_DATA
MuAcquireGlobalLock (
    PKLOCK_QUEUE_HANDLE LockHandle
);

PMU_GLOBAL_DATA
MuAcquireThreadRecordLock (
    PKLOCK_QUEUE_HANDLE LockHandle
);

void
MuReleaseSpinLock (
    PKLOCK_QUEUE_HANDLE LockHandle
);

NTSTATUS
MuMarkCallingThread (
    PIRP Irp
);

NTSTATUS
MuClearThreadRecord (
    PIRP Irp
);

NTSTATUS
MuInitializeUserModeHelper (
    PMU_GLOBAL_DATA GlobalData
);

NTSTATUS
MuLinkDll (
    PMU_GLOBAL_DATA GlobalData,
    PVOID ImageBase
);

BOOLEAN
MuPrepareHelperContext (
    PMU_DLL_ENTRY DllEntries,
    PVOID ImageBase
);

BOOLEAN
MuHookNtDll (
    PVOID ImageBase,
    ULONG ImageSize
);

NTSTATUS
MuGetNtLayerDllImageInfo (
    PVOID *ImageBase,
    PULONG ImageSize
);

PVOID
MuLookupExportRoutineEntryByName (
    PVOID pImageBase,
    PCSTR pRoutineName
);

void
MuInitializeGlobalData (
    PMU_GLOBAL_DATA GlobalData
);

void
MuWriteMemoryWithMdl (
    PVOID Dest,
    PVOID Data,
    ULONG NumberOfBytes
);

NTSTATUS
MuCreatePeb (
    PEPROCESS TargetProcess,
    PINITIAL_PEB InitialPeb,
    PPEB *Base
);

NTSTATUS
MuCreateTeb (
    PEPROCESS TargetProcess,
    PINITIAL_TEB InitialTeb,
    PCLIENT_ID ClientId,
    PTEB *Base
);

NTSTATUS
MuGetLebBase (
    PIRP Irp,
    PULONG BytesWritten
);

PMU_TEMPORARY_THREAD_RECORD
MuGetInvokerParameters (
    void
);

PMU_NLS_SOURCE_DESCRIPTOR
MuLoadCustomizeNlsTable (
    PMU_NLS_PARAMETER Parameter
);

PMU_GLOBAL_DATA
MuAcquireNsdLibraryMutex (
    void
);

void
MuReleaseNsdLibraryMutex (
    void
);

PMU_GLOBAL_DATA
MuAcquireProcessContextLock (
    PKLOCK_QUEUE_HANDLE LockHandle
);

PMU_PROCESS_CONTEXT
MuCreateProcessContext (
    void
);

void
MuDereferenceProcessContext (
    PMU_PROCESS_CONTEXT Context
);

PMU_PROCESS_CONTEXT
MuLookupCurrentProcessContext (
    void
);

PMU_PROCESS_CONTEXT
MuLookupProcessContext (
    PEPROCESS ProcessObject
);

PVOID
MuHookSSDT (
    PVOID ProcEntry,
    PVOID RedirectAddress
);

NTSTATUS
MuQueryDefaultLocale (
    BOOLEAN UserProfile,
    PLCID DefaultLocaleId
);

LCID
MuGetSessionLocaleId (
    void
);

NTSTATUS
MuCreateOrOpenDatabase (
    PCWSTR DatabaseName,
    GUID *DatabaseGuid,
    UCHAR MaxEntries,
    PMU_DATABASE_OBJECT *DatabaseObject,
    PBOOLEAN NewCreated
);

NTSTATUS
MuLoadDatabase (
    PMU_GLOBAL_DATA GlobalData
);

NTSTATUS
MuBuildDatabaseMemoryMirror (
    PMU_DATABASE_OBJECT DatabaseObject,
    PMU_DATABASE_HEADER DatabaseHeader
);

void
MuSetErrorCode (
    PUNICODE_STRING RootDir,
    ULONG PhaseId,
    NTSTATUS LastStatus
);

NTSTATUS
MuDeleteRegistryValue (
    PCWSTR DirName,
    PCWSTR ValueName
);

NTSTATUS
MuAllocateDatasetObject (
    USHORT DataSize,
    PMU_DATABASE_DATASET_INFO_IN_MEMORY *DatasetObject
);

NTSTATUS
MuUpdateDataset (
    PMU_DATABASE_OBJECT DatabaseObject,
    UCHAR EntryIndex,
    PMU_DATABASE_DATASET_INFO_IN_MEMORY DatasetObject,
    USHORT DataSize
);

NTSTATUS
MuRemoveDatasetFromDatabase (
    PMU_DATABASE_OBJECT DatabaseObject,
    UCHAR EntryIndex,
    PMU_DATABASE_DATASET_INFO_IN_MEMORY DatasetObject
);

NTSTATUS
MuAddDatasetToDatabase (
    PMU_DATABASE_OBJECT DatabaseObject,
    UCHAR EntryIndex,
    PMU_DATABASE_DATASET_INFO_IN_MEMORY DatasetObject
);

NTSTATUS
MuSetDatabaseState (
    PMU_DATABASE_OBJECT DatabaseObject,
    UCHAR State
);

void
MuAcquireDatabaseMutex (
    PMU_DATABASE_OBJECT DatabaseObject
);

void
MuReleaseDatabaseMutex (
    PMU_DATABASE_OBJECT DatabaseObject
);

BOOLEAN
MuLookupDatasetObjectFromEntryList (
    PMU_DATABASE_OBJECT DatabaseObject,
    UCHAR EntryIndex,
    PMU_DATABASE_DATASET_INFO_IN_MEMORY DatasetObject,
    PMU_DATABASE_DATASET_INFO_IN_MEMORY *PreviousPointer
);

NTSTATUS
MuSyncWriteFile (
    HANDLE FileHandle,
    PVOID Buffer,
    ULONG BufferLength,
    ULONG Offset
);

NTSTATUS
MuPopFreeEntry (
    PMU_DATABASE_OBJECT DatabaseObject,
    PMU_DATABASE_LOOKASIDE_LIST_IN_MEMORY LookasideObject,
    PMU_DATABASE_LOOKASIDE_LIST_IN_MEMORY PreviousPointer
);

PMU_DATABASE_LOOKASIDE_LIST_IN_MEMORY
MuGetFreeEntry (
    PMU_DATABASE_OBJECT DatabaseObject,
    USHORT RequiredSize,
    PMU_DATABASE_LOOKASIDE_LIST_IN_MEMORY *PreviousPointer
);

NTSTATUS
MuDeleteDataset (
    PMU_DATABASE_OBJECT DatabaseObject,
    UCHAR EntryIndex,
    PMU_DATABASE_DATASET_INFO_IN_MEMORY DatasetObject
);

NTSTATUS
MuRecoverFreeEntry (
    PMU_DATABASE_OBJECT DatabaseObject,
    ULONG ChunkOffset,
    USHORT ChunkSize
);

NTSTATUS
MuUpdateDatasetToDatabase (
    PMU_DATABASE_OBJECT DatabaseObject,
    UCHAR EntryIndex,
    PMU_DATABASE_DATASET_INFO_IN_MEMORY DatasetObject
);

NTSTATUS
MuSubstituteToFaceName (
    PIRP Irp,
    PULONG BytesWritten
);

NTSTATUS
MuAddAppConfig (
    PIRP Irp
);

NTSTATUS
MuEnumDataset (
    PMU_DATABASE_OBJECT DatabaseObject,
    UCHAR EntryIndex,
    MU_DATABASE_ENUM_DATASET_PROC Callback,
    PVOID CallerContext
);

BOOLEAN
MuFaceNameEnumProc (
    PMU_DATABASE_DATASET_INFO_IN_MEMORY DatasetObject,
    PMU_SUBSTITUTE_TO_FACE_NAME_CONTEXT Context,
    PNTSTATUS FinalStatus
);

BOOLEAN
MuHookModule (
    PVOID ImageBase,
    PMU_AUDIT_BLOCK AuditBlock,
    ULONG NumAuBlocks,
    BOOLEAN IgnoreVerification
);

PVOID
MuInlineHook (
    PVOID OriginalProcedure,
    PVOID RedirectAddress
);

PVOID
MuLocateCharacteristicCode (
    PVOID ImageBase,
    ULONG ImageSize,
    PUCHAR VerifyCode,
    PUCHAR VerifyMask,
    ULONG CodeLength
);

BOOLEAN
MuCheckAppPathConflictProc (
    PMU_DATABASE_DATASET_INFO_IN_MEMORY DatasetObject,
    PWSTR Context,
    PNTSTATUS FinalStatus
);

NTSTATUS
MuQueryLeb (
    PIRP Irp,
    PULONG BytesWritten
);

BOOLEAN
MuLookupLebByFilePathProc (
    PMU_DATABASE_DATASET_INFO_IN_MEMORY DatasetObject,
    PMU_CTLIN_QUERY_LEB Context,
    PNTSTATUS FinalStatus
);

BOOLEAN
MuConfigListEnumProc (
    PMU_DATABASE_DATASET_INFO_IN_MEMORY DatasetObject,
    PMU_ENUM_APPCONFIG_CONTEXT Context,
    PNTSTATUS FinalStatus
);

BOOLEAN
MuLookupAppConfigByFilePathProc (
    PMU_DATABASE_DATASET_INFO_IN_MEMORY DatasetObject,
    PMU_QUERY_APPCONFIG_CONTEXT Context,
    PNTSTATUS FinalStatus
);

NTSTATUS
MuRemoveAppConfig (
    PIRP Irp
);

NTSTATUS
MuEnumAppConfig (
    PIRP Irp,
    PULONG BytesWritten
);

NTSTATUS
MuQueryAppConfig (
    PIRP Irp,
    PULONG BytesWritten
);

BOOLEAN
MuFindAndRemoveConfigProc (
    PMU_DATABASE_DATASET_INFO_IN_MEMORY DatasetObject,
    PMU_DATABASE_DATASET_INFO_IN_MEMORY Context,
    PNTSTATUS FinalStatus
);

void
MuWriteDebugLog (
    ULONG Value
);

void
MuWriteDebugLogSpecifyName (
    PWSTR ValueName,
    ULONG Value
);

NTSTATUS
MuCreateFile (
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
);

NTSTATUS
MuOpenFile (
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess,
    ULONG OpenOptions
);

BOOLEAN
MuIsUnicodeLeadingString (
    PUNICODE_STRING StringSource,
    PWSTR StringToFind
);

NTSTATUS
MuOpenObjectByName (
    POBJECT_ATTRIBUTES ObjectAttributes,
    POBJECT_TYPE ObjectType,
    KPROCESSOR_MODE AccessMode,
    PACCESS_STATE AccessState,
    ACCESS_MASK DesiredAccess,
    PVOID ParseContext,
    PHANDLE Handle
);

NTSTATUS
MuStubOpenObjectByName (
    POBJECT_ATTRIBUTES ObjectAttributes,
    POBJECT_TYPE ObjectType,
    KPROCESSOR_MODE AccessMode,
    PACCESS_STATE AccessState,
    ACCESS_MASK DesiredAccess,
    PVOID ParseContext,
    PHANDLE Handle
);

BOOLEAN
MuCheckRoutineStackFrame (
    PVOID RoutineEntry
);

PMU_LOADER_ENVIRONMENT
MuLocateLeb (
    void
);

PMU_GLOBAL_DATA
MuAcquireImpersonationPathMutex (
    void
);

void
MuReleaseImpersonationPathMutex (
    void
);

ULONG
MuLookupImpersonationPathByJackName (
    PWSTR Path
);

ULONG
MuAllocateAndInsertPathMappingObject (
    PWSTR Path
);

void
MuInitNlsTables (
    PUSHORT AnsiNlsBase,
    PUSHORT OemNlsBase,
    PUSHORT LanguageNlsBase,
    PNLSTABLEINFO TableInfo
);