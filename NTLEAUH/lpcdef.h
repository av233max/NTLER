#define OPTIONAL

#define DECLSPEC_IMPORT     __declspec(dllimport)

//#define NTSYSAPI   DECLSPEC_IMPORT

typedef CONST int CINT;
typedef CONST char *PCSZ;
typedef CONST wchar_t CWSTR, *PCWSTR;
typedef ULONG CLONG;
typedef short CSHORT;
typedef CSHORT *PCSHORT;
typedef LARGE_INTEGER PHYSICAL_ADDRESS, *PPHYSICAL_ADDRESS;
typedef LONG KPRIORITY;
typedef LONG NTSTATUS, *PNTSTATUS;
typedef unsigned char BOOLEAN, *PBOOLEAN;

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

#define FILE_READ_DATA            ( 0x0001 )    // file & pipe
#define FILE_LIST_DIRECTORY       ( 0x0001 )    // directory

#define FILE_WRITE_DATA           ( 0x0002 )    // file & pipe
#define FILE_ADD_FILE             ( 0x0002 )    // directory

#define FILE_APPEND_DATA          ( 0x0004 )    // file
#define FILE_ADD_SUBDIRECTORY     ( 0x0004 )    // directory
#define FILE_CREATE_PIPE_INSTANCE ( 0x0004 )    // named pipe


#define FILE_READ_EA              ( 0x0008 )    // file & directory

#define FILE_WRITE_EA             ( 0x0010 )    // file & directory

#define FILE_EXECUTE              ( 0x0020 )    // file
#define FILE_TRAVERSE             ( 0x0020 )    // directory

#define FILE_DELETE_CHILD         ( 0x0040 )    // directory

#define FILE_READ_ATTRIBUTES      ( 0x0080 )    // all

#define FILE_WRITE_ATTRIBUTES     ( 0x0100 )    // all

#define FILE_GENERIC_READ         (STANDARD_RIGHTS_READ     |\
                                   FILE_READ_DATA           |\
                                   FILE_READ_ATTRIBUTES     |\
                                   FILE_READ_EA             |\
                                   SYNCHRONIZE)


#define FILE_GENERIC_WRITE        (STANDARD_RIGHTS_WRITE    |\
                                   FILE_WRITE_DATA          |\
                                   FILE_WRITE_ATTRIBUTES    |\
                                   FILE_WRITE_EA            |\
                                   FILE_APPEND_DATA         |\
                                   SYNCHRONIZE)


#define FILE_GENERIC_EXECUTE      (STANDARD_RIGHTS_EXECUTE  |\
                                   FILE_READ_ATTRIBUTES     |\
                                   FILE_EXECUTE             |\
                                   SYNCHRONIZE)

// end_winnt


//
// Define share access rights to files and directories
//

#define FILE_SHARE_READ                 0x00000001  // winnt
#define FILE_SHARE_WRITE                0x00000002  // winnt
#define FILE_SHARE_DELETE               0x00000004  // winnt
#define FILE_SHARE_VALID_FLAGS          0x00000007

//
// Define the file attributes values
//
// Note:  0x00000008 is reserved for use for the old DOS VOLID (volume ID)
//        and is therefore not considered valid in NT.
//
// Note:  0x00000010 is reserved for use for the old DOS SUBDIRECTORY flag
//        and is therefore not considered valid in NT.  This flag has
//        been disassociated with file attributes since the other flags are
//        protected with READ_ and WRITE_ATTRIBUTES access to the file.
//
// Note:  Note also that the order of these flags is set to allow both the
//        FAT and the Pinball File Systems to directly set the attributes
//        flags in attributes words without having to pick each flag out
//        individually.  The order of these flags should not be changed!
//

#define FILE_ATTRIBUTE_READONLY             0x00000001  // winnt
#define FILE_ATTRIBUTE_HIDDEN               0x00000002  // winnt
#define FILE_ATTRIBUTE_SYSTEM               0x00000004  // winnt
//OLD DOS VOLID                             0x00000008

#define FILE_ATTRIBUTE_DIRECTORY            0x00000010  // winnt
#define FILE_ATTRIBUTE_ARCHIVE              0x00000020  // winnt
#define FILE_ATTRIBUTE_DEVICE               0x00000040  // winnt
#define FILE_ATTRIBUTE_NORMAL               0x00000080  // winnt

#define FILE_ATTRIBUTE_TEMPORARY            0x00000100  // winnt
#define FILE_ATTRIBUTE_SPARSE_FILE          0x00000200  // winnt
#define FILE_ATTRIBUTE_REPARSE_POINT        0x00000400  // winnt
#define FILE_ATTRIBUTE_COMPRESSED           0x00000800  // winnt

#define FILE_ATTRIBUTE_OFFLINE              0x00001000  // winnt
#define FILE_ATTRIBUTE_NOT_CONTENT_INDEXED  0x00002000  // winnt

//
//  This definition is old and will disappear shortly
//

#define FILE_ATTRIBUTE_CONTENT_INDEXED      FILE_ATTRIBUTE_NOT_CONTENT_INDEXED

#define FILE_ATTRIBUTE_VALID_FLAGS      0x00007fb7
#define FILE_ATTRIBUTE_VALID_SET_FLAGS  0x000031a7

//
// Define the create disposition values
//

#define FILE_SUPERSEDE                  0x00000000
#define FILE_OPEN                       0x00000001
#define FILE_CREATE                     0x00000002
#define FILE_OPEN_IF                    0x00000003
#define FILE_OVERWRITE                  0x00000004
#define FILE_OVERWRITE_IF               0x00000005
#define FILE_MAXIMUM_DISPOSITION        0x00000005

//
// Define the create/open option flags
//

#define FILE_DIRECTORY_FILE                     0x00000001
#define FILE_WRITE_THROUGH                      0x00000002
#define FILE_SEQUENTIAL_ONLY                    0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING          0x00000008

#define FILE_SYNCHRONOUS_IO_ALERT               0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT            0x00000020
#define FILE_NON_DIRECTORY_FILE                 0x00000040
#define FILE_CREATE_TREE_CONNECTION             0x00000080

#define FILE_COMPLETE_IF_OPLOCKED               0x00000100
#define FILE_NO_EA_KNOWLEDGE                    0x00000200
#define FILE_OPEN_FOR_RECOVERY                  0x00000400
#define FILE_RANDOM_ACCESS                      0x00000800

#define FILE_DELETE_ON_CLOSE                    0x00001000
#define FILE_OPEN_BY_FILE_ID                    0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT             0x00004000
#define FILE_NO_COMPRESSION                     0x00008000

#define FILE_RESERVE_OPFILTER                   0x00100000
#define FILE_OPEN_REPARSE_POINT                 0x00200000
#define FILE_OPEN_NO_RECALL                     0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY          0x00800000

#define FILE_COPY_STRUCTURED_STORAGE            0x00000041
#define FILE_STRUCTURED_STORAGE                 0x00000441

#define FILE_VALID_OPTION_FLAGS                 0x00ffffff
#define FILE_VALID_PIPE_OPTION_FLAGS            0x00000032
#define FILE_VALID_MAILSLOT_OPTION_FLAGS        0x00000032
#define FILE_VALID_SET_FLAGS                    0x00000036

//
// Define the I/O status information return values for NtCreateFile/NtOpenFile
//

#define FILE_SUPERSEDED                 0x00000000
#define FILE_OPENED                     0x00000001
#define FILE_CREATED                    0x00000002
#define FILE_OVERWRITTEN                0x00000003
#define FILE_EXISTS                     0x00000004
#define FILE_DOES_NOT_EXIST             0x00000005

//
// Define special ByteOffset parameters for read and write operations
//

#define FILE_WRITE_TO_END_OF_FILE       0xffffffff
#define FILE_USE_FILE_POINTER_POSITION  0xfffffffe

//
// Define alignment requirement values
//

#define FILE_BYTE_ALIGNMENT             0x00000000
#define FILE_WORD_ALIGNMENT             0x00000001
#define FILE_LONG_ALIGNMENT             0x00000003
#define FILE_QUAD_ALIGNMENT             0x00000007
#define FILE_OCTA_ALIGNMENT             0x0000000f
#define FILE_32_BYTE_ALIGNMENT          0x0000001f
#define FILE_64_BYTE_ALIGNMENT          0x0000003f
#define FILE_128_BYTE_ALIGNMENT         0x0000007f
#define FILE_256_BYTE_ALIGNMENT         0x000000ff
#define FILE_512_BYTE_ALIGNMENT         0x000001ff

//
// Define the maximum length of a filename string
//

#define MAXIMUM_FILENAME_LENGTH         256

//
// Define the various device characteristics flags
//

#define FILE_REMOVABLE_MEDIA            0x00000001
#define FILE_READ_ONLY_DEVICE           0x00000002
#define FILE_FLOPPY_DISKETTE            0x00000004
#define FILE_WRITE_ONCE_MEDIA           0x00000008
#define FILE_REMOTE_DEVICE              0x00000010
#define FILE_DEVICE_IS_MOUNTED          0x00000020
#define FILE_VIRTUAL_VOLUME             0x00000040
#define FILE_AUTOGENERATED_DEVICE_NAME  0x00000080
#define FILE_DEVICE_SECURE_OPEN         0x00000100


#define FILE_DEVICE_BEEP                0x00000001
#define FILE_DEVICE_CD_ROM              0x00000002
#define FILE_DEVICE_CD_ROM_FILE_SYSTEM  0x00000003
#define FILE_DEVICE_CONTROLLER          0x00000004
#define FILE_DEVICE_DATALINK            0x00000005
#define FILE_DEVICE_DFS                 0x00000006
#define FILE_DEVICE_DISK                0x00000007
#define FILE_DEVICE_DISK_FILE_SYSTEM    0x00000008
#define FILE_DEVICE_FILE_SYSTEM         0x00000009
#define FILE_DEVICE_INPORT_PORT         0x0000000a
#define FILE_DEVICE_KEYBOARD            0x0000000b
#define FILE_DEVICE_MAILSLOT            0x0000000c
#define FILE_DEVICE_MIDI_IN             0x0000000d
#define FILE_DEVICE_MIDI_OUT            0x0000000e
#define FILE_DEVICE_MOUSE               0x0000000f
#define FILE_DEVICE_MULTI_UNC_PROVIDER  0x00000010
#define FILE_DEVICE_NAMED_PIPE          0x00000011
#define FILE_DEVICE_NETWORK             0x00000012
#define FILE_DEVICE_NETWORK_BROWSER     0x00000013
#define FILE_DEVICE_NETWORK_FILE_SYSTEM 0x00000014
#define FILE_DEVICE_NULL                0x00000015
#define FILE_DEVICE_PARALLEL_PORT       0x00000016
#define FILE_DEVICE_PHYSICAL_NETCARD    0x00000017
#define FILE_DEVICE_PRINTER             0x00000018
#define FILE_DEVICE_SCANNER             0x00000019
#define FILE_DEVICE_SERIAL_MOUSE_PORT   0x0000001a
#define FILE_DEVICE_SERIAL_PORT         0x0000001b
#define FILE_DEVICE_SCREEN              0x0000001c
#define FILE_DEVICE_SOUND               0x0000001d
#define FILE_DEVICE_STREAMS             0x0000001e
#define FILE_DEVICE_TAPE                0x0000001f
#define FILE_DEVICE_TAPE_FILE_SYSTEM    0x00000020
#define FILE_DEVICE_TRANSPORT           0x00000021
#define FILE_DEVICE_UNKNOWN             0x00000022
#define FILE_DEVICE_VIDEO               0x00000023
#define FILE_DEVICE_VIRTUAL_DISK        0x00000024
#define FILE_DEVICE_WAVE_IN             0x00000025
#define FILE_DEVICE_WAVE_OUT            0x00000026
#define FILE_DEVICE_8042_PORT           0x00000027
#define FILE_DEVICE_NETWORK_REDIRECTOR  0x00000028
#define FILE_DEVICE_BATTERY             0x00000029
#define FILE_DEVICE_BUS_EXTENDER        0x0000002a
#define FILE_DEVICE_MODEM               0x0000002b
#define FILE_DEVICE_VDM                 0x0000002c
#define FILE_DEVICE_MASS_STORAGE        0x0000002d
#define FILE_DEVICE_SMB                 0x0000002e
#define FILE_DEVICE_KS                  0x0000002f
#define FILE_DEVICE_CHANGER             0x00000030
#define FILE_DEVICE_SMARTCARD           0x00000031
#define FILE_DEVICE_ACPI                0x00000032
#define FILE_DEVICE_DVD                 0x00000033
#define FILE_DEVICE_FULLSCREEN_VIDEO    0x00000034
#define FILE_DEVICE_DFS_FILE_SYSTEM     0x00000035
#define FILE_DEVICE_DFS_VOLUME          0x00000036
#define FILE_DEVICE_SERENUM             0x00000037
#define FILE_DEVICE_TERMSRV             0x00000038
#define FILE_DEVICE_KSEC                0x00000039

//
// Macro definition for defining IOCTL and FSCTL function control codes.  Note
// that function codes 0-2047 are reserved for Microsoft Corporation, and
// 2048-4095 are reserved for customers.
//

#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
)

//
// Macro to extract device type out of the device io control code
//
#define DEVICE_TYPE_FROM_CTL_CODE(ctrlCode)     (((ULONG)(ctrlCode & 0xffff0000)) >> 16)

//
// Define the method codes for how buffers are passed for I/O and FS controls
//

#define METHOD_BUFFERED                 0
#define METHOD_IN_DIRECT                1
#define METHOD_OUT_DIRECT               2
#define METHOD_NEITHER                  3

//
// Define the access check value for any access
//
//
// The FILE_READ_ACCESS and FILE_WRITE_ACCESS constants are also defined in
// ntioapi.h as FILE_READ_DATA and FILE_WRITE_DATA. The values for these
// constants *MUST* always be in sync.
//
//
// FILE_SPECIAL_ACCESS is checked by the NT I/O system the same as FILE_ANY_ACCESS.
// The file systems, however, may add additional access checks for I/O and FS controls
// that use this value.
//


#define FILE_ANY_ACCESS                 0
#define FILE_SPECIAL_ACCESS    (FILE_ANY_ACCESS)
#define FILE_READ_ACCESS          ( 0x0001 )    // file & pipe
#define FILE_WRITE_ACCESS         ( 0x0002 )    // file & pipe

//
// Basic NT Types
//
#if !defined(_NTSECAPI_H) && !defined(_SUBAUTH_H) && !defined(_NTSECAPI_)

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    };

    ULONG Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
} STRING, *PSTRING;

typedef struct _CSTRING
{
    USHORT Length;
    USHORT MaximumLength;
    CONST CHAR *Buffer;
} CSTRING, *PCSTRING;

#endif

#define OBJ_INHERIT             0x00000002L
#define OBJ_PERMANENT           0x00000010L
#define OBJ_EXCLUSIVE           0x00000020L
#define OBJ_CASE_INSENSITIVE    0x00000040L
#define OBJ_OPENIF              0x00000080L
#define OBJ_OPENLINK            0x00000100L
#define OBJ_KERNEL_HANDLE       0x00000200L
#define OBJ_VALID_ATTRIBUTES    0x000003F2L

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

//
// ClientID Structure
//
typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef const UNICODE_STRING* PCUNICODE_STRING;
typedef STRING ANSI_STRING;
typedef PSTRING PANSI_STRING;
typedef STRING OEM_STRING;
typedef PSTRING POEM_STRING;
typedef CONST STRING* PCOEM_STRING;
typedef STRING CANSI_STRING;
typedef PSTRING PCANSI_STRING;

#define PORT_MAXIMUM_MESSAGE_LENGTH     0x130

//
// Port Object Access Masks
//
#define PORT_CONNECT                    0x1
#define PORT_ALL_ACCESS                 0x1

//
// Port Object Flags
//
#define LPCP_CONNECTION_PORT            0x00000001
#define LPCP_UNCONNECTED_PORT           0x00000002
#define LPCP_COMMUNICATION_PORT         0x00000003
#define LPCP_CLIENT_PORT                0x00000004
#define LPCP_PORT_TYPE_MASK             0x0000000F
#define LPCP_PORT_DELETED               0x10000000
#define LPCP_WAITABLE_PORT              0x20000000
#define LPCP_NAME_DELETED               0x40000000
#define LPCP_SECURITY_DYNAMIC           0x80000000

//
// LPC Message Types
//
typedef enum _LPC_TYPE
{
    LPC_NEW_MESSAGE,
    LPC_REQUEST,
    LPC_REPLY,
    LPC_DATAGRAM,
    LPC_LOST_REPLY,
    LPC_PORT_CLOSED,
    LPC_CLIENT_DIED,
    LPC_EXCEPTION,
    LPC_DEBUG_EVENT,
    LPC_ERROR_EVENT,
    LPC_CONNECTION_REQUEST,
    LPC_CONNECTION_REFUSED,
    LPC_MAXIMUM
} LPC_TYPE;

//
// Information Classes for NtQueryInformationPort
//
typedef enum _PORT_INFORMATION_CLASS
{
    PortNoInformation
} PORT_INFORMATION_CLASS;

//
// Portable LPC Types for 32/64-bit compatibility
//
#ifdef USE_LPC6432
#define LPC_CLIENT_ID CLIENT_ID64
#define LPC_SIZE_T ULONGLONG
#define LPC_PVOID ULONGLONG
#define LPC_HANDLE ULONGLONG
#else
#define LPC_CLIENT_ID CLIENT_ID
#define LPC_SIZE_T SIZE_T
#define LPC_PVOID PVOID
#define LPC_HANDLE HANDLE
#endif

//
// LPC Port Message
//
typedef struct _PORT_MESSAGE
{
    union
    {
        struct
        {
            CSHORT DataLength;
            CSHORT TotalLength;
        } s1;
        ULONG Length;
    } u1;
    union
    {
        struct
        {
            CSHORT Type;
            CSHORT DataInfoOffset;
        } s2;
        ULONG ZeroInit;
    } u2;
    union
    {
        LPC_CLIENT_ID ClientId;
        double DoNotUseThisField;
    };
    ULONG MessageId;
    union
    {
        LPC_SIZE_T ClientViewSize;
        ULONG CallbackId;
    };
} PORT_MESSAGE, *PPORT_MESSAGE;

//
// Local and Remove Port Views
//
typedef struct _PORT_VIEW
{
    ULONG Length;
    LPC_HANDLE SectionHandle;
    ULONG SectionOffset;
    LPC_SIZE_T ViewSize;
    LPC_PVOID ViewBase;
    LPC_PVOID ViewRemoteBase;
} PORT_VIEW, *PPORT_VIEW;

typedef struct _REMOTE_PORT_VIEW
{
    ULONG Length;
    LPC_SIZE_T ViewSize;
    LPC_PVOID ViewBase;
} REMOTE_PORT_VIEW, *PREMOTE_PORT_VIEW;

//
// LPC Kernel-Mode Message Structures defined for size only
//
typedef struct _LPCP_MESSAGE
{
    UCHAR Data[0x14];
    PORT_MESSAGE Request;
} LPCP_MESSAGE;

typedef struct _LPCP_CONNECTION_MESSAGE
{
    UCHAR Data[0x2C];
} LPCP_CONNECTION_MESSAGE;

//
// Client Died LPC Message
//
typedef struct _CLIENT_DIED_MSG
{
    PORT_MESSAGE h;
    LARGE_INTEGER CreateTime;
} CLIENT_DIED_MSG, *PCLIENT_DIED_MSG;

//
// Maximum total Kernel-Mode LPC Message Structure Size
//
#define LPCP_MAX_MESSAGE_SIZE \
    N_ROUND_UP(PORT_MAXIMUM_MESSAGE_LENGTH + \
    sizeof(LPCP_MESSAGE) + \
    sizeof(LPCP_CONNECTION_MESSAGE), 16)

//
// Maximum actual LPC Message Length
//
#define LPC_MAX_MESSAGE_LENGTH \
    (LPCP_MAX_MESSAGE_SIZE - \
    FIELD_OFFSET(LPCP_MESSAGE, Request))

//
// Maximum actual size of LPC Message Data
//
#define LPC_MAX_DATA_LENGTH \
    (LPC_MAX_MESSAGE_LENGTH - \
    sizeof(PORT_MESSAGE) - \
    sizeof(LPCP_CONNECTION_MESSAGE))
    
typedef union _SM_PORT_MESSAGE
{
    /*** LPC common header ***/
    PORT_MESSAGE Header;
    union
    {
        struct
        {
            UCHAR LpcHeader[sizeof(PORT_MESSAGE)];
            /*** SM common header ***/
            struct
            {
                DWORD       ApiIndex;
                NTSTATUS    Status;
                
                union
                {
                    DWORD   LaunchCode;
                    ULONG   SessionId;
                };
                
            } SmHeader;
            /*** SM per API arguments ***/
        };
        UCHAR PadBuffer[PORT_MAXIMUM_MESSAGE_LENGTH];
    };
} SM_PORT_MESSAGE, * PSM_PORT_MESSAGE;

typedef struct _FILE_FULL_EA_INFORMATION {
    ULONG NextEntryOffset;
    UCHAR Flags;
    UCHAR EaNameLength;
    USHORT EaValueLength;
    CHAR EaName[1];
} FILE_FULL_EA_INFORMATION, *PFILE_FULL_EA_INFORMATION;

NTSYSAPI
NTSTATUS
NTAPI
NtRequestPort(
    IN HANDLE PortHandle,
    IN PPORT_MESSAGE LpcMessage
);
    

NTSYSAPI
NTSTATUS
NTAPI
NtAcceptConnectPort(
    PHANDLE PortHandle,
    PVOID PortContext OPTIONAL,
    PPORT_MESSAGE ConnectionRequest,
    BOOLEAN AcceptConnection,
    PPORT_VIEW ServerView OPTIONAL,
    PREMOTE_PORT_VIEW ClientView OPTIONAL
);

NTSYSAPI
NTSTATUS
NTAPI
NtConnectPort(
    PHANDLE PortHandle,
    PUNICODE_STRING PortName,
    PSECURITY_QUALITY_OF_SERVICE SecurityQos,
    PPORT_VIEW ClientView OPTIONAL,
    PREMOTE_PORT_VIEW ServerView OPTIONAL,
    PULONG MaxMessageLength OPTIONAL,
    PVOID ConnectionInformation OPTIONAL,
    PULONG ConnectionInformationLength OPTIONAL
);

NTSYSAPI
VOID
NTAPI
RtlInitUnicodeString(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
    );
    
NTSYSAPI
VOID
NTAPI
RtlInitString(
    PSTRING DestinationString,
    PCSTR SourceString
    );
    
NTSYSAPI
NTSTATUS
NTAPI
NtRequestWaitReplyPort(
    IN HANDLE PortHandle,
    OUT PPORT_MESSAGE LpcReply,
    IN PPORT_MESSAGE LpcRequest
);

NTSYSAPI
NTSTATUS
NTAPI
NtCreatePort(
    PHANDLE PortHandle,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG MaxConnectionInfoLength,
    ULONG MaxMessageLength,
    ULONG MaxPoolUsage
);

NTSYSAPI
NTSTATUS
NTAPI
NtCreateFile(
    OUT PHANDLE FileHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PLARGE_INTEGER AllocationSize OPTIONAL,
    IN ULONG FileAttributes,
    IN ULONG ShareAccess,
    IN ULONG CreateDisposition,
    IN ULONG CreateOptions,
    IN PVOID EaBuffer OPTIONAL,
    IN ULONG EaLength
);

NTSYSAPI
NTSTATUS
NTAPI
NtDeviceIoControlFile(
    HANDLE FileHandle,
    HANDLE Event,
    PVOID ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG IoControlCode,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength
);

NTSYSAPI
NTSTATUS
NTAPI
NtClose(
    HANDLE Object
);

NTSYSAPI
NTSTATUS
NTAPI
NtReplyPort(
    IN HANDLE PortHandle,
    IN PPORT_MESSAGE LpcReply
);

NTSYSAPI
NTSTATUS
NTAPI
NtReplyWaitReceivePort(
    IN HANDLE PortHandle,
    OUT PVOID *PortContext OPTIONAL,
    IN PPORT_MESSAGE ReplyMessage OPTIONAL,
    OUT PPORT_MESSAGE ReceiveMessage
);

NTSYSAPI
NTSTATUS
NTAPI
NtAcceptConnectPort(
    PHANDLE PortHandle,
    PVOID PortContext OPTIONAL,
    PPORT_MESSAGE ConnectionRequest,
    BOOLEAN AcceptConnection,
    PPORT_VIEW ServerView OPTIONAL,
    PREMOTE_PORT_VIEW ClientView OPTIONAL
);

NTSYSAPI
NTSTATUS
NTAPI
NtCompleteConnectPort(
    HANDLE PortHandle
);

NTSYSAPI
void
NTAPI
RtlInitUnicodeString(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
);

NTSYSAPI
void
NTAPI
RtlInitUnicodeString(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
);

NTSYSAPI
NTSTATUS
NTAPI
NtDuplicateObject(
  IN HANDLE               SourceProcessHandle,
  IN PHANDLE              SourceHandle,
  IN HANDLE               TargetProcessHandle,
  OUT PHANDLE             TargetHandle,
  IN ACCESS_MASK          DesiredAccess OPTIONAL,
  IN BOOLEAN              InheritHandle,
  IN ULONG                Options
);

NTSYSAPI 
NTSTATUS
NTAPI
LdrGetProcedureAddress(
  IN HMODULE              ModuleHandle,
  IN PSTRING         FunctionName OPTIONAL,
  IN WORD                 Oridinal OPTIONAL,
  OUT PVOID               *FunctionAddress
);
 
NTSYSAPI 
NTSTATUS
NTAPI
RtlCompareUnicodeString(
  PUNICODE_STRING String1,
  PUNICODE_STRING String2,
  BOOLEAN CaseInSensitive
);

NTSYSAPI
void
NTAPI
RtlInitUnicodeString(
  IN OUT PUNICODE_STRING  DestinationString,
  IN PCWSTR  SourceString
  );
  
NTSYSAPI
NTSTATUS
NTAPI
NtOpenSection(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

NTSYSAPI
NTSTATUS
NTAPI
NtMapViewOfSection(
    IN HANDLE SectionHandle,
    IN HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN ULONG ZeroBits,
    IN ULONG CommitSize,
    IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
    IN OUT PSIZE_T ViewSize,
    IN SECTION_INHERIT InheritDisposition,
    IN ULONG AllocationType,
    IN ULONG Protect
    );

NTSYSAPI
NTSTATUS
NTAPI
NtUnmapViewOfSection(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress
    );
    
NTSYSAPI 
NTSTATUS
NTAPI
NtAllocateVirtualMemory(

  IN HANDLE               ProcessHandle,
  IN OUT PVOID            *BaseAddress,
  IN ULONG                ZeroBits,
  IN OUT PULONG           RegionSize,
  IN ULONG                AllocationType,
  IN ULONG                Protect );
  
NTSYSAPI 
NTSTATUS
NTAPI
NtProtectVirtualMemory(

  IN HANDLE               ProcessHandle,
  IN OUT PVOID            *BaseAddress,
  IN OUT PULONG           NumberOfBytesToProtect,
  IN ULONG                NewAccessProtection,
  OUT PULONG              OldAccessProtection );

NTSYSAPI 
NTSTATUS
NTAPI
NtFlushInstructionCache(

  IN HANDLE               ProcessHandle,
  IN PVOID                BaseAddress,
  IN ULONG                NumberOfBytesToFlush );

NTSYSAPI 
NTSTATUS
NTAPI
NtFreeVirtualMemory(

  IN HANDLE               ProcessHandle,
  IN PVOID                *BaseAddress,
  IN OUT PULONG           RegionSize,
  IN ULONG                FreeType );

NTSYSAPI 
NTSTATUS
NTAPI
LdrLoadDll(

  IN PWCHAR               PathToFile OPTIONAL,
  IN ULONG                Flags OPTIONAL,
  IN PUNICODE_STRING      ModuleFileName,
  OUT PHANDLE             ModuleHandle );

NTSYSAPI 
NTSTATUS
NTAPI
LdrUnloadDll(

  IN HANDLE               ModuleHandle );
  
typedef enum _OBJECT_WAIT_TYPE {


    WaitAllObject,
    WaitAnyObject


} OBJECT_WAIT_TYPE, *POBJECT_WAIT_TYPE;

  
NTSYSAPI 
NTSTATUS
NTAPI
NtWaitForMultipleObjects(

  IN ULONG                ObjectCount,
  IN PHANDLE              ObjectsArray,
  IN OBJECT_WAIT_TYPE     WaitType,
  IN BOOLEAN              Alertable,
  IN PLARGE_INTEGER       TimeOut OPTIONAL );

NTSYSAPI 
NTSTATUS
NTAPI
NtWaitForSingleObject(

  IN HANDLE               ObjectHandle,
  IN BOOLEAN              Alertable,
  IN PLARGE_INTEGER       TimeOut OPTIONAL );
  
typedef
VOID
(NTAPI *PIO_APC_ROUTINE) (
    IN PVOID ApcContext,
    IN PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG Reserved
    );
  
NTSYSAPI 
NTSTATUS
NTAPI
NtWriteFile(

  IN HANDLE               FileHandle,
  IN HANDLE               Event OPTIONAL,
  IN PIO_APC_ROUTINE      ApcRoutine OPTIONAL,
  IN PVOID                ApcContext OPTIONAL,
  OUT PIO_STATUS_BLOCK    IoStatusBlock,
  IN PVOID                Buffer,
  IN ULONG                Length,
  IN PLARGE_INTEGER       ByteOffset OPTIONAL,
  IN PULONG               Key OPTIONAL );

NTSYSAPI 
NTSTATUS
NTAPI
NtReadFile(

  IN HANDLE               FileHandle,
  IN HANDLE               Event OPTIONAL,
  IN PIO_APC_ROUTINE      ApcRoutine OPTIONAL,
  IN PVOID                ApcContext OPTIONAL,
  OUT PIO_STATUS_BLOCK    IoStatusBlock,
  OUT PVOID               Buffer,
  IN ULONG                Length,
  IN PLARGE_INTEGER       ByteOffset OPTIONAL,
  IN PULONG               Key OPTIONAL );


NTSYSAPI 
NTSTATUS
NTAPI
RtlGetVersion(
    IN OUT POSVERSIONINFOW  VersionInformation
    );
    
NTSYSAPI 
NTSTATUS
NTAPI
NtOpenKey(

  OUT PHANDLE             pKeyHandle,
  IN ACCESS_MASK          DesiredAccess,
  IN POBJECT_ATTRIBUTES   ObjectAttributes );
  
typedef enum _KEY_INFORMATION_CLASS {
    KeyBasicInformation,
    KeyNodeInformation,
    KeyFullInformation,
    KeyNameInformation,
    KeyCachedInformation,
    KeyFlagsInformation,
    KeyVirtualizationInformation,
    MaxKeyInfoClass  // MaxKeyInfoClass should always be the last enum
} KEY_INFORMATION_CLASS;

NTSYSAPI 
NTSTATUS
NTAPI
NtEnumerateKey(

  IN HANDLE               KeyHandle,
  IN ULONG                Index,
  IN KEY_INFORMATION_CLASS KeyInformationClass,
  OUT PVOID               KeyInformation,
  IN ULONG                Length,
  OUT PULONG              ResultLength );
  
typedef struct _KEY_BASIC_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG   TitleIndex;
    ULONG   NameLength;
    WCHAR   Name[1];            // Variable length string
} KEY_BASIC_INFORMATION, *PKEY_BASIC_INFORMATION;

typedef struct _KEY_NODE_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG   TitleIndex;
    ULONG   ClassOffset;
    ULONG   ClassLength;
    ULONG   NameLength;
    WCHAR   Name[1];            // Variable length string
//          Class[1];           // Variable length string not declared
} KEY_NODE_INFORMATION, *PKEY_NODE_INFORMATION;

typedef struct _KEY_FULL_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG   TitleIndex;
    ULONG   ClassOffset;
    ULONG   ClassLength;
    ULONG   SubKeys;
    ULONG   MaxNameLen;
    ULONG   MaxClassLen;
    ULONG   Values;
    ULONG   MaxValueNameLen;
    ULONG   MaxValueDataLen;
    WCHAR   Class[1];           // Variable length
} KEY_FULL_INFORMATION, *PKEY_FULL_INFORMATION;
  
typedef enum _KEY_VALUE_INFORMATION_CLASS {
    KeyValueBasicInformation,
    KeyValueFullInformation,
    KeyValuePartialInformation,
    KeyValueFullInformationAlign64,
    KeyValuePartialInformationAlign64,
    MaxKeyValueInfoClass  // MaxKeyValueInfoClass should always be the last enum
} KEY_VALUE_INFORMATION_CLASS;

NTSYSAPI 
NTSTATUS
NTAPI
NtQueryValueKey(

  IN HANDLE               KeyHandle,
  IN PUNICODE_STRING      ValueName,
  IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
  OUT PVOID               KeyValueInformation,
  IN ULONG                Length,
  OUT PULONG              ResultLength );
  
typedef struct _KEY_VALUE_BASIC_INFORMATION {
    ULONG   TitleIndex;
    ULONG   Type;
    ULONG   NameLength;
    WCHAR   Name[1];            // Variable size
} KEY_VALUE_BASIC_INFORMATION, *PKEY_VALUE_BASIC_INFORMATION;

typedef struct _KEY_VALUE_FULL_INFORMATION {
    ULONG   TitleIndex;
    ULONG   Type;
    ULONG   DataOffset;
    ULONG   DataLength;
    ULONG   NameLength;
    WCHAR   Name[1];            // Variable size
//          Data[1];            // Variable size data not declared
} KEY_VALUE_FULL_INFORMATION, *PKEY_VALUE_FULL_INFORMATION;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION {
    ULONG   TitleIndex;
    ULONG   Type;
    ULONG   DataLength;
    UCHAR   Data[1];            // Variable size
} KEY_VALUE_PARTIAL_INFORMATION, *PKEY_VALUE_PARTIAL_INFORMATION;

NTSYSAPI
NTSTATUS
NTAPI
NtCreateProcessEx (
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
    
#define NtCurrentProcess() ((HANDLE)-1)

NTSYSAPI
void
NTAPI
RtlInitAnsiString (
    PANSI_STRING DestinationString,
    PCSTR SourceString
    );
    
NTSYSAPI
NTSTATUS
NTAPI
NtCreateSymbolicLinkObject (
    PHANDLE LinkHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PUNICODE_STRING LinkTarget
    );

NTSYSAPI
NTSTATUS
NTAPI
NtOpenSymbolicLinkObject (
    PHANDLE LinkHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
    );

NTSYSAPI
NTSTATUS
NTAPI
NtQuerySymbolicLinkObject (
    HANDLE LinkHandle,
    PUNICODE_STRING LinkTarget,
    PULONG ReturnedLength
    );

#define SYMBOLIC_LINK_QUERY (0x0001)

#define SYMBOLIC_LINK_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0x1)

NTSYSAPI
NTSTATUS   NTAPI RtlUnicodeStringToAnsiString(    IN OUT PANSI_STRING  DestinationString,    IN PUNICODE_STRING  SourceString,    IN BOOLEAN  AllocateDestinationString    );

NTSYSAPI
NTSTATUS   NTAPI RtlAnsiStringToUnicodeString(    IN OUT PUNICODE_STRING  DestinationString,    IN PANSI_STRING  SourceString,    IN BOOLEAN  AllocateDestinationString    );

NTSYSAPI
LONG   NTAPI RtlCompareUnicodeString(    IN PUNICODE_STRING  String1,    IN PUNICODE_STRING  String2,    IN BOOLEAN  CaseInSensitive    );

NTSYSAPI VOID NTAPI  RtlFreeAnsiString(    IN PANSI_STRING  AnsiString    );

NTSYSAPI VOID  NTAPI   RtlFreeUnicodeString(    IN PUNICODE_STRING  UnicodeString    );