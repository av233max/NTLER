typedef struct _SYSTEM_MODULE {


  ULONG                Reserved1;
  ULONG                Reserved2;
  PVOID                ImageBaseAddress;
  ULONG                ImageSize;
  ULONG                Flags;
  USHORT               Id;
  USHORT               Rank;
  USHORT               w018;
  USHORT               NameOffset;
  UCHAR                Name[MAXIMUM_FILENAME_LENGTH];

} SYSTEM_MODULE, *PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION {


  ULONG                ModulesCount;
  SYSTEM_MODULE        Modules[0];


} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {


    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation,
    SystemLocksInformation,
    SystemStackTraceInformation,
    SystemPagedPoolInformation,
    SystemNonPagedPoolInformation,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPageFileInformation,
    SystemVdmInstemulInformation,
    SystemVdmBopInformation,
    SystemFileCacheInformation,
    SystemPoolTagInformation,
    SystemInterruptInformation,
    SystemDpcBehaviorInformation,
    SystemFullMemoryInformation,
    SystemLoadGdiDriverInformation,
    SystemUnloadGdiDriverInformation,
    SystemTimeAdjustmentInformation,
    SystemSummaryMemoryInformation,
    SystemNextEventIdInformation,
    SystemEventIdsInformation,
    SystemCrashDumpInformation,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemExtendServiceTableInformation,
    SystemPrioritySeperation,
    SystemPlugPlayBusInformation,
    SystemDockInformation,
    SystemPowerInformation_,
    SystemProcessorSpeedInformation,
    SystemCurrentTimeZoneInformation,
    SystemLookasideInformation


} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation (
  SYSTEM_INFORMATION_CLASS SystemInformationClass,
  PVOID SystemInformation,
  ULONG SystemInformationLength,
  PULONG ReturnLength
);

NTSYSAPI
void
NTAPI
ExFreePoolWithTag (
    IN PVOID  P,
    IN ULONG  Tag 
    );
    
#define MAXIMUM_LEADBYTES   12

typedef struct _CPTABLEINFO {
    USHORT CodePage;                    // code page number
    USHORT MaximumCharacterSize;        // max length (bytes) of a char
    USHORT DefaultChar;                 // default character (MB)
    USHORT UniDefaultChar;              // default character (Unicode)
    USHORT TransDefaultChar;            // translation of default char (Unicode)
    USHORT TransUniDefaultChar;         // translation of Unic default char (MB)
    USHORT DBCSCodePage;                // Non 0 for DBCS code pages
    UCHAR  LeadByte[MAXIMUM_LEADBYTES]; // lead byte ranges
    PUSHORT MultiByteTable;             // pointer to MB translation table
    PVOID   WideCharTable;              // pointer to WC translation table
    PUSHORT DBCSRanges;                 // pointer to DBCS ranges
    PUSHORT DBCSOffsets;                // pointer to DBCS offsets
} CPTABLEINFO, *PCPTABLEINFO;

typedef struct _NLSTABLEINFO {
    CPTABLEINFO OemTableInfo;
    CPTABLEINFO AnsiTableInfo;
    PUSHORT UpperCaseTable;             // 844 format upcase table
    PUSHORT LowerCaseTable;             // 844 format lower case table
} NLSTABLEINFO, *PNLSTABLEINFO;

#define MEM_COMMIT           0x1000     
#define MEM_RESERVE          0x2000     
#define MEM_DECOMMIT         0x4000     
#define MEM_RELEASE          0x8000     
#define MEM_FREE            0x10000     
#define MEM_PRIVATE         0x20000     
#define MEM_MAPPED          0x40000     
#define MEM_RESET           0x80000     
#define MEM_TOP_DOWN       0x100000     
#define MEM_WRITE_WATCH    0x200000     
#define MEM_PHYSICAL       0x400000     
#define MEM_ROTATE         0x800000     
#define MEM_LARGE_PAGES  0x20000000     
#define MEM_4MB_PAGES    0x80000000     
#define SEC_FILE           0x800000     
#define SEC_IMAGE         0x1000000     
#define SEC_PROTECTED_IMAGE  0x2000000     
#define SEC_RESERVE       0x4000000     
#define SEC_COMMIT        0x8000000     
#define SEC_NOCACHE      0x10000000     
#define SEC_WRITECOMBINE 0x40000000     
#define SEC_LARGE_PAGES  0x80000000     
#define MEM_IMAGE         SEC_IMAGE     
#define WRITE_WATCH_FLAG_RESET 0x01     

NTSYSAPI
NTSTATUS
NTAPI
MmMapViewOfSection (
     PVOID SectionToMap,
     PEPROCESS Process,
    PVOID *CapturedBase,
     ULONG_PTR ZeroBits,
     SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T CapturedViewSize,
     SECTION_INHERIT InheritDisposition,
     ULONG AllocationType,
     ULONG Win32Protect
    );

NTSYSAPI
NTSTATUS
NTAPI
MmUnmapViewOfSection (
     PEPROCESS Process,
     PVOID BaseAddress
     );
     
NTSYSAPI
NTSTATUS
NTAPI
MmMapViewInSystemSpace (
     PVOID Section,
    PVOID *MappedBase,
    PSIZE_T ViewSize
    );

NTSYSAPI
NTSTATUS
NTAPI
MmUnmapViewInSystemSpace (
     PVOID MappedBase
    );
    
NTSYSAPI
NTSTATUS
NTAPI
RtlMultiByteToUnicodeN(
     PWCH UnicodeString,
     ULONG MaxBytesInUnicodeString,
     PULONG BytesInUnicodeString,
     PCH CustomCPString,
     ULONG BytesInCustomCPString);
    
NTSYSAPI
NTSTATUS
NTAPI
RtlOemToUnicodeN(
     PWCH UnicodeString,
     ULONG MaxBytesInUnicodeString,
     PULONG BytesInUnicodeString,
     PCH CustomCPString,
     ULONG BytesInCustomCPString);
    
NTSYSAPI
NTSTATUS
NTAPI
RtlUnicodeToMultiByteN(
     PCH MultiByteString,
     ULONG MaxBytesInMultiByteString,
     PULONG BytesInMultiByteString,
     PWCH UnicodeString,
     ULONG BytesInUnicodeString);
    
NTSYSAPI
NTSTATUS
NTAPI
RtlUnicodeToOemN(
     PCH MultiByteString,
     ULONG MaxBytesInMultiByteString,
     PULONG BytesInMultiByteString,
     PWCH UnicodeString,
     ULONG BytesInUnicodeString);

NTSYSAPI
NTSTATUS
NTAPI
RtlCustomCPToUnicodeN(
     PCPTABLEINFO CustomCP,
     PWCH UnicodeString,
     ULONG MaxBytesInUnicodeString,
     PULONG BytesInUnicodeString,
     PCH CustomCPString,
     ULONG BytesInCustomCPString);

NTSYSAPI
NTSTATUS
NTAPI
RtlUnicodeToCustomCPN(
     PCPTABLEINFO CustomCP,
     PCH MultiByteString,
     ULONG MaxBytesInMultiByteString,
     PULONG BytesInMultiByteString,
     PWCH UnicodeString,
     ULONG BytesInUnicodeString);
     
NTSYSAPI
NTSTATUS
NTAPI
RtlMultiByteToUnicodeSize (
    PULONG BytesInUnicodeString,
    PCH MultiByteString,
    ULONG BytesInMultiByteString
);

NTSYSAPI
NTSTATUS
NTAPI
RtlUnicodeToMultiByteSize (
    PULONG BytesInMultiByteString,
    PWCH UnicodeString,
    ULONG BytesInUnicodeString
);

NTSYSAPI
void
NTAPI
RtlInitCodePageTable(
    IN PUSHORT TableBase,
    OUT PCPTABLEINFO CodePageTable
    );
     
NTSYSAPI
NTSTATUS
NTAPI RtlUpcaseUnicodeToMultiByteN(    OUT PCHAR  MultiByteString,    IN ULONG  MaxBytesInMultiByteString,    OUT PULONG  BytesInMultiByteString  OPTIONAL,    IN PWSTR  UnicodeString,    IN ULONG  BytesInUnicodeString    ); 

NTSYSAPI
NTSTATUS
NTAPI RtlUpcaseUnicodeToCustomCPN(    PCPTABLEINFO CustomCP, OUT PCHAR  MultiByteString,    IN ULONG  MaxBytesInMultiByteString,    OUT PULONG  BytesInMultiByteString  OPTIONAL,    IN PWSTR  UnicodeString,    IN ULONG  BytesInUnicodeString    ); 


NTSYSAPI
NTSTATUS
NTAPI RtlUpcaseUnicodeToOemN(    OUT PCHAR  OemString,    IN ULONG  MaxBytesInOemString,    OUT PULONG  BytesInOemString  OPTIONAL,    IN PWSTR  UnicodeString,    IN ULONG  BytesInUnicodeString    ); 

#define SEC_NO_CHANGE      0x400000

NTSYSAPI
NTSTATUS
NTAPI
PsLookupProcessByProcessId (
    IN HANDLE ProcessId,
    OUT PEPROCESS *Process
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwAllocateVirtualMemory (
    IN HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN ULONG_PTR ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect
    );
    
NTSYSAPI
NTSTATUS
NTAPI
ObOpenObjectByPointer (
  IN PVOID  Object,
  IN ULONG  HandleAttributes,
  IN PACCESS_STATE  PassedAccessState  OPTIONAL,
  IN ACCESS_MASK  DesiredAccess  OPTIONAL,
  IN POBJECT_TYPE  ObjectType  OPTIONAL,
  IN KPROCESSOR_MODE  AccessMode,
  OUT PHANDLE  Handle
  );
  
typedef struct _KAPC_STATE
{
	
    LIST_ENTRY  ApcListHead [2];
    PEPROCESS  Process;
    BOOLEAN  KernelApcInProgress;
    BOOLEAN  KernelApcPending;
    BOOLEAN  UserApcPending;
    
} KAPC_STATE, *PRKAPC_STATE;

NTSYSAPI
NTSTATUS
NTAPI
KeStackAttachProcess (
    PEPROCESS Process,
    PRKAPC_STATE ApcState
    );
    
NTSYSAPI
NTSTATUS
NTAPI
KeUnstackDetachProcess (
    PRKAPC_STATE ApcState
    );
    
typedef struct _INITIAL_PEB *PINITIAL_PEB;

typedef struct _PEB
{

    UCHAR Reserved[0x58];
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;

} PEB, *PPEB;

typedef struct _INITIAL_TEB *PINITIAL_TEB;

typedef struct _TEB
{

    UCHAR Reserved[0x30];
    PPEB Peb;
    UCHAR Reserved2[0x90];
    LCID CurrentLocale;

} TEB, *PTEB;

NTSYSAPI
int
__cdecl
swprintf( wchar_t * ws, 
              const wchar_t * format, 
             ... );
             
typedef struct _KSERVICE_TABLE_DESCRIPTOR {
    PULONG_PTR Base;
    PULONG Count;
    ULONG Limit;
    PUCHAR Number;
} KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryDefaultLocale(
    IN BOOLEAN UserProfile,
    OUT PLCID DefaultLocaleId
    );
    
NTSYSAPI
NTSTATUS
NTAPI
ZwQueryDefaultUILanguage(
    LANGID *LangId
);

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryInstallUILanguage(
    LANGID *LangId
);
    
NTSYSAPI
CCHAR
PsGetCurrentThreadPreviousMode(
    VOID
    );

NTSYSAPI
void
RtlGetDefaultCodePage(
    PUSHORT AnsiCodePage,
    PUSHORT OemCodePage
);
    
NTSYSAPI NTSTATUS   ZwOpenEvent(    OUT PHANDLE  EventHandle,    IN ACCESS_MASK  DesiredAccess,    IN POBJECT_ATTRIBUTES  ObjectAttributes    );
NTSYSAPI NTSTATUS  ZwSetEvent(     HANDLE  EventHandle,     PLONG  PreviousState     );
NTSYSAPI NTSTATUS  ZwWaitForSingleObject(     HANDLE  Handle,     BOOLEAN  Alertable,     PLARGE_INTEGER  Timeout    );

NTSYSAPI
VOID
KeAttachProcess (
    PEPROCESS Process
    );

NTSYSAPI
VOID
KeDetachProcess (
    VOID
    );
    
NTSYSAPI
NTSTATUS 
  ZwCreateSection(
    OUT PHANDLE  SectionHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES  ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER  MaximumSize OPTIONAL,
    IN ULONG  SectionPageProtection,
    IN ULONG  AllocationAttributes,
    IN HANDLE  FileHandle OPTIONAL
    );
    
NTSYSAPI
NTSTATUS
NTAPI
ZwCreateSymbolicLinkObject (
    PHANDLE LinkHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PUNICODE_STRING LinkTarget
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwOpenSymbolicLinkObject (
    PHANDLE LinkHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySymbolicLinkObject (
    HANDLE LinkHandle,
    PUNICODE_STRING LinkTarget,
    PULONG ReturnedLength
    );

#define SYMBOLIC_LINK_QUERY (0x0001)

#define SYMBOLIC_LINK_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0x1)

NTSYSAPI
NTSTATUS
NTAPI
ObOpenObjectByName (
    POBJECT_ATTRIBUTES ObjectAttributes,
    POBJECT_TYPE ObjectType,
    KPROCESSOR_MODE AccessMode,
    PACCESS_STATE AccessState,
    ACCESS_MASK DesiredAccess,
    PVOID ParseContext,
    PHANDLE Handle
);


NTSYSAPI
NTSTATUS
NTAPI
ZwFreeVirtualMemory(     HANDLE  ProcessHandle,     PVOID  *BaseAddress,    PSIZE_T  RegionSize,     ULONG  FreeType    ); 