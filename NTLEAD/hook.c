#include <ntddk.h>

#include "ntlead.h"


extern MU_GLOBAL_DATA g_GlobalData;
extern NTUNEXPPROC_RtlInitNlsTables RtlInitNlsTables;
extern NTUNEXPPROC_MmCreatePeb MmCreatePeb;
extern NTUNEXPPROC_MmCreateTeb MmCreateTeb;
extern NTUNEXPPROC_MmGetSessionLocaleId MmGetSessionLocaleId;
extern NTUNEXPPROC_NtQueryDefaultLocale NtQueryDefaultLocale;
extern NTUNEXPPROC_NtQueryDefaultUILanguage NtQueryDefaultUILanguage;
extern NTUNEXPPROC_NtQueryInstallUILanguage NtQueryInstallUILanguage;
extern NTPROC_NtCreateFile NtCreateFile_;
extern NTPROC_NtOpenFile NtOpenFile_;
extern PVOID ObOpenObjectByName_;

extern PBOOLEAN NlsMbCodePageTag;

#pragma alloc_text(PAGE, MuMultiByteToUnicodeN)
#pragma alloc_text(PAGE, MuUnicodeToMultiByteN)
#pragma alloc_text(PAGE, MuOemToUnicodeN)
#pragma alloc_text(PAGE, MuUnicodeToOemN)
#pragma alloc_text(PAGE, MuUpcaseUnicodeToMultiByteN)
#pragma alloc_text(PAGE, MuUpcaseUnicodeToOemN)
#pragma alloc_text(PAGE, MuCreatePeb)
#pragma alloc_text(PAGE, MuCreateTeb)
#pragma alloc_text(PAGE, MuGetDefaultCodePage)
#pragma alloc_text(PAGE, MuQueryDefaultLocale)
#pragma alloc_text(PAGE, MuQueryDefaultUILanguage)
#pragma alloc_text(PAGE, MuQueryInstallUILanguage)


NTSTATUS
MuMultiByteToUnicodeN (
    PWCH UnicodeString,
    ULONG MaxBytesInUnicodeString,
    PULONG BytesInUnicodeString,
    PCH MultiByteString,
    ULONG BytesInMultiByteString
)
{
    NTSTATUS status;
    PMU_PROCESS_CONTEXT context = MuLookupCurrentProcessContext();
    PCPTABLEINFO tabinfo;
    
    if (context)
        tabinfo = &context->CustomNlsTableInfo.AnsiTableInfo;
    else
        tabinfo = &g_GlobalData.SystemNlsTableInfo.AnsiTableInfo;
    
    status = RtlCustomCPToUnicodeN(tabinfo,
                                   UnicodeString,
                                   MaxBytesInUnicodeString,
                                   BytesInUnicodeString,
                                   MultiByteString,
                                   BytesInMultiByteString);
    
    if (context)
        MuDereferenceProcessContext(context);
    
    return status;
}

NTSTATUS
MuUnicodeToMultiByteN (
    PCH MultiByteString,
    ULONG MaxBytesInMultiByteString,
    PULONG BytesInMultiByteString,
    PWCH UnicodeString,
    ULONG BytesInUnicodeString
)
{
    NTSTATUS status;
    PMU_PROCESS_CONTEXT context = MuLookupCurrentProcessContext();
    PCPTABLEINFO tabinfo;
    
    if (context)
    {
        tabinfo = &context->CustomNlsTableInfo.AnsiTableInfo;
        
        if (!*NlsMbCodePageTag)
            MaxBytesInMultiByteString = BytesInUnicodeString;
    }
    else
    {
        tabinfo = &g_GlobalData.SystemNlsTableInfo.AnsiTableInfo;
    }
    
    status = RtlUnicodeToCustomCPN(tabinfo,
                                   MultiByteString,
                                   MaxBytesInMultiByteString,
                                   BytesInMultiByteString,
                                   UnicodeString,
                                   BytesInUnicodeString);
    
    if (context)
        MuDereferenceProcessContext(context);
    
    return status;
}

NTSTATUS
MuOemToUnicodeN (
    PWCH UnicodeString,
    ULONG MaxBytesInUnicodeString,
    PULONG BytesInUnicodeString,
    PCH MultiByteString,
    ULONG BytesInMultiByteString
)
{
    NTSTATUS status;
    PMU_PROCESS_CONTEXT context = MuLookupCurrentProcessContext();
    PCPTABLEINFO tabinfo;
    
    if (context)
        tabinfo = &context->CustomNlsTableInfo.OemTableInfo;
    else
        tabinfo = &g_GlobalData.SystemNlsTableInfo.OemTableInfo;
    
    status = RtlCustomCPToUnicodeN(tabinfo,
                                   UnicodeString,
                                   MaxBytesInUnicodeString,
                                   BytesInUnicodeString,
                                   MultiByteString,
                                   BytesInMultiByteString);
    
    if (context)
        MuDereferenceProcessContext(context);
    
    return status;
}

NTSTATUS
MuUnicodeToOemN (
    PCH MultiByteString,
    ULONG MaxBytesInMultiByteString,
    PULONG BytesInMultiByteString,
    PWCH UnicodeString,
    ULONG BytesInUnicodeString
)
{
    NTSTATUS status;
    PMU_PROCESS_CONTEXT context = MuLookupCurrentProcessContext();
    PCPTABLEINFO tabinfo;
    
    if (context)
        tabinfo = &context->CustomNlsTableInfo.OemTableInfo;
    else
        tabinfo = &g_GlobalData.SystemNlsTableInfo.OemTableInfo;
    
    status = RtlUnicodeToCustomCPN(tabinfo,
                                   MultiByteString,
                                   MaxBytesInMultiByteString,
                                   BytesInMultiByteString,
                                   UnicodeString,
                                   BytesInUnicodeString);
    
    if (context)
        MuDereferenceProcessContext(context);
    
    return status;
}

NTSTATUS
MuUpcaseUnicodeToMultiByteN (
    PCH MultiByteString,
    ULONG MaxBytesInMultiByteString,
    PULONG BytesInMultiByteString,
    PWCH UnicodeString,
    ULONG BytesInUnicodeString
)
{
    NTSTATUS status;
    PMU_PROCESS_CONTEXT context = MuLookupCurrentProcessContext();
    PCPTABLEINFO tabinfo;
    
    if (context)
        tabinfo = &context->CustomNlsTableInfo.AnsiTableInfo;
    else
        tabinfo = &g_GlobalData.SystemNlsTableInfo.AnsiTableInfo;
    
    status = RtlUpcaseUnicodeToCustomCPN(tabinfo,
                                         MultiByteString,
                                         MaxBytesInMultiByteString,
                                         BytesInMultiByteString,
                                         UnicodeString,
                                         BytesInUnicodeString);
    
    if (context)
        MuDereferenceProcessContext(context);
    
    return status;
}

NTSTATUS
MuUpcaseUnicodeToOemN (
    PCH MultiByteString,
    ULONG MaxBytesInMultiByteString,
    PULONG BytesInMultiByteString,
    PWCH UnicodeString,
    ULONG BytesInUnicodeString
)
{
    NTSTATUS status;
    PMU_PROCESS_CONTEXT context = MuLookupCurrentProcessContext();
    PCPTABLEINFO tabinfo;
    
    if (context)
        tabinfo = &context->CustomNlsTableInfo.OemTableInfo;
    else
        tabinfo = &g_GlobalData.SystemNlsTableInfo.OemTableInfo;
    
    status = RtlUpcaseUnicodeToCustomCPN(tabinfo,
                                         MultiByteString,
                                         MaxBytesInMultiByteString,
                                         BytesInMultiByteString,
                                         UnicodeString,
                                         BytesInUnicodeString);
    
    if (context)
        MuDereferenceProcessContext(context);
    
    return status;
}

NTSTATUS
MuMultiByteToUnicodeSize (
    PULONG BytesInUnicodeString,
    PCH MultiByteString,
    ULONG BytesInMultiByteString
)
{
    *BytesInUnicodeString = BytesInMultiByteString * sizeof(WCHAR);
    
    return STATUS_SUCCESS;
}

NTSTATUS
MuUnicodeToMultiByteSize (
    PULONG BytesInMultiByteString,
    PWCH UnicodeString,
    ULONG BytesInUnicodeString
)
{
    *BytesInMultiByteString = BytesInUnicodeString;
    
    return STATUS_SUCCESS;
}

NTSTATUS
MuCreatePeb (
    PEPROCESS TargetProcess,
    PINITIAL_PEB InitialPeb,
    PPEB *Base
)
{
    NTSTATUS status = MmCreatePeb(TargetProcess, InitialPeb, Base);
    HANDLE proc;
    PVOID secview = NULL;
    PMU_TEMPORARY_THREAD_RECORD record;
    PMU_NLS_SOURCE_DESCRIPTOR nsd;
    PMU_LOADER_ENVIRONMENT leb = MuLocateLeb();
    PMU_PROCESS_CONTEXT context;
    SIZE_T tabsize = 0, envsize = sizeof(MU_LOADER_ENVIRONMENT);
    LARGE_INTEGER secofs;
    
    if (!NT_SUCCESS(status))
        return status;
    
    KeAttachProcess(TargetProcess);
    
    status = ZwAllocateVirtualMemory(NtCurrentProcess(),
                                     &leb,
                                     0,
                                     &envsize,
                                     MEM_RESERVE,
                                     PAGE_READWRITE);
    
    if (NT_SUCCESS(status))
    {
        if (NT_SUCCESS(ZwAllocateVirtualMemory(NtCurrentProcess(),
                                               &leb,
                                               0,
                                               &envsize,
                                               MEM_COMMIT,
                                               PAGE_READWRITE)))
        {
            __try
            {
                RtlZeroMemory(leb, sizeof(MU_LOADER_ENVIRONMENT));
            }
            __except (1)
            {
                KeDetachProcess();
                
                return STATUS_SUCCESS;
            }
        }
    }
    
    KeDetachProcess();
    
    record = MuGetInvokerParameters();
    
    if (!record)
        return status;
    
    nsd = MuLoadCustomizeNlsTable(&record->Leb.NlsParam);
    
    if (!nsd)
        return status;
    
    context = MuCreateProcessContext();
    
    if (!context)
        return status;
    
    context->ProcessObject   = TargetProcess;
    context->EnhancedOptions = record->Leb.EnhancedOptions;
    context->Nsd = nsd;
    
    secofs.QuadPart = 0;
    
    KeAttachProcess(TargetProcess);   // avoid BSOD issue in xp?
    
    __try
    {
        RtlCopyMemory(leb, &record->Leb, sizeof(MU_LOADER_ENVIRONMENT));
    }
    __except (1)
    {
        KeDetachProcess();
        
        return STATUS_SUCCESS;
    }
    
    record->LockContext = FALSE;
    
    status = MmMapViewOfSection(nsd->CustomNlsSource.TableSection,
                                TargetProcess,
                                &secview,
                                0,
                                0,
                                &secofs,
                                &tabsize,
                                ViewShare,
                                MEM_TOP_DOWN | SEC_NO_CHANGE,
                                PAGE_READONLY);
    
    KeDetachProcess();
    
    if (NT_SUCCESS(status))
    {
        KeAttachProcess(TargetProcess);
        
        MuInitNlsTables((PUSHORT)((PUCHAR)secview + nsd->CustomNlsSource.AnsiTableOffset),
                        (PUSHORT)((PUCHAR)secview + nsd->CustomNlsSource.OemTableOffset),
                        (PUSHORT)((PUCHAR)secview + nsd->CustomNlsSource.LangTableOffset),
                        &context->CustomNlsTableInfo);
        
        __try
        {
            (*Base)->AnsiCodePageData     = (PVOID)((PUCHAR)secview + nsd->CustomNlsSource.AnsiTableOffset);
            (*Base)->OemCodePageData      = (PVOID)((PUCHAR)secview + nsd->CustomNlsSource.OemTableOffset);
            (*Base)->UnicodeCaseTableData = (PVOID)((PUCHAR)secview + nsd->CustomNlsSource.LangTableOffset);
        }
        __except (1)
        {
            KeDetachProcess();
            
            MuDereferenceProcessContext(context);
            
            return STATUS_SUCCESS;
        }
        
        KeDetachProcess();
    }
    else
    {
        MuDereferenceProcessContext(context);
    }
    
    return STATUS_SUCCESS;
}

NTSTATUS
MuCreateTeb (
    PEPROCESS TargetProcess,
    PINITIAL_TEB InitialTeb,
    PCLIENT_ID ClientId,
    PTEB *Base
)
{
    NTSTATUS status = MmCreateTeb(TargetProcess, InitialTeb, ClientId, Base);
    PMU_PROCESS_CONTEXT context;
    KAPC_STATE apcstate;
    
    __asm int 3
    __asm int 3
    
    if (NT_SUCCESS(status))
    {
        context = MuLookupProcessContext(TargetProcess);
        
        if (context)
        {
            KeStackAttachProcess(TargetProcess, &apcstate);
            
            __try
            {
                (*Base)->CurrentLocale = context->Nsd->NlsParam.LocaleId;
            }
            __except (1)
            {
                KeUnstackDetachProcess(&apcstate);
                
                MuDereferenceProcessContext(context);
                
                return GetExceptionCode();
            }
            
            KeUnstackDetachProcess(&apcstate);
            
            MuDereferenceProcessContext(context);
        }
    }
    
    return status;
}

void
MuGetDefaultCodePage (
    PUSHORT AnsiCodePage,
    PUSHORT OemCodePage
)
{
    PMU_PROCESS_CONTEXT context = MuLookupCurrentProcessContext();
    
    if (context)
    {
        *AnsiCodePage = (USHORT)context->Nsd->NlsParam.AnsiCodePage;
        *OemCodePage  = (USHORT)context->Nsd->NlsParam.OemCodePage;
        
        MuDereferenceProcessContext(context);
    }
    else
    {
        *AnsiCodePage = g_GlobalData.SystemNlsTableInfo.AnsiTableInfo.CodePage;
        *OemCodePage  = g_GlobalData.SystemNlsTableInfo.OemTableInfo.CodePage;
    }
}

PMU_TEMPORARY_THREAD_RECORD
MuGetInvokerParameters (
    void
)
{
    PETHREAD curtcb = PsGetCurrentThread();
    PMU_GLOBAL_DATA GlobalData;
    PMU_TEMPORARY_THREAD_RECORD currec;
    KLOCK_QUEUE_HANDLE lock;
    
    GlobalData = MuAcquireThreadRecordLock(&lock);
    
    currec = GlobalData->TempThreadRecord;
    
    while (currec)
    {
        if (currec->ThreadObject == curtcb)
        {
            currec->LockContext = TRUE;
            
            break;
        }
        
        currec = currec->Next;
    }
    
    MuReleaseSpinLock(&lock);
    
    return currec;
}

NTSTATUS
MuQueryDefaultLocale (
    BOOLEAN UserProfile,
    PLCID DefaultLocaleId
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PMU_PROCESS_CONTEXT context = MuLookupCurrentProcessContext();
    
    if (context)
    {
        __try
        {
            if (PsGetCurrentThreadPreviousMode() != KernelMode)
                ProbeForWrite(DefaultLocaleId, sizeof(LCID), 1);
            
            *DefaultLocaleId = context->Nsd->NlsParam.LocaleId;
        }
        __except (1)
        {
            status = GetExceptionCode();
        }
        
        MuDereferenceProcessContext(context);
    }
    else
    {
        status = NtQueryDefaultLocale(UserProfile, DefaultLocaleId);
    }
    
    return status;
}

NTSTATUS
MuQueryDefaultUILanguage (
    LANGID *DefaultUILanguageId
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PMU_PROCESS_CONTEXT context = MuLookupCurrentProcessContext();
    
    if (context && context->EnhancedOptions & MU_OPTION_CHANGE_UI_LANG_ID)
    {
        __try
        {
            if (PsGetCurrentThreadPreviousMode() != KernelMode)
                ProbeForWrite(DefaultUILanguageId, sizeof(LANGID), 1);
            
            *DefaultUILanguageId = (LANGID)context->Nsd->NlsParam.LocaleId;
        }
        __except (1)
        {
            status = GetExceptionCode();
        }
        
        MuDereferenceProcessContext(context);
    }
    else
    {
        status = NtQueryDefaultUILanguage(DefaultUILanguageId);
    }
    
    return status;
}

NTSTATUS
MuQueryInstallUILanguage (
    LANGID *InstallUILanguageId
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PMU_PROCESS_CONTEXT context = MuLookupCurrentProcessContext();
    
    if (context && context->EnhancedOptions & MU_OPTION_CHANGE_UI_LANG_ID)
    {
        __try
        {
            if (PsGetCurrentThreadPreviousMode() != KernelMode)
                ProbeForWrite(InstallUILanguageId, sizeof(LANGID), 1);
            
            *InstallUILanguageId = (LANGID)context->Nsd->NlsParam.LocaleId;
        }
        __except (1)
        {
            status = GetExceptionCode();
        }
        
        MuDereferenceProcessContext(context);
    }
    else
    {
        status = NtQueryInstallUILanguage(InstallUILanguageId);
    }
    
    return status;
}

LCID
MuGetSessionLocaleId (
    void
)
{
    LCID lcid;
    
    PMU_PROCESS_CONTEXT context = MuLookupCurrentProcessContext();
    
    if (context)
    {
        lcid = context->Nsd->NlsParam.LocaleId;
        
        MuDereferenceProcessContext(context);
    }
    else
    {
        lcid = MmGetSessionLocaleId();
    }
    
    return lcid;
}

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
)
{
    UNICODE_STRING fp;
    
    if (PsGetCurrentThreadPreviousMode() == KernelMode)
    {
        return NtCreateFile_(FileHandle,
                             DesiredAccess,
                             ObjectAttributes,
                             IoStatusBlock,
                             AllocationSize,
                             FileAttributes,
                             ShareAccess,
                             CreateDisposition,
                             CreateOptions,
                             EaBuffer,
                             EaLength);
    }
    else
    {
        if (MuIsUnicodeLeadingString(ObjectAttributes->ObjectName, L"\\??\\E:\\test000"))
        {
            RtlCopyMemory(ObjectAttributes->ObjectName->Buffer, L"\\??\\C:\\Windows", sizeof(L"\\??\\C:\\Windows") - 2);
        }
    }
    
        return NtCreateFile_(FileHandle,
                             DesiredAccess,
                             ObjectAttributes,
                             IoStatusBlock,
                             AllocationSize,
                             FileAttributes,
                             ShareAccess,
                             CreateDisposition,
                             CreateOptions,
                             EaBuffer,
                             EaLength);
}

NTSTATUS
MuOpenFile (
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess,
    ULONG OpenOptions
)
{
    UNICODE_STRING fp;
    
    if (PsGetCurrentThreadPreviousMode() == KernelMode)
    {
        return NtOpenFile_(FileHandle,
                           DesiredAccess,
                           ObjectAttributes,
                           IoStatusBlock,
                           ShareAccess,
                           OpenOptions);
    }
    else
    {
        if (MuIsUnicodeLeadingString(ObjectAttributes->ObjectName, L"\\??\\E:\\test000"))
        {
            RtlCopyMemory(ObjectAttributes->ObjectName->Buffer, L"\\??\\C:\\Windows", sizeof(L"\\??\\C:\\Windows") - 2);
        }
    }
    
        return NtOpenFile_(FileHandle,
                           DesiredAccess,
                           ObjectAttributes,
                           IoStatusBlock,
                           ShareAccess,
                           OpenOptions);
}

NTSTATUS
MuOpenObjectByName (
    POBJECT_ATTRIBUTES ObjectAttributes,
    POBJECT_TYPE ObjectType,
    KPROCESSOR_MODE AccessMode,
    PACCESS_STATE AccessState,
    ACCESS_MASK DesiredAccess,
    PVOID ParseContext,
    PHANDLE Handle
)
{
    NTSTATUS status;
    PMU_PATH_MAPPING_RECORD record;
    PMU_USER_OA_CONTEXT context = NULL;
    ULONG pathid, i, j;
    SIZE_T size;
    USHORT pathlen, namelen;
    WCHAR namebuf[64];
    
    if (AccessMode != KernelMode && g_GlobalData.MappedPathCount > 0)
    {
        __try
        {
            ProbeForRead(ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), 1);
            ProbeForRead(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, 1);
            
            if (ObjectAttributes->ObjectName->Length < GLOBAL_NAMESPACE_SIZE + sizeof(PASSING_DRIVE_LETTER))
                __leave;
            
            if (RtlCompareMemory(ObjectAttributes->ObjectName->Buffer, GLOBAL_NAMESPACE, GLOBAL_NAMESPACE_SIZE) != GLOBAL_NAMESPACE_SIZE)
                __leave;
            
            RtlCopyMemory(namebuf, ObjectAttributes->ObjectName->Buffer, GLOBAL_NAMESPACE_SIZE + sizeof(PASSING_DRIVE_LETTER));
            RtlCopyMemory((PVOID)((ULONG)namebuf + GLOBAL_NAMESPACE_SIZE + sizeof(PASSING_DRIVE_LETTER)), MU_IMPERSONATION_PATH_GUID, sizeof(MU_IMPERSONATION_PATH_GUID) - sizeof(WCHAR));
            
            for (i = 0 ; i < g_GlobalData.MappedPathCount ; i++)
            {
                swprintf((PWSTR)((ULONG)namebuf + GLOBAL_NAMESPACE_SIZE + sizeof(PASSING_DRIVE_LETTER) + sizeof(MU_IMPERSONATION_PATH_GUID) - sizeof(WCHAR)), MU_STRING_FORMAT_GUID_PATH, i + 1);
                
                if (MuIsUnicodeLeadingString(ObjectAttributes->ObjectName, namebuf))
                {
                    MuAcquireImpersonationPathMutex();
                    
                    record = g_GlobalData.PathMappingRecord;
                    
                    for (j = 0 ; j != i ; j++)
                        record = record->Next;
                    
                    MuReleaseImpersonationPathMutex();
                    
                    pathlen = (USHORT)wcslen(record->Path) * sizeof(WCHAR);
                    namelen = (USHORT)wcslen(namebuf) * sizeof(WCHAR);
                    
                    size = sizeof(MU_USER_OA_CONTEXT) + pathlen + (ObjectAttributes->ObjectName->Length - namelen);
                    
                    status = ZwAllocateVirtualMemory(NtCurrentProcess(),
                                                     &context,
                                                     0,
                                                     &size,
                                                     MEM_COMMIT,
                                                     PAGE_READWRITE);
                    
                    if (!NT_SUCCESS(status))
                        __leave;
                    
                    RtlCopyMemory(&context->ObjAttr, ObjectAttributes, sizeof(OBJECT_ATTRIBUTES));
                    RtlCopyMemory(context->NameBuffer, record->Path, pathlen);
                    RtlCopyMemory((PVOID)((ULONG)context->NameBuffer + pathlen), (PVOID)((ULONG)ObjectAttributes->ObjectName->Buffer + namelen), ObjectAttributes->ObjectName->Length - namelen);
                    
                    context->ObjAttr.ObjectName->Buffer        = context->NameBuffer;
                    context->ObjAttr.ObjectName->Length        = pathlen + (ObjectAttributes->ObjectName->Length - namelen);
                    context->ObjAttr.ObjectName->MaximumLength = 0;
                    
                    status = MuStubOpenObjectByName(&context->ObjAttr,
                                                    ObjectType,
                                                    AccessMode,
                                                    AccessState,
                                                    DesiredAccess,
                                                    ParseContext,
                                                    Handle);
                    
                    ZwFreeVirtualMemory(NtCurrentProcess(),
                                        &context,
                                        &size,
                                        MEM_DECOMMIT);
                    
                    return status;
                }
            }
        }
        __except (1)
        {
            return GetExceptionCode();
        }
    }
    
    return MuStubOpenObjectByName(ObjectAttributes,
                                  ObjectType,
                                  AccessMode,
                                  AccessState,
                                  DesiredAccess,
                                  ParseContext,
                                  Handle);
}

NTSTATUS
__declspec(naked)
MuStubOpenObjectByName (
    POBJECT_ATTRIBUTES ObjectAttributes,
    POBJECT_TYPE ObjectType,
    KPROCESSOR_MODE AccessMode,
    PACCESS_STATE AccessState,
    ACCESS_MASK DesiredAccess,
    PVOID ParseContext,
    PHANDLE Handle
)
{
    __asm
    {
        push ebp
        mov ebp,esp
        jmp [ObOpenObjectByName_]
    }
}