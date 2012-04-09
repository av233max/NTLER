#include <wchar.h>
#include <ntddk.h>

#include "ntlead.h"


extern PKSERVICE_TABLE_DESCRIPTOR KeServiceDescriptorTable;
extern PVOID *MmSectionObjectType;


extern ULONG OsVersion;
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

extern MU_LOCALE_SUBSITUTES_DESCRIPTOR LSD_NT5_0411_0;

extern MU_NTKERNEL_HOOK_DATA HookData_WINXP;

extern MU_VERIFY_DATA VerifyData_NtKernel_Export_WINXP_0;
extern MU_VERIFY_DATA VerifyData_NtKernel_Hook_WINXP_0;
extern MU_VERIFY_DATA VerifyData_NtDll_WINXP_0;

extern MU_VERIFY_DATA VerifyData_NtKernel_Export_WIN2K3_0;
extern MU_VERIFY_DATA VerifyData_NtKernel_Hook_WIN2K3_0;
extern MU_VERIFY_DATA VerifyData_NtDll_WIN2K3_0;

extern MU_VERIFY_DATA VerifyData_NtKernel_Hook_WIN7_0;

extern MU_AUDIT_BLOCK ABXP_NtKernel_Hook;
extern MU_AUDIT_BLOCK ABXP_NtKernel_Export;

extern GUID MuPrivateDatabaseGuid;

extern MU_AUDIT_BLOCK ABXP_Ntdll_2180_0;
extern MU_AUDIT_BLOCK ABW6_Ntdll_18000_0;


#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(INIT, MuInitializeKernelHook)
#pragma alloc_text(INIT, MuLoadSystemDefaultNlsTables)
#pragma alloc_text(INIT, MuHookKernel)
#pragma alloc_text(INIT, MuLocateUnexportedSystemRoutines)
#pragma alloc_text(INIT, MuGetNtKernelImageInfo)
#pragma alloc_text(INIT, MuInitializeUserModeHelper)
#pragma alloc_text(INIT, MuLinkDll)
#pragma alloc_text(INIT, MuPrepareHelperContext)
#pragma alloc_text(INIT, MuHookNtDll)
#pragma alloc_text(INIT, MuGetNtLayerDllImageInfo)
#pragma alloc_text(INIT, MuInitializeGlobalData)
#pragma alloc_text(INIT, MuHookSSDT)
#pragma alloc_text(INIT, MuLoadDatabase)
#pragma alloc_text(INIT, MuLocateCharacteristicCode)


ULONG g_DebugValue = 0;


NTSTATUS
DriverEntry (
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;
    HANDLE event;
    BOOLEAN clean = FALSE;
    PDEVICE_OBJECT devobj;
    ULONG maver, miver, phase;
    UNICODE_STRING dn;
    OBJECT_ATTRIBUTES oa;
    
    RtlInitUnicodeString(&dn, MU_EVENTNAME_BOOTSYNC);
    
    InitializeObjectAttributes(&oa,
                               &dn,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);
    
    status = ZwOpenEvent(&event,
                         EVENT_ALL_ACCESS,
                         &oa);
    
    if (NT_SUCCESS(status))
    {
        ZwSetEvent(event, NULL);
        
        ZwClose(event);
    }
    
    RtlInitUnicodeString(&dn, MU_DEVNAME_HOST_CONTROL);
    
    phase = PHASE_CREATE_DEVICE;
    
    status = IoCreateDevice(DriverObject,
                            0,
                            &dn,
                            FILE_DEVICE_UNKNOWN,
                            0,
                            FALSE,
                            &devobj);
    
    if (NT_SUCCESS(status))
    {
        PsGetVersion(&maver, &miver, NULL, NULL);
        
        OsVersion = (maver << 16) | miver;
        
        OsVersion |= MmIsThisAnNtAsSystem() ? 0x80000000 : 0;
        
        phase = PHASE_CHECK_OS_VERSION;
        
        switch (OsVersion)
        {
            case VER_WINXP:
            case VER_WIN2K3:
            case VER_WIN7:
            
                break;
            
            case VER_WIN2K8R2:
            case VER_WIN2K8:
            case VER_VISTA:
            
                //break;
                
            default:
            
                goto MuDriverEntry_Failure;
        }
        
        MuInitializeGlobalData(&g_GlobalData);
        
        phase = PHASE_LOAD_DATABASE;
        
        status = MuLoadDatabase(&g_GlobalData);
        
        if (!NT_SUCCESS(status))
            goto MuDriverEntry_Failure;
        
        phase = PHASE_INIT_KERNEL_HOOK;
        
        status = MuInitializeKernelHook(&g_GlobalData);
        
        if (!NT_SUCCESS(status))
            goto MuDriverEntry_Failure;
        
        phase = PHASE_SET_NOTIFY;
        
        status = PsSetCreateProcessNotifyRoutine(MuCreateProcessNotify, FALSE);
        
        if (!NT_SUCCESS(status))
            goto MuDriverEntry_Failure;
        
        clean = TRUE;
        
        phase = PHASE_INIT_HELPER;
        
        status = MuInitializeUserModeHelper(&g_GlobalData);
        
        if (!NT_SUCCESS(status))
            goto MuDriverEntry_Failure;
        
        DriverObject->MajorFunction[IRP_MJ_CREATE]         = MuDispatchCreateClose;
        DriverObject->MajorFunction[IRP_MJ_CLOSE]          = MuDispatchCreateClose;
        DriverObject->MajorFunction[IRP_MJ_POWER]          = MuDispatchPower;
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MuDispatchDeviceControl;
        
        goto MuDriverEntry_End;

MuDriverEntry_Failure:

        if (clean)
            PsSetCreateProcessNotifyRoutine(MuCreateProcessNotify, TRUE);
        
        IoDeleteDevice(devobj);
    }
    
MuDriverEntry_End:
    
    RegistryPath->Buffer[RegistryPath->Length / sizeof(WCHAR)] = 0;
    
    if (NT_SUCCESS(status))
        MuDeleteRegistryValue(RegistryPath->Buffer, MU_REGVAL_LAST_ERROR);
    else
        MuSetErrorCode(RegistryPath, phase, status);
    
    if (phase > PHASE_INIT_KERNEL_HOOK)
        return STATUS_SUCCESS;
    
    return status;
}

void
MuInitializeGlobalData (
    PMU_GLOBAL_DATA GlobalData
)
{
    RtlZeroMemory(GlobalData, sizeof(MU_GLOBAL_DATA));
    
    KeInitializeSpinLock(&GlobalData->GlobalLock);
    KeInitializeSpinLock(&GlobalData->ThreadRecordLock);
    
    ExInitializeFastMutex(&GlobalData->UserStorageMutex);
    ExInitializeFastMutex(&GlobalData->ImpersonationPathMutex);
    
    KeInitializeMutex(&GlobalData->NsdLibraryMutex, 0);
}

BOOLEAN
MuLocateUnexportedSystemRoutines (
    PVOID KernelBase,
    ULONG KernelSize
)
{
    PMU_AUDIT_BLOCK AuditBlock;
    PMU_PUBLIC_BLOCK PublicBlock;
    PMU_VERIFY_DATA VerifyData;
    PVOID addr;
    
    switch (OsVersion)
    {
        case VER_WINXP:
            
            VerifyData = &VerifyData_NtKernel_Export_WINXP_0;
            AuditBlock = &ABXP_NtKernel_Export;
            
            break;
        
        case VER_WIN2K3:
        
            VerifyData = &VerifyData_NtKernel_Export_WIN2K3_0;
            AuditBlock = &ABXP_NtKernel_Export;
            
            break;
        
        default:
        
            return TRUE;
    }
    
    if (OsVersion)
        return TRUE;
    
    PublicBlock = AuditBlock->PublicBlock;
    
    while (VerifyData)
    {
        addr = MuLocateCharacteristicCode(KernelBase,
                                          KernelSize,
                                          VerifyData->VerifyCode,
                                          VerifyData->VerifyMask,
                                          VerifyData->Length);
            
        if (!addr)
            return FALSE;
        
        PublicBlock->Offset = (ULONG)addr - (ULONG)KernelBase + VerifyData->OffsetToFix;
        
        (PUCHAR)PublicBlock += MU_GENERIC_BLOCK_SIZE;
        
        VerifyData = VerifyData->Next;
    }
    
    MuHookModule(KernelBase, AuditBlock, 1, TRUE);
    
    return TRUE;
}

BOOLEAN
MuHookKernel (
    PVOID KernelBase,
    ULONG KernelSize
)
{
    PMU_AUDIT_BLOCK AuditBlock;
    PMU_PUBLIC_BLOCK PublicBlock;
    PMU_VERIFY_DATA VerifyData;
    PVOID addr;
    
    switch (OsVersion)
    {
        case VER_WINXP:
            
            VerifyData = &VerifyData_NtKernel_Hook_WINXP_0;
            AuditBlock = &ABXP_NtKernel_Hook;
            
            break;
        
        case VER_WIN2K3:
        
            VerifyData = &VerifyData_NtKernel_Hook_WIN2K3_0;
            AuditBlock = &ABXP_NtKernel_Hook;
            
            break;
        
        case VER_WIN7:
        
            VerifyData = &VerifyData_NtKernel_Hook_WIN7_0;
            AuditBlock = &ABXP_NtKernel_Hook;
            
            break;
        
        default:
        
            return FALSE;
    }
    
    if (!MuCheckRoutineStackFrame(ObOpenObjectByName))
        return FALSE;
    
    PublicBlock = AuditBlock->PublicBlock;
    
    while (VerifyData)
    {
        addr = MuLocateCharacteristicCode(KernelBase,
                                          KernelSize,
                                          VerifyData->VerifyCode,
                                          VerifyData->VerifyMask,
                                          VerifyData->Length);
            
        if (!addr)
            return FALSE;
        
        PublicBlock->Offset = (ULONG)addr - (ULONG)KernelBase + VerifyData->OffsetToFix;
        
        (PUCHAR)PublicBlock += MU_GENERIC_BLOCK_SIZE;
        
        VerifyData = VerifyData->Next;
    }
    
    MuHookModule(KernelBase, AuditBlock, 1, TRUE);
    
    MuInlineHook(RtlMultiByteToUnicodeN, MuMultiByteToUnicodeN);
    MuInlineHook(RtlOemToUnicodeN, MuOemToUnicodeN);
    MuInlineHook(RtlUnicodeToMultiByteN, MuUnicodeToMultiByteN);
    MuInlineHook(RtlUnicodeToOemN, MuUnicodeToOemN);
    MuInlineHook(RtlUpcaseUnicodeToMultiByteN, MuUpcaseUnicodeToMultiByteN);
    MuInlineHook(RtlUpcaseUnicodeToOemN, MuUpcaseUnicodeToOemN);
    MuInlineHook(RtlGetDefaultCodePage, MuGetDefaultCodePage);
    
    //MuInlineHook(RtlMultiByteToUnicodeSize, MuMultiByteToUnicodeSize);
    //MuInlineHook(RtlUnicodeToMultiByteSize, MuUnicodeToMultiByteSize);
    
    NtQueryDefaultLocale     = (NTUNEXPPROC_NtQueryDefaultLocale)MuHookSSDT(ZwQueryDefaultLocale, MuQueryDefaultLocale);
    NtQueryDefaultUILanguage = (NTUNEXPPROC_NtQueryDefaultUILanguage)MuHookSSDT(ZwQueryDefaultUILanguage, MuQueryDefaultUILanguage);
    NtQueryInstallUILanguage = (NTUNEXPPROC_NtQueryInstallUILanguage)MuHookSSDT(ZwQueryInstallUILanguage, MuQueryInstallUILanguage);
    
    ObOpenObjectByName_ = MuInlineHook(ObOpenObjectByName, MuOpenObjectByName);
    
    return TRUE;
}

NTSTATUS
MuInitializeUserModeHelper (
    PMU_GLOBAL_DATA GlobalData
)
{
    NTSTATUS status;
    HANDLE file, proc, dllsec;
    SIZE_T imgsize = 0;
    PVOID secobj, dllbase = NULL;
    LARGE_INTEGER secofs;
    UNICODE_STRING fp;
    IO_STATUS_BLOCK iosb;
    OBJECT_ATTRIBUTES oa;
    WCHAR path[MAX_PATH];
    
    wcscpy(path, MU_ROOTDIR_SYSTEM32);
    wcscat(path, MU_FILENAME_HELPER_DLL);
    
    RtlInitUnicodeString(&fp, path);
    
    InitializeObjectAttributes(&oa,
                               &fp,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);
    
    status = ZwOpenFile(&file,
                        GENERIC_READ,
                        &oa,
                        &iosb,
                        FILE_SHARE_READ,
                        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    
    if (NT_SUCCESS(status))
    {
        status = ZwCreateSection(&dllsec,
                                 SECTION_ALL_ACCESS,
                                 NULL,
                                 NULL,
                                 PAGE_EXECUTE_READWRITE,
                                 SEC_IMAGE,
                                 file);
        
        ZwClose(file);
        
        if (!NT_SUCCESS(status))
            return status;
            
        status = ObReferenceObjectByHandle(dllsec,
                                           SECTION_ALL_ACCESS,
                                           *MmSectionObjectType,
                                           KernelMode,
                                           &secobj,
                                           NULL);
        
        ZwClose(dllsec);
        
        if (NT_SUCCESS(status))
        {
            secofs.QuadPart = 0;
            
            status = MmMapViewOfSection(secobj,
                                        PsGetCurrentProcess(),
                                        &dllbase,
                                        0,
                                        0,
                                        &secofs,
                                        &imgsize,
                                        ViewShare,
                                        0,
                                        PAGE_EXECUTE_READWRITE);
            
            if (NT_SUCCESS(status))
            {
                status = MuLinkDll(GlobalData, dllbase);
                
                MmUnmapViewOfSection(PsGetCurrentProcess(), dllbase);
            }
            
            if (!NT_SUCCESS(status))
            {
                ObDereferenceObject(secobj);
                
                secobj = NULL;
            }
            
            GlobalData->DllSection   = secobj;
            GlobalData->DllImageSize = imgsize;
            GlobalData->DllImageBase = dllbase;
        }
    }
    
    return status;
}


NTSTATUS
MuLinkDll (
    PMU_GLOBAL_DATA GlobalData,
    PVOID ImageBase
)
{
    NTSTATUS status;
    ULONG NtDllSize;
    PVOID NtDllBase;
    PVOID pFunc;
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((PUCHAR)ImageBase + (((PIMAGE_NT_HEADERS)((PUCHAR)ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew)))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    PIMAGE_THUNK_DATA pNameThunk, pAddressThunk;
    PIMAGE_IMPORT_BY_NAME pImportName;
    
    status = MuGetNtLayerDllImageInfo(&NtDllBase, &NtDllSize);
    
    if (!NT_SUCCESS(status))
        return status;
    
    while (pImportDesc->Name)
    {
        pNameThunk    = (PIMAGE_THUNK_DATA)((PUCHAR)ImageBase + pImportDesc->OriginalFirstThunk);
        pAddressThunk = (PIMAGE_THUNK_DATA)((PUCHAR)ImageBase + pImportDesc->FirstThunk);
        
        while (pNameThunk->u1.AddressOfData)
        {
            pImportName = (PIMAGE_IMPORT_BY_NAME)((PUCHAR)ImageBase + (ULONG)pNameThunk->u1.AddressOfData);
            
            pFunc = MuLookupExportRoutineEntryByName(NtDllBase, (PUCHAR)pImportName->Name);
            
            if (!pFunc)
                return STATUS_UNSUCCESSFUL;
            
            MuWriteMemoryDword(&pAddressThunk->u1.Function, (ULONG)pFunc);
            
            pAddressThunk++;
            pNameThunk++;
        }
        
        pImportDesc++;
    }
    
    if (!MuPrepareHelperContext(&GlobalData->DllEntries, ImageBase))
        return STATUS_UNSUCCESSFUL;
    
    MuWriteMemoryDword(GlobalData->DllEntries.MuLoaderEnvironment, (ULONG)ImageBase + LARGE_PAGE_SIZE);
    
    if (!MuHookNtDll(NtDllBase, NtDllSize))
        return STATUS_UNSUCCESSFUL;
        
    return STATUS_SUCCESS;
}

BOOLEAN
MuPrepareHelperContext (
    PMU_DLL_ENTRY DllEntries,
    PVOID ImageBase
)
{
    DllEntries->MuHookWalkImportDescriptor = MuLookupExportRoutineEntryByName(ImageBase, MU_HELPER_LDR_HOOK_NAME);
    DllEntries->MuLoaderEnvironment        = MuLookupExportRoutineEntryByName(ImageBase, MU_HELPER_LDR_ENV_NAME);
    
    if (DllEntries->MuHookWalkImportDescriptor == (PVOID)((ULONG)ImageBase + MU_HELPER_LDR_HOOK_OFFSET))
        DllEntries->MuOrgWalkImportDescriptor = (PVOID)((ULONG)ImageBase + MU_HELPER_LDR_ORG_OFFSET);
    
    if (DllEntries->MuHookWalkImportDescriptor && DllEntries->MuOrgWalkImportDescriptor)
        return TRUE;
    
    return FALSE;
}

BOOLEAN
MuHookNtDll (
    PVOID ImageBase,
    ULONG ImageSize
)
{
    PMU_AUDIT_BLOCK AuditBlock;
    PMU_PUBLIC_BLOCK PublicBlock;
    PMU_VERIFY_DATA VerifyData;
    PVOID addr;
    
    switch (OsVersion)
    {
        case VER_WINXP:
        
            VerifyData = &VerifyData_NtDll_WINXP_0;
            AuditBlock = &ABXP_Ntdll_2180_0;
            
            break;
        
        case VER_WIN2K3:
        
            VerifyData = &VerifyData_NtDll_WIN2K3_0;
            AuditBlock = &ABXP_Ntdll_2180_0;
            
            break;

        default:
        
            return FALSE;
    }
    
    PublicBlock = AuditBlock->PublicBlock;
    
    while (VerifyData)
    {
        addr = MuLocateCharacteristicCode(ImageBase,
                                          ImageSize,
                                          VerifyData->VerifyCode,
                                          VerifyData->VerifyMask,
                                          VerifyData->Length);
        
        if (!addr)
           return FALSE;
        
        PublicBlock->Offset = (ULONG)addr - (ULONG)ImageBase + VerifyData->OffsetToFix;
        
        (PUCHAR)PublicBlock += MU_GENERIC_BLOCK_SIZE;
        
        VerifyData = VerifyData->Next;
    }
    
    MuHookModule(ImageBase, AuditBlock, 1, TRUE);
    
    return TRUE;
}

NTSTATUS
MuGetNtLayerDllImageInfo (
    PVOID *ImageBase,
    PULONG ImageSize
)
{
    NTSTATUS status;
    PSYSTEM_MODULE SystemModule;
    PSYSTEM_MODULE_INFORMATION ModuleInfo = NULL;
    ULONG i, CbSize = 0;
    
    while (TRUE)
    {
        status = ZwQuerySystemInformation(SystemModuleInformation,
                                          ModuleInfo,
                                          CbSize,
                                          &CbSize);
                                          
        if (NT_SUCCESS(status))
        {
            SystemModule = &ModuleInfo->Modules[0];
            
            for (i = 0 ; i < ModuleInfo->ModulesCount ; i++)
            {
                if (!_stricmp(&SystemModule->Name[SystemModule->NameOffset], MU_FILENAME_NTSYSTEM_DLL))
                {
                    *ImageBase = SystemModule->ImageBaseAddress;
                    *ImageSize = SystemModule->ImageSize;
                    
                    MuFree(ModuleInfo);
                    
                    return STATUS_SUCCESS;
                }
                
                SystemModule++;
            }
            
            break;
        }
        else
        {
            if (status == STATUS_INFO_LENGTH_MISMATCH)
            {
                if (ModuleInfo)
                    MuFree(ModuleInfo);
                
                ModuleInfo = MuPagedAlloc(CbSize);
                
                if (!ModuleInfo)
                    break;
            }
            else
            {
                break;
            }
        }
    }
    
    if (ModuleInfo)
        MuFree(ModuleInfo);
    
    return status;
}

NTSTATUS
MuInitializeKernelHook (
    PMU_GLOBAL_DATA GlobalData
)
{
    NTSTATUS status;
    PVOID base;
    ULONG size;
    
    MuWriteDebugLog(0);
    
    status = MuGetNtKernelImageInfo(&base, &size);
    
    if (!NT_SUCCESS(status))
        return status;
    
    MuWriteDebugLogSpecifyName(L"krnlbase", (ULONG)base);
    MuWriteDebugLogSpecifyName(L"krnlsize", size);
    
    MuWriteDebugLog(10000);
    g_DebugValue = 10000;
    
    if (!MuLocateUnexportedSystemRoutines(base, size))
        return STATUS_UNSUCCESSFUL;
    
    MuWriteDebugLog(20000);
    g_DebugValue = 20000;
    
    status = MuLoadSystemDefaultNlsTables(GlobalData);
    
    if (!NT_SUCCESS(status))
        return status;
    
    MuWriteDebugLog(30000);
    g_DebugValue = 30000;
    
    if (!MuHookKernel(base, size))
        return STATUS_UNSUCCESSFUL;
    
    MuWriteDebugLog(99999);
    
    return STATUS_SUCCESS;
}

NTSTATUS
MuLoadSystemDefaultNlsTables (
    PMU_GLOBAL_DATA GlobalData
)
{
    NTSTATUS status;
    PVOID secview = NULL;
    SIZE_T viewsize = 0;
    WCHAR AnsiFileIndex[MU_MAX_INDEX_LENGTH], OemFileIndex[MU_MAX_INDEX_LENGTH], LangFileIndex[MU_MAX_INDEX_LENGTH];
    
    status = MuQueryNlsFileIndex(MU_REGPATH_CODEPAGE,
                                 MU_REGVAL_ACP,
                                 AnsiFileIndex);
    
    if (!NT_SUCCESS(status))
        return status;
    
    status = MuQueryNlsFileIndex(MU_REGPATH_CODEPAGE,
                                 MU_REGVAL_OEMCP,
                                 OemFileIndex);
    
    if (!NT_SUCCESS(status))
        return status;
    
    status = MuQueryNlsFileIndex(MU_REGPATH_LANGUAGE,
                                 MU_REGVAL_DEFAULT,
                                 LangFileIndex);
    
    if (!NT_SUCCESS(status))
        return status;
    
    status = MuLoadNlsTableIntoContiguousBuffer(AnsiFileIndex,
                                                OemFileIndex,
                                                LangFileIndex,
                                                &GlobalData->SystemNlsSource);
    
    if (NT_SUCCESS(status))
    {
        status = MmMapViewInSystemSpace(GlobalData->SystemNlsSource.TableSection,
                                        &secview,
                                        &viewsize);
        
        if (NT_SUCCESS(status))
        {
            MuInitNlsTables((PUSHORT)((PUCHAR)secview + GlobalData->SystemNlsSource.AnsiTableOffset),
                            (PUSHORT)((PUCHAR)secview + GlobalData->SystemNlsSource.OemTableOffset),
                            (PUSHORT)((PUCHAR)secview + GlobalData->SystemNlsSource.LangTableOffset),
                            &GlobalData->SystemNlsTableInfo);
        }
    }
    
    return status;
}

NTSTATUS
MuGetNtKernelImageInfo (
    PVOID *ImageBase,
    PULONG ImageSize
)
{
    NTSTATUS status;
    PSYSTEM_MODULE SystemModule;
    PSYSTEM_MODULE_INFORMATION ModuleInfo = NULL;
    ULONG CbSize = 0;
    
    while (TRUE)
    {
        status = ZwQuerySystemInformation(SystemModuleInformation,
                                          ModuleInfo,
                                          CbSize,
                                          &CbSize);
        
        if (NT_SUCCESS(status))
        {
            SystemModule = &ModuleInfo->Modules[0];
            
            *ImageBase = SystemModule->ImageBaseAddress;  // the first module is always ntoskrnl/ntkrnlmp/ntkrnlpa/ntkrpamp
            *ImageSize = SystemModule->ImageSize;
            
            break;
        }
        else
        {
            if (status == STATUS_INFO_LENGTH_MISMATCH)
            {
                if (ModuleInfo)
                    MuFree(ModuleInfo);
                
                ModuleInfo = MuPagedAlloc(CbSize);
                
                if (!ModuleInfo)
                    break;
            }
            else
            {
                break;
            }
        }
    }
    
    if (ModuleInfo)
        MuFree(ModuleInfo);
    
    return status;
}

PVOID
MuHookSSDT (
    PVOID ProcEntry,
    PVOID RedirectAddress
)
{
    ULONG index = *(PULONG)((ULONG)ProcEntry + 1);  // retrieve system call vector by "mov eax,XXXXXXXX"
    PVOID orgproc = (PVOID)*(KeServiceDescriptorTable->Base + index);
    
    MuWriteMemoryDword(KeServiceDescriptorTable->Base + index, (ULONG)RedirectAddress);
    
    return orgproc;
}

NTSTATUS
MuLoadDatabase (
    PMU_GLOBAL_DATA GlobalData
)
{
    PMU_DATABASE_DATASET_INFO_IN_MEMORY dataset;
    PMU_LOCALE_CONFIGURATION loccfg;
    PMU_LOCALE_SUBSITUTES_DESCRIPTOR lsd;
    PMU_SUBSITUTES_META_DATA subsmeta;
    ULONG numlocs;
    USHORT datasize;
    UCHAR i;
    BOOLEAN created;
    NTSTATUS status = MuCreateOrOpenDatabase(MU_TINY_DATABASE_NAME,
                                             &MuPrivateDatabaseGuid,
                                             TOTAL_DATABASE_ENTRIES,
                                             &GlobalData->DatabaseObject,
                                             &created);
    
    if (NT_SUCCESS(status))
    {
       //MuValidateDatabase(&GlobalData->DatabaseObject);
       
       if (created)
       {
           switch (OsVersion)
           {
               case VER_WINXP:
               case VER_WIN2K3:
                   
                   lsd     = &LSD_NT5_0411_0;
                   numlocs = 6;  // jap 1 chs 2 cht 3
                   
                   break;
               
               default:
               
                   return status;
           }
           
           while (numlocs--)
           {
               datasize = (USHORT)(sizeof(MU_LOCALE_CONFIGURATION) + ((lsd->NumMetaData - 1) * sizeof(MU_FONT_SUBSTITUTE_DESCRIPTOR)));
               
               status = MuAllocateDatasetObject(datasize, &dataset);
               
               if (!NT_SUCCESS(status))
                   return status;
               
               loccfg = (PMU_LOCALE_CONFIGURATION)dataset->Data;
               
               loccfg->LocaleId       = lsd->LocaleId;
               loccfg->NumSubstitutes = lsd->NumMetaData;
               loccfg->DefaultFont[0] = 0;
               
               subsmeta = lsd->MetaData;
               
               for (i = 0 ; i < lsd->NumMetaData ; i++)
               {
                   wcscpy(loccfg->Fsd[i].SubstituteName, subsmeta->SubstituteName);
                   wcscpy(loccfg->Fsd[i].RealFaceName, subsmeta->RealFaceName);
                   
                   subsmeta++;
               }
               
               status = MuUpdateDataset(GlobalData->DatabaseObject, ENTRY_LOCALE_CONFIGURATION, dataset, datasize);
               
               if (!NT_SUCCESS(status))
                   return status;
               
               lsd++;
           }
       }
    }
    
    return status;
}

PVOID
MuLocateCharacteristicCode (
    PVOID ImageBase,
    ULONG ImageSize,
    PUCHAR VerifyCode,
    PUCHAR VerifyMask,
    ULONG CodeLength
)
{
    ULONG i, Found = 0;
    PUCHAR ImageNow = (PUCHAR)ImageBase;
    PVOID Offset;
    
    g_DebugValue += 1000;
    
    __try
    {
        if ((ULONG)ImageBase + ImageSize < (ULONG)MmHighestUserAddress)
            ProbeForRead((PUCHAR)ImageBase, ImageSize, 1);
        
        while ((ULONG)ImageNow < (ULONG)ImageBase + ImageSize)
        {
            for (i = 0 ; i < CodeLength ; i++)
            {
                if (!VerifyMask[i])
                {
                    if (*ImageNow++ != VerifyCode[i])
                        break;
                }
                else
                {
                    ImageNow++;
                }
                
                if ((ULONG)ImageNow >= (ULONG)ImageBase + ImageSize)
                    break;
            }
            
            if (i == CodeLength)
            {
                Offset = (PVOID)((ULONG)ImageNow - CodeLength);
                
                Found++;
                
                break;  // BUGBUG
            }
        }
    }
    __except (1)
    {
    }
    
    if (Found != 1)
    {
        MuWriteDebugLog(g_DebugValue + (Found * 100));
    }
    
    return Found == 1 ? Offset : NULL;
}