#include <wchar.h>
#include <ntddk.h>

#include "ntlead.h"


extern MU_GLOBAL_DATA g_GlobalData;


#pragma alloc_text(PAGE, MuDispatchCreateClose)
#pragma alloc_text(PAGE, MuDispatchPower)
#pragma alloc_text(PAGE, MuGetLebBase)
#pragma alloc_text(PAGE, MuDispatchDeviceControl)
#pragma alloc_text(PAGE, MuCreateProcessNotify)
#pragma alloc_text(PAGE, MuFaceNameEnumProc)
#pragma alloc_text(PAGE, MuCheckAppPathConflictProc)
#pragma alloc_text(PAGE, MuSubstituteToFaceName)
#pragma alloc_text(PAGE, MuAddAppConfig)
#pragma alloc_text(PAGE, MuLookupLebByFilePathProc)
#pragma alloc_text(PAGE, MuQueryLeb)
#pragma alloc_text(PAGE, MuConfigListEnumProc)
#pragma alloc_text(PAGE, MuEnumAppConfig)
#pragma alloc_text(PAGE, MuFindAndRemoveConfigProc)
#pragma alloc_text(PAGE, MuRemoveAppConfig)

NTSTATUS
MuDispatchCreateClose (
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    
    if (Irp->RequestorMode == UserMode)
        status = STATUS_SUCCESS;
    
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    
    return status;
}

NTSTATUS
MuDispatchPower (
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
{
    PoStartNextPowerIrp(Irp);
    
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    
    return STATUS_SUCCESS;
}

NTSTATUS
MuMarkCallingThread (
    PIRP Irp
)
{
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    PETHREAD curtcb;
    PMU_GLOBAL_DATA GlobalData;
    PMU_TEMPORARY_THREAD_RECORD previous = NULL, current;
    KLOCK_QUEUE_HANDLE lock;
    
    if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(MU_CTLIN_MARK_CALLING_THREAD))
        return STATUS_BUFFER_TOO_SMALL;
    
    curtcb = PsGetCurrentThread();
    
    GlobalData = MuAcquireThreadRecordLock(&lock);
    
    current = GlobalData->TempThreadRecord;
    
    while (current)
    {
        if (current->ThreadObject == curtcb)
            break;
        
        previous = current;
        current  = current->Next;
    }
    
    if (!current)
    {
        current = (PMU_TEMPORARY_THREAD_RECORD)MuAlloc(sizeof(MU_TEMPORARY_THREAD_RECORD));
        
        if (current)
        {
            RtlZeroMemory(current, sizeof(MU_TEMPORARY_THREAD_RECORD));
            
            current->ThreadObject = curtcb;
            
            RtlCopyMemory(&current->Leb, Irp->AssociatedIrp.SystemBuffer, sizeof(MU_CTLIN_MARK_CALLING_THREAD));
            
            if (previous)
                previous->Next = current;
            else
                GlobalData->TempThreadRecord = current;
            
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    
    MuReleaseSpinLock(&lock);
    
    return status;
}

NTSTATUS
MuClearThreadRecord (
    PIRP Irp
)
{
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    PETHREAD curtcb = PsGetCurrentThread();
    PMU_GLOBAL_DATA GlobalData;
    PMU_TEMPORARY_THREAD_RECORD previous = NULL, current;
    KLOCK_QUEUE_HANDLE lock;
    
    GlobalData = MuAcquireThreadRecordLock(&lock);
    
    current = GlobalData->TempThreadRecord;
    
    while (current)
    {
        if (current->ThreadObject == curtcb && current->LockContext == FALSE)
            break;
        
        previous = current;
        current  = current->Next;
    }
    
    if (current)
    {
        if (previous)
            previous->Next = current->Next;
        else
            GlobalData->TempThreadRecord = NULL;
        
        MuFree(current);
        
        status = STATUS_SUCCESS;
    }
    
    MuReleaseSpinLock(&lock);
    
    return status;
}

NTSTATUS
MuGetLebBase (
    PIRP Irp,
    PULONG BytesWritten
)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    
    if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(MU_CTLOUT_GET_LEB_BASE))
        return STATUS_BUFFER_TOO_SMALL;
    
    ((PMU_CTLOUT_GET_LEB_BASE)Irp->AssociatedIrp.SystemBuffer)->Base = MuLocateLeb();
    
    *BytesWritten = sizeof(MU_CTLOUT_GET_LEB_BASE);
    
    return STATUS_SUCCESS;
}

BOOLEAN
MuFaceNameEnumProc (
    PMU_DATABASE_DATASET_INFO_IN_MEMORY DatasetObject,
    PMU_SUBSTITUTE_TO_FACE_NAME_CONTEXT Context,
    PNTSTATUS FinalStatus
)
{
    UCHAR i;
    PMU_LOCALE_CONFIGURATION loccfg = (PMU_LOCALE_CONFIGURATION)DatasetObject->Data;
    
    if (loccfg->LocaleId == Context->LocaleId)
    {
        if (!wcslen(Context->InputBuffer->FaceName))
        {
            wcscpy(Context->OutputBuffer->FaceName, loccfg->DefaultFont);
            
            *FinalStatus = STATUS_SUCCESS;
        }
        else
        {
            for (i = 0 ; i < loccfg->NumSubstitutes ; i++)
            {
                if (!_wcsicmp(Context->InputBuffer->FaceName, loccfg->Fsd[i].SubstituteName))
                {
                    wcscpy(Context->OutputBuffer->FaceName, loccfg->Fsd[i].RealFaceName);
                    
                    *FinalStatus = STATUS_SUCCESS;
                    
                    break;
                }
            }
        }
        
        return TRUE;
    }
    
    return FALSE;
}

BOOLEAN
MuCheckAppPathConflictProc (
    PMU_DATABASE_DATASET_INFO_IN_MEMORY DatasetObject,
    PWSTR Context,
    PNTSTATUS FinalStatus
)
{
    PMU_APPLICATION_CONFIGURATION appcfg = (PMU_APPLICATION_CONFIGURATION)&DatasetObject->Data[0];
    PWSTR path = (PWSTR)((ULONG)&appcfg->UserStorage[0] + appcfg->UserStorageLength);
    
    if (!_wcsicmp(path, Context))
    {
        *FinalStatus = STATUS_OBJECT_NAME_COLLISION;
        
        return TRUE;
    }
    
    return FALSE;
}

BOOLEAN
MuLookupLebByFilePathProc (
    PMU_DATABASE_DATASET_INFO_IN_MEMORY DatasetObject,
    PMU_CTLIN_QUERY_LEB Context,
    PNTSTATUS FinalStatus
)
{
    PMU_APPLICATION_CONFIGURATION appcfg = (PMU_APPLICATION_CONFIGURATION)&DatasetObject->Data[0];
    PWSTR path = (PWSTR)((ULONG)&appcfg->UserStorage[0] + appcfg->UserStorageLength);
    
    if (!_wcsicmp(path, Context->FilePath))
    {
        ((PMU_CTLOUT_QUERY_LEB)Context)->Leb = appcfg->Leb;
        
        *FinalStatus = STATUS_SUCCESS;
        
        return TRUE;
    }
    
    return FALSE;
}

NTSTATUS
MuQueryLeb (
    PIRP Irp,
    PULONG BytesWritten
)
{
    NTSTATUS status;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG datasize = stack->Parameters.DeviceIoControl.InputBufferLength;
    PMU_CTLIN_QUERY_LEB queryleb = (PMU_CTLIN_QUERY_LEB)Irp->AssociatedIrp.SystemBuffer;
    
    if (datasize < sizeof(MU_CTLIN_QUERY_LEB) || stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(MU_CTLOUT_QUERY_LEB))
        return STATUS_BUFFER_TOO_SMALL;
    
    if (datasize > sizeof(MU_CTLIN_QUERY_LEB) + ((MAX_PATH - 1) * sizeof(WCHAR)))
        return STATUS_INVALID_DEVICE_REQUEST;
    
    queryleb->FilePath[(datasize - sizeof(MU_CTLIN_QUERY_LEB)) / sizeof(WCHAR)] = 0;  // avoid overflow
    
    status = MuEnumDataset(g_GlobalData.DatabaseObject,
                           ENTRY_APPLICATION_CONFIGURATION,
                           (MU_DATABASE_ENUM_DATASET_PROC)MuLookupLebByFilePathProc,
                           queryleb);
    
    if (NT_SUCCESS(status))
        *BytesWritten = sizeof(MU_CTLOUT_QUERY_LEB);
    
    return status;
}

NTSTATUS
MuSubstituteToFaceName (
    PIRP Irp,
    PULONG BytesWritten
)
{
    NTSTATUS status;
    PMU_PROCESS_CONTEXT context;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    MU_SUBSTITUTE_TO_FACE_NAME_CONTEXT param;
    
    if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(MU_CTLIN_SUBSTITUTE_TO_FACE_NAME) || stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(MU_CTLOUT_SUBSTITUTE_TO_FACE_NAME))
        return STATUS_BUFFER_TOO_SMALL;
    
    context = MuLookupCurrentProcessContext();
    
    if (context)
    {
        param.LocaleId     = context->Nsd->NlsParam.LocaleId;
        param.InputBuffer  = (PMU_CTLIN_SUBSTITUTE_TO_FACE_NAME)Irp->AssociatedIrp.SystemBuffer;
        param.OutputBuffer = (PMU_CTLOUT_SUBSTITUTE_TO_FACE_NAME)Irp->AssociatedIrp.SystemBuffer;
        
        param.InputBuffer->FaceName[LF_FACESIZE - 1] = 0; // avoid overflow
        
        if (param.InputBuffer->FaceName[0] == '@')
            param.InputBuffer = (PMU_CTLIN_SUBSTITUTE_TO_FACE_NAME)(&param.InputBuffer->FaceName[1]);
        
        status = MuEnumDataset(g_GlobalData.DatabaseObject,
                               ENTRY_LOCALE_CONFIGURATION,
                               (MU_DATABASE_ENUM_DATASET_PROC)MuFaceNameEnumProc,
                               &param);
        
        MuDereferenceProcessContext(context);
        
        if (NT_SUCCESS(status))
            *BytesWritten = sizeof(MU_CTLOUT_SUBSTITUTE_TO_FACE_NAME);
        
        return status;
    }
    
    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS
MuAddAppConfig (
    PIRP Irp
)
{
    NTSTATUS status;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG datasize = stack->Parameters.DeviceIoControl.InputBufferLength;
    PMU_CTLIN_ADD_APPCONFIG addapp = (PMU_CTLIN_ADD_APPCONFIG)Irp->AssociatedIrp.SystemBuffer;
    PMU_DATABASE_DATASET_INFO_IN_MEMORY dataset;
    PWSTR path;
    
    if (datasize < sizeof(MU_CTLIN_ADD_APPCONFIG))
        return STATUS_BUFFER_TOO_SMALL;
    
    if (datasize > sizeof(MU_CTLIN_ADD_APPCONFIG) - 1 + addapp->AppConfig.UserStorageLength + ((MAX_PATH - 1) * sizeof(WCHAR)))
        return STATUS_INVALID_DEVICE_REQUEST;
    
    path = (PWSTR)((ULONG)&addapp->AppConfig.UserStorage[0] + addapp->AppConfig.UserStorageLength);
    
    *(PWSTR)((ULONG)addapp + datasize - sizeof(WCHAR)) = 0;  // avoid overflow
    
    status = MuEnumDataset(g_GlobalData.DatabaseObject,
                           ENTRY_APPLICATION_CONFIGURATION,
                           (MU_DATABASE_ENUM_DATASET_PROC)MuCheckAppPathConflictProc,
                           path);
    
    if (!NT_SUCCESS(status))
    {
        if (status != STATUS_NOT_FOUND)
            return status;
    }
    
    datasize = sizeof(MU_APPLICATION_CONFIGURATION) - 1 + addapp->AppConfig.UserStorageLength + (wcslen(path) * sizeof(WCHAR));
    
    status = MuAllocateDatasetObject((USHORT)datasize, &dataset);
    
    if (NT_SUCCESS(status))
    {
        RtlCopyMemory(dataset->Data, &addapp->AppConfig, datasize);
        
        status = MuUpdateDataset(g_GlobalData.DatabaseObject,
                                 ENTRY_APPLICATION_CONFIGURATION,
                                 dataset,
                                 (USHORT)datasize);
    }
    
    return status;
}

BOOLEAN
MuConfigListEnumProc (
    PMU_DATABASE_DATASET_INFO_IN_MEMORY DatasetObject,
    PMU_ENUM_APPCONFIG_CONTEXT Context,
    PNTSTATUS FinalStatus
)
{
    if (Context->BufferSize - Context->BytesWritten >= MU_DATABASE_CARRY_ALIGN((ULONG)DatasetObject->DataSize) + sizeof(ULONG))
    {
        ((PMU_APPLICATION_CONFIGURATION_WITH_KEY)((ULONG)Context->OutputBuffer + Context->BytesWritten))->Key = (ULONG)DatasetObject;
        
        Context->BytesWritten += sizeof(ULONG);
        
        RtlCopyMemory((PUCHAR)Context->OutputBuffer + Context->BytesWritten, DatasetObject->Data, DatasetObject->DataSize);
        
        Context->BytesWritten += MU_DATABASE_CARRY_ALIGN(DatasetObject->DataSize);
    }
    
    Context->OutputBuffer->RequiredBufferSize += MU_DATABASE_CARRY_ALIGN(DatasetObject->DataSize) + sizeof(ULONG);
    
    return FALSE;
}

BOOLEAN
MuFindAndRemoveConfigProc (
    PMU_DATABASE_DATASET_INFO_IN_MEMORY DatasetObject,
    PMU_DATABASE_DATASET_INFO_IN_MEMORY Context,
    PNTSTATUS FinalStatus
)
{
    if (DatasetObject == Context)
    {
        *FinalStatus = MuDeleteDataset(g_GlobalData.DatabaseObject, ENTRY_APPLICATION_CONFIGURATION, DatasetObject);
        
        return TRUE;
    }
    
    return FALSE;
}

BOOLEAN
MuLookupAppConfigByFilePathProc (
    PMU_DATABASE_DATASET_INFO_IN_MEMORY DatasetObject,
    PMU_QUERY_APPCONFIG_CONTEXT Context,
    PNTSTATUS FinalStatus
)
{
    PMU_APPLICATION_CONFIGURATION appcfg = (PMU_APPLICATION_CONFIGURATION)&DatasetObject->Data[0];
    PWSTR path = (PWSTR)((ULONG)&appcfg->UserStorage[0] + appcfg->UserStorageLength);
    
    if (!_wcsicmp(path, Context->InputBuffer->FilePath))
    {
        Context->OutputBuffer->RequiredBufferSize = sizeof(ULONG) + sizeof(ULONG) + DatasetObject->DataSize;
        
        Context->BytesWritten = sizeof(ULONG);
        
        if (Context->OutputBufferSize >= Context->OutputBuffer->RequiredBufferSize)
        {
            Context->OutputBuffer->AppConfigWithKey.Key = (ULONG)DatasetObject;
            
            RtlCopyMemory(&Context->OutputBuffer->AppConfigWithKey.AppConfig, DatasetObject->Data, DatasetObject->DataSize);
            
            Context->BytesWritten = Context->OutputBuffer->RequiredBufferSize;
        }
        
        *FinalStatus = STATUS_SUCCESS;
        
        return TRUE;
    }
    
    return FALSE;
}

NTSTATUS
MuQueryAppConfig (
    PIRP Irp,
    PULONG BytesWritten
)
{
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG inputsize = stack->Parameters.DeviceIoControl.InputBufferLength, outputsize = stack->Parameters.DeviceIoControl.OutputBufferLength;
    PMU_CTLIN_QUERY_APPCONFIG querycfg = (PMU_CTLIN_QUERY_APPCONFIG)Irp->AssociatedIrp.SystemBuffer;
    MU_QUERY_APPCONFIG_CONTEXT param;
    
    if (inputsize < sizeof(MU_CTLIN_QUERY_APPCONFIG) || outputsize < sizeof(MU_CTLOUT_QUERY_APPCONFIG))
        return STATUS_BUFFER_TOO_SMALL;
    
    if (inputsize > sizeof(MU_CTLIN_QUERY_APPCONFIG) + ((MAX_PATH - 1) * sizeof(WCHAR)))
        return STATUS_INVALID_DEVICE_REQUEST;
    
    querycfg->FilePath[(inputsize - sizeof(MU_CTLIN_QUERY_APPCONFIG)) / sizeof(WCHAR)] = 0;  // avoid overflow
    
    param.OutputBufferSize = outputsize;
    param.InputBuffer      = querycfg;
    param.OutputBuffer     = (PMU_CTLOUT_QUERY_APPCONFIG)querycfg;
    
    status = MuEnumDataset(g_GlobalData.DatabaseObject,
                           ENTRY_APPLICATION_CONFIGURATION,
                           (MU_DATABASE_ENUM_DATASET_PROC)MuLookupAppConfigByFilePathProc,
                           &param);
    
    if (NT_SUCCESS(status))
        *BytesWritten = param.BytesWritten;
    
    return status;
}

NTSTATUS
MuEnumAppConfig (
    PIRP Irp,
    PULONG BytesWritten
)
{
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    MU_ENUM_APPCONFIG_CONTEXT param;
    
    param.BufferSize = stack->Parameters.DeviceIoControl.OutputBufferLength;
    
    if (param.BufferSize < sizeof(MU_CTLOUT_ENUM_APPCONFIG))
        return STATUS_BUFFER_TOO_SMALL;
    
    __try
    {
        param.OutputBuffer = (PMU_CTLOUT_ENUM_APPCONFIG)MmMapLockedPagesSpecifyCache(Irp->MdlAddress,
                                                                                     KernelMode,
                                                                                     MmCached,
                                                                                     NULL,
                                                                                     FALSE,
                                                                                     NormalPagePriority);
        
        if (!param.OutputBuffer)
            __leave;
        
        param.BytesWritten                     = sizeof(ULONG);
        param.OutputBuffer->RequiredBufferSize = sizeof(ULONG);
        
        status = MuEnumDataset(g_GlobalData.DatabaseObject,
                               ENTRY_APPLICATION_CONFIGURATION,
                               (MU_DATABASE_ENUM_DATASET_PROC)MuConfigListEnumProc,
                               &param);
        
        if (status == STATUS_NOT_FOUND)
            status = STATUS_SUCCESS;
        
        if (NT_SUCCESS(status))
            *BytesWritten = param.BytesWritten;
        
        MmUnmapLockedPages(param.OutputBuffer, Irp->MdlAddress);
    }
    __except (1)
    {
        status = GetExceptionCode();
    }
    
    return status;
}

NTSTATUS
MuRemoveAppConfig (
    PIRP Irp
)
{
    NTSTATUS status;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    
    if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(MU_CTLIN_REMOVE_APPCONFIG))
        return STATUS_BUFFER_TOO_SMALL;
    
    return MuEnumDataset(g_GlobalData.DatabaseObject,
                         ENTRY_APPLICATION_CONFIGURATION,
                         (MU_DATABASE_ENUM_DATASET_PROC)MuFindAndRemoveConfigProc,
                         (PVOID)((PMU_CTLIN_REMOVE_APPCONFIG)Irp->AssociatedIrp.SystemBuffer)->Key);
}

NTSTATUS
MuCreateSymbolicLink (
    PIRP Irp,
    PULONG BytesWritten
)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG datasize = stack->Parameters.DeviceIoControl.InputBufferLength;
    PMU_CTLIN_CREATE_SYMBOLIC_LINK creatlink = (PMU_CTLIN_CREATE_SYMBOLIC_LINK)Irp->AssociatedIrp.SystemBuffer;
    PMU_GLOBAL_DATA globaldata;
    ULONG pathid;
    WCHAR pathbuf[MAX_PATH + (sizeof(GLOBAL_NAMESPACE) / sizeof(WCHAR))];
    
    if (datasize < sizeof(MU_CTLIN_CREATE_SYMBOLIC_LINK) || stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(MU_CTLOUT_CREATE_SYMBOLIC_LINK))
        return STATUS_BUFFER_TOO_SMALL;
    
    if (datasize > sizeof(MU_CTLIN_CREATE_SYMBOLIC_LINK) + ((MAX_PATH - 1) * sizeof(WCHAR)))
        return STATUS_INVALID_DEVICE_REQUEST;
    
    creatlink->FolderPath[(datasize - sizeof(MU_CTLIN_CREATE_SYMBOLIC_LINK)) / sizeof(WCHAR)] = 0;  // avoid overflow
    
    wcscpy(pathbuf, GLOBAL_NAMESPACE);
    wcscat(pathbuf, creatlink->FolderPath);
    
    MuAcquireImpersonationPathMutex();
    
    pathid = MuLookupImpersonationPathByJackName(pathbuf);
    
    if (!pathid)
        pathid = MuAllocateAndInsertPathMappingObject(pathbuf);
    
    MuReleaseImpersonationPathMutex();
    
    if (!pathid)
        return STATUS_INSUFFICIENT_RESOURCES;
    
    ((PMU_CTLOUT_CREATE_SYMBOLIC_LINK)Irp->AssociatedIrp.SystemBuffer)->ImpersonationPathId = pathid;
    
    *BytesWritten = sizeof(ULONG);
    
    return STATUS_SUCCESS;
}

NTSTATUS
MuDispatchDeviceControl (
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
{
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG BytesWritten = 0;
    
    switch (stack->Parameters.DeviceIoControl.IoControlCode)
    {
        case IOCTL_MARK_CALLING_THREAD:
        
            status = MuMarkCallingThread(Irp);
            
            break;
        
        case IOCTL_CLEAR_THREAD_RECORD:
        
            status = MuClearThreadRecord(Irp);
            
            break;
        
        case IOCTL_GET_LEB_BASE:
        
            status = MuGetLebBase(Irp, &BytesWritten);
            
            break;
        
        case IOCTL_SUBSTITUTE_TO_FACENAME:
        
            status = MuSubstituteToFaceName(Irp, &BytesWritten);
            
            break;
        
        case IOCTL_ADD_APPCONFIG:
        
            status = MuAddAppConfig(Irp);
            
            break;
        
        case IOCTL_ENUM_APPCONFIG:
        
            status = MuEnumAppConfig(Irp, &BytesWritten);
            
            break;
        
        case IOCTL_REMOVE_APPCONFIG:
        
            status = MuRemoveAppConfig(Irp);
            
            break;
        
        case IOCTL_QUERY_LEB:
        
            status = MuQueryLeb(Irp, &BytesWritten);
            
            break;
       
        case IOCTL_QUERY_APPCONFIG:
        
            status = MuQueryAppConfig(Irp, &BytesWritten);
            
            break;
        
        case IOCTL_CREATE_SYMBOLIC_LINK:
        
            status = MuCreateSymbolicLink(Irp, &BytesWritten);
            
            break;
    }
    
    Irp->IoStatus.Status      = status;
    Irp->IoStatus.Information = BytesWritten;
    
    IoCompleteRequest(Irp, IO_NO_INCREMENT);  // no StartIo routine and no pending request
    
    return status;
}

VOID
MuCreateProcessNotify (
    HANDLE ParentId,
    HANDLE ProcessId,
    BOOLEAN Create
)
{
    NTSTATUS status;
    SIZE_T imgsize = 0;
    PEPROCESS procobj;
    PVOID dllbase;
    PMU_PROCESS_CONTEXT context;
    LARGE_INTEGER secofs;
    BOOLEAN attached = FALSE;
    
    if (!g_GlobalData.DllSection)
        return;
    
    status = PsLookupProcessByProcessId(ProcessId, &procobj);
    
    if (NT_SUCCESS(status))
    {
        if (Create)
        {
            secofs.QuadPart = 0;
            
            dllbase = g_GlobalData.DllImageBase;
            
            if (PsGetCurrentProcess() != procobj)
            {
                KeAttachProcess(procobj);
                
                attached = TRUE;
            }
            
            status = MmMapViewOfSection(g_GlobalData.DllSection,
                                        procobj,
                                        &dllbase,
                                        0,
                                        0,
                                        &secofs,
                                        &imgsize,
                                        ViewShare,
                                        SEC_NO_CHANGE,
                                        PAGE_EXECUTE_READWRITE);
            
            if (attached)
                KeDetachProcess();
            
            if (!NT_SUCCESS(status))  // may return STATUS_CONFLICTING_ADDRESSES if address has been used by EXE
            {
                //KeBugCheck(PROCESS_INITIALIZATION_FAILED);
            }
        }
        else
        {
            context = MuLookupProcessContext(procobj);
            
            if (context)
            {
                MuDereferenceProcessContext(context);
                MuDereferenceProcessContext(context);
            }
        }
        
        ObDereferenceObject(procobj);
    }
}

PMU_LOADER_ENVIRONMENT
MuLocateLeb (
    void
)
{
    return (PMU_LOADER_ENVIRONMENT)((ULONG)g_GlobalData.DllImageBase + LARGE_PAGE_SIZE);
};