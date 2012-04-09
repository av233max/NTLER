#include "ntleal.h"

int
__stdcall
main (
    void *ptr0,
    void *ptr1,
    void *ptr2
)
{
    return TRUE;
}

HANDLE
MUAPI
MuOpenControlDevice (
    void
)
{
    HANDLE DeviceHandle;
    UNICODE_STRING DeviceName;
    IO_STATUS_BLOCK IoStatus;
    OBJECT_ATTRIBUTES ObjAttr;
    
    RtlInitUnicodeString(&DeviceName, MU_DEVNAME_HOST_CONTROL);
    
    memset(&ObjAttr, 0, sizeof(ObjAttr));
    
    ObjAttr.Length     = sizeof(ObjAttr);
    ObjAttr.Attributes = OBJ_CASE_INSENSITIVE;
    ObjAttr.ObjectName = &DeviceName;
    
    if (!NT_SUCCESS(NtCreateFile(&DeviceHandle,
                                 FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                                 &ObjAttr,
                                 &IoStatus,
                                 NULL,
                                 FILE_ATTRIBUTE_NORMAL,
                                 0,
                                 FILE_OPEN,
                                 FILE_NON_DIRECTORY_FILE,
                                 NULL,
                                 0)))
        return NULL;
    
    return DeviceHandle;
}

PMU_LOADER_ENVIRONMENT
MUAPI
MuQueryLebBase (
    HANDLE DeviceHandle
)
{
    MU_CTLOUT_GET_LEB_BASE leb;
    
    MuSyncSendControl(DeviceHandle,
                      IOCTL_GET_LEB_BASE,
                      NULL,
                      0,
                      &leb,
                      sizeof(MU_CTLOUT_GET_LEB_BASE),
                      NULL);
    
    return leb.Base;
}

BOOLEAN
MUAPI
MuCloseControlDevice (
    HANDLE DeviceHandle
)
{
    return NT_SUCCESS(NtClose(DeviceHandle)) ? TRUE : FALSE;
}

BOOLEAN
MUAPI
MuAddAppConfig (
    HANDLE DeviceHandle,
    PMU_APPLICATION_CONFIGURATION AppConfig
)
{
    PWSTR path = (PWSTR)((ULONG)&AppConfig->UserStorage[0] + AppConfig->UserStorageLength);
    
    return MuSyncSendControl(DeviceHandle,
                             IOCTL_ADD_APPCONFIG,
                             AppConfig,
                             sizeof(MU_APPLICATION_CONFIGURATION) - 1 + AppConfig->UserStorageLength + (wcslen(path) * sizeof(WCHAR)),
                             NULL,
                             0,
                             NULL);
}

ULONG
MUAPI
MuEnumAppConfig (
    HANDLE DeviceHandle,
    PMU_CTLOUT_ENUM_APPCONFIG EnumConfig,
    ULONG BufferSize
)
{
    ULONG BytesWritten = 0;
    
    MuSyncSendControl(DeviceHandle,
                      IOCTL_ENUM_APPCONFIG,
                      NULL,
                      0,
                      EnumConfig,
                      BufferSize,
                      &BytesWritten);
    
    return BytesWritten;
}

ULONG
MUAPI
MuQueryAppConfig (
    HANDLE DeviceHandle,
    PMU_CTLIN_QUERY_APPCONFIG QueryConfigInput,
    PMU_CTLOUT_QUERY_APPCONFIG QueryConfigOutput,
    ULONG OutputBufferSize
)
{
    ULONG BytesWritten = 0;
    
    MuSyncSendControl(DeviceHandle,
                      IOCTL_QUERY_APPCONFIG,
                      QueryConfigInput,
                      sizeof(MU_CTLIN_QUERY_APPCONFIG) + (wcslen(QueryConfigInput->FilePath) * sizeof(WCHAR)),
                      QueryConfigOutput,
                      OutputBufferSize,
                      &BytesWritten);
    
    return BytesWritten;
}

BOOLEAN
MUAPI
MuRemoveAppConfig (
    HANDLE DeviceHandle,
    ULONG Key
)
{
    return MuSyncSendControl(DeviceHandle,
                             IOCTL_REMOVE_APPCONFIG,
                             &Key,
                             sizeof(ULONG),
                             NULL,
                             0,
                             NULL);
}

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
)
{
    NTSTATUS status;
    IO_STATUS_BLOCK IoStatus;
    
    status = NtDeviceIoControlFile(DeviceHandle,
                                   NULL,
                                   NULL,
                                   NULL,
                                   &IoStatus,
                                   ControlCode,
                                   InBuffer,
                                   InBufferSize,
                                   OutBuffer,
                                   OutBufferSize);
    
    if (NT_SUCCESS(status))
    {
        if (ReturnSize)
            *ReturnSize = IoStatus.Information;
            
        return TRUE;
    }
    
    return FALSE;
}