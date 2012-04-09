#include <ntddk.h>

#include "bootcfg.h"


#pragma alloc_text(PAGE, DriverEntry)

extern PULONG InitSafeBootMode;

NTSTATUS
DriverEntry (
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE hthread;
    
    if (*InitSafeBootMode)
    {
        status = PsCreateSystemThread(&hthread,
                                      THREAD_ALL_ACCESS,
                                      NULL,
                                      NULL,
                                      NULL,
                                      (PKSTART_ROUTINE)MuStartup,
                                      NULL);
                                      
        if (NT_SUCCESS(status))
            ZwClose(hthread);
    }
    
    return status;
}

void
MuStartup (
    PVOID Context
)
{
    NTSTATUS status;
    HANDLE driver, event, key;
    ULONG i, state = 0, scancode = 0, start = SERVICE_DISABLED;
    LARGE_INTEGER time;
    UNICODE_STRING dn;
    IO_STATUS_BLOCK iosb;
    OBJECT_ATTRIBUTES oa;
    PVOID drvobj;
    
    time.QuadPart = 10 * DELAY_ONE_MILLISECOND;
    
    RtlInitUnicodeString(&dn, MU_EVENTNAME_BOOTSYNC);
    
    InitializeObjectAttributes(&oa,
                               &dn,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);
                               
    status = ZwCreateEvent(&event,
                           EVENT_ALL_ACCESS,
                           &oa,
                           NotificationEvent,
                           FALSE);
                           
    if (NT_SUCCESS(status))
    {
        VidDisplayStringXY(MU_TEXT_PROMPTING, MU_TEXT_COORD_X, MU_TEXT_COORD_Y, TRUE);
        
        for (i = 0 ; i < MU_DELAY_COUNT ; i++)
        {
            state = (UCHAR)READ_PORT_UCHAR((PUCHAR)0x64);
            
            if (state & 1)
            {
                scancode = (UCHAR)READ_PORT_UCHAR((PUCHAR)0x60);
                
                if (scancode == 0x01 || scancode == 0x76) // scancode for ESC in scancodes set 1/2
                    break;
                else
                    scancode = 0;
            }
            
            if (ZwWaitForSingleObject(event, FALSE, &time) == STATUS_SUCCESS)
            {
                ZwClose(event);
                
                break;
            }
        }
        
        VidSolidColorFill(MU_TEXT_COORD_X,
                          MU_TEXT_COORD_Y,
                          MU_TEXT_COORD_X + TEXT_TOTAL_WIDTH,
                          MU_TEXT_COORD_Y + TEXT_HEIGHT,
                          COLOR_BLACK);
    
        if (scancode)
        {
            RtlInitUnicodeString(&dn, MU_REGPATH_HOST_CONTROL);
            
            InitializeObjectAttributes(&oa,
                                       &dn,
                                       OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                       NULL,
                                       NULL);
                               
            if (NT_SUCCESS(ZwOpenKey(&key, KEY_WRITE, &oa)))
            {
                RtlInitUnicodeString(&dn, MU_REGVALUE_START_TYPE);
                
                if (NT_SUCCESS(ZwSetValueKey(key,
                                             &dn,
                                             0,
                                             REG_DWORD,
                                             &start,
                                             sizeof(ULONG))))
                {
                    ZwFlushKey(key);
                    
                    VidDisplayStringXY(MU_TEXT_FEEDBACK, MU_TEXT_COORD_X, MU_TEXT_COORD_Y, TRUE);
                }
                
                ZwClose(key);
            }
        }
    }
    
    PsTerminateSystemThread(STATUS_SUCCESS);
}