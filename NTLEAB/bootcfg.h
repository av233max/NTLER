#include "ntintdef.h"

#define    MU_EVENTNAME_BOOTSYNC      L"\\NTLEA_BootSyncEvent"

#define    MU_REGPATH_HOST_CONTROL    L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\NTLEA_MulLocEmuDrv"

#define    MU_REGVALUE_START_TYPE     L"Start"

#define    MU_TEXT_PROMPTING          "Press Esc to cancel loading NTLEA..."
#define    MU_TEXT_FEEDBACK           "The loading action has been cancelled"

#define    DELAY_ONE_MICROSECOND      (-10)
#define    DELAY_ONE_MILLISECOND      (DELAY_ONE_MICROSECOND*1000)
#define    DELAY_ONE_SECOND           (DELAY_ONE_MILLISECOND*1000)

#define    MU_TEXT_COORD_X            176
#define    MU_TEXT_COORD_Y            408
#define    TEXT_HEIGHT                13
#define    TEXT_TOTAL_WIDTH           300

#define    COLOR_BLACK                0

#define    MU_DELAY_COUNT             200


NTSTATUS
DriverEntry (
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
);

void
MuStartup (
    PVOID Context
);