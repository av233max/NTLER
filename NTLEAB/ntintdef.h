NTSYSAPI
void
NTAPI
VidDisplayStringXY (
  PUCHAR  String,  
  ULONG  Left,  
  ULONG  Top,  
  BOOLEAN  Transparent   
 );

NTSYSAPI
ULONG
NTAPI
VidSetTextColor (
  ULONG  Color
  );

NTSYSAPI
void
NTAPI
VidSolidColorFill  (
  IN ULONG  Left,  
  IN ULONG  Top,  
  IN ULONG  Right,  
  IN ULONG  Bottom,  
  IN UCHAR  Color   
  );
  
NTSYSAPI
NTSTATUS 
ObReferenceObjectByName( 
    IN PUNICODE_STRING ObjectName, 
    IN ULONG Attributes, 
    IN PACCESS_STATE PassedAccessState OPTIONAL, 
    IN ACCESS_MASK DesiredAccess OPTIONAL, 
    IN POBJECT_TYPE ObjectType, 
    IN KPROCESSOR_MODE AccessMode, 
    IN OUT PVOID ParseContext OPTIONAL, 
    OUT PVOID *Object 
    );
    
extern POBJECT_TYPE IoDriverObjectType;

NTSYSAPI NTSTATUS  ZwCreateEvent(    OUT PHANDLE  EventHandle,    IN ACCESS_MASK  DesiredAccess,    IN POBJECT_ATTRIBUTES  ObjectAttributes OPTIONAL,    IN EVENT_TYPE  EventType,    IN BOOLEAN  InitialState    );

NTSYSAPI NTSTATUS  ZwWaitForSingleObject(    __in HANDLE  Handle,    __in BOOLEAN  Alertable,    __in_opt PLARGE_INTEGER  Timeout    );