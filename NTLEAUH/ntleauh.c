#include "ntleauh.h"

#pragma pack(push)
#pragma pack(16)

MU_AUDIT_PARAMETER APXP_0 = {
    MU_FILENAME_KERNEL32_DLL,
    0,
    0,
    NULL
};

MU_AUDIT_PARAMETER APXP_1 = {
    MU_FILENAME_SHELL32_DLL,
    0,
    0,
    NULL
};

MU_AUDIT_PARAMETER APXP_2 = {
    MU_FILENAME_GDI32_DLL,
    0,
    0,
    NULL
};

MU_AUDIT_PARAMETER APXP_3 = {
    MU_FILENAME_USER32_DLL,
    0,
    0,
    NULL
};

#pragma pack(pop)


#pragma data_seg(".leb") 

MUVAL PMU_LOADER_ENVIRONMENT MuLoaderEnvironment = NULL;

#pragma data_seg()

#pragma comment(linker, "/SECTION:.leb,RWS") 

//#define GET_LEB(x) (x = (PMU_LOADER_ENVIRONMENT)MuLoaderEnvironment)


PVOID SHGetFolderPathW_;
PVOID CreateFontIndirectExW_;
PVOID CreateCompatibleDC_;

PWINMM_GET_PNPINFO WinmmGetPnpInfo;

PREG_OPEN_KEY_EX_W MmdevapiRegOpenKeyExW;

PNT_CREATE_PROCESS_EX KrnlCreateProcessEx;

PGDI32_FONT_CREATE NtGdiHfontCreate = NULL;

PGDI32_SELECT_OBJECT SelectObject_;

WCHAR DataFlowName[MAX_DATA_FLOW][16] = {DFN_RENDER, DFN_CAPTURE, DFN_REMOTE_RENDER, DFN_REMOTE_CAPTURE};

ULONG FilterRule[MAX_DATA_FLOW] = {FRF_GET_RENDER  | FRF_FILTER_NP_DEVICES,
                                   FRF_GET_CAPTURE | FRF_FILTER_NP_DEVICES,
                                   FRF_GET_REMOTE_RENDER,
                                   FRF_GET_CAPTURE | FRF_SELECT_NP_DEVICE};

UCHAR TestCode[] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90};

UCHAR TestCode2[] = {0xB8, 0x00, 0, 0, 0, 0xC3};

UCHAR StackFrameHeader[] = {0x8B, 0xFF, 0x55, 0x8B, 0xEC};

int test = 0;

int
__stdcall
main (
    void *ptr0,
    void *ptr1,
    void *ptr2
)
{
    return 0;
}

NTSTATUS
MUAPI
MuProcessStaticImports (
    PNTDLL_IMAGE_INFO ImageInfo,
    PVOID Unknown
)
{
    NTSTATUS status = MuProcessStaticImports(ImageInfo, Unknown);
    
    MuProcessUserModeHook(ImageInfo);
    
    return status;
}

NTSTATUS
MUAPI
MuWalkImportDescriptor (
    PVOID Unknown,
    PNTDLL_IMAGE_INFO ImageInfo
)
{
    NTSTATUS status = MuWalkImportDescriptor(Unknown, ImageInfo);
    
    MuProcessUserModeHook(ImageInfo);
    
    return status;
}

void
MuProcessUserModeHook (
    PNTDLL_IMAGE_INFO ImageInfo
)
{
    OSVERSIONINFOEXW VerInfo;
    
    VerInfo.dwOSVersionInfoSize = sizeof(VerInfo);
    
    RtlGetVersion(&VerInfo);
    
    __try
    {
        MuHookSystemRoutines(ImageInfo->ImageStart,
                             ImageInfo->ImageSize,
                             &ImageInfo->ImageFileName,
                             &APXP_0,
                             4,
                             &VerInfo);
    
    /*
        MuHookSystemRoutines(ImageInfo->ImageStart,
                             ImageInfo->ImageSize,
                             &ImageInfo->ImageFileName,
                             &APW6_0,
                             1);
    */
    }
    __except (1)
    {
    }
}

void
MuHookSystemRoutines (
    PVOID ImageBase,
    ULONG ImageSize,
    PUNICODE_STRING ImageFileName,
    PMU_AUDIT_PARAMETER AuditParam,
    ULONG NumFilesToPatch,
    POSVERSIONINFOW OsVersion
)
{
    PVOID OriginalAddress;
    ULONG RedirectAddress;
    UNICODE_STRING fn;
    
    /*
    NTSTATUS status;
    OBJECT_ATTRIBUTES oa;
    HANDLE SectionHandle;
    SIZE_T ViewSize = 0;
    PVOID BaseAddress = NULL;
    
    
    memset(&oa, 0, sizeof(oa));
    
    */
    
    while (NumFilesToPatch--)
    {
        RtlInitUnicodeString(&fn, AuditParam->FileName);
        
        if (!RtlCompareUnicodeString(ImageFileName, &fn, TRUE))
        {
            if (AuditParam->FileName == MU_FILENAME_KERNEL32_DLL)
            {
                __try
                {
                    __try
                    {
                        if (MuLoaderEnvironment->NlsParam.LocaleId)
                        {
                            OriginalAddress = EATLookupRoutineEntryByName(ImageBase, "GetUserDefaultLCID");
                            
                            if (OriginalAddress)
                            {
                                MuInlineHook(OriginalAddress, MuGetUserDefaultLCID);
                            }
                        }
                        
                        /*
                        if (MuLoaderEnvironment->EnhancedOptions & MU_OPTION_CHANGE_UI_LANG_ID)
                        {
                            OriginalAddress = EATLookupRoutineEntryByName(ImageBase, "GetUserDefaultUILanguage");
                            
                            if (OriginalAddress)
                            {
                                MuInlineHook(OriginalAddress, MuGetUserDefaultLCID);
                            }
                            
                            OriginalAddress = EATLookupRoutineEntryByName(ImageBase, "GetSystemDefaultUILanguage");
                            
                            if (OriginalAddress)
                            {
                                MuInlineHook(OriginalAddress, MuGetUserDefaultLCID);
                            }
                        }
                        */
                    }
                    __except (1)
                    {
                    }
                }
                __finally
                {
                    if (OsVersion->dwMinorVersion == 1)
                    {
                        OriginalAddress = IATHookRoutineByName(ImageBase, "NtCreateProcessEx", MuStubHookCreateProcessEx_XP);
                    }
                    else
                    {
                        OriginalAddress = IATHookRoutineByName(ImageBase, "NtCreateProcessEx", MuStubHookCreateProcessEx_2K3);
                    }
                    
                    if (OriginalAddress)
                        KrnlCreateProcessEx = (PNT_CREATE_PROCESS_EX)OriginalAddress;
                }
            }
            else if (AuditParam->FileName == MU_FILENAME_SHELL32_DLL)
            {
                __try
                {
                    if (MuLoaderEnvironment->EnhancedOptions & MU_OPTION_MAP_SPECIAL_FOLDERS)
                    {
                        OriginalAddress = EATLookupRoutineEntryByName(ImageBase, "SHGetFolderPathW");
                        
                        if (OriginalAddress)
                        {
                            if (!MuCheckRoutineStackFrame(OriginalAddress))
                                return;
                            
                            SHGetFolderPathW_ = MuInlineHook(OriginalAddress, MuGetFolderPathW);
                        }
                    }
                }
                __except (1)
                {
                }
            }
            else if (AuditParam->FileName == MU_FILENAME_GDI32_DLL)
            {
                __try
                {
                    if (MuLoaderEnvironment->NlsParam.LocaleId)
                    {
                        OriginalAddress = EATLookupRoutineEntryByName(ImageBase, "SelectObject");
                        
                        if (OriginalAddress)
                            SelectObject_ = (PGDI32_SELECT_OBJECT)OriginalAddress;
                        else
                            return;
                        
                        OriginalAddress = EATLookupRoutineEntryByName(ImageBase, "CreateFontIndirectExW");
                        
                        if (OriginalAddress)
                        {
                            if (!MuCheckRoutineStackFrame(OriginalAddress))
                                return;
                            
                            CreateFontIndirectExW_ = MuInlineHook(OriginalAddress, MuCreateFontIndirectExW);
                        }
                        else
                        {
                            return;
                        }
                        
                        /*
                        
                        OriginalAddress = EATLookupRoutineEntryByName(ImageBase, "CreateCompatibleDC");
                        
                        if (OriginalAddress)
                        {
                            if (!MuCheckRoutineStackFrame(OriginalAddress))
                                return;
                            
                            CreateCompatibleDC_ = MuInlineHook(OriginalAddress, MuCreateCompatibleDC);
                        }
                        */
                    }
                }
                __except (1)
                {
                }
            }
            else if (AuditParam->FileName == MU_FILENAME_USER32_DLL)
            {
                __try
                {
                    if (MuLoaderEnvironment->NlsParam.LocaleId)
                        IATHookRoutineByName(ImageBase, "GetTextFaceAliasW", MuStubGetTextFaceAliasW_NT5);
                }
                __except (1)
                {
                }
            }
        }
        
        (PUCHAR)AuditParam += 16;
    }
}

void
MuHookAddress (
    PVOID Destination,
    ULONG Value
)
{
    MuWriteProtectedAddress(Destination, &Value, sizeof(ULONG), TRUE);
}

LCID
WINAPI
MuGetUserDefaultLCID (
    void
)
{
    return MuLoaderEnvironment->NlsParam.LocaleId;
}

HRESULT
WINAPI
MuGetFolderPathW (
    HWND hwndOwner,
    int nFolder,
    HANDLE hToken,
    DWORD dwFlags,
    LPTSTR pszPath
)
{
    NTSTATUS status;
    ANSI_STRING ansistr;
    UNICODE_STRING unistr, path;
    LONG diff;
    ULONG pathid;
    HANDLE dev;
    HRESULT retval = MuStubGetFolderPathW(hwndOwner,
                                          nFolder,
                                          hToken,
                                          dwFlags,
                                          pszPath);
    
    if (retval != S_OK)
        return retval;
    
    RtlInitUnicodeString(&path, pszPath);
    
    if (!NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansistr, &path, TRUE)))
        return S_OK;
    
    status = RtlAnsiStringToUnicodeString(&unistr, &ansistr, TRUE);
    
    RtlFreeAnsiString(&ansistr);
    
    if (!NT_SUCCESS(status))
        return S_OK;
    
    diff = RtlCompareUnicodeString(&path, &unistr, FALSE);
    
    RtlFreeUnicodeString(&unistr);
    
    if (diff)
    {
        dev = MuOpenControlDevice();
        
        if (!dev)
            return S_OK;
        
        status = MuSyncSendControl(dev,
                                   IOCTL_CREATE_SYMBOLIC_LINK,
                                   pszPath,
                                   path.Length + sizeof(WCHAR),
                                   &pathid,
                                   sizeof(ULONG),
                                   NULL);
        
        NtClose(dev);
        
        if (NT_SUCCESS(status))
            swprintf((PWSTR)((ULONG)pszPath + sizeof(PASSING_DRIVE_LETTER)), MU_STRING_FORMAT_GUID_PATH, MU_IMPERSONATION_PATH_GUID, pathid);
    }
    
    return S_OK;
}

int
__declspec(naked)
NTAPI
MuStubGetTextFaceAliasW_NT5 (
    HDC hdc,
    int nCount,
    LPTSTR lpFaceName
)
{
    __asm
    {
        mov eax,DWORD PTR[ebp - 0xB8]  //NT5 all?
        push ebp
        mov ebp,esp
        push eax
        push [lpFaceName]
        call MuCopyFaceName
        pop ebp
        retn 0x0C
    }
}

int
NTAPI
MuCopyFaceName (
    LPWSTR ToStr,
    LPWSTR FromStr
)
{
    int i;
    
    for (i = 0 ; i < LF_FACESIZE ; i++)
    {
        if (!(ToStr[i] = FromStr[i]))
            break;
    }
    
    return i;
}


HRESULT
__declspec(naked)
NTAPI
MuStubGetFolderPathW (
    HWND hwndOwner,
    int nFolder,
    HANDLE hToken,
    DWORD dwFlags,
    LPTSTR pszPath
)
{
    __asm
    {
        push ebp
        mov ebp,esp
        jmp [SHGetFolderPathW_]
    }
}

void
MuWriteProtectedAddress (
    PVOID Destination,
    PVOID Source,
    ULONG Length,
    BOOLEAN FlushCode
)
{
    PVOID BaseAddress = Destination;
    ULONG OldProtection, temp, BytesProtect = Length;
    
    if (NT_SUCCESS(NtProtectVirtualMemory(NtCurrentProcess(),
                                          &BaseAddress,
                                          &BytesProtect,
                                          PAGE_READWRITE,
                                          &OldProtection)))
    {
        memcpy(Destination, Source, Length);
        
        NtProtectVirtualMemory(NtCurrentProcess(),
                               &BaseAddress,
                               &BytesProtect,
                               OldProtection,
                               &temp);
                               
        if (FlushCode)
            NtFlushInstructionCache(NtCurrentProcess(),
                                    Destination,
                                    Length);
    }
}

HFONT
WINAPI
MuCreateFontIndirectExW (
    PENUMLOGFONTEXDV penumlfex
)
{
    HANDLE dev;
    ENUMLOGFONTEXDV enumlfex;
    
    memcpy(&enumlfex, penumlfex, sizeof(enumlfex));
    
    dev = MuOpenControlDevice();
    
    if (dev)
    {
        MuSyncSendControl(dev,
                          IOCTL_SUBSTITUTE_TO_FACENAME,
                          enumlfex.elfEnumLogfontEx.elfLogFont.lfFaceName,
                          LF_FACESIZE * sizeof(WCHAR),
                          enumlfex.elfEnumLogfontEx.elfLogFont.lfFaceName,
                          LF_FACESIZE * sizeof(WCHAR),
                          NULL);
        
        NtClose(dev);
    }
    
    return MuStubCreateFontIndirectExW(&enumlfex);
}

HDC
WINAPI
MuCreateCompatibleDC (
    HDC hdc
)
{
    HFONT font;
    ENUMLOGFONTEXDV enumlfex;
    HDC retdc = MuStubCreateCompatibleDC(hdc);
    
    
    if (retdc)
    {
        memset(&enumlfex, 0, sizeof(enumlfex));
        
        enumlfex.elfEnumLogfontEx.elfLogFont.lfOutPrecision  = OUT_DEFAULT_PRECIS;
        enumlfex.elfEnumLogfontEx.elfLogFont.lfClipPrecision = CLIP_DEFAULT_PRECIS;
        enumlfex.elfEnumLogfontEx.elfLogFont.lfQuality       = DEFAULT_QUALITY;
        wcscpy(enumlfex.elfEnumLogfontEx.elfLogFont.lfFaceName, L"MS Gothic");
        
        font = MuCreateFontIndirectExW(&enumlfex);
        
        if (font)
            SelectObject_(retdc, font);
    }
    
    return retdc;
}

HDC
__declspec(naked)
WINAPI
MuStubCreateCompatibleDC (
    HDC hdc
)
{
    __asm
    {
        push ebp
        mov ebp,esp
        jmp [CreateCompatibleDC_]
    }
}

HFONT
__declspec(naked)
WINAPI
MuStubCreateFontIndirectExW (
    PENUMLOGFONTEXDV penumlfex
)
{
    __asm
    {
        push ebp
        mov ebp,esp
        jmp [CreateFontIndirectExW_]
    }
}

HANDLE
__stdcall
MuGdiHfontCreate (
    PLOGFONT LogFont,
    PVOID Unknown0,
    PVOID Unknown1,
    PVOID Unknown2,
    PVOID Unknown3
)
{
    BOOLEAN inherit = FALSE;
    
    __try
    {
        __try
        {
            inherit = MuLoaderEnvironment->NlsParam.LocaleId ? TRUE : FALSE;
        }
        __finally
        {
            if (inherit)
            {
                if (++test < 0xFFFFFF)
                {
                	/*
                  if (!wcscmp(LogFont->lfFaceName, L"ËÎÌו"))
                      __asm int 3*/
                
                /*
                LogFont->lfHeight = -10;
                LogFont->lfWidth = 0;
                LogFont->lfWeight = 400;
                LogFont->lfCharSet = GB2312_CHARSET;//SHIFTJIS_CHARSET;
                LogFont->lfPitchAndFamily = FIXED_PITCH | FF_MODERN;
                LogFont->lfQuality = DRAFT_QUALITY;
                LogFont->lfClipPrecision = CLIP_STROKE_PRECIS | CLIP_DFA_DISABLE;
                LogFont->lfOutPrecision = OUT_STROKE_PRECIS | OUT_TT_ONLY_PRECIS;
                */
                }
                
                
                if(!wcsicmp(LogFont->lfFaceName, L"Lucida Sans Unicode"))
                    wcscpy(LogFont->lfFaceName, L"MS UI Gothic");
                
                if(!wcsicmp(LogFont->lfFaceName, L"SimSun"))
                    wcscpy(LogFont->lfFaceName, L"MS UI Gothic");
                
                if(!wcsicmp(LogFont->lfFaceName, L"Tahoma"))
                    wcscpy(LogFont->lfFaceName, L"MS UI Gothic");
                
                if(!wcsicmp(LogFont->lfFaceName, L"Microsoft Sans Serif"))
                    wcscpy(LogFont->lfFaceName, L"MS UI Gothic");
                /*
                if(!wcsicmp(LogFont->lfFaceName, L"MS Shell Dlg"))
                {
                    LogFont->lfHeight = -12;
                    wcscpy(LogFont->lfFaceName, L"MS UI Gothic");
                }
                
                if(!wcsicmp(LogFont->lfFaceName, L"MS Shell Dlg 2"))
                {
                    LogFont->lfHeight = -12;
                    wcscpy(LogFont->lfFaceName, L"MS UI Gothic");
                }
                */
            }
            
            return NtGdiHfontCreate(LogFont,
                                    Unknown0,
                                    Unknown1,
                                    Unknown2,
                                    Unknown3);
        }
    }
    __except (1)
    {
        return NULL;
    }
}

NTSTATUS
__declspec(naked)
NTAPI
MuStubHookCreateProcessEx_XP (
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    ULONG Flags,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    ULONG JobMemberLevel
)
{
    __asm
    {
        mov eax,DWORD PTR[ebp - 0x71C]  //xp all?
        push ebp
        mov ebp,esp
        push [JobMemberLevel]
        push [ExceptionPort]
        push [DebugPort]
        push [SectionHandle]
        push [Flags]
        push [ParentProcess]
        push [ObjectAttributes]
        push [DesiredAccess]
        push [ProcessHandle]
        push eax
        call MuHookCreateProcessEx
        pop ebp
        retn 0x24
    }
}

NTSTATUS
__declspec(naked)
NTAPI
MuStubHookCreateProcessEx_2K3 (
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    ULONG Flags,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    ULONG JobMemberLevel
)
{
    __asm
    {
        mov eax,DWORD PTR[ebp - 0x46C]  //2k3 all?
        push ebp
        mov ebp,esp
        push [JobMemberLevel]
        push [ExceptionPort]
        push [DebugPort]
        push [SectionHandle]
        push [Flags]
        push [ParentProcess]
        push [ObjectAttributes]
        push [DesiredAccess]
        push [ProcessHandle]
        push eax
        call MuHookCreateProcessEx
        pop ebp
        retn 0x24
    }
}

NTSTATUS
NTAPI
MuHookCreateProcessEx (
    PCWSTR ImageFilePath,
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    ULONG Flags,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    ULONG JobMemberLevel
)
{
    NTSTATUS status;
    HANDLE dev = NULL;
    PVOID copyptr;
    BOOLEAN inherit = FALSE, run = FALSE;
    MU_CTLIN_MARK_CALLING_THREAD markprm;
    MU_CTLOUT_QUERY_LEB queryleb;
    
    __try
    {
        __try
        {
            inherit = MuLoaderEnvironment->NlsParam.LocaleId ? TRUE : FALSE;
            
            copyptr = MuLoaderEnvironment;
        }
        __finally
        {
            dev = MuOpenControlDevice();
            
            if (dev)
            {
                if (MuSyncSendControl(dev,
                                      IOCTL_QUERY_LEB,
                                      (PMU_CTLIN_QUERY_LEB)ImageFilePath,
                                      (wcslen(ImageFilePath) + 1) * sizeof(WCHAR),
                                      &queryleb,
                                      sizeof(queryleb),
                                      NULL))
                {
                    inherit = TRUE;
                    
                    copyptr = &queryleb;
                }
                
                NtClose(dev);
                
                dev = NULL;
            }
            
            if (inherit)
            {
                dev = MuOpenControlDevice();
                
                if (dev)
                {
                    memcpy(&markprm, copyptr, sizeof(MU_LOADER_ENVIRONMENT));
                    
                    MuSyncSendControl(dev,
                                      IOCTL_MARK_CALLING_THREAD,
                                      &markprm,
                                      sizeof(markprm),
                                      NULL,
                                      0,
                                      NULL);
                }
            }
            
            status = KrnlCreateProcessEx(ProcessHandle,
                                         DesiredAccess,
                                         ObjectAttributes,
                                         ParentProcess,
                                         Flags,
                                         SectionHandle,
                                         DebugPort,
                                         ExceptionPort,
                                         JobMemberLevel);
            
            run = TRUE;
            
            if (dev)
            {
                MuSyncSendControl(dev,
                                  IOCTL_CLEAR_THREAD_RECORD,
                                  NULL,
                                  0,
                                  NULL,
                                  0,
                                  NULL);
                
                NtClose(dev);
                
                dev = NULL;
            }
            
            return status;
        }
    }
    __except (1)
    {
        if (dev)
            NtClose(dev);
        
        if (!run)
        {
             return KrnlCreateProcessEx(ProcessHandle,
                                        DesiredAccess,
                                        ObjectAttributes,
                                        ParentProcess,
                                        Flags,
                                        SectionHandle,
                                        DebugPort,
                                        ExceptionPort,
                                        JobMemberLevel);
        }
        
        return STATUS_UNSUCCESSFUL;
    }
}

HANDLE
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

BOOLEAN
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

PVOID
IATHookRoutineByName (
	PVOID pImageBase,
	PCSTR pRoutineName,
	PVOID pRedirectRoutine
)
{
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((PUCHAR)pImageBase + (((PIMAGE_NT_HEADERS)((PUCHAR)pImageBase + ((PIMAGE_DOS_HEADER)pImageBase)->e_lfanew)))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    PVOID pOriginalRoutine = NULL;
    PIMAGE_THUNK_DATA pNameThunk, pAddressThunk;
    PIMAGE_IMPORT_BY_NAME pImportName;
    
    while (pImportDesc->Name)
    {
        pNameThunk    = (PIMAGE_THUNK_DATA)((PUCHAR)pImageBase + pImportDesc->OriginalFirstThunk);
        pAddressThunk = (PIMAGE_THUNK_DATA)((PUCHAR)pImageBase + pImportDesc->FirstThunk);
        
        while (pNameThunk->u1.AddressOfData)
        {
            pImportName = (PIMAGE_IMPORT_BY_NAME)((PUCHAR)pImageBase + (ULONG)pNameThunk->u1.AddressOfData);
            
            if (!strcmp((PUCHAR)pImportName->Name, (PUCHAR)pRoutineName))
            {
                pOriginalRoutine = (PVOID)pAddressThunk->u1.Function;
                
                if (pOriginalRoutine == pRedirectRoutine)
                    return NULL;
                
                WriteAddressUlong(&pAddressThunk->u1.Function, (ULONG)pRedirectRoutine);
            
                break;
            }
            
            pAddressThunk++;
            pNameThunk++;
        }
        
        if (pOriginalRoutine)
            break;
    
        pImportDesc++;
    }
    
    return pOriginalRoutine;
}

PVOID
EATLookupRoutineEntryByName (
	PVOID pImageBase,
	PCSTR pRoutineName
)
{
    PIMAGE_EXPORT_DIRECTORY pExportDict = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)pImageBase + (((PIMAGE_NT_HEADERS)((PUCHAR)pImageBase + ((PIMAGE_DOS_HEADER)pImageBase)->e_lfanew)))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PUCHAR *pName = (PUCHAR *)((PUCHAR)pImageBase + pExportDict->AddressOfNames);
    ULONG Index;

    for (Index = 0 ; Index < pExportDict->NumberOfNames ; Index++)
    {
        if (!strcmp((PUCHAR)pImageBase + (ULONG)*(pName + Index), (PUCHAR)pRoutineName))
            return (PUCHAR)pImageBase + (ULONG)*((PVOID *)((PUCHAR)pImageBase + pExportDict->AddressOfFunctions) + *((PUSHORT)((PUCHAR)pImageBase + pExportDict->AddressOfNameOrdinals) + Index));
    }
    
    return NULL;
}

PVOID
MuInlineHook (
    PVOID OriginalProcedure,
    PVOID RedirectAddress
)
{
    UCHAR jmpcode[5];
    
    jmpcode[0] = 0xE9;  // x86 opcode "jmp offset32"
    
    *((PULONG)&jmpcode[1]) = (ULONG)RedirectAddress - (ULONG)OriginalProcedure - 5;
    
    MuWriteProtectedAddress(OriginalProcedure, jmpcode, 5, TRUE);
    
    return (PVOID)((ULONG)OriginalProcedure + 5);
}

BOOLEAN
MuCheckRoutineStackFrame (
    PVOID RoutineEntry
)
{
    SIZE_T i;
    
    for (i = 0 ; i < sizeof(StackFrameHeader) ; i++)
    {
        if (((PUCHAR)RoutineEntry)[i] != StackFrameHeader[i])
            return FALSE;
    }
    
    return TRUE;
};