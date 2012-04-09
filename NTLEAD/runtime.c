#include <wchar.h>
#include <ntddk.h>

#include "ntlead.h"


UCHAR StackFrameHeader[] = {0x8B, 0xFF, 0x55, 0x8B, 0xEC};


#pragma alloc_text(PAGE, MuReadFileInSystemFolder)
#pragma alloc_text(PAGE, MuQueryRegistryValue)
#pragma alloc_text(PAGE, MuQueryRegistryStringValue)
#pragma alloc_text(PAGE, MuPagedAlloc)
#pragma alloc_text(PAGE, MuWriteDebugLogSpecifyName)
#pragma alloc_text(PAGE, MuWriteDebugLog)
#pragma alloc_text(PAGE, MuSetErrorCode)
#pragma alloc_text(PAGE, MuSyncWriteFile)
#pragma alloc_text(PAGE, MuInlineHook)
#pragma alloc_text(PAGE, MuWriteMemoryDword)


PVOID
MuPagedAlloc (
    SIZE_T Bytes
)
{
    return ExAllocatePoolWithTag(PagedPool, Bytes, MU_POOL_TAG);
}

PVOID
MuAlloc (
    SIZE_T Bytes
)
{
    return ExAllocatePoolWithTag(NonPagedPool, Bytes, MU_POOL_TAG);
}

void
MuFree (
    PVOID Pointer
)
{
    ExFreePoolWithTag(Pointer, MU_POOL_TAG);
}

NTSTATUS
MuDeleteRegistryValue (
    PCWSTR DirName,
    PCWSTR ValueName
)
{
    return RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, DirName, ValueName);
}

NTSTATUS
MuQueryRegistryValue (
    PCWSTR DirName,
    PCWSTR ValueName,
    PKEY_VALUE_PARTIAL_INFORMATION *ValueInfo
)
{
    NTSTATUS status;
    HANDLE key;
    ULONG len = 0;
    UNICODE_STRING kp, vn;
    OBJECT_ATTRIBUTES oa;
    
    RtlInitUnicodeString(&kp, DirName);
    
    InitializeObjectAttributes(&oa,
                               &kp,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);
                               
    status = ZwOpenKey(&key, KEY_READ, &oa);
    
    if (NT_SUCCESS(status))
    {
        RtlInitUnicodeString(&vn, ValueName);
        
        status = ZwQueryValueKey(key,
                                 &vn,
                                 KeyValuePartialInformation,
                                 NULL,
                                 0,
                                 &len);
        
        if (status == STATUS_BUFFER_TOO_SMALL)
        {
            *ValueInfo = MuPagedAlloc(len);
            
            if (*ValueInfo)
            {
                status = ZwQueryValueKey(key,
                                         &vn,
                                         KeyValuePartialInformation,
                                         *ValueInfo,
                                         len,
                                         &len);
            }
            else
            {
                status = STATUS_INSUFFICIENT_RESOURCES;
            }
        }
        
        ZwClose(key);
    }
    
    return status;
}


NTSTATUS
MuReadFileInSystemFolder (
    PCWSTR FileName,
    PVOID *Buffer,
    PULONG DataLength,
    ULONG LengthLimit
)
{
    NTSTATUS status;
    HANDLE file;
    UNICODE_STRING fp;
    IO_STATUS_BLOCK iosb;
    OBJECT_ATTRIBUTES oa;
    FILE_STANDARD_INFORMATION fi;
    WCHAR path[MAX_PATH];
    
    wcscpy(path, MU_ROOTDIR_SYSTEM32);
    wcscat(path, FileName);
    
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
                        FILE_NON_DIRECTORY_FILE | FILE_SEQUENTIAL_ONLY | FILE_SYNCHRONOUS_IO_NONALERT);
    
    if (NT_SUCCESS(status))
    {
        status = ZwQueryInformationFile(file,
                                        &iosb,
                                        &fi,
                                        sizeof(fi),
                                        FileStandardInformation);
                                        
        if (NT_SUCCESS(status))
        {
            status = STATUS_INVALID_PARAMETER;
            
            if (!fi.EndOfFile.HighPart)
            {
                if (!LengthLimit)
                    LengthLimit = 0x1000000;

                if (LengthLimit >= fi.EndOfFile.LowPart)
                {
                    *DataLength = fi.EndOfFile.LowPart;
                    
                    *Buffer = MuPagedAlloc(*DataLength);
                    
                    if (*Buffer)
                        status = STATUS_SUCCESS;
                }
            }
            
            if (NT_SUCCESS(status))
            {
                status = ZwReadFile(file,
                                    NULL,
                                    NULL,
                                    NULL,
                                    &iosb,
                                    *Buffer,
                                    *DataLength,
                                    NULL,
                                    NULL);
                                    
                if (status == STATUS_PENDING)
                {
                    ZwWaitForSingleObject(file,
                                          FALSE,
                                          NULL);
                                          
                    status = iosb.Status;
                }
            }
        }
        
        ZwClose(file);
    }
    
    return status;
}

NTSTATUS
MuQueryRegistryStringValue (
    PCWSTR DirName,
    PCWSTR ValueName,
    PWSTR Buffer,
    ULONG LengthInChar
)
{
    NTSTATUS status;
    PKEY_VALUE_PARTIAL_INFORMATION vi;
    
    status = MuQueryRegistryValue(DirName,
                                  ValueName,
                                  &vi);
    
    if (NT_SUCCESS(status))
    {
        if (vi->DataLength >= LengthInChar * sizeof(WCHAR) || vi->Type != REG_SZ)
        {
            MuFree(vi);
            
            return STATUS_INVALID_PARAMETER;
        }
        
        RtlCopyMemory(Buffer, &vi->Data[0], vi->DataLength);
        
        Buffer[vi->DataLength / sizeof(WCHAR)] = 0;
        
        MuFree(vi);
    }
    
    return status;
}

void
MuWriteMemoryDword (
    PVOID Dest,
    ULONG Value
)
{
    MuWriteMemory(Dest, &Value, sizeof(ULONG));
}

void
MuWriteMemory (
    PVOID Dest,
    PVOID Data,
    ULONG NumberOfBytes
)
{
    KIRQL irql;
    
    KeRaiseIrql(APC_LEVEL, &irql);
    
    if (RtlCompareMemory(Dest, Data, NumberOfBytes) != NumberOfBytes)
    {
        __asm
        {
            cli
            mov eax,cr0
            push eax
            btr eax,16
            mov cr0,eax
        }
        
        RtlCopyMemory(Dest, Data, NumberOfBytes);
        
        __asm
        {
            pop eax
            mov cr0,eax
            sti
        }
    }
    
    KeLowerIrql(irql);
}

void
MuWriteMemoryWithMdl (
    PVOID Dest,
    PVOID Data,
    ULONG NumberOfBytes
)
{
    PMDL mdl = IoAllocateMdl(Dest,
                             NumberOfBytes,
                             FALSE,
                             FALSE,
                             NULL);
    
    if (mdl)
    {
        __try
        {
            MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess);
            
            Dest = MmMapLockedPagesSpecifyCache(mdl,
                                                KernelMode,
                                                MmCached,
                                                NULL,
                                                FALSE,
                                                NormalPagePriority);
            
            if (Dest)
            {
                RtlCopyMemory(Dest, Data, NumberOfBytes);
                
                MmUnmapLockedPages(Dest, mdl);
            }
            
            MmUnlockPages(mdl);
        }
        __except (1)
        {
        }
        
        IoFreeMdl(mdl);
    }
}

PVOID
MuLookupExportRoutineEntryByName (
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

void
MuSetErrorCode (
    PUNICODE_STRING RootDir,
    ULONG PhaseId,
    NTSTATUS LastStatus
)
{
    HANDLE key;
    UNICODE_STRING vn;
    OBJECT_ATTRIBUTES oa;
    WCHAR text[32];
    
    InitializeObjectAttributes(&oa,
                               RootDir,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);
    
    if (NT_SUCCESS(ZwOpenKey(&key, KEY_WRITE, &oa)))
    {
        swprintf(text, MU_ERROR_TEXT_FORMAT, PhaseId, LastStatus);
        
        RtlInitUnicodeString(&vn, MU_REGVAL_LAST_ERROR);
        
        ZwSetValueKey(key,
                      &vn,
                      0,
                      REG_SZ,
                      text,
                      wcslen(text) * sizeof(WCHAR));
        
        ZwFlushKey(key);
        
        ZwClose(key);
    }
}

NTSTATUS
MuSyncWriteFile (
    HANDLE FileHandle,
    PVOID Buffer,
    ULONG BufferLength,
    ULONG Offset
)
{
    NTSTATUS status;
    LARGE_INTEGER byteofs;
    IO_STATUS_BLOCK iosb;
    
    byteofs.HighPart = 0;
    byteofs.LowPart  = Offset;
    
    status = ZwWriteFile(FileHandle,
                         NULL,
                         NULL,
                         NULL,
                         &iosb,
                         Buffer,
                         BufferLength,
                         &byteofs,
                         NULL);
    
    if (status == STATUS_PENDING)
    {
        ZwWaitForSingleObject(FileHandle, FALSE, NULL);
        
        status = iosb.Status;
    }
    
    return status;
}

BOOLEAN
MuHookModule (
    PVOID ImageBase,
    PMU_AUDIT_BLOCK AuditBlock,
    ULONG NumAuBlocks,
    BOOLEAN IgnoreVerification
)
{
    ULONG NumCodeBlocks;
    ULONG OriginalAddress, RedirectAddress;
    PMU_VERIFY_BLOCK VerifyBlock;
    PMU_PUBLIC_BLOCK PublicBlock;
    PMU_HOOK_CALL_BLOCK HookCallBlock;
    PMU_REPLACE_CALL_BLOCK ReplaceCallBlock;
    PMU_LOCATE_ENTRY_BLOCK LocateEntryBlock;
    BOOLEAN success;
    
    while (NumAuBlocks--)
    {
        VerifyBlock   = AuditBlock->VerifyBlock;
        NumCodeBlocks = AuditBlock->NumCodeBlocks;
        
        success = TRUE;
        
        if (!IgnoreVerification)
        {
            while (NumCodeBlocks--)
            {
                __try
                {
                    if ((ULONG)ImageBase + VerifyBlock->Offset < (ULONG)MmHighestUserAddress)
                        ProbeForRead((PUCHAR)ImageBase + VerifyBlock->Offset, VerifyBlock->Length, 1);
                    
                    if (RtlCompareMemory((PUCHAR)ImageBase + VerifyBlock->Offset, VerifyBlock->Bytes, VerifyBlock->Length) != VerifyBlock->Length)
                        success = FALSE;
                }
                __except (1)
                {
                    success = FALSE;
                }
                
                if (!success)
                    break;
                
                (PUCHAR)VerifyBlock += MU_GENERIC_BLOCK_SIZE;
            }
        }
        
        if (success)
        {
            NumCodeBlocks = AuditBlock->NumCodeBlocks;
            PublicBlock   = AuditBlock->PublicBlock;
            
            while (NumCodeBlocks--)
            {
                if (PublicBlock->OperationType == OP_MODIFY)
                {
                    __asm int 3
                }
                else if (PublicBlock->OperationType == OP_REPLACE_CALL)
                {
                    ReplaceCallBlock = (PMU_REPLACE_CALL_BLOCK)PublicBlock;
                    
                    OriginalAddress = (ULONG)ImageBase + ReplaceCallBlock->Offset + *(PULONG)((ULONG)ImageBase + ReplaceCallBlock->Offset) + 4;
                    
                    MuWriteMemoryDword(*ReplaceCallBlock->OriginalCall, OriginalAddress - *(PULONG)ReplaceCallBlock->OriginalCall - 4);
                    
                    RedirectAddress = (ULONG)*ReplaceCallBlock->RedirectCall - ((ULONG)ImageBase + ReplaceCallBlock->Offset) - 4;
                    
                    MuWriteMemoryDword((PVOID)((ULONG)ImageBase + ReplaceCallBlock->Offset), RedirectAddress);
                }
                else if (PublicBlock->OperationType == OP_HOOK_CALL)
                {
                    HookCallBlock = (PMU_HOOK_CALL_BLOCK)PublicBlock;
                    
                    *HookCallBlock->OriginalAddress = (PVOID)((ULONG)ImageBase + HookCallBlock->Offset + *(PULONG)((ULONG)ImageBase + HookCallBlock->Offset) + 4);
                    
                    RedirectAddress = (ULONG)HookCallBlock->RedirectAddress - ((ULONG)ImageBase + HookCallBlock->Offset) - 4;
                    
                    MuWriteMemoryDword((PVOID)((ULONG)ImageBase + HookCallBlock->Offset), RedirectAddress);
                }
                else if (PublicBlock->OperationType == OP_LOCATE_ENTRY)
                {
                    LocateEntryBlock = (PMU_LOCATE_ENTRY_BLOCK)PublicBlock;
                    
                    *LocateEntryBlock->EntryAddress = (PVOID)((ULONG)ImageBase + LocateEntryBlock->Offset);
                }
                else
                {
                    __asm int 3
                }
                
                (PUCHAR)PublicBlock += MU_GENERIC_BLOCK_SIZE;
            }
            
            return TRUE;
        }
        
        (PUCHAR)AuditBlock += MU_GENERIC_BLOCK_SIZE;
    }
    
    return FALSE;
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
    
    MuWriteMemory(OriginalProcedure, jmpcode, 5);
    
    return (PVOID)((ULONG)OriginalProcedure + 5);
}

void
MuWriteDebugLog (
    ULONG Value
)
{
    MuWriteDebugLogSpecifyName(MU_REGVAL_INFORMATION, Value);
}

void
MuWriteDebugLogSpecifyName (
    PWSTR ValueName,
    ULONG Value
)
{
    HANDLE key;
    UNICODE_STRING kn, vn;
    OBJECT_ATTRIBUTES oa;
    WCHAR text[32];
    
    RtlInitUnicodeString(&kn, MU_REGPATH_NTLEA_DEBUG_ROOT);
    
    InitializeObjectAttributes(&oa,
                               &kn,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);
    
    if (NT_SUCCESS(ZwCreateKey(&key,
                               KEY_ALL_ACCESS,
                               &oa,
                               0,
                               NULL,
                               REG_OPTION_VOLATILE,
                               NULL)))
    {
        swprintf(text, MU_DEBUG_INFO_FORMAT, Value);
        
        RtlInitUnicodeString(&vn, ValueName);
        
        ZwSetValueKey(key,
                      &vn,
                      0,
                      REG_SZ,
                      text,
                      wcslen(text) * sizeof(WCHAR));
        
        ZwFlushKey(key);
        
        ZwClose(key);
    }
}

BOOLEAN
MuIsUnicodeLeadingString (
    PUNICODE_STRING StringSource,
    PWSTR StringToFind
)
{
    USHORT i, c0, c1;
    
    for (i = 0 ; i < (StringSource->Length / sizeof(WCHAR)) ; i++)
    {
        c0 = StringToFind[i];
        
        if (!c0)
            return TRUE;
        
        c1 = ((PWSTR)(StringSource->Buffer))[i];
        
        if (c0 >= 'A' && c0 <= 'Z')
            c0 += 'a' - 'A';
        
        if (c1 >= 'A' && c1 <= 'Z')
            c1 += 'a' - 'A';
        
        if (c0 != c1)
            return FALSE;
    }
    
    if (StringToFind[i])
        return FALSE;
    
    return TRUE;
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
}