#include <ntddk.h>

#include "ntlead.h"


extern PVOID *MmSectionObjectType;


#pragma alloc_text(PAGE, MuLoadCustomizeNlsTable)
#pragma alloc_text(PAGE, MuLoadNlsTableIntoContiguousBuffer)
#pragma alloc_text(PAGE, MuQueryNlsFileIndex)
#pragma alloc_text(PAGE, MuInitNlsTables)


NTSTATUS
MuQueryNlsFileIndex (
    PCWSTR DirName,
    PCWSTR ValueName,
    PWSTR FileIndex
)
{
    return MuQueryRegistryStringValue(DirName,
                                      ValueName,
                                      FileIndex,
                                      MU_MAX_INDEX_LENGTH);
}

void
MuInitNlsTables (
    PUSHORT AnsiNlsBase,
    PUSHORT OemNlsBase,
    PUSHORT LanguageNlsBase,
    PNLSTABLEINFO TableInfo
)
{
    RtlInitCodePageTable(AnsiNlsBase, &TableInfo->AnsiTableInfo);
    RtlInitCodePageTable(OemNlsBase, &TableInfo->OemTableInfo);
    //RtlpInitUpcaseTable(LanguageNlsBase, TableInfo);
}

PMU_NLS_SOURCE_DESCRIPTOR
MuLoadCustomizeNlsTable (
    PMU_NLS_PARAMETER Parameter
)
{
    PMU_NLS_SOURCE_DESCRIPTOR previous = NULL, current;
    PMU_GLOBAL_DATA GlobalData = MuAcquireNsdLibraryMutex();
    WCHAR AnsiFileIndex[MU_MAX_INDEX_LENGTH], OemFileIndex[MU_MAX_INDEX_LENGTH], LangFileIndex[MU_MAX_INDEX_LENGTH];
    
    current = GlobalData->NsdLibrary;
    
    while (current)
    {
        if (RtlCompareMemory(&current->NlsParam, Parameter, sizeof(MU_NLS_PARAMETER)) == sizeof(MU_NLS_PARAMETER))
            break;
        
        previous = current;
        current  = current->Next;
    }
    
    if (!current)
    {
        current = (PMU_NLS_SOURCE_DESCRIPTOR)MuAlloc(sizeof(MU_NLS_SOURCE_DESCRIPTOR));
        
        if (current)
        {
            swprintf(AnsiFileIndex, MU_STRING_FORMAT_CODEPAGE,  Parameter->AnsiCodePage);
            swprintf(OemFileIndex,  MU_STRING_FORMAT_CODEPAGE,  Parameter->OemCodePage);
            swprintf(LangFileIndex, MU_STRING_FORMAT_LOCALE_ID, Parameter->LocaleId);
            
            if (NT_SUCCESS(MuLoadNlsTableIntoContiguousBuffer(AnsiFileIndex,
                                                              OemFileIndex,
                                                              LangFileIndex,
                                                              &current->CustomNlsSource)))
            {
                RtlCopyMemory(&current->NlsParam, Parameter, sizeof(MU_NLS_PARAMETER));
                
                current->Next = NULL;
                
                if (previous)
                    previous->Next = current;
                else
                    GlobalData->NsdLibrary = current;
            }
            else
            {
                MuFree(current);
                
                current = NULL;
            }
        }
    }
    
    MuReleaseNsdLibraryMutex();
    
    return current;
}

NTSTATUS
MuLoadNlsTableIntoContiguousBuffer (
    PCWSTR AnsiFileIndex,
    PCWSTR OemFileIndex,
    PCWSTR LangFileIndex,
    PMU_NLS_SOURCE NlsSource
)
{
    NTSTATUS status;
    HANDLE tabsec = NULL;
    LARGE_INTEGER secsize;
    SIZE_T viewsize = 0;
    ULONG tabsize, ansisize, oemsize, langsize;
    PVOID secview = NULL, secobj = NULL, ansibuf = NULL, oembuf = NULL, langbuf = NULL;
    WCHAR fn[MAX_PATH];
    
    status = MuQueryRegistryStringValue(MU_REGPATH_CODEPAGE,
                                        AnsiFileIndex,
                                        fn,
                                        MAX_PATH);
    
    if (!NT_SUCCESS(status))
        return status;
    
    status = MuReadFileInSystemFolder(fn,
                                      &ansibuf,
                                      &ansisize,
                                      0);
    
    if (!NT_SUCCESS(status))
        return status;
    
    status = MuQueryRegistryStringValue(MU_REGPATH_CODEPAGE,
                                        OemFileIndex,
                                        fn,
                                        MAX_PATH);
    
    if (!NT_SUCCESS(status))
        goto MuLoadNlsTableIntoContiguousBuffer_Failure;
    
    status = MuReadFileInSystemFolder(fn,
                                      &oembuf,
                                      &oemsize,
                                      0);
    
    if (!NT_SUCCESS(status))
        goto MuLoadNlsTableIntoContiguousBuffer_Failure;
    
    status = MuQueryRegistryStringValue(MU_REGPATH_LANGUAGE,
                                        LangFileIndex,
                                        fn,
                                        MAX_PATH);
    
    if (!NT_SUCCESS(status))
        goto MuLoadNlsTableIntoContiguousBuffer_Failure;
    
    status = MuReadFileInSystemFolder(fn,
                                      &langbuf,
                                      &langsize,
                                      0);
    
    if (!NT_SUCCESS(status))
        goto MuLoadNlsTableIntoContiguousBuffer_Failure;
        
    tabsize = ansisize + oemsize + langsize;
    
    secsize.HighPart = 0;
    secsize.LowPart  = tabsize;
    
    status = ZwCreateSection(&tabsec,
                             SECTION_ALL_ACCESS,
                             NULL,
                             &secsize,
                             PAGE_READWRITE,
                             SEC_COMMIT,
                             NULL);
                             
    if (!NT_SUCCESS(status))
        goto MuLoadNlsTableIntoContiguousBuffer_Failure;
        
    status = ObReferenceObjectByHandle(tabsec,
                                       SECTION_ALL_ACCESS,
                                       *MmSectionObjectType,
                                       KernelMode,
                                       &secobj,
                                       NULL);
    
    if (!NT_SUCCESS(status))
        goto MuLoadNlsTableIntoContiguousBuffer_Failure;
    
    status = MmMapViewInSystemSpace(secobj, &secview, &viewsize);
    
    if (!NT_SUCCESS(status))
        goto MuLoadNlsTableIntoContiguousBuffer_Failure;
    
    NlsSource->TableSection    = secobj;
    NlsSource->AnsiTableOffset = 0;
    NlsSource->OemTableOffset  = ansisize;
    NlsSource->LangTableOffset = ansisize + oemsize;
    
    RtlCopyMemory((PUCHAR)secview + NlsSource->AnsiTableOffset, ansibuf, ansisize);
    RtlCopyMemory((PUCHAR)secview + NlsSource->OemTableOffset, oembuf, oemsize);
    RtlCopyMemory((PUCHAR)secview + NlsSource->LangTableOffset, langbuf, langsize);
    
    MuFree(ansibuf);
    MuFree(oembuf);
    MuFree(langbuf);
    
    ZwClose(tabsec);
    
    MmUnmapViewInSystemSpace(secview);
    
    return STATUS_SUCCESS;
    
MuLoadNlsTableIntoContiguousBuffer_Failure:
    
    if (ansibuf)
        MuFree(ansibuf);
    
    if (oembuf)
        MuFree(oembuf);
    
    if (langbuf)
        MuFree(langbuf);
    
    if (tabsec)
        ZwClose(tabsec);
    
    if (secobj)
        ObDereferenceObject(secobj);
    
    return status;
}