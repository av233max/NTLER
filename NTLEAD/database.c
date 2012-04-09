#include <wchar.h>
#include <ntddk.h>

#include "ntlead.h"


extern GUID MuKnownDatabaseGuid;

extern PVOID *MmSectionObjectType;


#pragma alloc_text(PAGE, MuCreateOrOpenDatabase)
#pragma alloc_text(PAGE, MuBuildDatabaseMemoryMirror)
#pragma alloc_text(PAGE, MuAllocateDatasetObject)
#pragma alloc_text(PAGE, MuUpdateDataset)
#pragma alloc_text(PAGE, MuDeleteDataset)
#pragma alloc_text(PAGE, MuAcquireDatabaseMutex)
#pragma alloc_text(PAGE, MuReleaseDatabaseMutex)
#pragma alloc_text(PAGE, MuRemoveDatasetFromDatabase)
#pragma alloc_text(PAGE, MuAddDatasetToDatabase)
#pragma alloc_text(PAGE, MuGetFreeEntry)
#pragma alloc_text(PAGE, MuPopFreeEntry)
#pragma alloc_text(PAGE, MuRecoverFreeEntry)
#pragma alloc_text(PAGE, MuSetDatabaseState)
#pragma alloc_text(PAGE, MuLookupDatasetObjectFromEntryList)


NTSTATUS
MuCreateOrOpenDatabase (
    PCWSTR DatabaseName,
    GUID *DatabaseGuid,
    UCHAR MaxEntries,
    PMU_DATABASE_OBJECT *DatabaseObject,
    PBOOLEAN NewCreated
)
{
    NTSTATUS status;
    BOOLEAN lastchance = FALSE;
    HANDLE file = NULL, section;
    ULONG offset;
    PVOID secobj = NULL;
    PMU_DATABASE_HEADER secview = NULL;
    PMU_DATABASE_HEADER header = NULL;
    PMU_DATABASE_OBJECT dbobj = NULL;
    PMU_DATABASE_LOOKASIDE_LIST_IN_MEMORY prevla, curla;
    SIZE_T headersize, objsize, viewsize = 0;
    UNICODE_STRING fp;
    IO_STATUS_BLOCK iosb;
    OBJECT_ATTRIBUTES oa;
    FILE_STANDARD_INFORMATION fi;
    WCHAR path[MAX_PATH];
    
    *NewCreated = FALSE;
    
    wcscpy(path, MU_ROOTDIR_SYSTEM32);
    wcscat(path, DatabaseName);
    
    RtlInitUnicodeString(&fp, path);
    
    InitializeObjectAttributes(&oa,
                               &fp,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);
    
    status = ZwOpenFile(&file,
                        FILE_ALL_ACCESS,
                        &oa,
                        &iosb,
                        0,
                        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    
    if (!NT_SUCCESS(status))
        goto MuCreateOrOpenDatabase_Failure;
        
    status = ZwQueryInformationFile(file,
                                    &iosb,
                                    &fi,
                                    sizeof(fi),
                                    FileStandardInformation);
    
    if (!NT_SUCCESS(status))
        goto MuCreateOrOpenDatabase_Failure;
    
    status = STATUS_UNSUCCESSFUL;
    
    if (fi.EndOfFile.HighPart != 0)
        goto MuCreateOrOpenDatabase_Failure;
    
    if (fi.EndOfFile.LowPart >= MU_MIN_DATABASE_SIZE && fi.EndOfFile.LowPart <= MU_MAX_DATABASE_SIZE)
    {
        status = ZwCreateSection(&section,
                                 SECTION_ALL_ACCESS,
                                 NULL,
                                 NULL,
                                 PAGE_READONLY,
                                 SEC_COMMIT,
                                 file);
        
        if (!NT_SUCCESS(status))
            goto MuCreateOrOpenDatabase_Failure;
        
        status = ObReferenceObjectByHandle(section,
                                           SECTION_ALL_ACCESS,
                                           *MmSectionObjectType,
                                           KernelMode,
                                           &secobj,
                                           NULL);
        
        ZwClose(section);
        
        if (!NT_SUCCESS(status))
            goto MuCreateOrOpenDatabase_Failure;
            
        status = MmMapViewInSystemSpace(secobj, &secview, &viewsize);
        
        if (!NT_SUCCESS(status))
            goto MuCreateOrOpenDatabase_Failure;
        
        status = STATUS_UNSUCCESSFUL;
        
        __try
        {
            if (RtlCompareMemory(&secview->KnownGuid, &MuKnownDatabaseGuid, sizeof(GUID) != sizeof(GUID)))
                __leave;
            
            if (secview->Version != MU_DATABASE_VERSION)
            
                __leave;
            
            if (RtlCompareMemory(&secview->PrivateGuid, DatabaseGuid, sizeof(GUID) != sizeof(GUID)))
                __leave;
            
            if (secview->State & STATE_WRITE_PENDING)
                __leave;
            
            headersize = ((secview->EntryCount - 1) * sizeof(MU_DATABASE_ENTRY_CATALOG)) + MU_MIN_DATABASE_SIZE;
            
            if (headersize > fi.EndOfFile.LowPart)
                __leave;
                
            if (secview->EntryCount != MaxEntries)
                __leave;
                
            status = STATUS_SUCCESS;
        }
        __except (1)
        {
            status = GetExceptionCode();
        }
        
        if (!NT_SUCCESS(status))
            goto MuCreateOrOpenDatabase_Failure;
        
        objsize = sizeof(MU_DATABASE_OBJECT) + ((MaxEntries - 1) * sizeof(PVOID));
        
        dbobj = (PMU_DATABASE_OBJECT)MuAlloc(objsize);
        
        if (!dbobj)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            
            goto MuCreateOrOpenDatabase_Failure;
        }
        
        RtlZeroMemory(dbobj, objsize);
        
        dbobj->FileSize = fi.EndOfFile.LowPart;
        
        status = STATUS_UNSUCCESSFUL;
        
        __try
        {
            offset = MU_DATABASE_ALIGN(secview->Lookaside.FirstEntryOffset);
            
            if (offset)
            {
                prevla = NULL;
                
                while (offset)
                {
                    if (offset + sizeof(MU_DATABASE_LOOKASIDE_LIST) > dbobj->FileSize)
                        __leave;
                    
                    dbobj->BytesAllocated += sizeof(MU_DATABASE_LOOKASIDE_LIST_IN_MEMORY);
                    
                    if (dbobj->BytesAllocated > MU_MAX_LIST_ENTRY_SIZE)
                        __leave;
                    
                    curla = (PMU_DATABASE_LOOKASIDE_LIST_IN_MEMORY)MuPagedAlloc(sizeof(MU_DATABASE_LOOKASIDE_LIST_IN_MEMORY));
                    
                    if (!curla)
                    {
                        status = STATUS_INSUFFICIENT_RESOURCES;
                        
                        __leave;
                    }
                    
                    curla->Next               = NULL;
                    curla->CurrentChunkOffset = offset;
                    curla->NextChunkOffset    = ((PMU_DATABASE_LOOKASIDE_LIST)((ULONG)secview + offset))->NextChunkOffset;
                    curla->ChunkSize          = ((PMU_DATABASE_LOOKASIDE_LIST)((ULONG)secview + offset))->ChunkSize;
                    
                    if (prevla)
                        prevla->Next = curla;
                    else
                        dbobj->LookasideList = curla;
                    
                    prevla = curla;
                    
                    offset = curla->NextChunkOffset;
                }
            }
            
            status = STATUS_SUCCESS;
        }
        __except (1)
        {
            status = GetExceptionCode();
        }
        
        if (!NT_SUCCESS(status))
            goto MuCreateOrOpenDatabase_Failure;
        
        status = MuBuildDatabaseMemoryMirror(dbobj, (PMU_DATABASE_HEADER)secview);
        
        MmUnmapViewInSystemSpace(secview);
        
        if (NT_SUCCESS(status))
            goto MuCreateOrOpenDatabase_FillInformation;
    }
    
MuCreateOrOpenDatabase_Failure:

    if (header)
    {
        MuFree(header);
        
        header = NULL;
    }
    
    if (dbobj)
    {
        curla = dbobj->LookasideList;
        
        if (curla)
        {
            while (curla)
            {
                prevla = curla;
                curla = curla->Next;
                
                MuFree(prevla);
            }
        }
        
        MuFree(dbobj);
        
        dbobj = NULL;
    }
    
    if (secview)
    {
        MmUnmapViewInSystemSpace(secview);
        
        secview = NULL;
    }
    
    if (secobj)
    {
        ObDereferenceObject(secobj);
        
        secobj = NULL;
    }
    
    if (file)
    {
        ZwClose(file);
        
        file = NULL;
    }
    
    if (lastchance)
        return status;
    
    lastchance = TRUE;
    
    status = ZwCreateFile(&file,
                          FILE_ALL_ACCESS,
                          &oa,
                          &iosb,
                          NULL,
                          FILE_ATTRIBUTE_NORMAL,
                          0,
                          FILE_SUPERSEDE,
                          FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                          NULL,
                          0);
    
    if (!NT_SUCCESS(status))
        goto MuCreateOrOpenDatabase_Failure;
    
    objsize = sizeof(MU_DATABASE_OBJECT) + ((MaxEntries - 1) * sizeof(PVOID));
    
    dbobj = (PMU_DATABASE_OBJECT)MuAlloc(objsize);
    
    if (!dbobj)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        
        goto MuCreateOrOpenDatabase_Failure;
    }
    
    RtlZeroMemory(dbobj, objsize);
    
    headersize = ((MaxEntries - 1) * sizeof(MU_DATABASE_ENTRY_CATALOG)) + MU_MIN_DATABASE_SIZE;
    
    header = (PMU_DATABASE_HEADER)MuPagedAlloc(headersize);
    
    if (!header)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        
        goto MuCreateOrOpenDatabase_Failure;
    }
    
    RtlZeroMemory(header, headersize);
    
    RtlCopyMemory(&header->KnownGuid, &MuKnownDatabaseGuid, sizeof(GUID));
    RtlCopyMemory(&header->PrivateGuid, DatabaseGuid, sizeof(GUID));
    
    header->Version    = MU_DATABASE_VERSION;
    header->EntryCount = MaxEntries;
    
    status = MuSyncWriteFile(file,
                             header,
                             headersize,
                             0);
    
    if (!NT_SUCCESS(status))
        goto MuCreateOrOpenDatabase_Failure;
    
    dbobj->FileSize = headersize;
    
    MuFree(header);
    
    *NewCreated = TRUE;
    
MuCreateOrOpenDatabase_FillInformation:

    dbobj->FileHandle  = file;
    dbobj->EntryCount  = MaxEntries;
    
    KeInitializeMutex(&dbobj->AccessMutex, 0);
    
    *DatabaseObject = dbobj;
    
    return status;
}

NTSTATUS
MuBuildDatabaseMemoryMirror (
    PMU_DATABASE_OBJECT DatabaseObject,
    PMU_DATABASE_HEADER DatabaseHeader
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG offset;
    PMU_DATABASE_DATASET_INFO_IN_MEMORY prevset, curset;
    USHORT chunksize, datasize;
    UCHAR i;
    
    __try
    {
        for (i = 0 ; i < DatabaseHeader->EntryCount ; i++)
        {
            offset = MU_DATABASE_ALIGN(DatabaseHeader->Entries[i].FirstEntryOffset);
            
            prevset = NULL;
            
            while (offset)
            {
                if (offset + sizeof(MU_DATABASE_DATASET_INFO) > DatabaseObject->FileSize)
                    __leave;
                
                chunksize = ((PMU_DATABASE_DATASET_INFO)((ULONG)DatabaseHeader + offset))->ChunkSize;
                
                if (offset + sizeof(MU_DATABASE_LOOKASIDE_LIST) + chunksize > DatabaseObject->FileSize)
                    __leave;
                    
                datasize = ((PMU_DATABASE_DATASET_INFO)((ULONG)DatabaseHeader + offset))->DataSize;
                
                if (datasize > chunksize)
                    __leave;
                
                DatabaseObject->BytesAllocated += datasize + sizeof(MU_DATABASE_LOOKASIDE_LIST_IN_MEMORY);
                
                if (DatabaseObject->BytesAllocated > MU_MAX_LIST_ENTRY_SIZE)
                    __leave;
                    
                curset = (PMU_DATABASE_DATASET_INFO_IN_MEMORY)MuPagedAlloc(datasize + sizeof(MU_DATABASE_LOOKASIDE_LIST_IN_MEMORY));
                
                if (!curset)
                {
                    status = STATUS_INSUFFICIENT_RESOURCES;
                    
                    __leave;
                }
                
                curset->Next               = NULL;
                curset->CurrentChunkOffset = offset;
                curset->NextChunkOffset    = ((PMU_DATABASE_DATASET_INFO)((ULONG)DatabaseHeader + offset))->NextChunkOffset;
                curset->ChunkSize          = chunksize;
                curset->DataSize           = datasize;
                
                RtlCopyMemory(&curset->Data[0], &((PMU_DATABASE_DATASET_INFO)((ULONG)DatabaseHeader + offset))->Data[0], datasize);
                
                if (prevset)
                    prevset->Next = curset;
                else
                    DatabaseObject->EntryList[i] = curset;
                
                prevset = curset;
                
                offset = curset->NextChunkOffset;
            }
        }
        
        status = STATUS_SUCCESS;
    }
    __except (1)
    {
        status = GetExceptionCode();
    }
    
    return status;
}

NTSTATUS
MuAllocateDatasetObject (
    USHORT DataSize,
    PMU_DATABASE_DATASET_INFO_IN_MEMORY *DatasetObject
)
{
    if (DataSize == 0 || DataSize > MU_MAX_DATASET_SIZE)
        return STATUS_INVALID_PARAMETER;
    
    *DatasetObject = (PMU_DATABASE_DATASET_INFO_IN_MEMORY)MuPagedAlloc(sizeof(MU_DATABASE_LOOKASIDE_LIST_IN_MEMORY) + MU_DATABASE_CARRY_ALIGN(DataSize));
    
    if (!*DatasetObject)
        return STATUS_INSUFFICIENT_RESOURCES;
    
    (*DatasetObject)->Next               = NULL;
    (*DatasetObject)->CurrentChunkOffset = 0;
    (*DatasetObject)->NextChunkOffset    = 0;
    (*DatasetObject)->DataSize           = 0;
    
    return STATUS_SUCCESS;
}

NTSTATUS
MuUpdateDataset (
    PMU_DATABASE_OBJECT DatabaseObject,
    UCHAR EntryIndex,
    PMU_DATABASE_DATASET_INFO_IN_MEMORY DatasetObject,
    USHORT DataSize
)
{
    NTSTATUS status;
    
    if (DataSize > MU_MAX_DATASET_SIZE || EntryIndex >= DatabaseObject->EntryCount)
        return STATUS_INVALID_PARAMETER;
    
    MuAcquireDatabaseMutex(DatabaseObject);
    
    if (DatasetObject->CurrentChunkOffset)
    {
        if (DataSize != DatasetObject->DataSize)
        {
            status = MuRemoveDatasetFromDatabase(DatabaseObject, EntryIndex, DatasetObject);
            
            if (NT_SUCCESS(status))
            {
                DatasetObject->DataSize = DataSize;
                
                status = MuAddDatasetToDatabase(DatabaseObject, EntryIndex, DatasetObject);
            }
        }
        else
        {
            status = MuUpdateDatasetToDatabase(DatabaseObject, EntryIndex, DatasetObject);
        }
    }
    else
    {
        DatasetObject->DataSize = DataSize;
        
        status = MuAddDatasetToDatabase(DatabaseObject, EntryIndex, DatasetObject);
    }
    
    MuReleaseDatabaseMutex(DatabaseObject);
    
    return status;
}

NTSTATUS
MuDeleteDataset (
    PMU_DATABASE_OBJECT DatabaseObject,
    UCHAR EntryIndex,
    PMU_DATABASE_DATASET_INFO_IN_MEMORY DatasetObject
)
{
    NTSTATUS status = STATUS_SUCCESS;
    
    if (EntryIndex >= DatabaseObject->EntryCount)
        return STATUS_INVALID_PARAMETER;
    
    MuAcquireDatabaseMutex(DatabaseObject);
    
    if (DatasetObject->CurrentChunkOffset)
        status = MuRemoveDatasetFromDatabase(DatabaseObject, EntryIndex, DatasetObject);
    
    if (NT_SUCCESS(status))
        MuFree(DatasetObject);
    
    MuReleaseDatabaseMutex(DatabaseObject);
    
    return status;
}

NTSTATUS
MuUpdateDatasetToDatabase (
    PMU_DATABASE_OBJECT DatabaseObject,
    UCHAR EntryIndex,
    PMU_DATABASE_DATASET_INFO_IN_MEMORY DatasetObject
)
{
    NTSTATUS status = MuSetDatabaseState(DatabaseObject, STATE_WRITE_PENDING);
    
    if (!NT_SUCCESS(status))
        return status;
        
    status = MuSyncWriteFile(DatabaseObject->FileHandle,
                             &DatasetObject->Data[0],
                             DatasetObject->DataSize,
                             DatasetObject->CurrentChunkOffset + OFFSET_OF(MU_DATABASE_DATASET_INFO, Data[0]));
    
    if (!NT_SUCCESS(status))
        return status;
    
    return MuSetDatabaseState(DatabaseObject, STATE_UNLOCKED);
}

NTSTATUS
MuRemoveDatasetFromDatabase (
    PMU_DATABASE_OBJECT DatabaseObject,
    UCHAR EntryIndex,
    PMU_DATABASE_DATASET_INFO_IN_MEMORY DatasetObject
)
{
    NTSTATUS status;
    PMU_DATABASE_DATASET_INFO_IN_MEMORY prevset;
    
    if (!MuLookupDatasetObjectFromEntryList(DatabaseObject, EntryIndex, DatasetObject, &prevset))
        return STATUS_INVALID_PARAMETER;
    
    status = MuSetDatabaseState(DatabaseObject, STATE_WRITE_PENDING);
    
    if (!NT_SUCCESS(status))
        return status;
        
    if (prevset)
    {
        prevset->Next            = DatasetObject->Next;
        prevset->NextChunkOffset = DatasetObject->NextChunkOffset;
        
        status = MuSyncWriteFile(DatabaseObject->FileHandle,
                                 &DatasetObject->NextChunkOffset,
                                 sizeof(ULONG),
                                 prevset->CurrentChunkOffset + OFFSET_OF(MU_DATABASE_DATASET_INFO, NextChunkOffset));
    }
    else
    {
        DatabaseObject->EntryList[EntryIndex] = DatasetObject->Next;
        
        status = MuSyncWriteFile(DatabaseObject->FileHandle,
                                 &DatasetObject->NextChunkOffset,
                                 sizeof(ULONG),
                                 OFFSET_OF(MU_DATABASE_HEADER, Entries[EntryIndex]));
    }
    
    if (!NT_SUCCESS(status))
        return status;
    
    DatasetObject->Next               = NULL;
    DatasetObject->NextChunkOffset    = 0;
    
    status = MuSyncWriteFile(DatabaseObject->FileHandle,
                             &DatasetObject->NextChunkOffset,
                             sizeof(ULONG),
                             DatasetObject->CurrentChunkOffset + OFFSET_OF(MU_DATABASE_DATASET_INFO, NextChunkOffset));
    
    if (!NT_SUCCESS(status))
        return status;
    
    status = MuRecoverFreeEntry(DatabaseObject, DatasetObject->CurrentChunkOffset, DatasetObject->ChunkSize);
    
    DatasetObject->CurrentChunkOffset = 0;
    
    if (!NT_SUCCESS(status))
        return status;
    
    DatabaseObject->BytesAllocated -= MU_DATABASE_CARRY_ALIGN(DatasetObject->DataSize) + sizeof(MU_DATABASE_LOOKASIDE_LIST_IN_MEMORY);
    
    return MuSetDatabaseState(DatabaseObject, STATE_UNLOCKED);
}

NTSTATUS
MuAddDatasetToDatabase (
    PMU_DATABASE_OBJECT DatabaseObject,
    UCHAR EntryIndex,
    PMU_DATABASE_DATASET_INFO_IN_MEMORY DatasetObject
)
{
    NTSTATUS status;
    PMU_DATABASE_LOOKASIDE_LIST_IN_MEMORY prevla, curla;
    PMU_DATABASE_DATASET_INFO_IN_MEMORY curset;
    
    DatabaseObject->BytesAllocated += MU_DATABASE_CARRY_ALIGN(DatasetObject->DataSize) + sizeof(MU_DATABASE_LOOKASIDE_LIST_IN_MEMORY);
    
    if (DatabaseObject->BytesAllocated > MU_MAX_LIST_ENTRY_SIZE)
        return STATUS_UNSUCCESSFUL;
    
    status = MuSetDatabaseState(DatabaseObject, STATE_WRITE_PENDING);
    
    if (!NT_SUCCESS(status))
        return status;
    
    curla = MuGetFreeEntry(DatabaseObject, DatasetObject->DataSize, &prevla);
    
    if (curla)
    {
        DatasetObject->CurrentChunkOffset = curla->CurrentChunkOffset;
        DatasetObject->ChunkSize          = curla->ChunkSize;
        
        status = MuPopFreeEntry(DatabaseObject, curla, prevla);
        
        if (!NT_SUCCESS(status))
            return status;
    }
    else
    {
        DatasetObject->CurrentChunkOffset = DatabaseObject->FileSize;
        DatasetObject->ChunkSize          = MU_DATABASE_CARRY_ALIGN(DatasetObject->DataSize);
    }
    
    status = MuSyncWriteFile(DatabaseObject->FileHandle,
                             &DatasetObject->NextChunkOffset,
                             MU_DATABASE_CARRY_ALIGN(DatasetObject->DataSize) + sizeof(MU_DATABASE_LOOKASIDE_LIST),
                             DatasetObject->CurrentChunkOffset);
    
    if (!NT_SUCCESS(status))
        return status;
    
    if (!curla)
        DatabaseObject->FileSize += DatasetObject->ChunkSize + sizeof(MU_DATABASE_LOOKASIDE_LIST);
    
    curset = DatabaseObject->EntryList[EntryIndex];
    
    if (curset)
    {
        while (curset->Next)
            curset = curset->Next;
        
        curset->Next            = DatasetObject;
        curset->NextChunkOffset = DatasetObject->CurrentChunkOffset;
        
        status = MuSyncWriteFile(DatabaseObject->FileHandle,
                                 &curset->NextChunkOffset,
                                 sizeof(ULONG),
                                 curset->CurrentChunkOffset + OFFSET_OF(MU_DATABASE_DATASET_INFO, NextChunkOffset));
    }
    else
    {
        DatabaseObject->EntryList[EntryIndex] = DatasetObject;
        
        status = MuSyncWriteFile(DatabaseObject->FileHandle,
                                 &DatasetObject->CurrentChunkOffset,
                                 sizeof(ULONG),
                                 OFFSET_OF(MU_DATABASE_HEADER, Entries[EntryIndex]));
    }
    
    if (!NT_SUCCESS(status))
        return status;
    
    return MuSetDatabaseState(DatabaseObject, STATE_UNLOCKED);
}

NTSTATUS
MuRecoverFreeEntry (
    PMU_DATABASE_OBJECT DatabaseObject,
    ULONG ChunkOffset,
    USHORT ChunkSize
)
{
    NTSTATUS status;
    PMU_DATABASE_LOOKASIDE_LIST_IN_MEMORY lanode, lookaside;
    
    ASSERT(ChunkOffset < DatabaseObject->FileSize);
    
    DatabaseObject->BytesAllocated += sizeof(MU_DATABASE_LOOKASIDE_LIST_IN_MEMORY);
    
    if (DatabaseObject->BytesAllocated > MU_MAX_LIST_ENTRY_SIZE)
        return STATUS_UNSUCCESSFUL;
    
    lookaside = (PMU_DATABASE_LOOKASIDE_LIST_IN_MEMORY)MuPagedAlloc(sizeof(MU_DATABASE_LOOKASIDE_LIST_IN_MEMORY));
    
    if (!lookaside)
        return STATUS_INSUFFICIENT_RESOURCES;
    
    lookaside->Next               = NULL;
    lookaside->CurrentChunkOffset = ChunkOffset;
    lookaside->NextChunkOffset    = 0;
    lookaside->ChunkSize          = ChunkSize;
    
    lanode = DatabaseObject->LookasideList;
    
    if (lanode)
    {
        while (lanode->Next)
            lanode = lanode->Next;
            
        lanode->Next = lookaside;
        
        status = MuSyncWriteFile(DatabaseObject->FileHandle,
                                 &ChunkOffset,
                                 sizeof(ULONG),
                                 lanode->CurrentChunkOffset + OFFSET_OF(MU_DATABASE_LOOKASIDE_LIST, NextChunkOffset));
    }
    else
    {
        DatabaseObject->LookasideList = lookaside;
        
        status = MuSyncWriteFile(DatabaseObject->FileHandle,
                                 &ChunkOffset,
                                 sizeof(ULONG),
                                 OFFSET_OF(MU_DATABASE_HEADER, Lookaside));
    }
    
    return status;
}

PMU_DATABASE_LOOKASIDE_LIST_IN_MEMORY
MuGetFreeEntry (
    PMU_DATABASE_OBJECT DatabaseObject,
    USHORT RequiredSize,
    PMU_DATABASE_LOOKASIDE_LIST_IN_MEMORY *PreviousPointer
)
{
    PMU_DATABASE_LOOKASIDE_LIST_IN_MEMORY prev = NULL, cur, choosen = NULL;
    USHORT bestfitsize = 0xFFFF;
    
    cur = DatabaseObject->LookasideList;
    
    while (cur)
    {
        if (cur->ChunkSize >= RequiredSize)
        {
            if (cur->ChunkSize < bestfitsize)
            {
                bestfitsize = cur->ChunkSize;
                
                *PreviousPointer = prev;
                
                choosen = cur;
            }
        }
        
        prev = cur;
        cur  = cur->Next;
    }
    
    return choosen;
}

NTSTATUS
MuPopFreeEntry (
    PMU_DATABASE_OBJECT DatabaseObject,
    PMU_DATABASE_LOOKASIDE_LIST_IN_MEMORY LookasideObject,
    PMU_DATABASE_LOOKASIDE_LIST_IN_MEMORY PreviousPointer
)
{
    NTSTATUS status;
    
    if (PreviousPointer)
    {
        PreviousPointer->Next            = LookasideObject->Next;
        PreviousPointer->NextChunkOffset = LookasideObject->NextChunkOffset;
        
        status = MuSyncWriteFile(DatabaseObject->FileHandle,
                                 &LookasideObject->NextChunkOffset,
                                 sizeof(ULONG),
                                 PreviousPointer->CurrentChunkOffset + OFFSET_OF(MU_DATABASE_LOOKASIDE_LIST, NextChunkOffset));
    }
    else
    {
        DatabaseObject->LookasideList = LookasideObject->Next;
        
        status = MuSyncWriteFile(DatabaseObject->FileHandle,
                                 &LookasideObject->NextChunkOffset,
                                 sizeof(ULONG),
                                 OFFSET_OF(MU_DATABASE_HEADER, Lookaside.FirstEntryOffset));
    }
    
    DatabaseObject->BytesAllocated -= sizeof(MU_DATABASE_LOOKASIDE_LIST_IN_MEMORY);
    
    MuFree(LookasideObject);
    
    return status;
}

BOOLEAN
MuLookupDatasetObjectFromEntryList (
    PMU_DATABASE_OBJECT DatabaseObject,
    UCHAR EntryIndex,
    PMU_DATABASE_DATASET_INFO_IN_MEMORY DatasetObject,
    PMU_DATABASE_DATASET_INFO_IN_MEMORY *PreviousPointer
)
{
    PMU_DATABASE_DATASET_INFO_IN_MEMORY prev = NULL, cur;
    
    ASSERT(EntryIndex < DatabaseObject->EntryCount);
    
    cur = DatabaseObject->EntryList[EntryIndex];
    
    while (cur)
    {
        if (cur == DatasetObject)
        {
            *PreviousPointer = prev;
            
            return TRUE;
        }
        
        prev = cur;
        cur  = cur->Next;
    }
    
    return FALSE;
}

NTSTATUS
MuSetDatabaseState (
    PMU_DATABASE_OBJECT DatabaseObject,
    UCHAR State
)
{
    return MuSyncWriteFile(DatabaseObject->FileHandle,
                           &State,
                           sizeof(UCHAR),
                           OFFSET_OF(MU_DATABASE_HEADER, State));
}

void
MuAcquireDatabaseMutex (
    PMU_DATABASE_OBJECT DatabaseObject
)
{
    KeWaitForMutexObject(&DatabaseObject->AccessMutex,
                         Executive,
                         KernelMode,
                         FALSE,
                         NULL);
}

void
MuReleaseDatabaseMutex (
    PMU_DATABASE_OBJECT DatabaseObject
)
{
    KeReleaseMutex(&DatabaseObject->AccessMutex, FALSE);
}

NTSTATUS
MuEnumDataset (
    PMU_DATABASE_OBJECT DatabaseObject,
    UCHAR EntryIndex,
    MU_DATABASE_ENUM_DATASET_PROC Callback,
    PVOID CallerContext
)
{
    NTSTATUS status = STATUS_NOT_FOUND;
    PMU_DATABASE_DATASET_INFO_IN_MEMORY dataset;
    
    if (EntryIndex >= DatabaseObject->EntryCount)
        return STATUS_INVALID_PARAMETER;
    
    MuAcquireDatabaseMutex(DatabaseObject);
    
    dataset = DatabaseObject->EntryList[EntryIndex];
    
    while (dataset)
    {
        if (Callback(dataset, CallerContext, &status))
            break;
        
        dataset = dataset->Next;
    }
    
    MuReleaseDatabaseMutex(DatabaseObject);
    
    return status;
}