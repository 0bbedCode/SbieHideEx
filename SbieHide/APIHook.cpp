#include "APIHook.h"
#include "MemoryImageHideInformation.h"
#include <windows.h>
#include <stdio.h>

#ifdef _DEBUG
#ifdef _WIN64
#pragma comment(lib, "libMinHook.x64.mtd.lib")
#else
#pragma comment(lib, "libMinHook.x86.mtd.lib")
#endif
#else
#ifdef _WIN64
#pragma comment(lib, "libMinHook.x64.mt.lib")
#else
#pragma comment(lib, "libMinHook.x86.mt.lib")
#endif
#endif

typedef NTSTATUS(NTAPI* NtQueryVirtualMemoryType)(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress, _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass, _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation, _In_ SIZE_T MemoryInformationLength, _Out_opt_ PSIZE_T ReturnLength);
NtQueryVirtualMemoryType NtQueryVirtualMemorySaved = nullptr;

typedef NTSTATUS(NTAPI* NtQueryObjectType)(_In_opt_ HANDLE Handle, _In_ OBJECT_INFORMATION_CLASS ObjectInformationClass, _Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation, _In_ ULONG ObjectInformationLength, _Out_opt_ PULONG ReturnLength);
NtQueryObjectType NtQueryObjectSaved = nullptr;

typedef NTSTATUS(NTAPI* NtQueryInformationFileType)(_In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _Out_writes_bytes_(Length) PVOID FileInformation, _In_ ULONG Length, _In_ FILE_INFORMATION_CLASS FileInformationClass);
NtQueryInformationFileType NtQueryInformationFileSaved = nullptr;

typedef NTSTATUS(NTAPI* NtQuerySectionType)(_In_ HANDLE SectionHandle, _In_ SECTION_INFORMATION_CLASS SectionInformationClass, _Out_writes_bytes_(SectionInformationLength) PVOID SectionInformation, _In_ SIZE_T SectionInformationLength, _Out_opt_ PSIZE_T ReturnLength);
NtQuerySectionType NtQuerySectionSaved = nullptr;

typedef NTSTATUS(NTAPI* NtCreateMutantType)(
    _Out_ PHANDLE MutantHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ BOOLEAN InitialOwner
    );
NtCreateMutantType NtCreateMutantSaved = nullptr;

typedef NTSTATUS(NTAPI* NtOpenMutantType)(
    _Out_ PHANDLE MutantHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    );
NtOpenMutantType NtOpenMutantSaved = nullptr;


NTSTATUS NTAPI NtQueryVirtualMemoryProxy(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress, _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass, _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation, _In_ SIZE_T MemoryInformationLength, _Out_opt_ PSIZE_T ReturnLength) {
    if (IsAddressShouldHide(BaseAddress)) {
        switch (MemoryInformationClass) {
        case MemoryBasicInformation:
        case MemoryMappedFilenameInformation:
        case MemoryRegionInformation:
        case MemoryImageInformation:
        case MemoryRegionInformationEx:
        case MemoryEnclaveImageInformation:
        case MemoryBasicInformationCapped:
            return STATUS_ACCESS_DENIED;
        default:
            break;
        }
    }

    return NtQueryVirtualMemorySaved(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
}

NTSTATUS NTAPI NtQueryObjectProxy(_In_opt_ HANDLE Handle, _In_ OBJECT_INFORMATION_CLASS ObjectInformationClass, _Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation, _In_ ULONG ObjectInformationLength, _Out_opt_ PULONG ReturnLength) {
    NTSTATUS Status = STATUS_SUCCESS;

    Status = NtQueryObjectSaved(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);

    if (NT_SUCCESS(Status) && ObjectInformationClass == ObjectNameInformation && ObjectInformation != nullptr) {
        UNICODE_STRING ObjectName = {};

        if (!NT_SUCCESS(RtlUpcaseUnicodeString(&ObjectName, &reinterpret_cast<POBJECT_NAME_INFORMATION>(ObjectInformation)->Name, TRUE))) {
            return Status;
        }

        if (ObjectName.Buffer == NULL || ObjectName.Length == 0) {
            RtlFreeUnicodeString(&ObjectName);
            return Status;
        }

        if (ObjectName.Length < 7) {
            RtlFreeUnicodeString(&ObjectName);
            return Status;
        }

        if ((wcsstr(ObjectName.Buffer, L"SBIEDLL") != 0) || (wcsstr(ObjectName.Buffer, L"SBIEHIDE") != 0)) {
            RtlZeroMemory(reinterpret_cast<POBJECT_NAME_INFORMATION>(ObjectInformation)->Name.Buffer, reinterpret_cast<POBJECT_NAME_INFORMATION>(ObjectInformation)->Name.MaximumLength);
            reinterpret_cast<POBJECT_NAME_INFORMATION>(ObjectInformation)->Name.Length = 0;
            RtlFreeUnicodeString(&ObjectName);
            return STATUS_ACCESS_DENIED;
        }

        RtlFreeUnicodeString(&ObjectName);
    }

    return Status;
}

NTSTATUS NTAPI NtQueryInformationFileProxy(_In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _Out_writes_bytes_(Length) PVOID FileInformation, _In_ ULONG Length, _In_ FILE_INFORMATION_CLASS FileInformationClass) {
    NTSTATUS               Status = STATUS_SUCCESS;
    UNICODE_STRING         FileName = {};
    UNICODE_STRING         UpperFileName = {};
    PFILE_ALL_INFORMATION  AllInformation = {};
    PFILE_NAME_INFORMATION NameInformation = {};

    Status = NtQueryInformationFileSaved(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);

    if (NT_SUCCESS(Status) && FileInformation != nullptr) {
        switch (FileInformationClass) {
        case FileNameInformation:
            NameInformation = reinterpret_cast<PFILE_NAME_INFORMATION>(FileInformation);

            FileName.Buffer = NameInformation->FileName;
            FileName.Length = static_cast<USHORT>(NameInformation->FileNameLength);
            FileName.MaximumLength = static_cast<USHORT>(NameInformation->FileNameLength);

            if (!NT_SUCCESS(RtlUpcaseUnicodeString(&UpperFileName, &FileName, TRUE))) {
                return Status;
            }

            if (UpperFileName.Buffer == NULL || UpperFileName.Length == 0) {
                RtlFreeUnicodeString(&UpperFileName);
                return Status;
            }

            if (UpperFileName.Length < 7) {
                RtlFreeUnicodeString(&UpperFileName);
                return Status;
            }

            if ((wcsstr(UpperFileName.Buffer, L"SBIEDLL") != 0) || (wcsstr(UpperFileName.Buffer, L"SBIEHIDE") != 0)) {
                RtlZeroMemory(FileInformation, Length);
                RtlFreeUnicodeString(&UpperFileName);
                return STATUS_ACCESS_DENIED;
            }

            RtlFreeUnicodeString(&UpperFileName);

            return Status;

        case FileAllInformation:
            AllInformation = reinterpret_cast<PFILE_ALL_INFORMATION>(FileInformation);
            NameInformation = &AllInformation->NameInformation;

            FileName.Buffer = NameInformation->FileName;
            FileName.Length = static_cast<USHORT>(NameInformation->FileNameLength);
            FileName.MaximumLength = static_cast<USHORT>(NameInformation->FileNameLength);

            if (!NT_SUCCESS(RtlUpcaseUnicodeString(&UpperFileName, &FileName, TRUE))) {
                return Status;
            }

            if (UpperFileName.Buffer == NULL || UpperFileName.Length == 0) {
                RtlFreeUnicodeString(&UpperFileName);
                return Status;
            }

            if (UpperFileName.Length < 7) {
                RtlFreeUnicodeString(&UpperFileName);
                return Status;
            }

            if ((wcsstr(UpperFileName.Buffer, L"SBIEDLL") != 0) || (wcsstr(UpperFileName.Buffer, L"SBIEHIDE") != 0)) {
                RtlZeroMemory(FileInformation, Length);
                RtlFreeUnicodeString(&UpperFileName);
                return STATUS_ACCESS_DENIED;
            }

            RtlFreeUnicodeString(&UpperFileName);

            return Status;

        default:
            break;
        }
    }

    return Status;
}

NTSTATUS NTAPI NtQuerySectionProxy(_In_ HANDLE SectionHandle, _In_ SECTION_INFORMATION_CLASS SectionInformationClass, _Out_writes_bytes_(SectionInformationLength) PVOID SectionInformation, _In_ SIZE_T SectionInformationLength, _Out_opt_ PSIZE_T ReturnLength) {
    NTSTATUS Status = STATUS_SUCCESS;

    Status = NtQuerySectionSaved(SectionHandle, SectionInformationClass, SectionInformation, SectionInformationLength, ReturnLength);

    if (NT_SUCCESS(Status) && SectionInformation != nullptr && SectionInformationClass == SectionOriginalBaseInformation) {
        if (IsAddressShouldHide(*reinterpret_cast<PULONG_PTR>(SectionInformation))) {
            ZeroMemory(SectionInformation, SectionInformationLength);
            return STATUS_ACCESS_DENIED;
        }
    }

    return Status;
}

NTSTATUS NTAPI NtCreateMutantProxy(_Out_ PHANDLE MutantHandle, _In_ ACCESS_MASK DesiredAccess, _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes, _In_ BOOLEAN InitialOwner) {
    //printf("Entry of [NtCreateMutantProxy]...\n");
    NTSTATUS status = NtCreateMutantSaved(MutantHandle, DesiredAccess, ObjectAttributes, InitialOwner);
    if (ObjectAttributes != nullptr && ObjectAttributes->ObjectName != nullptr) {
        UNICODE_STRING* objectName = ObjectAttributes->ObjectName;
        //wprintf(L"MUTEX: %.*ls\n", objectName->Length / sizeof(WCHAR), objectName->Buffer);
        //printf("The DWORD Access is: %lu\n", DesiredAccess);
        //0x40000000 = 1073741824
        //STATUS_OBJECT_NAME_EXISTS
        //
        //Return 0 if not found or is all good
        if (wcsstr(objectName->Buffer, L"Sandboxie_SingleInstanceMutex_Control") != 0 ||
            wcsstr(objectName->Buffer, L"SBIE_BOXED_ServiceInitComplete_Mutex1") != 0) {
            if (status == STATUS_OBJECT_NAME_EXISTS) {
                status = NtOpenMutantSaved(MutantHandle, DesiredAccess, ObjectAttributes);
            }
        }
    }
    return status;
}


NTSTATUS NTAPI NtOpenMutantProxy(_Out_ PHANDLE MutantHandle, _In_ ACCESS_MASK DesiredAccess, _In_ POBJECT_ATTRIBUTES ObjectAttributes) {
    //times++;
    //printf("The DWORD [NtOpenMutantProxy] times: %lu\n", times);
    //ERROR_FILE_NOT_FOUND = (2) 0x2, this will return (2) if not found
    //Thats Kernel32:OpenMutext for NT version should return "STATUS_OBJECT_NAME_NOT_FOUND"

    //If injects
    //SbieSvc.exe
    //SandboxieRpcSs.exe
    //It will throw an error as blocking it from Sandboxie isnt a wise idea
    if (ObjectAttributes != nullptr && ObjectAttributes->ObjectName != nullptr) {
        UNICODE_STRING* objectName = ObjectAttributes->ObjectName;
        if (
            wcsstr(objectName->Buffer, L"SBIE_BOXED_ServiceInitComplete_Mutex1") != 0 ||
            wcsstr(objectName->Buffer, L"Sandboxie_SingleInstanceMutex_Control") != 0) {
            //Check if process name is "SandboxieRpcSs.exe"
            WCHAR szFileName[MAX_PATH];
            if (GetModuleFileNameW(nullptr, szFileName, MAX_PATH)) {
                if (wcsstr(szFileName, L"SandboxieRpcSs.exe") == 0 &&
                    wcsstr(szFileName, L"SbieSvc.exe") == 0) {
                    //We can do a deeper check most likely
                    //printf("Sandboxie Is Detected: %ls\n", szFileName);

                    *MutantHandle = nullptr;
                    return STATUS_OBJECT_NAME_NOT_FOUND;
                }
            }
        }
    }

    return NtOpenMutantSaved(MutantHandle, DesiredAccess, ObjectAttributes);
}

BOOLEAN EnableApiHook() {

    if (MH_Initialize() != MH_OK) {
        return FALSE;
    }

    if (MH_CreateHook(NtOpenMutant, NtOpenMutantProxy, reinterpret_cast<PVOID*>(&NtOpenMutantSaved)) == MH_OK) {
        MH_EnableHook(NtOpenMutant);
    }

    if (MH_CreateHook(NtCreateMutant, NtCreateMutantProxy, reinterpret_cast<PVOID*>(&NtCreateMutantSaved)) == MH_OK) {
        MH_EnableHook(NtCreateMutant);
    }


    if (MH_CreateHook(NtQueryVirtualMemory, NtQueryVirtualMemoryProxy, reinterpret_cast<PVOID*>(&NtQueryVirtualMemorySaved)) == MH_OK) {
        MH_EnableHook(NtQueryVirtualMemory);
    }

    if (MH_CreateHook(NtQueryObject, NtQueryObjectProxy, reinterpret_cast<PVOID*>(&NtQueryObjectSaved)) == MH_OK) {
        MH_EnableHook(NtQueryObject);
    }

    if (MH_CreateHook(NtQueryInformationFile, NtQueryInformationFileProxy, reinterpret_cast<PVOID*>(&NtQueryInformationFileSaved)) == MH_OK) {
        MH_EnableHook(NtQueryInformationFile);
    }

    if (MH_CreateHook(NtQuerySection, NtQuerySectionProxy, reinterpret_cast<PVOID*>(&NtQuerySectionSaved)) == MH_OK) {
        MH_EnableHook(NtQuerySection);
    }

    return TRUE;
}
