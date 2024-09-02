#include "MINT.h"
#include <stdio.h>
#include <tchar.h>
#include <stdio.h>
#include <psapi.h>
#include "Process.h"

char            NameBuffer[0x1000] = {};
PUNICODE_STRING MemoryMappedFilename = reinterpret_cast<PUNICODE_STRING>(NameBuffer);

bool HasMutex(LPCWSTR lpName) {
    HANDLE hObject = NULL;
    SetLastError(0);
    hObject = CreateMutex(NULL, FALSE, lpName);
    DWORD dwError = GetLastError();
    if (hObject) {
        CloseHandle(hObject);
    }

    if (dwError == ERROR_ALREADY_EXISTS) {
        printf("[CreateMutex] Already Exists: %ls\n", lpName);
        return true;
    }

    //2031617
    SetLastError(0);
    hObject = OpenMutex(MUTEX_ALL_ACCESS, FALSE, lpName);
    dwError = GetLastError();
    if (hObject) {
        printf("[OpenMutex] Successful: %ls\n", lpName);
        CloseHandle(hObject);
        return true;
    }

    if (dwError != ERROR_FILE_NOT_FOUND) {
        printf("[OpenMutext] Did not have last error of [ERROR_FILE_NOT_FOUND][0x2] Sus... Last Error:%d\n", dwError);
        return true;
    }

    return false;
}

int CheckMutexes() {
    printf("\nChecking Sandboxie Mutexes\n");
    printf("Has Mutext [SBIE_BOXED_ServiceInitComplete_Mutex1]: %s\n", HasMutex(L"SBIE_BOXED_ServiceInitComplete_Mutex1") ? "true" : "false");
    printf("Has Mutext [Sandboxie_SingleInstanceMutex_Control]: %s\n", HasMutex(L"Sandboxie_SingleInstanceMutex_Control") ? "true" : "false");
    return 0;
}

int PrintModules(DWORD processID) {
    HMODULE      hMods[1024];
    HANDLE       hProcess;
    DWORD        cbNeeded;
    unsigned int i;

    printf("\nProcess ID: %u\n", processID);

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (NULL == hProcess)
        return 1;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            TCHAR szModName[MAX_PATH];

            if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {

                _tprintf(TEXT("\t%s (0x%08X)\n"), szModName, hMods[i]);
            }
        }
    }

    CloseHandle(hProcess);

    return 0;
}

VOID CheckSandboxieByGetModuleHandle() {
    printf("Handle of SbieHide.dll is 0x%016llX\n", reinterpret_cast<UINT64>(GetModuleHandleA("SbieHide.dll")));
    printf("Handle of SbieDll.dll is 0x%016llX\n", reinterpret_cast<UINT64>(GetModuleHandleA("SbieDll.dll")));
}

VOID CheckSandboxieByQueryVirtualMemoryMappedFilename() {
    SIZE_T   ReturnedLength = 0;
    NTSTATUS Status = STATUS_SUCCESS;
    HMODULE  SbieHideDllAddress = GetModuleHandleA("sbiehide.dll");

    if (SbieHideDllAddress == NULL) {
        printf("disable EraseModuleNameFromPeb(L\"sbiehide.dll\"); in sbiehide first!\n");
        return;
    }

    Status = NtQueryVirtualMemory(NtCurrentProcess(), GetModuleHandleA("sbiehide.dll") + 100, MemoryMappedFilenameInformation, NameBuffer, 0x1000, &ReturnedLength);

    if (Status != STATUS_ACCESS_DENIED) {
        printf("Sbiedll found! check hook\n");
    }
    else {
        printf("Test pass\n");
    }
}

int main() {
    CheckSandboxieByGetModuleHandle();
    CheckSandboxieByQueryVirtualMemoryMappedFilename();
    CheckMutexes();
    PrintModules(reinterpret_cast<DWORD>(NtCurrentProcessId()));

    getchar();
    return 0;
}