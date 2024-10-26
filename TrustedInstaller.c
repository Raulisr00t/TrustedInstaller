#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <sddl.h>

#define SE_DEBUG_NAME TEXT("SeDebugPrivilege")
#define TI_SERVICE_NAME TEXT("TrustedInstaller")

BOOL EnablePrivilege(LPCWSTR privilege) {
    HANDLE token;
    TOKEN_PRIVILEGES tokenPrivileges;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        printf("Failed to open process token.\n");
        return FALSE;
    }

    LookupPrivilegeValue(NULL, privilege, &tokenPrivileges.Privileges[0].Luid);
    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(token, FALSE, &tokenPrivileges, 0, NULL, NULL);
    CloseHandle(token);

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("Privilege not assigned.\n");
        return FALSE;
    }
    return TRUE;
}

// Get the PID of the TrustedInstaller service
DWORD GetTrustedInstallerPid() {
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) {
        printf("Cannot open service manager.\n");
        return 0;
    }

    SC_HANDLE service = OpenService(scm, TI_SERVICE_NAME, SERVICE_QUERY_STATUS | SERVICE_START);
    if (!service) {
        printf("Cannot open TrustedInstaller service.\n");
        CloseServiceHandle(scm);
        return 0;
    }

    SERVICE_STATUS_PROCESS status;
    DWORD bytesNeeded;
    QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&status, sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded);

    if (status.dwCurrentState != SERVICE_RUNNING) {
        printf("Starting TrustedInstaller service...\n");
        StartService(service, 0, NULL);
        Sleep(500);  // Wait for service to start
        QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&status, sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded);
    }

    DWORD pid = status.dwProcessId;
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return pid;
}

// Run a process as a child of another process
BOOL RunAsTrustedInstaller(LPCWSTR appPath) {
    DWORD tiPid = GetTrustedInstallerPid();
    if (tiPid == 0) {
        printf("Failed to get TrustedInstaller PID.\n");
        return FALSE;
    }

    HANDLE tiProcess = OpenProcess(PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE | PROCESS_SET_INFORMATION, TRUE, tiPid);
    if (!tiProcess) {
        printf("Cannot open TrustedInstaller process. Error: %d\n", GetLastError());
        return FALSE;
    }

    STARTUPINFOEXW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(STARTUPINFOEXW));
    si.StartupInfo.cb = sizeof(STARTUPINFOEXW);

    SIZE_T size;
    InitializeProcThreadAttributeList(NULL, 1, 0, &size);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, size);
    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size);
    UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &tiProcess, sizeof(HANDLE), NULL, NULL);

    BOOL result = CreateProcessW(appPath, NULL, NULL, NULL, TRUE, EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE, NULL, NULL, &si.StartupInfo, &pi);

    if (!result) {
        printf("Failed to start process. Error: %d\n", GetLastError());
    }
    else {
        printf("Started process with PID: %d\n", pi.dwProcessId);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    DeleteProcThreadAttributeList(si.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
    CloseHandle(tiProcess);
    return result;
}

int main() {
    if (!EnablePrivilege(SE_DEBUG_NAME)) {
        printf("Cannot enable SeDebugPrivilege.\n");
        return 1;
    }

    if (!RunAsTrustedInstaller(L"C:\\Windows\\System32\\cmd.exe")) {
        printf("Failed to run process as TrustedInstaller.\n");
        return 1;
    }

    return 0;
}
