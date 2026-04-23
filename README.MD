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
