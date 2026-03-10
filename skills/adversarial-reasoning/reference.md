# Adversarial Reasoning -- Reference

## Contents

- [A. Vulnerability Class Encyclopedia](#a-vulnerability-class-encyclopedia)
  - [A.1 Logical Vulnerabilities](#a1-logical-vulnerabilities)
  - [A.2 Memory Corruption Vulnerabilities](#a2-memory-corruption-vulnerabilities)
- [B. Windows Attack Patterns](#b-windows-attack-patterns)
- [C. Research Playbooks](#c-research-playbooks)
- [D. Variant Analysis Methodology](#d-variant-analysis-methodology)
- [E. Hypothesis Templates](#e-hypothesis-templates)

---

## A. Vulnerability Class Encyclopedia

### A.1 Logical Vulnerabilities

#### A.1.1 Authentication / Authorization Bypass

**Definition:** A privileged operation executes without verifying the caller has the required identity or permissions.

**Windows manifestation:** RPC/COM server methods that operate with the server's token instead of impersonating the client. Service handlers that skip access checks on alternate code paths. Functions gated by flags the caller controls.

**Detection signals in decompiled code:**

- RPC handler body with no `RpcImpersonateClient` / `CoImpersonateClient` call
- `AccessCheck` / `AuthzAccessCheck` present on primary path but missing on error/fallback paths
- Security check gated by a bitmask parameter the caller supplies
- `goto cleanup` paths that skip the authorization check

**Workspace commands:**

- `/audit <module> <func>` -- builds dossier showing reachability and dangerous ops
- `/taint <module> <func> --params 1` -- traces whether caller-controlled parameter reaches the privileged operation without passing through a check
- `/search <module> RpcImpersonateClient` -- find all impersonation sites; compare with RPC handler count

**Red flags:** Function is `RPC_HANDLER` entry type but has zero `security` category APIs in its call chain. Function has multiple `goto` labels and the security check only appears before one of them.

---

#### A.1.2 TOCTOU / Race Conditions

**Definition:** A gap between checking a resource's state and using it allows an attacker to change the resource between the check and the use.

**Windows manifestation:** File existence check followed by file open (attacker swaps via junction). Token duplication followed by separate impersonation call. Registry key read followed by separate use of the value.

**Detection signals:**

- Two separate `CreateFileW` calls on the same path (check then use)
- `GetFileAttributesW` or `PathFileExistsW` followed by `CreateFileW` on the same variable
- `RegQueryValueExW` followed by buffer allocation and `RegGetValueW` (size race)
- `FindFirstFileW` for validation followed by separate open
- File opened with `FILE_SHARE_WRITE` or `FILE_SHARE_DELETE` (concurrent modification)

**Workspace commands:**

- `/data-flow forward <module> <func>` -- trace the path variable to see if it is revalidated
- `/verify <module> <func>` -- confirm decompiler accurately represents the two operations
- `/audit <module> <func>` -- check if the function operates at elevated privilege

**Red flags:** Time-sensitive operations on user-writable paths. Functions that stat/check a file, then open it in a separate API call. Registry queries that assume the value did not change between size query and data query.

---

#### A.1.3 Symlink / Junction Attacks

**Definition:** An attacker plants a filesystem redirect (directory junction, mount point, or NTFS symlink) so that a privileged operation targets an unintended location.

**Windows manifestation:** A service writes to `C:\ProgramData\App\config.ini` -- attacker replaces `App\` with a junction pointing to `C:\Windows\System32\`. The write now targets a system file.

**Detection signals:**

- `CreateFileW` on paths under user-writable directories (`%TEMP%`, `C:\ProgramData\`, `C:\Users\Public\`)
- Privileged operations (write, delete, rename) on paths built from string concatenation
- No use of `FILE_FLAG_OPEN_REPARSE_POINT` (would detect the junction)
- Directory creation followed by file write in the new directory (junction window)

**Workspace commands:**

- `/search <module> ProgramData` or `/search <module> \\Temp\\` -- find path strings
- `/data-flow forward <module> <func> --param <path_param>` -- trace the path from entry to file operation
- `/taint <module> <func>` -- check if path is attacker-influenced

**Red flags:** Privileged write to a path containing any user-writable ancestor directory. Use of `CreateDirectoryW` followed by `CreateFileW` without atomicity.

---

#### A.1.4 Privilege Escalation

**Definition:** An attacker at a lower privilege level triggers a higher-privilege operation to act on attacker-controlled resources.

**Windows manifestation:** Medium-IL process triggers a SYSTEM service to write an attacker-controlled file. AppContainer process sends a COM request to a broker that performs the operation at medium IL.

**Detection signals:**

- Service entry points (`SERVICE_MAIN`) that accept client parameters and reach `CreateProcessW`, `CreateFileW`, `RegSetValueExW`
- `ImpersonateLoggedOnUser` / `SetThreadToken` in call chain (token may be attacker-supplied)
- `AdjustTokenPrivileges` enabling `SeDebugPrivilege`, `SeTcbPrivilege`, `SeAssignPrimaryTokenPrivilege`
- Named pipe server that calls `ImpersonateNamedPipeClient` with `SECURITY_IMPERSONATION`

**Workspace commands:**

- `/triage <module>` -- identify if the module runs as a service or elevated process
- `/audit <module> <func>` -- full security dossier
- `/audit <module> <export> --diagram` -- audit entry point with call graph to privileged operations
- `/taint <module> <func>` -- trace attacker parameters to privileged sinks

**Red flags:** Module description says "service" or "system component." Entry points are `SERVICE_MAIN`, `RPC_HANDLER`, or `COM_METHOD`. Call chain reaches `CreateProcess*` or file write APIs.

---

#### A.1.5 Information Disclosure

**Definition:** Sensitive data is exposed to an unauthorized party through unintended channels.

**Windows manifestation:** Uninitialized stack buffer returned to RPC caller. Error messages containing internal paths or memory addresses. Timing differences revealing whether a user account exists.

**Detection signals:**

- Stack-allocated buffer passed to RPC out-parameter without full initialization
- Error paths that return different HRESULT codes for "user not found" vs "wrong password"
- `memset` or `RtlZeroMemory` missing before returning a buffer
- Format strings that include pointer values (`%p`) or full paths in error messages

**Workspace commands:**

- `/verify <module> <func>` -- check for uninitialized variable issues
- `/search <module> "%p"` or `/search <module> "%s"` -- find format strings that may leak data
- `/data-flow forward <module> <func>` -- trace what data reaches the output buffer

**Red flags:** RPC handler with output buffer parameter and no `memset`/`RtlZeroMemory` in the function. Error handling that returns different codes for semantically equivalent failures.

---

#### A.1.6 Denial of Service

**Definition:** An attacker can crash or hang the target process/service, denying its functionality to legitimate users.

**Windows manifestation:** Unhandled exception in a service dispatcher. Deadlock from lock ordering violation. Resource exhaustion from unbounded allocation.

**Detection signals:**

- Exception handling: `__try/__except` blocks with `EXCEPTION_CONTINUE_EXECUTION` (masks crashes)
- Missing `__try/__except` in RPC handler (unhandled exception terminates service)
- Lock acquisition without timeout (`WaitForSingleObject(INFINITE)`)
- Allocation sizes controlled by client input without upper bound

**Workspace commands:**

- `/search <module> WaitForSingleObject` -- find lock operations, check for INFINITE timeout
- `/taint <module> <func>` -- check if allocation sizes are attacker-controlled
- `/verify <module> <func>` -- confirm exception handling structure

**Red flags:** RPC/COM handler with no exception handling. Recursive function with no depth limit. Allocation size derived from client parameter without cap.

---

#### A.1.7 State Machine Logic Errors

**Definition:** A state machine accepts transitions that should be invalid, skips required states, or handles out-of-order operations unsafely.

**Windows manifestation:** A protocol handler processes a "data" message before "authentication" completes. A service control handler accepts `SERVICE_CONTROL_STOP` while initialization is still running.

**Detection signals:**

- `switch` statement on a state variable without covering all valid states
- Missing `default` case in dispatch handlers
- State variable writable from multiple threads without synchronization
- Operation allowed when the state enum is at an unexpected value

**Workspace commands:**

- `/state-machines <module> <func>` -- extract the dispatch table and state transitions
- `/data-flow forward <module> <func>` -- trace the state variable through transitions
- `/search <module> <state_enum_name>` -- find all readers/writers of the state

**Red flags:** Dispatch table with missing cases. State variable is a global accessed from multiple functions without locking.

---

#### A.1.8 Insecure Defaults

**Definition:** A component ships with security-relevant settings that are permissive by default, relying on the administrator to harden them.

**Windows manifestation:** Service creates a named pipe with a NULL DACL (world-accessible). COM server registers with permissive launch permissions. File created with inherited ACL in a world-writable directory.

**Detection signals:**

- `NULL` passed as `SECURITY_ATTRIBUTES` parameter to `CreateNamedPipeW`, `CreateFileW`, `CreateMutexW`
- `ConvertStringSecurityDescriptorToSecurityDescriptor` with `"D:(A;;GA;;;WD)"` (Everyone: Full)
- `RegCreateKeyExW` without explicit DACL on the key
- `SetSecurityInfo` / `SetNamedSecurityInfo` setting permissive ACLs

**Workspace commands:**

- `/search <module> SecurityAttributes` -- find security descriptor construction
- `/search <module> ConvertStringSecurityDescriptor` -- find SDDL-based ACL setup
- `/taint <module> <func>` -- check if the DACL is configurable or hardcoded

**Red flags:** `NULL` security attributes on any named kernel object. SDDL strings with `WD` (World/Everyone) or `BA` (Built-in Administrators) grants that are too broad.

---

### A.2 Memory Corruption Vulnerabilities

#### A.2.1 Stack Buffer Overflow

**Definition:** Write beyond a fixed-size stack buffer, corrupting adjacent stack data (return address, saved registers, SEH records).

**Detection signals:**

- Fixed-size `WCHAR path[MAX_PATH]` or `char buf[256]` on the stack
- `wcscpy` / `strcpy` / `wcscat` / `strcat` with no prior length check
- Loop writing to stack buffer with loop bound derived from input
- No stack canary (`has_canary: false` in dossier) on functions with large stack frames

**Workspace commands:**

- `/verify <module> <func>` -- check decompiler accuracy for buffer sizes
- `/taint <module> <func>` -- trace input to the copy operation
- `/audit <module> <func>` -- check `has_canary` and `local_vars_size`

**Red flags:** `has_canary: false` + `local_vars_size > 256`. Use of `wcscpy`/`strcpy` on stack buffers. Module `canary_coverage_pct` < 30%.

---

#### A.2.2 Heap Corruption (UAF, Double Free, Overflow)

**Definition:** Write/read beyond heap allocation bounds, use memory after it is freed, or free the same allocation twice.

**Detection signals:**

- Object freed in error path, pointer not nulled, used later in normal path (UAF)
- `delete this` in a method where the caller continues using the object
- `HeapAlloc(size)` where `size = user_count * element_size` without overflow check (heap overflow)
- Two `HeapFree` / `delete` calls on the same pointer in different error paths (double free)

**Workspace commands:**

- `/data-flow forward <module> <func>` -- trace object pointer from allocation through use and free
- `/verify <module> <func>` -- confirm decompiler correctly represents free/use ordering
- `/audit <module> <export> --diagram` -- map object lifetime across call chain

**Red flags:** Destructor pattern (`~ClassName`) called from error handler while object is still referenced by caller. Allocation and free in different functions without clear ownership protocol.

---

#### A.2.3 Integer Overflow / Underflow

**Definition:** Arithmetic on integer values wraps around, producing an unexpectedly small (or large) value used for allocation or bounds checking.

**Detection signals:**

- `size = count * element_size` passed to `HeapAlloc` / `malloc` / `LocalAlloc` without `ULongMult` / `SizeTMult`
- `total = offset + length` used as buffer bound without checking for wrap
- `size_t` subtraction that can underflow (producing a very large positive value)
- Truncation: 64-bit size stored in 32-bit variable before use

**Workspace commands:**

- `/verify <module> <func>` -- check assembly for overflow checks (`jo`, `jc` instructions)
- `/taint <module> <func> --params <size_param>` -- trace the size value to allocation
- `/search <module> HeapAlloc` -- find all allocations, cross-reference with taint data

**Red flags:** Multiplication used for allocation size without safe-math wrapper. 32-bit variable holding a size that could exceed 4GB. Subtraction of two user-controlled values used as a length.

---

#### A.2.4 Type Confusion

**Definition:** A pointer or object is treated as a type it does not actually represent, causing field misalignment or vtable corruption.

**Detection signals:**

- `void*` cast to specific struct type without tag/magic check
- COM `QueryInterface` result used without checking the returned HRESULT
- `union` with overlapping fields of different sizes accessed through the wrong member
- Variant dispatch: `switch` on type tag, but one case handles the wrong underlying type

**Workspace commands:**

- `/reconstruct-types <module> <class>` -- verify struct layout and vtable
- `/verify <module> <func>` -- confirm decompiler type annotations
- `/search <module> QueryInterface` -- find COM interface casts

**Red flags:** Function accepts `void*` and casts based on a flag parameter without validation. COM method called on interface pointer without prior `QueryInterface` success check. Union accessed with member from different variant case.

---

#### A.2.5 Uninitialized Variables

**Definition:** A variable is read before being written on all code paths, exposing stale stack/heap data.

**Detection signals:**

- Stack variable used in conditional before assignment on all paths
- `if (err) goto cleanup` where the cleanup path reads a variable only set after the check
- Struct output parameter not zeroed before partial field assignment
- Decompiler shows variable first appearing in a conditional read (no prior store)

**Workspace commands:**

- `/verify <module> <func>` -- decompiler verification catches many uninitialized variable issues
- `/data-flow forward <module> <func>` -- trace the variable to see if all paths initialize it

**Red flags:** Large local struct partially filled by multiple branches. Error/early-return paths that skip initialization. Output buffer returned to caller without `memset`.

---

#### A.2.6 Format String Bugs

**Definition:** User-controlled data is passed as the format argument to a `printf`-family function, allowing stack reads/writes via format specifiers.

**Detection signals:**

- `StringCchPrintfW(buf, size, user_string)` where `user_string` is a parameter, not a literal
- `wprintf(arg1)` where `arg1` flows from an external source
- `DbgPrint` / `OutputDebugString` with attacker-influenced format argument

**Workspace commands:**

- `/taint <module> <func>` -- trace input to the format argument position
- `/search <module> printf` -- find all printf-family call sites

**Red flags:** `StringCchPrintf*` or `sprintf` where the format argument is not a string literal. Any `printf` variant where the format parameter comes from an external source.

---

#### A.2.7 Off-by-One Errors

**Definition:** A boundary calculation is wrong by exactly one element, causing a single-element overread or overwrite.

**Detection signals:**

- `for (i = 0; i <= count; i++)` instead of `< count` (writes one past end)
- Buffer allocated as `strlen(s)` instead of `strlen(s) + 1` (missing null terminator space)
- Array index uses `>=` where `>` was intended (or vice versa)
- `wcsncpy` with size `sizeof(buf)` instead of `sizeof(buf)/sizeof(WCHAR)` (byte/element confusion)

**Workspace commands:**

- `/verify <module> <func>` -- compare loop bounds in decompiled vs assembly
- `/taint <module> <func>` -- trace the count/size value through the loop

**Red flags:** Loop iterates `<= N` instead of `< N`. Buffer sized by `strlen` without `+1`. Character-count and byte-count mixed in the same expression.

---

## B. Windows Attack Patterns

### B.1 RPC/ALPC Authentication Bypass

**Threat model:** Local attacker calls an RPC endpoint served by a SYSTEM service.

**Preconditions:** RPC server uses `ncalrpc` or `ncacn_np` transport. Server does not call `RpcImpersonateClient` or calls it but performs operations after `RpcRevertToSelf`.

**Detection signals:**

- `RPC_HANDLER` entry points without `RpcImpersonateClient` in their call tree
- `RpcImpersonateClient` + `RpcRevertToSelf` not properly paired on all exit paths
- Operations that occur _after_ `RpcRevertToSelf` (server is back to its own SYSTEM token)

**Workspace investigation:**

```
/search <module> RpcImpersonateClient
/triage <module>                          # find all RPC handlers
/audit <module> <rpc_handler>             # check each handler
/taint <module> <handler> --params 1,2    # trace client params to sinks
```

---

### B.2 COM Cross-Process Privilege Escalation

**Threat model:** Medium-IL process activates a COM server running at high IL or SYSTEM, passing attacker-controlled arguments to server methods.

**Preconditions:** COM class registered with `LocalServer32` or runs in a privileged service. Activation permissions allow medium-IL callers.

**Detection signals:**

- `DllGetClassObject` / `DllCanUnloadNow` exports (COM class factory)
- VTable methods receiving `BSTR`, `VARIANT`, or `IStream` parameters (attacker-controlled data)
- Missing `CoImpersonateClient` in method implementations
- `CLSCTX_LOCAL_SERVER` usage patterns

**Workspace investigation:**

```
/reconstruct-types <module> <com_class>   # vtable layout
/audit <module> DllGetClassObject --diagram  # factory chain
/search <module> CoImpersonateClient      # impersonation usage
/taint <module> <method> --params 1       # trace VARIANT/BSTR input
```

---

### B.3 Named Pipe Impersonation to SYSTEM

**Threat model:** Attacker creates a named pipe first (name squatting), waits for a SYSTEM process to connect, then impersonates the connecting client.

**Preconditions:** SYSTEM service connects to a predictable pipe name. Pipe is created with `PIPE_ACCESS_INBOUND` and impersonation is available.

**Detection signals:**

- `CreateNamedPipeW` with hardcoded or predictable pipe name
- `ConnectNamedPipe` + `ImpersonateNamedPipeClient` pattern
- Pipe name visible in string literals (`\\.\pipe\ServiceName`)

**Workspace investigation:**

```
/search <module> CreateNamedPipe           # find pipe creation
/search <module> "\\\\.\\\pipe\\"          # find pipe name strings
/data-flow forward <module> <pipe_func>    # trace pipe handle usage
/taint <module> <handler>                  # trace data from pipe read
```

---

### B.4 Service Binary DLL Hijacking

**Threat model:** A service loads a DLL from a location where the attacker can plant a malicious DLL.

**Preconditions:** Service uses `LoadLibraryW` with a relative path or searches user-writable directories. Service binary is in a directory writable by non-admin users.

**Detection signals:**

- `LoadLibraryW` / `LoadLibraryExW` with a name that does not include a full path
- `AddDllDirectory` or `SetDllDirectoryW` with user-controllable path
- Service binary path in `C:\Program Files\App Name\` with spaces (unquoted service path)

**Workspace investigation:**

```
/search <module> LoadLibrary               # find DLL load sites
/data-flow forward <module> <load_func>    # trace the DLL path argument
/triage <module>                           # module identity and path
```

---

### B.5 Token Handle Inheritance / Impersonation Level Downgrade

**Threat model:** A child process inherits a handle to a privileged token, or an impersonation token is created at too low a level and later used at a higher level.

**Preconditions:** Process creates a token handle with `HANDLE_FLAG_INHERIT`. Impersonation level check is missing or uses wrong comparison.

**Detection signals:**

- `DuplicateTokenEx` creating a token at `SecurityImpersonation` level
- `SetHandleInformation` with `HANDLE_FLAG_INHERIT` on token handles
- `CreateProcessAsUserW` / `CreateProcessWithTokenW` with inherited handle table
- Comparison of `SECURITY_IMPERSONATION_LEVEL` using `==` instead of `>=`

**Workspace investigation:**

```
/search <module> DuplicateToken            # token duplication
/search <module> SetHandleInformation      # handle inheritance
/audit <module> <token_func>               # security dossier
/data-flow forward <module> <func>         # trace token handle
```

---

### B.6 Object Manager Namespace Squatting

**Threat model:** Attacker creates a named kernel object (mutex, event, section) before the legitimate owner, gaining control over synchronization or shared memory.

**Preconditions:** Privileged process creates a named object without checking whether it already exists. Object name is predictable.

**Detection signals:**

- `CreateMutexW` / `CreateEventW` / `CreateFileMappingW` with hardcoded name and NULL security attributes
- Missing check of `GetLastError() == ERROR_ALREADY_EXISTS` after creation
- Object name visible in string literals (e.g., `Global\ServiceLock`)

**Workspace investigation:**

```
/search <module> CreateMutex               # find named object creation
/search <module> "Global\\"               # find global namespace names
/data-flow forward <module> <func>         # trace object handle usage
```

---

### B.7 Oplock-Assisted TOCTOU

**Threat model:** Attacker uses an oplock (opportunistic lock) to pause a privileged file operation at a precise point, then swaps the file target via junction/symlink before releasing the oplock.

**Preconditions:** Privileged process opens a file, performs a check, then performs a write/delete as a separate operation (not atomic). The path traverses a user-writable directory.

**Detection signals:**

- Two separate `CreateFileW` calls on the same path variable
- `GetFileAttributesW` / `FindFirstFileW` followed by a separate `CreateFileW`
- File operations on paths under `%TEMP%`, `C:\ProgramData\`, or other user-writable locations
- No use of `OPEN_EXISTING` with exclusive share mode between check and use

**Workspace investigation:**

```
/data-flow forward <module> <func>         # trace path variable through both operations
/verify <module> <func>                    # confirm two separate file operations
/search <module> GetFileAttributes         # find check-before-use patterns
/audit <module> <func>                     # privilege level and entry reachability
```

---

### B.8 Arbitrary File Write to SYSTEM

**Threat model:** Attacker exploits a junction/symlink/TOCTOU to redirect a privileged file write to an arbitrary location, then leverages the written file for code execution (DLL plant, config overwrite, scheduled task).

**Preconditions:** Privileged service writes to a user-influenceable path. The write content is partially or fully attacker-controlled.

**Detection signals:**

- Service writes to `%ProgramData%`, `%TEMP%`, or user-profile-derived paths
- `MoveFileExW` / `CopyFileW` used with user-influenced source or destination
- Log file or temp file written with attacker-controlled content and predictable name
- Combination of patterns B.3 or B.7 leading to a file write

**Workspace investigation:**

```
/taint <module> <write_func>               # trace input to file write content
/data-flow forward <module> <func>         # trace path to write API
/search <module> MoveFileEx                # find file move/copy operations
/search <module> ProgramData               # find writable directory paths
```

---

### B.9 Registry Symlink Races

**Threat model:** Attacker creates a volatile registry key symlink that redirects a privileged registry operation to an arbitrary key.

**Preconditions:** Privileged process opens a registry key under a path where the attacker can create volatile subkeys. Key access check and key use are separate operations.

**Detection signals:**

- `RegOpenKeyExW` on a path under `HKCU\` or writable `HKLM\` subkeys
- Separate open-then-read pattern (not atomic)
- Registry paths containing user-specific or configurable components

**Workspace investigation:**

```
/search <module> RegOpenKeyEx              # find registry access
/search <module> "SOFTWARE\\"             # find registry paths in strings
/data-flow forward <module> <func>         # trace the key handle from open to use
```

---

### B.10 Kernel Callback / Filter Driver Abuse

**Threat model:** User-mode attacker triggers a kernel callback or minifilter that runs with elevated privilege, passing data that the callback does not properly validate.

**Preconditions:** Driver registers a callback (`PsSetCreateProcessNotifyRoutine`, minifilter pre/post callbacks) that processes user-controlled data. Callback trusts the data without sanitization.

**Detection signals:**

- (For user-mode analysis) Functions that format data specifically for kernel consumption
- `DeviceIoControl` with attacker-controlled input/output buffer sizes
- Structured data passed to driver via `NtDeviceIoControlFile`

**Workspace investigation:**

```
/search <module> DeviceIoControl           # find IOCTL calls
/taint <module> <ioctl_func>              # trace input buffer content
/search <module> NtDeviceIoControlFile     # find direct syscall variant
```

---

## C. Research Playbooks

### Playbook 1: "I have a Windows service -- find privilege escalation"

**When to use:** Module runs as a Windows service (SYSTEM, LOCAL SERVICE, or NETWORK SERVICE).

**Prerequisites:** Run `/triage <module>` first.

**Steps:**

1. **Map the attack surface:**

   ```
   /hunt-plan surface <module>
   ```

   Focus on: RPC handlers, named pipe handlers, COM methods, service control handler.

2. **Identify the entry points:**

   ```
   /search <module> RpcImpersonateClient    # are handlers impersonating?
   /search <module> CreateNamedPipe         # any pipe servers?
   ```

3. **For each RPC/pipe entry point, check auth:**

   ```
   /audit <module> <handler_func>           # full security dossier
   /taint <module> <handler_func>           # trace params to dangerous sinks
   ```

4. **Check for dangerous output operations:**

   ```
   /search <module> CreateProcess           # process creation from service
   /search <module> CreateFile              # file writes from service
   /search <module> RegSetValue             # registry writes from service
   ```

5. **For each dangerous sink reachable from entry:**

   ```
   /data-flow forward <module> <entry_func> --param <attacker_param>
   ```

   Verify whether attacker-controlled data reaches the sink.

6. **Formulate hypotheses and validate:**
   Apply hypothesis generation framework from SKILL.md, then validate using the strategy matrix.

---

### Playbook 2: "I have a COM server -- find cross-process attacks"

**When to use:** Module exports `DllGetClassObject` / `DllCanUnloadNow` or registers COM classes.

**Steps:**

1. **Discover COM surface:**

   ```
   /reconstruct-types <module>              # find all vtable classes
   /search <module> DllGetClassObject       # confirm COM class factory
   /search <module> CoImpersonateClient     # check impersonation
   ```

2. **For each COM class, map vtable methods:**

   ```
   /reconstruct-types <module> <ClassName>
   /audit <module> DllGetClassObject --diagram
   ```

3. **Audit each non-trivial vtable method:**

   ```
   /audit <module> <vtable_method>          # reachability, dangerous ops
   /taint <module> <vtable_method>          # trace VARIANT/BSTR params
   ```

4. **Check for marshaling attacks:**
   ```
   /search <module> IMarshal                # custom marshaling
   /search <module> CoMarshalInterface      # marshal/unmarshal patterns
   ```

---

### Playbook 3: "I have an RPC interface -- find auth bypass"

**When to use:** Module hosts RPC server functions (detected by `/triage` as `RPC_HANDLER` entries).

**Steps:**

1. **List all RPC handlers:**

   ```
   /triage <module>                         # entry point discovery
   /search <module> RpcServerRegisterIf     # find interface registration
   ```

2. **Check each handler for impersonation:**

   ```
   /search <module> RpcImpersonateClient
   ```

   Compare: number of handlers vs number of impersonation calls. Missing calls = potential bypass.

3. **For each handler without impersonation:**

   ```
   /audit <module> <handler>
   /taint <module> <handler> --params 1,2,3
   ```

4. **Check security callback:**
   ```
   /search <module> RpcServerRegisterIf3    # has security callback?
   /search <module> RPC_IF_ALLOW_LOCAL_ONLY # interface flags
   ```

---

### Playbook 4: "I found file path handling -- check for symlink/junction attacks"

**When to use:** Function operates on file paths that may be attacker-influenced.

**Steps:**

1. **Find all file operations on the path:**

   ```
   /data-flow forward <module> <func> --param <path_param>
   ```

2. **Check for TOCTOU pattern:**

   ```
   /verify <module> <func>                  # are there two file operations?
   ```

   Look for: stat-then-open, check-then-write, or create-then-use patterns.

3. **Check if path traverses writable directories:**

   ```
   /search <module> ProgramData
   /search <module> Temp
   /search <module> Users
   ```

4. **Check for junction-safe flags:**
   Look for `FILE_FLAG_OPEN_REPARSE_POINT` in the `CreateFileW` call. Absence means junctions are followed blindly.

5. **If vulnerable:** The path traverses a writable directory, two separate operations exist on it, and no reparse-point flag is used. This is a junction/symlink attack candidate.

---

### Playbook 5: "I found impersonation code -- check for token leaks"

**When to use:** Function calls `RpcImpersonateClient`, `ImpersonateNamedPipeClient`, `ImpersonateLoggedOnUser`, or `SetThreadToken`.

**Steps:**

1. **Map all impersonation and revert calls:**

   ```
   /search <module> Impersonate
   /search <module> RevertToSelf
   /search <module> RpcRevertToSelf
   ```

2. **For each impersonation site, verify pairing:**

   ```
   /audit <module> <impersonating_func>
   ```

   Check: is `RevertToSelf` called on _every_ exit path (including error, exception, early return)?

3. **Check what happens between impersonate and revert:**

   ```
   /audit <module> <func> --diagram
   ```

   Operations between impersonate/revert happen as the impersonated user. Operations _after_ revert happen as the server (SYSTEM).

4. **If revert is missing on error path:** This is a token leak. SYSTEM operations will execute under the (possibly low-privilege) impersonated token until the thread exits or another impersonation occurs.

---

### Playbook 6: "I found a parser -- check for memory corruption"

**When to use:** Function parses structured input (file format, network protocol, serialized data).

**Steps:**

1. **Assess the function's complexity and safety:**

   ```
   /audit <module> <parser_func>            # instruction count, loops, canary
   /verify <module> <parser_func>           # decompiler accuracy
   ```

2. **Trace all input parameters:**

   ```
   /taint <module> <parser_func> --depth 3  # all params, deep trace
   ```

3. **Look for the classic memory corruption signals:**
   - Size parameter reaching `HeapAlloc` without overflow check -> integer overflow
   - Input reaching `memcpy`/`RtlCopyMemory` length argument -> buffer overflow
   - Loop bound from input without cap -> stack/heap overflow
   - Type tag from input controlling a cast -> type confusion

4. **Check safety features:**
   ```
   /audit <module> <parser_func>            # has_canary, CFG status
   ```

---

### Playbook 7: "I know a CVE pattern -- find variants in this module"

**When to use:** Researcher knows a specific vulnerability pattern and wants to find similar instances.

**Steps:**

1. **Decompose the known pattern** into searchable components:
   - What API is the sink? (e.g., `CreateProcessW`)
   - What type of check is missing? (e.g., path validation)
   - What entry point type is involved? (e.g., RPC handler)
   - What data flow shape? (e.g., parameter -> file path -> process creation)

2. **Search for the sink API across the module:**

   ```
   /search <module> <sink_api>
   ```

3. **For each hit, check the data flow:**

   ```
   /taint <module> <calling_func>
   ```

   Does the data flow match the known pattern?

4. **For each match, verify the missing check:**

   ```
   /audit <module> <candidate>
   ```

   Is the same type of check missing?

5. **Expand to other modules:**
   ```
   /search --all <sink_api>                 # search all extracted modules
   ```

---

### Playbook 8: "I want to map all trust boundaries in this binary"

**When to use:** Starting a new research campaign and need to understand the security architecture.

**Steps:**

1. **Module identity and privilege level:**

   ```
   /triage <module>
   ```

   Determine: service vs user-mode, integrity level, security features.

2. **Entry point enumeration:**

   ```
   /hunt-plan surface <module>
   ```

   Map: exports, RPC handlers, COM methods, pipe handlers, callbacks.

3. **IPC surface:**

   ```
   /search <module> Rpc
   /search <module> CreateNamedPipe
   /search <module> CoRegisterClassObject
   /search <module> DeviceIoControl
   ```

4. **For each IPC mechanism, identify the trust boundary:**
   - Who can call this? (ACL, interface flags, transport type)
   - What privilege does the handler run at?
   - What operations can the caller trigger?

5. **Draw the boundary map:**
   - List each trust boundary crossing
   - For each, note: caller privilege, callee privilege, data crossing the boundary
   - Rank by attack value using the prioritization rubric

---

## D. Variant Analysis Methodology

### Step 1: Decompose the Known Vulnerability

Break a known bug into its constituent parts:

| Component                | Example (CVE junction attack)                                 |
| ------------------------ | ------------------------------------------------------------- |
| **Entry point type**     | RPC handler in a SYSTEM service                               |
| **Data flow shape**      | Client parameter -> string concat -> file path -> CreateFileW |
| **Missing check**        | No validation that path does not traverse a junction          |
| **Sink operation**       | File write to attacker-redirected location                    |
| **Exploitation outcome** | Arbitrary file write as SYSTEM                                |

### Step 2: Create an Exact Match

Start with a pattern that matches ONLY the known vulnerable instance:

```
/search <module> <exact_vulnerable_pattern>
```

Verify: Does it match exactly one location (the original)? If it matches
zero, the search term doesn't appear in decompiled code -- try the API
name or a unique string from the function.

### Step 3: Identify Abstraction Points

Decide what to generalize using this table adapted for decompiled code:

| Element            | Keep Specific                                                 | Abstract                                                                               |
| ------------------ | ------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| Function name      | If unique to the bug pattern                                  | If the pattern applies to a family of functions                                        |
| Variable names     | Never (Hex-Rays names are arbitrary: `v1`, `a2`)              | Always use API/structural patterns instead                                             |
| API call           | If the specific API matters (`CreateFileW` vs `NtCreateFile`) | Generalize to API category via `classify_api()` if the calling pattern is what matters |
| Literal values     | If a magic number triggers the bug (buffer size, flag value)  | If any value triggers it                                                               |
| Return value check | If a specific check matters                                   | Abstract to "missing check" pattern                                                    |
| Argument position  | If a specific parameter position matters                      | Use `...` wildcards for any position                                                   |

### Step 4: Iteratively Generalize

Change ONE element at a time:

1. Modify one element from the abstraction table
2. Run the search: `/search <module> <pattern>` or `classify_module.py --category <cat>`
3. Review ALL new matches -- classify each as true positive or false positive
4. If FP rate is acceptable (below ~50%), keep the generalization and proceed
5. If FP rate is too high, revert and try a different abstraction
6. Repeat until further generalization produces diminishing returns

**Stop when the false positive rate exceeds ~50%.** At that point, the
pattern is too generic to be useful.

### Step 5: Search Across Modules

Do not limit the search to the module where the original bug was found:

```
/search --all <generalized_pattern>
/search <related_module> <pattern>
```

Use `import-export-resolver` to find related modules that share the same
internal libraries or API patterns:

```bash
python .agent/skills/import-export-resolver/scripts/module_deps.py --module <module> --consumers --json
```

### Step 6: Triage Results

For each match, document:

- **Function ID and module**: Use `--id` in all subsequent calls
- **Confidence**: High (matches 4+ decomposed components) / Medium (2-3) / Low (1)
- **Exploitability**: Run `exploitability-assessment` on confirmed matches
- **Priority**: Based on the research prioritization rubric from SKILL.md

### Step 7: Confirm or Refute

For each surviving candidate, apply the validation strategy matrix from
the SKILL.md. Use `finding-verification` for structured true/false
positive determination.

### Critical Pitfalls for Binary Variant Analysis

These mistakes cause analysts to miss real variants:

**1. Searching only one module.** Bug in `foo.dll` may have variants in
`bar.dll` that uses the same internal library. Use `import-export-resolver`
to find modules sharing the same code patterns. Always search cross-module.

**2. Pattern too specific to Hex-Rays output.** Decompiled variable names
vary across functions and compilations. `v3 = CreateFileW(a1, ...)` in
one function is `v7 = CreateFileW(a2, ...)` in another. Search by API
call patterns and structural shapes, not variable names.

**3. Single vulnerability class.** The root cause (e.g., unchecked
user-controlled size) may manifest as buffer overflow in one function,
integer overflow in another, and OOB read in a third. List all possible
manifestations of the root cause before searching.

**4. Missing edge cases.** Test patterns with null handles, zero-length
buffers, maximum integer values, and error return paths. Variants often
hide in the edge cases that the original bug missed.

---

## E. Hypothesis Templates

Use these fill-in-the-blank templates to generate structured, testable hypotheses from observations.

### Template 1: Missing Access Check

```
OBSERVATION: Function <func> is a <entry_type> that reaches <dangerous_api>
             in <hop_count> hops without any security API in the call path.
HYPOTHESIS:  <func> performs <operation> without verifying the caller's identity
             or permissions, allowing a <attacker_level> attacker to trigger
             <dangerous_operation> directly.
BECAUSE:     The dossier shows externally_reachable=YES, dangerous_ops_reachable=<N>,
             and no security-category APIs in the call chain.
TEST:        /audit <module> <func>
             /taint <module> <func> --params <attacker_params>
REFUTES IF:  Taint analysis shows a hard guard (attacker_controllable=NO) between
             entry and sink, or the function is not actually reachable from an
             untrusted entry point.
CONFIRMS IF: Taint shows CRITICAL finding with bypass_difficulty=easy and no
             non-attacker-controllable guards on the path.
NEXT:        Build PoC: craft <entry_type> call with controlled parameters.
```

### Template 2: TOCTOU / Race Condition

```
OBSERVATION: Function <func> calls <check_api> on <resource> and then separately
             calls <use_api> on the same <resource> without holding an exclusive lock.
HYPOTHESIS:  An attacker can modify <resource> between the check and the use,
             bypassing the validation performed by <check_api>.
BECAUSE:     The two operations are not atomic, and <resource> is in a location
             writable by a <attacker_level> attacker.
TEST:        /data-flow forward <module> <func> --param <resource_param>
             /verify <module> <func>
REFUTES IF:  The resource is opened exclusively (no FILE_SHARE_WRITE/DELETE) at
             check time and the handle is reused, or the path is not user-writable.
CONFIRMS IF: Two separate opens on the same path with a time gap between them,
             path traverses a user-writable directory, no exclusive lock held.
NEXT:        Build PoC: oplock on target file, junction swap on release.
```

### Template 3: Integer Overflow

```
OBSERVATION: Function <func> computes <size_expr> for an allocation (<alloc_api>)
             using attacker-controlled parameter <param>.
HYPOTHESIS:  An attacker can supply values that cause <size_expr> to overflow,
             resulting in a small allocation followed by a large write, producing
             a heap buffer overflow.
BECAUSE:     The multiplication/addition is performed without safe-math wrappers
             (no ULongMult/SizeTMult/overflow check in assembly).
TEST:        /verify <module> <func>    (check assembly for overflow guards)
             /taint <module> <func> --params <param>
REFUTES IF:  Assembly shows `jo`/`jc` branch after the arithmetic, or a safe-math
             wrapper is used, or the parameter has a hard upper-bound check.
CONFIRMS IF: No overflow check in assembly, parameter flows directly to allocation
             size without bounds validation.
NEXT:        Build PoC: supply values near UINT_MAX / element_size boundary.
```

### Template 4: Privilege Escalation via IPC

```
OBSERVATION: Module <module> runs as <privilege_level> and exposes <ipc_type>
             entry points callable by <attacker_level> processes. Entry point
             <func> reaches <dangerous_api> with <hop_count> hops.
HYPOTHESIS:  A <attacker_level> attacker can invoke <func> to trigger
             <dangerous_operation> at <privilege_level>, achieving privilege
             escalation.
BECAUSE:     The entry point is externally reachable (attack_score=<score>),
             parameters are attacker-controlled (param_risk_score=<risk>), and
             the call chain reaches <dangerous_api> without adequate checks.
TEST:        /audit <module> <func>
             /audit <module> <func> --diagram
             /taint <module> <func>
REFUTES IF:  All paths from entry to sink pass through a hard security check that
             the attacker cannot bypass (auth check with attacker_controllable=NO).
CONFIRMS IF: Direct or lightly-guarded path from IPC entry to privileged operation
             with attacker-controlled parameters.
NEXT:        Determine the IPC trigger mechanism and craft a calling harness.
```

### Template 5: Variant Pattern Match

```
OBSERVATION: Known CVE <cve_id> in <original_module> exploited <pattern_description>.
             Function <candidate_func> in <target_module> exhibits similar signals:
             same sink API (<api>), same entry type (<type>), similar data flow.
HYPOTHESIS:  <candidate_func> contains a variant of <cve_id> where <specific_similarity>.
BECAUSE:     The decomposed pattern matches on <N> of 4 components: entry type,
             data flow shape, missing check type, and sink operation.
TEST:        /audit <module> <candidate_func>
             /taint <module> <candidate_func>
REFUTES IF:  The candidate has the check that was missing in the original, or the
             data flow does not actually reach the sink, or the entry point is not
             externally reachable.
CONFIRMS IF: Same check is missing, same data flow shape confirmed by taint,
             entry point is reachable with attacker-controlled parameters.
NEXT:        Adapt the original CVE's PoC to target the new function.
```
