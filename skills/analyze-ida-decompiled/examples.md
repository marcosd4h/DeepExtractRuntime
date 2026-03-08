# Analysis Examples

These examples use real data from the `appinfo_dll` extraction (Windows Application Information Service).

## Example 1: Orienting in a Module

**User asks:** "What is appinfo.dll and what does it do?"

**Approach:** Read `file_info.json` metadata sections.

```json
// basic_file_info
"file_name": "appinfo.dll",
"size_bytes": 413696,
"md5_hash": "e98d25a9e871f83d0f05e0ea27d315bc"

// pe_version_info
"company_name": "Microsoft Corporation",
"product_name": "Microsoft® Windows® Operating System",
"file_description": "Application Information Service"
```

Then check `function_summary` for scope:
- **Total functions**: 1173
- **Classes**: BinaryAndStrategy, CCommandLineParser, LUATelemetry (53 methods), RateLimiter, SlidingWindowStrategy, StateRepository (45 methods), Windows (42 methods), wil (428 methods), plus many lambda classes
- **Standalone functions**: ~900+ functions

**Answer:** `appinfo.dll` is the Windows Application Information Service (AIS), responsible for UAC elevation decisions and application compatibility. It has ~1173 decompiled functions, with major classes including `LUATelemetry` (elevation telemetry), `StateRepository` (state persistence), and `RateLimiter` (throttling). The `wil` class (428 methods) is Windows Implementation Library infrastructure.

---

## Example 2: Finding and Analyzing a Specific Function

**User asks:** "How does AiCheckSecureApplicationDirectory work?"

**Step 1: Locate the function.**

Search `function_summary.standalone_functions` in `file_info.json`:
```json
{ "name": "AiCheckSecureApplicationDirectory", "signature": "unsigned long AiCheckSecureApplicationDirectory(unsigned short const *, unsigned long *)" }
```

It's a standalone function, so search in `appinfo_dll_standalone_group_*.cpp` files. Found in `appinfo_dll_standalone_group_9.cpp`.

**Step 2: Read the comment header.**

```cpp
// Function Name: AiCheckSecureApplicationDirectory
// Mangled Name: ?AiCheckSecureApplicationDirectory@@YAKPEBGPEAK@Z
// Function Signature (Extended): unsigned int AiCheckSecureApplicationDirectory(const unsigned __int16 *, unsigned int *)
// Function Signature: unsigned long AiCheckSecureApplicationDirectory(unsigned short const *, unsigned long *)
```

Parameters: `a1` = path string (LPCWSTR), `a2` = output result pointer.

**Step 3: Trace the logic.**

```cpp
FileW = CreateFileW(a1, 0x80000000, 5u, 0, 3u, 0x2000000u, 0);
//       CreateFileW(path, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_DELETE,
//                   NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL)
```

The function opens the directory, resolves its final path via `GetFinalPathNameByHandleW`, then uses `RtlDosPathNameToRelativeNtPathName_U_WithStatus` and `RtlEqualUnicodeString` to validate it against a secure path.

**Step 4: Look up Win32 APIs in imports.**

```json
{
    "function_name": "CreateFileW",
    "function_signature_extended": "HANDLE (__stdcall *CreateFileW)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)",
    "module_name": "kernel32.dll"
}
```

**Answer:** `AiCheckSecureApplicationDirectory` validates whether an application's directory is in a secure location. It opens the directory, resolves the final NT path (following symlinks/junctions), and compares it against expected secure paths. Returns 0 on success, or a Win32 error code.

---

## Example 3: Analyzing a Class Method (Grouped File)

**User asks:** "What does LUATelemetry::AppXSyncActivity::StartActivity do?"

**Step 1: Find the class.**

In `function_summary.class_methods`:
```json
{ "class_name": "LUATelemetry", "method_count": 53 }
```

Search `appinfo_dll_LUATelemetry_group_*.cpp` files for `StartActivity`.

**Step 2: Read the function.**

Found in `appinfo_dll_LUATelemetry_group_1.cpp`:
```cpp
// Function Name: LUATelemetry::AppXSyncActivity::StartActivity
// Mangled Name: ?StartActivity@AppXSyncActivity@LUATelemetry@@QEAAXXZ
void __fastcall LUATelemetry::AppXSyncActivity::StartActivity(LUATelemetry::AppXSyncActivity *this)
{
  wil::ActivityBase<...>::zInternalStart((__int64)this);
  v2 = LUATelemetry::Instance();
  // ... ETW telemetry event writing via _tlgWriteTemplate ...
  wil::ActivityBase<...>::EnsureWatchingCurrentThread((__int64)this);
}
```

**Answer:** This starts a WIL activity for AppX sync telemetry. It initializes the activity via `zInternalStart`, gets the telemetry provider singleton, writes an ETW event with the current thread ID using TraceLogging, and ensures the current thread is being monitored for activity completion.

---

## Example 4: Tracing an Entry Point

**User asks:** "What happens when the service starts?"

**Step 1: Check entry_points in file_info.json.**

```json
{
    "function_name": "ServiceMain(ulong,ushort * *)",
    "function_signature_extended": "void __fastcall ServiceMain(unsigned int, unsigned __int16 **)",
    "ordinal": 3,
    "is_primary": false,
    "confidence": 95.0
}
```

**Step 2: Find ServiceMain in the code.**

Located in `appinfo_dll_standalone_group_68.cpp`. The function:
1. Initializes multiple `RateLimiter` instances (for various event types)
2. Sets up RPC binding vectors for the service's RPC interface
3. Creates additional rate limiters for "garrulous events"
4. Registers the service control handler

**Step 3: Follow the call chain.**

From `ServiceMain`, trace calls to:
- `RateLimiter::New` -> found in `appinfo_dll_RateLimiter_group_1.cpp`
- `SlidingWindowStrategy::*` -> rate limiting strategy implementation
- RPC server functions in imports -> `RpcServerUseProtseqEpW`, etc.

---

## Example 5: Cross-Referencing Imports

**User asks:** "What security-sensitive APIs does this module use?"

**Approach:** Scan `imports` in `file_info.json` for notable APIs:

```
kernel32.dll: CreateProcessAsUserW, CreateProcessW, OpenProcess, OpenThread
advapi32.dll: SetSecurityInfo, GetTokenInformation, ImpersonateLoggedOnUser
              RevertToSelf, AdjustTokenPrivileges, RegOpenKeyExW
ntdll.dll:    NtQueryInformationProcess, NtSetInformationFile
rpcrt4.dll:   RpcServerRegisterIf3, RpcImpersonateClient
```

These APIs indicate `appinfo.dll` handles:
- **Process creation with alternate credentials** (UAC elevation via `CreateProcessAsUserW`)
- **Token manipulation** (impersonation, privilege adjustment)
- **RPC server** (remote procedure call interface for elevation requests)
- **Registry access** (policy and configuration)

---

## Example 6: Understanding Grouped File Structure

Each grouped file contains multiple functions separated by comment headers. To find a specific function:

1. **Know the function name** -- search across `*_group_*.cpp` for `// Function Name: YourFunction`
2. **Know the class** -- narrow to `{module}_{ClassName}_group_*.cpp` files first
3. **Browse alphabetically** -- functions within each group are in alphabetical order

For example, in `appinfo_dll_standalone_group_9.cpp`:
```
// Function Name: AiCheckLUA                         (line ~1)
// Function Name: AiCheckSecureApplicationDirectory  (line ~114)
// Function Name: AiCreateProcess                    (line ~200)
```

Functions starting with "Ai" (Application Information) are grouped nearby because of alphabetical ordering.
