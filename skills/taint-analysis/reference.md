# Taint Analysis -- Technical Reference

## Taint Propagation Rules

### Forward propagation

1. A parameter `aN` of the target function is marked **tainted**.
2. Any function call that receives a tainted variable as an argument propagates taint to that callee's corresponding parameter.
3. If a tainted variable is assigned to a local (`v3 = a1`), the local inherits the taint.
4. Taint propagates through pointer dereferences (`*a1`, `a1->field`).
5. Taint does **not** propagate through constants, string literals, or values returned by unrelated calls.
6. Recursion depth is controlled by `--depth` (default 2).

### Backward propagation

1. For each tainted parameter, find all callers via `CallGraph.callers_of()` and inbound xrefs.
2. For each caller, use `backward_trace.py --target <our_function>` to determine what expression the caller passes for the tainted parameter.
3. Classify each origin expression: `parameter` (high risk), `call_result`, `global`, `constant` (no risk), `local_variable` (trace further), `string_literal`.

## Guard Classification

Guards are `if`/`while` conditions found between the taint source line and a sink line.

### Guard types

| Type | Detection method |
|------|-----------------|
| `auth_check` | Condition calls a known auth API (IsAdmin, AccessCheck, CheckTokenMembership, PrivilegeCheck, etc.) |
| `bounds_check` | Condition contains a comparison pattern: `var < CONST`, `len <= size` |
| `null_check` | Condition contains null comparison: `ptr != 0`, `!ptr`, `ptr == NULL` |
| `validation` | Condition calls an API matching Validate*, Verify*, Is*Valid, Check*, Ensure* |
| `error_check` | Condition uses SUCCEEDED(), FAILED(), NT_SUCCESS(), GetLastError() |
| `function_check` | Condition calls a non-categorized function |
| `comparison` | Generic comparison without matching any pattern above |

### Bypass difficulty

| Level | Meaning |
|-------|---------|
| `easy` | All variables in the condition are tainted -- attacker fully controls the check |
| `medium` | Some variables are tainted, some are not -- partial attacker influence |
| `hard` | No tainted variables in the condition -- guard must already be satisfied (attacker cannot bypass directly) |

## Sink Categories

Sinks are detected via `classify_sink()` in `_common.py`, which first tries the shared `classify_api_security()` from `helpers/api_taxonomy.py`, then falls back to an extended prefix table covering ~250 additional APIs sourced from `DeepExtractIDA/deep_extract/data/dangerous_apis.json`.

### Core categories (from shared taxonomy)

| Category | Weight | Example APIs |
|----------|--------|-------------|
| `command_execution` | 1.0 | CreateProcess, ShellExecute, WinExec, system, TerminateProcess, NtCreateProcess, CreateThread |
| `code_injection` | 0.95 | WriteProcessMemory, CreateRemoteThread, QueueUserAPC, SetThreadContext, NtQueueApcThread, CallWindowProc |
| `memory_unsafe` | 0.9 | strcpy, sprintf, memcpy, memmove, gets, fgets, RtlCopyMemory, alloca, MultiByteToWideChar |
| `privilege` | 0.85 | AdjustTokenPrivileges, ImpersonateLoggedOnUser, DuplicateHandle, NtCreateToken, RtlAdjustPrivilege, SetNamedSecurityInfo |
| `code_loading` | 0.8 | LoadLibrary, GetProcAddress, LdrLoadDll, NtLoadDriver, LoadTypeLib |

### Extended categories (taint-specific)

| Category | Weight | Example APIs |
|----------|--------|-------------|
| `named_pipe` | 0.75 | CreateNamedPipe, ConnectNamedPipe, PeekNamedPipe, NtCreateNamedPipeFile |
| `device_io` | 0.75 | DeviceIoControl, NtDeviceIoControlFile, NtFsControlFile |
| `alpc_ipc` | 0.75 | NtAlpcCreatePort, NtCreatePort, NtConnectPort, NtSecureConnectPort |
| `file_write` | 0.7 | CreateFile, WriteFile, DeleteFile, CreateHardLink, NtCreateFile, ReplaceFile, SHFileOperation |
| `registry_write` | 0.7 | RegSetValue, RegCreateKey, NtSetValueKey, RtlWriteRegistryValue, SHRegSetValue |
| `service_control` | 0.7 | StartService, ControlService, DeleteService, CreateService, ChangeServiceConfig |
| `com_marshaling` | 0.65 | CoCreateInstance, OleLoad, CoMarshalInterface, StgCreateStorage, CoGetObject |
| `dde` | 0.65 | DdeInitialize, DdeConnect, DdeCreateDataHandle, DdeAccessData |
| `network` | 0.6 | connect, send, socket, URLDownloadToFile, WinHttpReadData, InternetReadFile, NdrClientCall |
| `debug_control` | 0.55 | IsDebuggerPresent, MiniDumpWriteDump, NtDebugActiveProcess, NtSystemDebugControl |
| `memory_alloc` | 0.5 | VirtualAlloc, HeapAlloc, MapViewOfFile, NtMapViewOfSection, NtProtectVirtualMemory |
| `process_enum` | 0.4 | EnumProcesses, CreateToolhelp32Snapshot, ReadProcessMemory, OpenProcess |
| `wow64` | 0.35 | Wow64DisableWow64FsRedirection, Wow64RevertWow64FsRedirection |

Category `sync` is not flagged as a taint sink (it is security-relevant for race conditions but not a direct exploitation target from tainted data).

## Logic Effects

Beyond sinks, tainted data can affect internal logic in exploitable ways:

| Effect | Pattern | Risk |
|--------|---------|------|
| `branch_steering` | Tainted var appears in `if`/`while` condition | Attacker controls code path selection |
| `array_index` | Tainted var used as array index `arr[aN]` | Potential out-of-bounds read/write |
| `loop_bound` | Tainted var controls loop iteration count | Denial of service, excessive computation |
| `size_argument` | Tainted var passed as size to alloc/memcpy | Integer overflow, heap overflow |
| `returned` | Tainted var is returned from the function | Taint propagates to callers |

## Severity Scoring Formula

```
score = sink_weight * (1 / sqrt(path_hops)) * guard_penalty
```

Where:
- `sink_weight` is from the sink category table above
- `path_hops` is the number of call hops from source to sink
- `guard_penalty = max(0.0, 1.0 - 0.15 * non_tainted_guard_count)`

Severity bands:
- **CRITICAL**: score >= 0.8
- **HIGH**: 0.6 <= score < 0.8
- **MEDIUM**: 0.3 <= score < 0.6
- **LOW**: score < 0.3
