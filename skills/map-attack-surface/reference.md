# Attack Surface Mapper -- Technical Reference

## Entry Point Type Taxonomy

### Tier 1: Explicit (highest confidence)

| Type | Enum | Source | Description |
|---|---|---|---|
| DLL Export | `EXPORT_DLL` | `file_info.exports` | Named exported functions callable by any DLL consumer |
| Ordinal-Only Export | `EXPORT_ORDINAL_ONLY` | `file_info.exports` | Exports without names; harder to discover but still callable |
| Forwarded Export | `FORWARDED_EXPORT` | `file_info.exports` | Export forwarded to another DLL; the other DLL is the real target |
| Main Entry | `MAIN_ENTRY` | `file_info.entry_point` + name | main/WinMain/wmain/wWinMain |
| DllMain | `DLLMAIN` | `file_info.entry_point` + name | DllMain/DllEntryPoint; called on DLL load/unload |
| ServiceMain | `SERVICE_MAIN` | `file_info.entry_point` + name + API | ServiceMain/SvcMain; Windows service entry |
| TLS Callback | `TLS_CALLBACK` | `file_info.tls_callbacks` | PE TLS callbacks; execute before main/DllMain |

### Tier 2: Interface-Based (high confidence)

| Type | Enum | Source | Description |
|---|---|---|---|
| COM Method | `COM_METHOD` | `functions.vtable_contexts` | Methods on COM interfaces (IUnknown-derived vtables) |
| WinRT Method | `WINRT_METHOD` | `functions.vtable_contexts` | WRL/WinRT activation factory and interface methods |
| COM Class Factory | `COM_CLASS_FACTORY` | Export names + API calls | DllGetClassObject, DllCanUnloadNow, CoRegisterClassObject |

### Tier 3: Protocol Handlers (high value)

| Type | Enum | Source | Description |
|---|---|---|---|
| RPC Handler | `RPC_HANDLER` | API calls + name patterns + strings | RPC server-side stubs and dispatch functions |
| Named Pipe Handler | `NAMED_PIPE_HANDLER` | API calls + string patterns | Named pipe server/dispatcher functions |
| IPC Dispatcher | `IPC_DISPATCHER` | ALPC/LPC API calls + strings | ALPC, LPC, mailslot, shared memory handlers |
| TCP/UDP Handler | `TCP_UDP_HANDLER` | Socket API clusters + strings | Socket accept/recv loops, HTTP request handlers |

### Tier 4: Callback-Based (medium confidence)

| Type | Enum | Source | Description |
|---|---|---|---|
| Callback Registration | `CALLBACK_REGISTRATION` | Outbound xrefs to registration APIs | Functions passed to CreateThread, etc. |
| Window Procedure | `WINDOW_PROC` | Name patterns + RegisterClass targets | Window/dialog message handlers |
| Service Ctrl Handler | `SERVICE_CTRL_HANDLER` | RegisterServiceCtrlHandler targets | Service control request handlers |
| Scheduled Callback | `SCHEDULED_CALLBACK` | Timer/APC/threadpool registration | SetTimer, QueueUserAPC, threadpool targets |
| Hook Procedure | `HOOK_PROCEDURE` | SetWindowsHookEx targets | Windows hook callback functions |
| Exception Handler | `EXCEPTION_HANDLER` | VEH/SEH registration APIs | Vectored/structured exception handlers |

### Tier 5: Specialized

| Type | Enum | Source | Description |
|---|---|---|---|
| Driver Dispatch | `DRIVER_DISPATCH` | Name patterns | DriverEntry, IRP dispatch routines |

## Scoring Algorithm

### Composite Attack Score (0.0 - 1.0)

```
attack_score = param_signal   * 0.25   # 1.0 if attacker-typed input (buffer+size, string, COM), 0.3 if any params, 0.0 if none
             + danger_reach    * 0.30
             + danger_proximity * 0.15
             + reach_breadth   * 0.15
             + type_bonus      * 0.15
```

### Component Details

**1. Parameter Signal (0.25 weight)**

Parameter signal derived from `param_surface` metadata (boolean: has attacker-typed input).

**2. Dangerous Operations Reachable (0.30 weight)**

BFS traversal of the callgraph from each entry point. Counts how many dangerous API sinks are reachable. Normalized across all entry points in the module.

Dangerous sinks include: `strcpy`, `memcpy`, `CreateProcess`, `ShellExecute`, `VirtualAllocEx`, `WriteProcessMemory`, `RegSetValueEx`, `LoadLibrary`, `send`, `WinHttpSendRequest`, etc. (170+ APIs in the database).

**3. Proximity to Danger (0.15 weight)**

Computed as `1 / (1 + depth_to_first_danger)`. Entry points that can reach a dangerous operation in 1-2 hops score higher than those requiring 5+ hops.

**4. Reachability Breadth (0.15 weight)**

Number of internal functions reachable from the entry point, normalized. Entry points that are "hubs" reaching many functions have more code exposed.

**5. Type Inherent Risk Bonus (0.15 weight)**

| Entry Type | Bonus | Rationale |
|---|---|---|
| RPC_HANDLER | 0.9 | Remote, cross-process, serialized input |
| DRIVER_DISPATCH | 0.9 | Kernel-mode, IRP-based input |
| NAMED_PIPE_HANDLER | 0.85 | Cross-process, often privileged |
| TCP_UDP_HANDLER | 0.85 | Network-accessible |
| IPC_DISPATCHER | 0.8 | Cross-process communication |
| COM_METHOD | 0.7 | Cross-process via DCOM/marshaling |
| COM_CLASS_FACTORY | 0.7 | Controls object instantiation |
| WINRT_METHOD | 0.65 | App container boundary |
| HOOK_PROCEDURE | 0.65 | Cross-process injection vector |
| WINDOW_PROC | 0.6 | Message-driven, can receive crafted messages |
| SERVICE_MAIN | 0.6 | Service entry, often privileged |
| SERVICE_CTRL_HANDLER | 0.55 | Service control, can change service state |
| CALLBACK_REGISTRATION | 0.5 | Indirect entry, context-dependent |
| SCHEDULED_CALLBACK | 0.5 | Timer/APC driven |
| DLLMAIN | 0.5 | Loader-lock constraints limit exploitation |
| MAIN_ENTRY | 0.5 | Primary entry, but usually well-known |
| TLS_CALLBACK | 0.6 | Pre-main execution, often anti-debug |
| EXCEPTION_HANDLER | 0.4 | Triggered by exceptions, harder to control |
| EXPORT_ORDINAL_ONLY | 0.35 | Unnamed but still callable |
| EXPORT_DLL | 0.3 | Standard export, well-known interface |
| FORWARDED_EXPORT | 0.3 | Redirected, real target is elsewhere |

## Tainted Argument Inference

For each entry point, the ranker infers which arguments an attacker can control:

| Parameter Pattern | Taint Level | Label |
|---|---|---|
| `void*`, `char*`, `BYTE*`, `wchar_t*` | Full | `TAINT` |
| `LPWSTR`, `LPSTR`, `BSTR` | Full | `TAINT` |
| `LPVOID`, `PVOID`, `LPBYTE` | Full | `TAINT` |
| `IUnknown*`, `IDispatch*` | Full | `TAINT` |
| `VARIANT`, `SAFEARRAY` | Full | `TAINT` |
| `HANDLE`, `SOCKET` | Partial | `PARTIAL_TAINT` |
| Size/length after buffer | Full | `TAINT (controls buffer bounds)` |

## Callback Registration API Database

The discovery engine monitors calls to 60+ APIs that register callback functions:

- **Thread creation**: CreateThread, CreateRemoteThread, _beginthreadex, RtlCreateUserThread, CreateFiber
- **Timers**: SetTimer, CreateTimerQueueTimer, SetWaitableTimer, timeSetEvent
- **Thread pool**: CreateThreadpoolWork/Timer/Wait/Io, QueueUserWorkItem, RegisterWaitForSingleObject
- **Window procedures**: RegisterClassW/ExW, SetWindowLongPtrW, DialogBoxParamW, CreateDialogParamW
- **APCs**: QueueUserAPC, NtQueueApcThread
- **Hooks**: SetWindowsHookExW/A
- **Exception handlers**: AddVectoredExceptionHandler, SetUnhandledExceptionFilter
- **Service handlers**: RegisterServiceCtrlHandlerW/ExW
- **I/O completion**: ReadFileEx, WriteFileEx, BindIoCompletionCallback
- **Socket callbacks**: WSARecv, WSASend
- **Enumeration**: EnumWindows, EnumChildWindows, EnumDesktopWindows, EnumFontFamiliesExW

## CRS Entrypoints JSON Schema

The `generate_entrypoints_json.py` output follows this schema:

```
version:                    "1.0"
generated_at:               ISO-8601 timestamp
generator:                  "map-attack-surface/generate_entrypoints_json.py"
module:
  file_name:                Binary filename
  md5_hash / sha256_hash:   Content hashes
  file_size_bytes:          File size
  total_functions:          Total functions in the DB
attack_surface_summary:
  total_entry_points:       Count of discovered entry points
  entry_point_coverage:     Percentage of all functions that are entry points
  avg_attack_score:         Mean score across all entry points
  max_attack_score:         Highest individual score
  entry_points_with_danger: Count with reachable dangerous operations
type_distribution:          { type_name -> count }
entry_points[]:
  rank:                     1-based rank
  function_name:            Function name
  attack_score:             0.0-1.0 composite score
  entry_type:               Type enum name
  signature:                Extended function signature
  analysis:
    param_surface:          dict (structured metadata)
    reachable_functions:    Count of reachable internal functions
    dangerous_ops_reachable: Count of dangerous API sinks reachable
    depth_to_first_danger:  BFS depth to nearest danger (null if none)
    dangerous_apis[]:       List of dangerous API names reachable
  tainted_arguments[]:      Recommended taint labels per argument
danger_hotspots[]:
  api:                      Dangerous API name
  reachable_from_n_entrypoints: How many entry points can reach this sink
```
