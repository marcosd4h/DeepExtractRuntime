# Classification Reference

Detailed reference for the function classification taxonomy, signal sources, scoring algorithm, and API category definitions.

## Signal Sources

The classifier uses five signal sources in priority order:

### 1. Mangled Name Patterns (weight: 12.0)

Most reliable signal -- Microsoft C++ mangled names encode class/method semantics.

| Prefix | Category | Meaning |
|--------|----------|---------|
| `??0` | `initialization` | Constructor `Class::Class()` |
| `??1` | `resource_management` | Destructor `Class::~Class()` |
| `??_G` | `resource_management` | Scalar deleting destructor |
| `??_7` | `compiler_generated` | VFTable data |

### 2. Function Name Patterns (weight: 10.0)

Name-based heuristics matched in order; first match wins.

**Telemetry** (`telemetry`): `Wpp*`, `_tlg*`, `wil_*`, `TraceLogging*`, `ETW*`, `*Telemetry*`

**Compiler-generated** (`compiler_generated`): `__security*`, `_guard_*`, `__GSHandler*`, `_CRT_*`, `__scrt_*`, `_initterm*`, `__C_specific_handler`, `_RTC_*`, `__report_rangecheckfailure`, `memcpy`, `memset`, `memmove`, `memcmp`

**Initialization** (`initialization`): `DllMain`, `ServiceMain`, `WinMain`, `main`, `*Init*`, `*Initialize*`, `Register*`, `Setup*`, `Configure*`, `Start*`

**Resource management** (`resource_management`): `*Cleanup`, `Free*`, `*Destroy`, `Alloc*`, `Release*`, `Close*`

**Dispatch/routing** (`dispatch_routing`): `*Dispatch*`, `*Handler`, `*Callback`, `On*`, `Process*Message`, `Process*Request`

**Data parsing** (`data_parsing`): `*Parse*`, `*Serialize*`, `*Convert*`, `*Decode*`, `*Encode*`, `*Format*`, `*Validate*`, `Read*Config`, `Write*Config`

**Error handling** (`error_handling`): `*LogError*`, `*ReportError*`, `*HandleError*`, `Fail*`, `OnFailure`, `OnError`

### 3. API-Based Classification (weight: 5.0 per API, capped at 25.0)

Outbound xrefs from `simple_outbound_xrefs` are matched against API prefix tables. Data refs (`function_type=4`) and vtable refs (`function_type=8`) are excluded.

Import prefixes are stripped: `__imp_`, `_imp_`, `j_`, `cs:`.

**API categories and key prefixes:**

| Category | Representative APIs |
|----------|-------------------|
| `file_io` | CreateFile, ReadFile, WriteFile, DeleteFile, FindFirstFile, GetTempPath, NtCreateFile |
| `registry` | RegOpenKey, RegQueryValue, RegSetValue, RegCreateKey, NtOpenKey, NtQueryValueKey |
| `network` | WSAStartup, connect, send, recv, WinHttpOpen, InternetOpen, HttpOpenRequest |
| `process_thread` | CreateProcess, ShellExecute, CreateThread, OpenProcess, TerminateProcess, CreateRemoteThread |
| `crypto` | BCrypt*, NCrypt*, Crypt*, CertOpen*, CertFind*, CertVerify* |
| `security` | CheckTokenMembership, AdjustTokenPrivileges, OpenProcessToken, AccessCheck, ConvertSidToStringSid |
| `com_ole` | CoCreateInstance, CoInitializeEx, CoGetClassObject, OleInitialize, CLSIDFromProgID |
| `rpc` | RpcServerListen, NdrClientCall, RpcBindingFromStringBinding, NdrAsyncClientCall |
| `ui_shell` | MessageBox, CreateWindow, DialogBox, GetMessage, DispatchMessage, LoadString, ShellExecuteEx |
| `sync` | EnterCriticalSection, WaitForSingleObject, CreateEvent, CreateMutex, AcquireSRWLockExclusive |
| `memory` | VirtualAlloc, HeapAlloc, MapViewOfFile, LocalAlloc, RtlAllocateHeap |
| `string_manipulation` | lstrcpy, MultiByteToWideChar, StringCchCopy, sprintf, wcsncpy |
| `service` | StartServiceCtrlDispatcher, RegisterServiceCtrlHandler, OpenSCManager, SetServiceStatus |
| `error_handling` | SetLastError, GetLastError, FormatMessage, RaiseException, _CxxThrowException |
| `telemetry` | EventRegister, EventWrite, TraceEvent, WppAutoLogStart, TlgWrite |
| `debug_diagnostics` | OutputDebugString, IsDebuggerPresent, ReadProcessMemory, MiniDumpWriteDump |

See `helpers/api_taxonomy.py:API_TAXONOMY` for the complete list of ~500 API prefixes (canonical source shared by all skills).

### 4. String Content Analysis (weight: 2.0 per pattern, capped at 10.0)

String literals are matched against content patterns:

| Pattern | Category | Example Match |
|---------|----------|---------------|
| `\Registry\`, `HKEY_`, `SOFTWARE\` | `registry` | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft` |
| `ncalrpc:`, `ncacn_np:`, `ncacn_ip_tcp:` | `com_rpc` | `ncalrpc:[appinfo]` |
| `\\.\pipe\` | `com_rpc` | `\\.\pipe\appinfo` |
| `http://`, `https://`, `ftp://` | `network` | `https://microsoft.com/...` |
| `Microsoft-Windows-` | `telemetry` | `Microsoft-Windows-AppInfo` |
| `%d`, `%s`, `%x`, `%08x` | `data_parsing` | `Error %d: %s` |

### 5. Structural Analysis (weight: 4.0)

Assembly and loop metrics provide supporting evidence:

| Pattern | Category | Threshold |
|---------|----------|-----------|
| Many loops + high complexity | `data_parsing` | loops >= 3, cyclomatic >= 5 |
| Many branches + calls, few loops | `dispatch_routing` | branches > 15, calls > 5, loops <= 1 |
| Tiny function | `utility` | < 10 assembly instructions |
| Leaf function | `utility` | 0 calls, < 20 instructions |

Assembly metrics extracted from `assembly_code`:
- **Instruction count**: total non-empty, non-comment lines
- **Call count**: lines containing `call` mnemonic
- **Branch count**: conditional jumps (je, jne, jz, jnz, jg, jl, ja, jb, etc.)
- **Return count**: `ret`/`retn` instructions
- **Syscall detection**: `syscall` or `int 2Eh` instructions

## Scoring Algorithm

For each function, signals accumulate into per-category scores:

```
score[category] += weight * match_count  (capped per signal source)
```

The primary category is the one with the highest total score. Secondary categories are the next two highest-scoring (if > 0). If no signals match, the function is classified as `unknown`.

### Weight Summary

| Signal Source | Weight | Cap |
|---|---|---|
| Mangled name pattern | 12.0 | First match only |
| Function name pattern | 10.0 | First match only |
| API call match | 5.0 each | 25.0 per category |
| String pattern match | 2.0 each | 10.0 per category |
| Structural pattern | 4.0 | Per-rule |

## Interest Score Algorithm

The interest score (0-10) helps prioritize functions for human review:

```
+1 to +3  for dangerous API calls (count, capped at 3)
+1        for 2+ loops
+1        for cyclomatic complexity >= 5
+1        for substantial size (50+ assembly instructions)
+1        for rich string context (3+ string literals)
+1        for having decompiled code
-3        if primary category is telemetry or compiler_generated
-2        if utility AND tiny (<10 instructions)
```

Clamped to [0, 10].

## DB Fields Used

| Field | Usage |
|---|---|
| `function_name` | Name pattern matching |
| `mangled_name` | C++ role detection (ctor/dtor/vftable) |
| `simple_outbound_xrefs` | API call classification |
| `string_literals` | Content pattern analysis |
| `assembly_code` | Instruction/call/branch counting |
| `loop_analysis` | Loop count and cyclomatic complexity |
| `dangerous_api_calls` | Interest score boosting |
| `decompiled_code` | Presence check for interest score |

## Extending the Classifier

To add new API categories or patterns, edit `scripts/_common.py`:

- **New API category**: Add entries to `helpers/api_taxonomy.py:API_TAXONOMY` dict (shared by all skills)
- **New name pattern**: Add tuple to `NAME_RULES` list (compiled regex, category, description)
- **New string pattern**: Add tuple to `STRING_RULES` list
- **New structural rule**: Add logic in `classify_function()` after the structural section

The classifier is designed to be extended without modifying the script entry points.
