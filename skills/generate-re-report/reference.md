# Report Generation Reference

Detailed reference for section data sources, API taxonomy categories, string categorization patterns, and Rich header decoding.

## Report Sections vs Data Sources

| Section | DB Fields Used | Script |
|---|---|---|
| 1. Executive Summary | `file_info.*`, imports, function count | `generate_report.py` |
| 2. Provenance & Build | `rich_header`, `pdb_path`, `time_date_stamp_str`, `is_net_assembly`, `clr_metadata` | `generate_report.py` |
| 3. Security Posture | `security_features`, `dll_characteristics`, `load_config`, `sections`, `stack_frame.has_canary` | `generate_report.py` + `analyze_complexity.py` |
| 4. External Interface | `imports`, `exports` | `analyze_imports.py` |
| 5. Internal Architecture | `function_name` (class detection via `::`), `mangled_name` | `generate_report.py` |
| 6. Complexity Hotspots | `loop_analysis`, `simple_inbound_xrefs`, `simple_outbound_xrefs`, `global_var_accesses`, `assembly_code`, `analysis_errors`, `stack_frame` | `analyze_complexity.py` |
| 7. String Intelligence | `string_literals` (all functions) | `analyze_strings.py` |
| 8. Cross-Reference Topology | `simple_outbound_xrefs`, `simple_inbound_xrefs`, `exports`, `entry_point` | `analyze_topology.py` |
| 9. Anomalies | `tls_callbacks`, `analysis_errors`, `assembly_code` (size), `global_var_accesses` | `generate_report.py` |
| 10. Recommendations | All above (synthesis) | `generate_report.py` |

## API Taxonomy Categories

The import categorizer maps ~500 Win32/NT API name prefixes to 15 categories. Each import function name is tested with `startswith()` after stripping `__imp_`/`_imp_`/`j_`/`cs:` prefixes.

| Category | Description | API Count | Examples |
|---|---|---|---|
| `file_io` | File/directory operations | ~50 | CreateFile, ReadFile, WriteFile, FindFirstFile, PathFileExists, SHGetKnownFolderPath |
| `registry` | Registry read/write | ~30 | RegOpenKey, RegQueryValue, RegSetValue, NtOpenKey, NtQueryValueKey |
| `network` | Sockets, HTTP, WinHTTP | ~50 | WSAStartup, connect, send, recv, WinHttpOpen, InternetOpen |
| `process_thread` | Process/thread management | ~35 | CreateProcess, OpenProcess, CreateThread, ShellExecute, QueueUserAPC |
| `crypto` | Encryption, hashing, certs | ~50 | BCrypt*, NCrypt*, Crypt*, CertOpenStore, CertFindCertificateInStore |
| `security` | Tokens, privileges, ACLs | ~45 | CheckTokenMembership, OpenProcessToken, AccessCheck, ConvertSidToStringSid |
| `com_ole` | COM/OLE operations | ~20 | CoCreateInstance, CoInitializeEx, OleInitialize, CLSIDFromString |
| `rpc` | RPC/NDR calls | ~20 | RpcServerListen, NdrClientCall, RpcBindingFromStringBinding |
| `memory` | Memory allocation/mapping | ~30 | VirtualAlloc, HeapAlloc, MapViewOfFile, RtlAllocateHeap |
| `ui_shell` | Window/shell operations | ~35 | MessageBox, CreateWindow, ShellExecuteEx, LoadLibrary |
| `sync` | Synchronization primitives | ~30 | EnterCriticalSection, WaitForSingleObject, CreateEvent, AcquireSRWLock |
| `string_manipulation` | String operations | ~40 | lstrcpy, MultiByteToWideChar, StringCchCopy, sprintf |
| `error_handling` | Error/exception handling | ~12 | SetLastError, GetLastError, FormatMessage, RaiseException |
| `service` | Windows service management | ~15 | StartServiceCtrlDispatcher, OpenSCManager, CreateService |
| `telemetry` | ETW/WPP/TraceLogging | ~30 | EventWrite, TraceEvent, WppAutoLogStart, TlgWrite |
| `debug_diagnostics` | Debug/diagnostic APIs | ~12 | OutputDebugString, IsDebuggerPresent, ReadProcessMemory |

The full taxonomy is in `helpers/api_taxonomy.py:API_TAXONOMY` (canonical source shared by all skills). Each category lists API prefixes that match via `startswith()`, so `CreateFileW`, `CreateFileA`, `CreateFileMappingW` all match the `CreateFile` prefix under `file_io`.

## String Categorization Patterns

String literals are categorized by regex matching:

| Category | Pattern | Examples |
|---|---|---|
| `file_path` | Drive letters, device paths, env vars, system paths, PE extensions | `C:\Windows\System32\...`, `%SystemRoot%\...` |
| `registry_key` | `\Registry\`, `HKEY_*`, `SOFTWARE\`, `CurrentControlSet` | `HKLM\SOFTWARE\Microsoft\...` |
| `url` | `http://`, `https://`, `ftp://`, `wss://` | `https://api.microsoft.com/...` |
| `rpc_endpoint` | `ncalrpc:`, `ncacn_np:`, `ncacn_ip_tcp:` | `ncalrpc:[appinfo]` |
| `named_pipe` | `\\.\pipe\` patterns | `\\.\pipe\appinfo` |
| `etw_provider` | `Microsoft-Windows-*` | `Microsoft-Windows-AppInfo` |
| `guid` | `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` | `{12345678-1234-1234-1234-123456789abc}` |
| `error_message` | error, fail, invalid, denied, refused, exception | `Access denied`, `Invalid parameter` |
| `format_string` | printf-style `%d`, `%s`, `%x`, etc. | `Error %d: %s` |
| `debug_trace` | TraceLogging, TRACE_LEVEL, ETW_KEYWORD, WPP_ | `TRACE_LEVEL_VERBOSE` |

Patterns are checked in order; first match wins. Defined in `scripts/_common.py:STRING_CATEGORIES`.

## Rich Header Decoding

The Rich header contains build toolchain metadata. Each entry has `product_id` (tool type) and `build_number` (compiler version).

### Tool Types (product_id)

| ID Range | Tool |
|---|---|
| 0 | Unmarked objects |
| 2, 4, 14 | Linker |
| 5 | CVTRES (resource compiler) |
| 6, 261 | MASM |
| 7, 40, 45, 83, 94, 96, 255, 257 | Utc C compiler |
| 8, 41, 84, 93, 95, 105, 256, 258, 260 | Utc C++ compiler |
| 10 | Resource compiler |

### MSVC Version Mapping (build_number / 100)

| Major | Version |
|---|---|
| 14.40 | VS 2022 17.10+ |
| 14.30-14.39 | VS 2022 17.0-17.9 |
| 14.20-14.29 | VS 2019 16.0-16.11 |
| 14.10-14.16 | VS 2017 15.0-15.9 |
| 14.00 | VS 2015 |
| 12.00 | VS 2013 |
| 11.00 | VS 2012 |
| 10.00 | VS 2010 |

## Topology Algorithms

### Entry Point Reachability
BFS from each export/entry point through `simple_outbound_xrefs` edges. Reports count and percentage of total functions reachable.

### Dead Code Detection
Functions with zero `simple_inbound_xrefs` entries that are not in the export/entry point set. Excludes compiler-generated functions (`__*`, `_guard_*`).

### Strongly Connected Components
Tarjan's SCC algorithm on the call graph. Groups with >1 member indicate mutual recursion.

### Bottleneck Score
Approximate betweenness: `inbound_count * outbound_count` for functions with >= 3 inbound and >= 3 outbound edges.

## Function Size Buckets

| Bucket | Assembly Instructions |
|---|---|
| Tiny | 0-9 |
| Small | 10-49 |
| Medium | 50-199 |
| Large | 200-499 |
| Huge | 500+ |

## Extending the Report

### Adding API categories
Edit `helpers/api_taxonomy.py:API_TAXONOMY` -- add a new category key with list of API name prefixes. This is the canonical source shared by all skills.

### Adding string patterns
Edit `scripts/_common.py:STRING_CATEGORIES` -- add a tuple of `(compiled_regex, category, description)`.

### Adding report sections
Implement a new `_section_*` function in `generate_report.py` and add it to the `generate_report()` function's section list.

### Adding analyzer scripts
Follow the pattern: import `_common`, define `analyze_*()` returning a dict, `format_*_report()` returning markdown, `main()` with argparse. Import into `generate_report.py`.
