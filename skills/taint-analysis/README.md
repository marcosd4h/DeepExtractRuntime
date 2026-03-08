# Taint Analysis

Trace attacker-controlled function inputs to dangerous sinks, with guard/bypass detection and logic-effect analysis. Built for vulnerability research.

## Quick Start

```bash
# 1. Find the module DB
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py appinfo.dll

# 2. Run taint analysis
python .agent/skills/taint-analysis/scripts/taint_function.py extracted_dbs/appinfo_dll_e98d25a9e8.db AiLaunchProcess
```

## What It Does

Given a function, marks its parameters as tainted (attacker-controlled) and traces where that data flows:

| Analysis | What It Answers |
|----------|----------------|
| **Sink Reachability** | Does tainted data reach a dangerous API (CreateProcess, memcpy, LoadLibrary)? |
| **Guards to Bypass** | What checks sit between source and sink? Auth, bounds, null, validation? |
| **Attacker Controllability** | Does the attacker control the guard condition, or is it independent? |
| **Logic Effects** | Does tainted data steer branches, index arrays, bound loops, control allocation sizes? |
| **Caller Origins** (backward) | Where does the tainted data come from? Export param, file read, registry? |

## Usage

```bash
# Forward trace all parameters (default)
python .agent/skills/taint-analysis/scripts/taint_function.py <db_path> <function_name>

# Trace specific parameters
python .agent/skills/taint-analysis/scripts/taint_function.py <db_path> <function_name> --params 1,3

# Both forward and backward, deeper recursion
python .agent/skills/taint-analysis/scripts/taint_function.py <db_path> <function_name> --params 1 --depth 3 --direction both

# Backward only (caller origins)
python .agent/skills/taint-analysis/scripts/taint_function.py <db_path> <function_name> --direction backward

# JSON output
python .agent/skills/taint-analysis/scripts/taint_function.py <db_path> --id <fid> --json
```

Individual scripts can also be run directly:

```bash
# Forward only
python .agent/skills/taint-analysis/scripts/trace_taint_forward.py <db_path> <function_name> --params 1,3 --depth 2

# Backward only
python .agent/skills/taint-analysis/scripts/trace_taint_backward.py <db_path> <function_name> --params 1 --depth 2
```

## Example Output

```
==============================================================================
Forward Taint: AiLaunchProcess
==============================================================================
Module: appinfo.dll
Signature: __int64 __fastcall AiLaunchProcess(__int64, __int64, unsigned int, ...)
Tainted params: a1, a3
Depth: 3

--- 2 Finding(s) ---

[1] HIGH (0.72) -- a1 reaches CreateProcessAsUserW (command_execution)
    Path: AiLaunchProcess.a1 -> AiLaunchConsentDialog.a1 -> CreateProcessAsUserW.arg2
    Guards to bypass (2):
      [AUTH_CHECK] AccessCheck(v12, ...) at L58  (attacker-controllable: NO, difficulty: hard)
      [NULL_CHECK] !v3 at L72  (attacker-controllable: NO, difficulty: hard)

[2] MEDIUM (0.45) -- a1 reaches CreateFileW (file_write)
    Path: AiLaunchProcess.a1 -> AiCheckSecureApplicationDirectory.a1 -> CreateFileW.arg1
    Guards to bypass (1):
      [VALIDATION] AiIsEXESafeToAutoApprove(a1) at L34  (attacker-controllable: YES, difficulty: easy)

--- Logic Effects ---
  a1: BRANCH_STEERING at L34 -- if ( AiIsEXESafeToAutoApprove(a1) )
  a3: SIZE_ARGUMENT at L89 -- HeapAlloc(v5, 0, a3)

Summary: 2 sinks | HIGH=1 MEDIUM=1 | 2 params with logic effects
```

## Key Indicators

| Indicator | Risk |
|-----------|------|
| **CRITICAL/HIGH findings** | Tainted data reaches dangerous sinks with few/weak guards |
| **attacker_controllable: YES** | The guard depends on tainted data -- attacker controls the check |
| **bypass_difficulty: easy** | Attacker directly controls inputs to the guard condition |
| **bypass_difficulty: hard** | Guard is independent of tainted data -- must already be satisfied |
| **branch_steering** | Tainted data controls which code path executes |
| **array_index** | Potential out-of-bounds read/write |
| **size_argument** | Tainted data controls allocation or copy size |
| **loop_bound** | Tainted data controls iteration count (DoS) |

## Guard Types

| Guard | Detection |
|-------|-----------|
| `auth_check` | Calls IsAdmin, AccessCheck, CheckTokenMembership, PrivilegeCheck |
| `bounds_check` | Comparisons like `var < CONST`, `len <= size` |
| `null_check` | Null comparisons: `ptr != 0`, `!ptr`, `ptr == NULL` |
| `validation` | Calls matching Validate*, Verify*, Is*Valid, Check*, Ensure* |
| `error_check` | Uses SUCCEEDED(), FAILED(), NT_SUCCESS(), GetLastError() |

## Severity Scoring

Score = sink_weight * (1/sqrt(hops)) * guard_penalty

| Sink Category | Weight | Examples |
|---------------|--------|----------|
| command_execution | 1.0 | CreateProcess, ShellExecute, TerminateProcess, NtCreateProcess, CreateThread |
| code_injection | 0.95 | WriteProcessMemory, CreateRemoteThread, SetThreadContext, CallWindowProc |
| memory_unsafe | 0.9 | strcpy, memcpy, sprintf, RtlCopyMemory, alloca, fgets |
| privilege | 0.85 | AdjustTokenPrivileges, DuplicateHandle, NtCreateToken, RtlAdjustPrivilege |
| code_loading | 0.8 | LoadLibrary, LdrLoadDll, NtLoadDriver, LoadTypeLib |
| named_pipe / device_io / alpc_ipc | 0.75 | CreateNamedPipe, DeviceIoControl, NtAlpcCreatePort |
| file_write / registry_write / service_control | 0.7 | CreateFile, NtSetValueKey, StartService, CreateHardLink |
| com_marshaling / dde | 0.65 | CoCreateInstance, OleLoad, DdeConnect, StgCreateStorage |
| network | 0.6 | connect, URLDownloadToFile, NdrClientCall, WinHttpReadData |
| debug_control | 0.55 | IsDebuggerPresent, MiniDumpWriteDump, NtSystemDebugControl |
| memory_alloc | 0.5 | VirtualAlloc, HeapAlloc, NtMapViewOfSection, NtProtectVirtualMemory |
| process_enum | 0.4 | EnumProcesses, ReadProcessMemory, OpenProcess |

Each hard (non-attacker-controllable) guard reduces score by 0.15.

Bands: CRITICAL >= 0.8, HIGH >= 0.6, MEDIUM >= 0.3, LOW < 0.3

## Files

```
taint-analysis/
├── SKILL.md                    # Agent skill instructions (read by Cursor)
├── reference.md                # Technical reference (propagation rules, guard types, scoring)
├── README.md                   # This file
└── scripts/
    ├── _common.py              # Bootstrapping, param inference, severity scoring, logic effects
    ├── taint_function.py       # Orchestrator -- entry point for full analysis
    ├── trace_taint_forward.py  # Forward propagation with sink + guard + effect detection
    ├── trace_taint_backward.py # Backward caller chain origin analysis
    └── generate_taint_report.py# Dual JSON + markdown report generation
```

## Dependencies

- Python 3.10+
- `.agent/helpers/` module -- provides `api_taxonomy`, `callgraph`, `guard_classifier`, `decompiled_parser`
- `.agent/skills/data-flow-tracer/` -- `forward_trace.py` and `backward_trace.py` (invoked via subprocess)
- SQLite analysis databases from DeepExtractIDA

## Related Skills

- [security-dossier](../security-dossier/SKILL.md) -- Build security dossiers before taint analysis
- [data-flow-tracer](../data-flow-tracer/SKILL.md) -- Lower-level forward/backward data flow tracing
- [callgraph-tracer](../callgraph-tracer/SKILL.md) -- Trace call chains across modules
- [map-attack-surface](../map-attack-surface/SKILL.md) -- Map entry points and rank by attack value
- [code-lifting](../code-lifting/SKILL.md) -- Lift flagged functions to clean code for review
- [verify-decompiled](../verify-decompiled/SKILL.md) -- Verify decompiler accuracy on flagged functions
