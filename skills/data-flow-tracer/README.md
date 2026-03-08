# Data Flow & Taint Tracer

Answer: **"Where does this data come from and where does it go?"**

Traces how specific data moves through extracted Windows PE binaries -- forward parameter flow into callees, backward argument origin from API calls, global variable producer/consumer maps, and string literal usage chains. Purely for understanding data relationships; no security judgments.

## Quick Start

```bash
# 1. Find the module DB
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py appinfo.dll

# 2. Forward trace: where does parameter 2 flow?
python .agent/skills/data-flow-tracer/scripts/forward_trace.py extracted_dbs/appinfo_dll_e98d25a9e8.db AiCheckLUA --param 2

# 3. Backward trace: where does CreateFileW's 1st argument come from?
python .agent/skills/data-flow-tracer/scripts/backward_trace.py extracted_dbs/appinfo_dll_e98d25a9e8.db AiCheckSecureApplicationDirectory --target CreateFileW --arg 1 --callers

# 4. Global state map: who reads/writes each global?
python .agent/skills/data-flow-tracer/scripts/global_state_map.py extracted_dbs/cmd_exe_6d109a3a00.db --summary

# 5. String trace: which functions use this string?
python .agent/skills/data-flow-tracer/scripts/string_trace.py extracted_dbs/coredpus_dll_319f60b0a5.db --string "wapdpu" --callers
```

## Scripts

| Script | Purpose |
|--------|---------|
| `forward_trace.py` | Track where a function parameter flows: which calls receive it, which globals it's written to, whether it's returned |
| `backward_trace.py` | Find where an API call's arguments originate: parameter, return value, global, constant, or expression |
| `global_state_map.py` | Build a producer/consumer map for all global variables in a module |
| `string_trace.py` | Find functions referencing a string, show code context, and trace caller chains |

## Example Output

### forward_trace.py

```
================================================================================
[Start] Forward trace: AiCheckLUA  param 2 (a2)
================================================================================
Module: appinfo.dll
Signature: unsigned long AiCheckLUA(unsigned long, unsigned long *, ...)

References to 'a2' (10 lines):
  L  32: v16 = AipRequireElevationPrompt(a1, a2, a4);
  L  35: v17 = *a2;
  L  44: *a2 = *a2 & 0xFFF7FFF7 | 8;
  L  53: v18 = AiLaunchConsentUI(a4, a5, a6, a7, TokenInformation, *a2, a3, a9, a10, &TokenHandle);

Passed as argument to (2 call sites):
  -> AipRequireElevationPrompt() arg 2: a2 (direct)  [internal, ID=198]
  -> AiLaunchConsentUI() arg 6: *a2 (in expression)  [internal, ID=650]

Assembly register tracking (param 2 = rdx):
  Tracked registers: dl, dx, edx, rdx, rsi
```

### backward_trace.py

```
================================================================================
[Start] Backward trace: AiCheckSecureApplicationDirectory  target=CreateFileW
================================================================================
--- Call site 1: L24 ---
  FileW = CreateFileW(v94, 0x80000000, 5u, 0, 3u, 0x2000000u, 0);

  Argument 1: a1
    -> PARAMETER a1

  Origin traced to parameter(s): a1
  Checking callers to see what they pass...

  Caller: AiIsEXESafeToAutoApprove  [ID=130]
    L176: v34 = AiCheckSecureApplicationDirectory((const unsigned __int16 *)*v11, &v36);
    Passes as param 1: (const unsigned __int16 *)*v11

  Caller: RAiLaunchAdminProcess  [ID=1020]
    L420: Reply = AiCheckSecureApplicationDirectory(v63, &v87);
    Passes as param 1: v63
      -> LOCAL VARIABLE v63
```

### global_state_map.py

```
Global State Summary
============================================================
Total globals: 572
  Shared (R+W): 167  |  Write-only: 38  |  Read-only: 367

Top shared globals (most accessors):
  __security_cookie                        1W / 139R
  uint DosErr                              33W / 23R
  int LastRetCode                          35W / 6R
  uchar fEnableExtensions                  4W / 37R
  batdata * CurrentBatchFile               3W / 26R
```

### string_trace.py

```
String Trace: "wapdpu"
============================================================
Found 16 function(s) referencing matching strings.

------------------------------------------------------------
Function: CDdfInfo::IsNodeSupported  [ID=843]
Matched strings (1):
  "onecoreuap\admin\dm\coredpus\wapdpu\ddfinfo.cpp"

Decompiled code context (2 lines):
  L  67: (int)"onecoreuap\\admin\\dm\\coredpus\\wapdpu\\ddfinfo.cpp",

Caller chain:
  <- CWapNodeValidator::ValidateNode  [ID=850]
    <- CWapDPU::ProcessData  [ID=789]
```

## Trace Types

| Trace | Question Answered | Key Data Sources |
|-------|-------------------|-----------------|
| **Forward** | "What happens to parameter N?" | `decompiled_code`, `assembly_code`, `simple_outbound_xrefs`, `global_var_accesses` |
| **Backward** | "Where does this API argument come from?" | `decompiled_code`, `simple_inbound_xrefs`, variable assignment chains |
| **Global map** | "Who reads/writes this global?" | `global_var_accesses` across all functions |
| **String** | "Where is this string used?" | `string_literals`, `simple_inbound_xrefs`, decompiled code context |

## Expression Classification

The backward tracer classifies each argument origin:

| Type | Meaning | Example |
|------|---------|---------|
| `parameter` | From the function's own parameter | `a1`, `a2` |
| `call_result` | Return value of another function | `GetLastError()` |
| `constant` | Hardcoded value | `0x80000000`, `NULL` |
| `string_literal` | String constant | `L"COPYCMD"` |
| `global` | IDA-named global variable | `dword_18005C380` |
| `local_variable` | Local variable (traced further through assignments) | `v5` -> `a2` |
| `param_dereference` | Pointer dereference through a parameter | `*(DWORD*)(a1 + 0x10)` |

## Common Workflows

**Trace a parameter through the call chain:**
```bash
python .agent/skills/data-flow-tracer/scripts/forward_trace.py <db_path> <function> --param 2 --depth 2
```

**Find where an API gets its file path argument:**
```bash
python .agent/skills/data-flow-tracer/scripts/backward_trace.py <db_path> <function> --target CreateFileW --arg 1 --callers
```

**Map all shared global state in a module:**
```bash
python .agent/skills/data-flow-tracer/scripts/global_state_map.py <db_path> --shared-only
```

**Drill into a specific global variable:**
```bash
python .agent/skills/data-flow-tracer/scripts/global_state_map.py <db_path> --global CurrentBatchFile
```

**Find all functions that reference a string:**
```bash
python .agent/skills/data-flow-tracer/scripts/string_trace.py <db_path> --string "PATH" --callers --depth 2
```

**Show all strings used by a function:**
```bash
python .agent/skills/data-flow-tracer/scripts/string_trace.py <db_path> --function ExecPgm
```

**List all unique strings in a module:**
```bash
python .agent/skills/data-flow-tracer/scripts/string_trace.py <db_path> --list-strings
```

**Export global map as JSON for further processing:**
```bash
python .agent/skills/data-flow-tracer/scripts/global_state_map.py <db_path> --json > globals.json
```

## Files

```
data-flow-tracer/
├── SKILL.md              # Agent skill instructions (read by Cursor)
├── reference.md          # Technical reference: DB fields, expression types,
│                         #   assembly register mapping, helper module API
├── README.md             # This file
└── scripts/
    ├── _common.py            # Shared: decompiled code parsing, expression
    │                         #   classification, x64 register mapping, JSON helpers
    ├── forward_trace.py      # Parameter forward flow tracing
    ├── backward_trace.py     # API argument origin tracing
    ├── global_state_map.py   # Global variable producer/consumer map
    └── string_trace.py       # String literal usage and caller chains
```

## Dependencies

- Python 3.10+
- `.agent/helpers/` module (workspace root) -- provides `open_individual_analysis_db`, `open_analyzed_files_db`
- SQLite analysis databases from DeepExtractIDA

## Related Skills

- [callgraph-tracer](../callgraph-tracer/SKILL.md) -- Trace call chains and execution flow across modules
- [classify-functions](../classify-functions/SKILL.md) -- Categorize functions by purpose and interest
- [code-lifting](../code-lifting/SKILL.md) -- Lift functions into clean, readable code
- [reconstruct-types](../reconstruct-types/SKILL.md) -- Reconstruct struct/class definitions from memory access
- [analyze-ida-decompiled](../analyze-ida-decompiled/SKILL.md) -- Analyze and navigate decompiled code
