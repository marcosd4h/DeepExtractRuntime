# Function Purpose Classifier

Answer: **"What does each function in this binary do?"**

Automatically categorizes every function in a DeepExtractIDA module into 18 purpose categories using API signatures, string analysis, naming patterns, assembly metrics, and loop complexity. Each function gets an interest score (0--10) for triage prioritization, letting you cut through 1000+ function binaries and focus on what matters.

## Quick Start

```bash
# 1. Find the module DB
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py appinfo.dll

# 2. Get a high-level triage summary
python .agent/skills/classify-functions/scripts/triage_summary.py extracted_dbs/appinfo_dll_e98d25a9e8.db

# 3. Full categorized index (filter to what matters)
python .agent/skills/classify-functions/scripts/classify_module.py extracted_dbs/appinfo_dll_e98d25a9e8.db --min-interest 4 --no-telemetry --no-compiler

# 4. Deep-dive into a specific function
python .agent/skills/classify-functions/scripts/classify_function.py extracted_dbs/appinfo_dll_e98d25a9e8.db --id 752
```

## Scripts

| Script | Purpose |
|--------|---------|
| `triage_summary.py` | Quick module overview: category distribution, size histogram, API breakdown, top-N most interesting functions |
| `classify_module.py` | Full categorized function index with filtering by category, interest threshold, and noise exclusion |
| `classify_function.py` | Detailed single-function classification with all signals, scores, and reasoning |

## Example Output

### triage_summary.py

```
################################################################################
  MODULE TRIAGE SUMMARY
################################################################################
  Module:      appinfo.dll
  Description: Application Information Service
  Company:     Microsoft Corporation
  Version:     10.0.26100.7462

  Total functions:         1173
  With decompiled code:    1173
  Signal (interesting):    981
  Noise (infra/compiler):  192
  Unclassified:            414
  With dangerous APIs:     127 (176 refs)
  With loops:              226 (490 total loops)

  SIZE DISTRIBUTION (assembly instructions):
    Tiny (<10):      252  ########################################
    Small (10-50):   543  ########################################
    Medium (50-200): 325  ########################################
    Large (200-500):  44  ########
    Huge (500+):       9  #

  CATEGORY DISTRIBUTION:
  Category                Count      %  Bar
  ---------------------- ------ ------  ----------------------------------------
  initialization             30   2.6%  #
  security                   22   1.9%  
  telemetry                 181  15.4%  ###### *
  resource_management       109   9.3%  ###
  sync                       74   6.3%  ##
  utility                   184  15.7%  ######
  unknown                   414  35.3%  ##############

  TOP 10 MOST INTERESTING FUNCTIONS:
      ID  Int  Category                Loops    ASM  Name
  ------  ---  ----------------------  -----  -----  ----------------------------------------
     752    7  error_handling              4   1733  AipLaunchProcessWithIdentityHelper
     194    7  memory                     13   1535  AiLaunchProcess
    1020    7  error_handling              8   1105  RAiLaunchAdminProcess
     192    6  com_rpc                     4    810  ServiceMain
    1074    6  registry                    2    186  AiCopyRegistry
```

### classify_function.py --id 752

```
======================================================================
  CLASSIFICATION RESULT
======================================================================
  Primary Category:   error_handling
  Secondary:          security, process_thread
  Interest Score:     7/10

  CATEGORY SCORES:
    error_handling              20.0 <-- PRIMARY
    security                    20.0
    process_thread              15.0
    memory                      10.0
    data_parsing                 6.0
    file_io                      5.0

  STRUCTURAL METRICS:
    Assembly instructions: 1733
    Call instructions:     145
    Branch instructions:   239
    Loop count:            4
    Has decompiled code:   True

  DANGEROUS APIs (9):
    ! memset, GetCurrentProcess, OpenThread, TerminateProcess,
    ! OpenProcess, ImpersonateLoggedOnUser, ResumeThread,
    ! CreateFileW, DuplicateHandle
```

## Classification Categories (18)

| Category | Description | Key Signals |
|----------|-------------|-------------|
| `initialization` | Entry points, constructors, setup | DllMain, ServiceMain, `??0` ctors, Init* names |
| `error_handling` | Error checking, exception handling | GetLastError, FormatMessage, error strings |
| `data_parsing` | Parsing, serialization, conversion | Parse*, Convert*, format strings, high loop count |
| `com_rpc` | COM, RPC, named pipes | CoCreateInstance, NdrClientCall, RPC protocol strings |
| `ui` | Window management, dialogs | CreateWindow, MessageBox, dialog APIs |
| `telemetry` | WPP, ETW, TraceLogging, WIL | Wpp*, _tlg*, wil_*, ETW provider strings |
| `crypto` | Encryption, hashing, certificates | BCrypt*, NCrypt*, Cert*, Crypt* APIs |
| `resource_management` | Allocation, cleanup, RAII | Destructors (`??1`), Free*, Release*, Close* |
| `dispatch_routing` | Message pumps, dispatchers | Dispatch*, *Handler, *Callback, branchy assembly |
| `file_io` | File and directory operations | CreateFile, ReadFile, WriteFile, FindFirstFile |
| `registry` | Registry read/write | RegOpenKey, RegQueryValue, registry path strings |
| `network` | Sockets, HTTP, WinHTTP | WSA*, WinHttp*, connect, URL strings |
| `process_thread` | Process/thread management | CreateProcess, CreateThread, ShellExecute |
| `security` | Tokens, privileges, ACLs | OpenProcessToken, AccessCheck, privilege APIs |
| `sync` | Synchronization primitives | Critical sections, events, mutexes, SRW locks |
| `memory` | Memory allocation/management | VirtualAlloc, HeapAlloc, MapViewOfFile |
| `service` | Windows service management | StartServiceCtrlDispatcher, OpenSCManager |
| `compiler_generated` | CRT startup, security cookies | __security*, _guard_*, __scrt_*, memcpy |

## Interest Score (0--10)

Each function gets a triage priority score:

| Factor | Score Impact |
|--------|-------------|
| Dangerous API calls | +1 to +3 (capped) |
| Complex loops (2+) | +1 |
| High cyclomatic complexity (5+) | +1 |
| Substantial size (50+ instructions) | +1 |
| Rich string context (3+ strings) | +1 |
| Has decompiled code | +1 |
| Telemetry/compiler category | -3 (noise penalty) |
| Tiny utility | -2 |

## Signal Sources & Weights

Five signal sources feed the classifier, in priority order:

| Signal Source | Weight | Cap | Description |
|---------------|--------|-----|-------------|
| Mangled name pattern | 12.0 | First match | `??0` = ctor, `??1` = dtor, `??_7` = vftable |
| Function name pattern | 10.0 | First match | Wpp*, Init*, Parse*, Check*, Dispatch*, etc. |
| API call match | 5.0 each | 25.0/category | ~250 API prefixes across 12 categories |
| String content match | 2.0 each | 10.0/category | Registry paths, URLs, ETW providers, format strings |
| Structural pattern | 4.0 | Per-rule | Loop count, branch density, function size |

Primary category = highest total score. See [reference.md](reference.md) for the full taxonomy.

## Common Workflows

**Triage an unknown module:**
```bash
python .agent/skills/classify-functions/scripts/triage_summary.py <db_path> --top 15
```

**Find all crypto and security functions:**
```bash
python .agent/skills/classify-functions/scripts/classify_module.py <db_path> --category crypto --category security
```

**Filter out noise, show only interesting functions:**
```bash
python .agent/skills/classify-functions/scripts/classify_module.py <db_path> --no-telemetry --no-compiler --min-interest 3
```

**Export full classification as JSON:**
```bash
python .agent/skills/classify-functions/scripts/classify_module.py <db_path> --json > classification.json
```

**Search for functions by name and classify matches:**
```bash
python .agent/skills/classify-functions/scripts/classify_function.py <db_path> --search "Check"
```

**Cross-dimensional search (names, strings, APIs, classes, exports):**
```bash
python .agent/helpers/unified_search.py <db_path> --query "Check"
```

## Tested Modules

| Module | Functions | Signal | Noise | Dangerous | Runtime |
|--------|-----------|--------|-------|-----------|---------|
| appinfo.dll (UAC service) | 1,173 | 981 (84%) | 192 (16%) | 127 | ~4s |
| cmd.exe (command processor) | 817 | 753 (92%) | 64 (8%) | 168 | ~5s |
| coredpus.dll (device provisioning) | 1,080 | 1,032 (96%) | 48 (4%) | 76 | ~4s |

## Files

```
classify-functions/
├── SKILL.md              # Agent skill instructions (read by Cursor)
├── reference.md          # Full taxonomy, signal definitions, scoring algorithm
├── README.md             # This file
└── scripts/
    ├── _common.py            # Shared: 250+ API prefixes, name rules, string rules,
    │                         #   structural heuristics, classification engine
    ├── triage_summary.py     # Quick module-level triage overview
    ├── classify_module.py    # Full categorized function index with filtering
    └── classify_function.py  # Detailed single-function classification
```

## Dependencies

- Python 3.10+
- `.agent/helpers/` module (workspace root) -- provides `open_individual_analysis_db`, `open_analyzed_files_db`
- SQLite analysis databases from DeepExtractIDA

## Related Skills

- [security-dossier](../security-dossier/SKILL.md) -- Deep security context for individual functions
- [map-attack-surface](../map-attack-surface/SKILL.md) -- Map module-wide attack surface and rank entry points
- [callgraph-tracer](../callgraph-tracer/SKILL.md) -- Trace call chains across modules
- [reconstruct-types](../reconstruct-types/SKILL.md) -- Reconstruct struct/class definitions
