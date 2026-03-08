---
name: classify-functions
description: Automatically classify and triage every function in a DeepExtractIDA module by purpose (file I/O, registry, network, crypto, security, telemetry, dispatch, initialization, etc.) using API calls, string analysis, naming patterns, assembly metrics, and loop complexity. Use when the user asks to classify functions, triage a binary, understand what a module does at a high level, find functions by category, identify interesting functions, filter out noise, or asks about function purpose distribution in an extracted module.
---

# Function Purpose Classification & Triage

## Purpose

Automatically categorize every function in a DeepExtractIDA analysis database into purpose categories using multiple signal sources:

- **API usage signature**: outbound xrefs classified by category (file I/O, registry, network, crypto, etc.)
- **String analysis**: registry paths, error messages, format strings, URLs, ETW providers
- **Naming patterns**: `Wpp*`/`_tlg*`/`wil_*` = telemetry; `??0`/`??1` = constructors/destructors; `sub_*` = unnamed
- **Assembly metrics**: instruction count, call count, branch count, leaf detection (from raw assembly)
- **Structural metrics**: loop count, cyclomatic complexity from loop analysis

Output is a categorized function index for the entire module, enabling researchers to triage 1000+ function binaries and focus effort on the most interesting functions.

## Data Sources

### SQLite Databases (primary)

Individual analysis DBs in `extracted_dbs/` provide per-function data:

- `simple_outbound_xrefs` -- API calls (classified into categories)
- `string_literals` -- string content analysis
- `function_name` / `mangled_name` -- naming pattern matching
- `assembly_code` -- structural metrics (instruction/call/branch counts)
- `loop_analysis` -- loop count and cyclomatic complexity
- `dangerous_api_calls` -- security-relevant API usage

### Finding a Module DB

Reuse the decompiled-code-extractor skill's `find_module_db.py`:

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py --list
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py appinfo.dll
```

### Quick Cross-Dimensional Search

To search across function names, strings, APIs, classes, and exports in one call, use the unified search helper:

```bash
python .agent/helpers/unified_search.py <db_path> --query "CreateProcess"
python .agent/helpers/unified_search.py <db_path> --query "registry" --json
```

## Utility Scripts

Pre-built scripts in `scripts/` handle all classification. Run from the workspace root.

### triage_summary.py -- Quick Module Overview (Start Here)

Get a high-level overview of any module in seconds:

```bash
# Full triage summary with top-10 most interesting functions
python .agent/skills/classify-functions/scripts/triage_summary.py <db_path>

# Show top-20 most interesting functions
python .agent/skills/classify-functions/scripts/triage_summary.py <db_path> --top 20

# JSON output for programmatic use
python .agent/skills/classify-functions/scripts/triage_summary.py <db_path> --json
```

Output includes: category distribution, size distribution, API usage breakdown, top-N most interesting functions, largest functions, most complex functions, and triage recommendations.

### classify_module.py -- Full Categorized Index

Classify every function and output the complete categorized index:

```bash
# Human-readable categorized index
python .agent/skills/classify-functions/scripts/classify_module.py <db_path>

# JSON output
python .agent/skills/classify-functions/scripts/classify_module.py <db_path> --json

# Filter to specific categories
python .agent/skills/classify-functions/scripts/classify_module.py <db_path> --category security --category crypto

# Only high-interest functions (score >= 4)
python .agent/skills/classify-functions/scripts/classify_module.py <db_path> --min-interest 4

# Exclude infrastructure noise
python .agent/skills/classify-functions/scripts/classify_module.py <db_path> --no-telemetry --no-compiler
```

Options: `--json`, `--category <name>` (repeatable), `--min-interest N`, `--no-telemetry`, `--no-compiler`.

### classify_function.py -- Detailed Single Function Analysis

Show detailed classification reasoning for one function:

```bash
# By function name
python .agent/skills/classify-functions/scripts/classify_function.py <db_path> AiCheckSecureApplicationDirectory

# By function ID
python .agent/skills/classify-functions/scripts/classify_function.py <db_path> --id 124

# Search and classify matches
python .agent/skills/classify-functions/scripts/classify_function.py <db_path> --search "Check"

# JSON output
python .agent/skills/classify-functions/scripts/classify_function.py <db_path> --id 124 --json
```

Output includes: primary/secondary categories, all category scores, signal evidence (which APIs, strings, name patterns matched), assembly metrics, API call list with per-API categorization, dangerous APIs, and string literals.

## Classification Categories

| Category              | Description                        | Key Signals                                           |
| --------------------- | ---------------------------------- | ----------------------------------------------------- |
| `initialization`      | Entry points, constructors, setup  | DllMain, ServiceMain, `??0` ctors, Init\* names       |
| `error_handling`      | Error checking, exception handling | GetLastError, FormatMessage, error strings            |
| `data_parsing`        | Parsing, serialization, conversion | Parse*, Convert*, format strings, high loop count     |
| `com_rpc`             | COM, RPC, named pipes              | CoCreateInstance, NdrClientCall, RPC protocol strings |
| `ui`                  | Window management, dialogs         | CreateWindow, MessageBox, dialog APIs                 |
| `telemetry`           | WPP, ETW, TraceLogging, WIL        | Wpp*, \_tlg*, wil\_\*, ETW provider strings           |
| `crypto`              | Encryption, hashing, certificates  | BCrypt*, NCrypt*, Cert*, Crypt* APIs                  |
| `resource_management` | Allocation, cleanup, RAII          | Destructors (`??1`), Free*, Release*, Close\*         |
| `dispatch_routing`    | Message pumps, dispatchers         | Dispatch*, *Handler, \*Callback, branchy assembly     |
| `file_io`             | File and directory operations      | CreateFile, ReadFile, WriteFile, FindFirstFile        |
| `registry`            | Registry read/write                | RegOpenKey, RegQueryValue, registry path strings      |
| `network`             | Sockets, HTTP, WinHTTP             | WSA*, WinHttp*, connect, URL strings                  |
| `process_thread`      | Process/thread management          | CreateProcess, CreateThread, ShellExecute             |
| `security`            | Tokens, privileges, ACLs           | OpenProcessToken, AccessCheck, privilege APIs         |
| `sync`                | Synchronization primitives         | Critical sections, events, mutexes, SRW locks         |
| `memory`              | Memory allocation/management       | VirtualAlloc, HeapAlloc, MapViewOfFile                |
| `service`             | Windows service management         | StartServiceCtrlDispatcher, OpenSCManager             |
| `compiler_generated`  | CRT startup, security cookies      | **security*, *guard**, **scrt\_\*, memcpy             |
| `utility`             | Small helpers, wrappers            | Tiny functions, leaf functions, no strong signals     |
| `unknown`             | Unable to classify                 | No signals, unnamed `sub_*` functions                 |

## Interest Score

Each function receives an interest score (0-10) for triage prioritization:

| Factor                              | Score Impact       |
| ----------------------------------- | ------------------ |
| Dangerous API calls                 | +1 to +3 (capped)  |
| Complex loops (2+)                  | +1                 |
| High cyclomatic complexity (5+)     | +1                 |
| Substantial size (50+ instructions) | +1                 |
| Rich string context (3+ strings)    | +1                 |
| Has decompiled code                 | +1                 |
| Telemetry/compiler category         | -3 (noise penalty) |
| Tiny utility                        | -2                 |

## Workflows

### Workflow 1: "Triage an unknown module"

```
Triage Progress:
- [ ] Step 1: Find the module DB
- [ ] Step 2: Run triage summary for high-level overview
- [ ] Step 3: Review category distribution and top interesting functions
- [ ] Step 4: Drill into specific categories of interest
- [ ] Step 5: Examine individual high-interest functions
```

**Step 1**: Find the module DB

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py appinfo.dll
```

**Step 2**: Get the triage summary

```bash
python .agent/skills/classify-functions/scripts/triage_summary.py <db_path> --top 15
```

**Step 3**: Review the output -- focus on:

- Category distribution (what does this module primarily do?)
- Functions with dangerous APIs (security-relevant)
- Top interesting functions (highest priority for analysis)
- Noise ratio (how much is telemetry/compiler infrastructure?)

**Step 4**: Drill into categories

```bash
# Show all security functions
python .agent/skills/classify-functions/scripts/classify_module.py <db_path> --category security

# Show all functions with interest >= 5, excluding noise
python .agent/skills/classify-functions/scripts/classify_module.py <db_path> --min-interest 5 --no-telemetry --no-compiler
```

**Step 5**: Examine specific functions

```bash
python .agent/skills/classify-functions/scripts/classify_function.py <db_path> --id <function_id>
```

### Workflow 2: "Find all crypto/security functions"

```bash
python .agent/skills/classify-functions/scripts/classify_module.py <db_path> --category crypto --category security
```

### Workflow 3: "Filter out noise and find what matters"

```bash
# Exclude telemetry and compiler-generated, only show interesting
python .agent/skills/classify-functions/scripts/classify_module.py <db_path> --no-telemetry --no-compiler --min-interest 3
```

### Workflow 4: "Get JSON for downstream processing"

```bash
# Full classification as JSON (pipe to jq, other tools, or read programmatically)
python .agent/skills/classify-functions/scripts/classify_module.py <db_path> --json > classification.json
```

## Direct Helper Module Access

For custom queries not covered by scripts:

```python
from helpers import open_individual_analysis_db

with open_individual_analysis_db("extracted_dbs/module_hash.db") as db:
    funcs = db.search_functions(has_dangerous_apis=True)
    for f in funcs:
        print(f.function_name, f.parsed_dangerous_api_calls)
```

## Integration with Other Skills

| Task | Recommended Skill |
|------|-------------------|
| Trace call chains for interesting functions | callgraph-tracer |
| Build security dossier for high-interest functions | security-dossier |
| Map attack surface using classified entry points | map-attack-surface |
| Lift high-priority functions to clean code | code-lifting / batch-lift |
| Reconstruct types used by classified functions | reconstruct-types |

## Performance

| Operation | Typical Time | Notes |
|-----------|-------------|-------|
| Classify single function | ~1s | Pure Python classification |
| Classify full module | ~10-20s | Scales linearly with function count |
| Triage summary | ~10-15s | Includes top-N ranking |

## Additional Resources

- For detailed classification taxonomy and signal definitions, see [reference.md](reference.md)
- For DB schema and JSON field formats, see [data_format_reference.md](../../docs/data_format_reference.md)
- For code analysis, see [analyze-ida-decompiled](../analyze-ida-decompiled/SKILL.md)
- For code lifting, see [code-lifting](../code-lifting/SKILL.md)
- For call graph tracing, see [callgraph-tracer](../callgraph-tracer/SKILL.md)
- For type reconstruction, see [reconstruct-types](../reconstruct-types/SKILL.md)
