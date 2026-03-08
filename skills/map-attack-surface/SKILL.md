---
name: map-attack-surface
description: Map the complete attack surface of a Windows PE binary by discovering all entry points (exports, COM vtable methods, RPC handlers, WinRT methods, callbacks, window procedures, service handlers, TLS callbacks, IPC dispatchers, socket handlers, and more), ranking them by attack value using callgraph reachability to dangerous operations, and generating CRS-compatible entrypoints.json. Use when the user asks to map attack surface, find entry points, discover where an attacker can enter a binary, rank exports by risk, generate entrypoints for fuzzing, identify attack-accessible functions, or asks about the attack surface of an extracted module.
---

# Attack Surface Mapper

## Purpose

Answer: **"Where can an attacker enter this binary?"**

Automatically discover, classify, and rank every possible entry point in an analyzed Windows PE binary, from obvious DLL exports to hidden COM vtable methods, RPC stubs, callback registrations, and socket dispatchers. Each entry point is ranked by attack value using callgraph reachability to dangerous operations.

## Data Sources

### SQLite Databases (primary)

Individual analysis DBs in `extracted_dbs/` provide:

- `file_info.entry_point` -- PE-detected entry points
- `file_info.exports` -- All exported functions with signatures
- `file_info.tls_callbacks` -- TLS callback metadata with threat scoring
- `file_info.imports` -- Imported APIs (used for API pattern detection)
- `functions.simple_outbound_xrefs` -- Callgraph edges for reachability analysis
- `functions.vtable_contexts` -- COM/WRL vtable reconstructions
- `functions.dangerous_api_calls` -- Dangerous API sinks per function
- `functions.string_literals` -- String patterns (pipe names, RPC protocols)

### Finding a Module DB

Reuse the decompiled-code-extractor skill's `find_module_db.py`:

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py --list
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py appinfo.dll
```

### Quick Cross-Dimensional Search

To search across function names, strings, APIs, classes, and exports in one call:

```bash
python .agent/helpers/unified_search.py <db_path> --query "SearchTerm"
python .agent/helpers/unified_search.py <db_path> --query "SearchTerm" --json
```

## Utility Scripts

All scripts are in `scripts/`. Auto-resolve workspace root and `.agent/helpers/` imports. Run from the workspace root.

### discover_entrypoints.py -- Discover All Entry Points (Start Here)

Scan a module for every type of entry point:

```bash
# Full discovery scan
python .agent/skills/map-attack-surface/scripts/discover_entrypoints.py <db_path>

# JSON output
python .agent/skills/map-attack-surface/scripts/discover_entrypoints.py <db_path> --json

# Filter to specific types
python .agent/skills/map-attack-surface/scripts/discover_entrypoints.py <db_path> --type RPC_HANDLER --type COM_METHOD
```

**Detected entry point types:**

| Type                    | Detection Source                                          |
| ----------------------- | --------------------------------------------------------- |
| `EXPORT_DLL`            | `file_info.exports`                                       |
| `EXPORT_ORDINAL_ONLY`   | `file_info.exports` (unnamed ordinals)                    |
| `MAIN_ENTRY`            | Name patterns: main, WinMain, wmain                       |
| `DLLMAIN`               | Name patterns: DllMain, DllEntryPoint                     |
| `SERVICE_MAIN`          | Name patterns + ServiceMain exports                       |
| `COM_METHOD`            | `vtable_contexts` with IUnknown/COM patterns              |
| `WINRT_METHOD`          | `vtable_contexts` with WRL/WinRT patterns                 |
| `RPC_HANDLER`           | RPC server API calls + `s_*` naming + RPC string patterns |
| `NAMED_PIPE_HANDLER`    | Named pipe APIs + `\\.\pipe\` string patterns             |
| `CALLBACK_REGISTRATION` | Functions passed to CreateThread, SetTimer, etc.          |
| `WINDOW_PROC`           | WndProc/DlgProc patterns + RegisterClassEx targets        |
| `SERVICE_CTRL_HANDLER`  | RegisterServiceCtrlHandler targets                        |
| `TLS_CALLBACK`          | `file_info.tls_callbacks` with threat analysis            |
| `IPC_DISPATCHER`        | ALPC/LPC APIs + IPC string patterns                       |
| `TCP_UDP_HANDLER`       | Socket server APIs (accept/recv/listen patterns)          |
| `EXCEPTION_HANDLER`     | VEH/SEH handler registration APIs                         |
| `COM_CLASS_FACTORY`     | DllGetClassObject/DllCanUnloadNow exports                 |
| `SCHEDULED_CALLBACK`    | Timer, APC, threadpool callback targets                   |
| `HOOK_PROCEDURE`        | SetWindowsHookEx targets                                  |
| `FORWARDED_EXPORT`      | Forwarded DLL exports                                     |

### rank_entrypoints.py -- Rank by Attack Value

Rank all discovered entry points using callgraph reachability analysis:

```bash
# Full ranking
python .agent/skills/map-attack-surface/scripts/rank_entrypoints.py <db_path>

# Top 20 with deeper analysis
python .agent/skills/map-attack-surface/scripts/rank_entrypoints.py <db_path> --top 20 --depth 12

# JSON output with minimum score filter
python .agent/skills/map-attack-surface/scripts/rank_entrypoints.py <db_path> --json --min-score 0.3
```

**Ranking factors (weighted composite score 0-1):**

- **Dangerous operations reachable** (30%): How many dangerous API sinks (strcpy, CreateProcess, etc.) are reachable via the callgraph
- **Parameter risk** (25%): Buffer/string pointer params > handle params > flag params
- **Proximity to danger** (15%): Inverse of depth to first dangerous operation
- **Reachability breadth** (15%): Number of internal functions reachable
- **Entry type inherent risk** (15%): RPC/pipe/socket handlers score higher than plain exports

**Output includes:** Per-entry-point tainted argument recommendations.

Library-tagged functions (from function_index) are unlikely attack entry points. Use `get_library_tag_for_function()` from helpers to deprioritize WIL/CRT/STL exports.

### generate_entrypoints_json.py -- Generate CRS-Compatible Output

Produce a structured entrypoints.json file for downstream tooling:

```bash
# To stdout
python .agent/skills/map-attack-surface/scripts/generate_entrypoints_json.py <db_path>

# To file
python .agent/skills/map-attack-surface/scripts/generate_entrypoints_json.py <db_path> -o output/entrypoints.json

# Top 30, score >= 0.2
python .agent/skills/map-attack-surface/scripts/generate_entrypoints_json.py <db_path> -o entrypoints.json --top 30 --min-score 0.2
```

**Output schema:**

```json
{
  "version": "1.0",
  "module": { "file_name", "md5_hash", "security_features", ... },
  "attack_surface_summary": { "total_entry_points", "avg_attack_score", ... },
  "type_distribution": { "EXPORT_DLL": N, "RPC_HANDLER": N, ... },
  "entry_points": [
    {
      "rank": 1,
      "function_name": "ServiceMain",
      "attack_score": 0.82,
      "entry_type": "SERVICE_MAIN",
      "signature": "void __fastcall ServiceMain(unsigned int, ...)",
      "analysis": {
        "reachable_functions": 45,
        "dangerous_ops_reachable": 12,
        "depth_to_first_danger": 2,
        "dangerous_apis": ["CreateProcessW", "RegSetValueExW", ...]
      },
      "tainted_arguments": ["arg0 (...): buffer pointer - TAINT", ...]
    }
  ],
  "danger_hotspots": [
    { "api": "CreateProcessW", "reachable_from_n_entrypoints": 5 }
  ]
}
```

## Workflows

### Workflow 1: "Where can an attacker enter this binary?"

The primary use case -- full attack surface mapping.

```
Attack Surface Mapping Progress:
- [ ] Step 1: Find the module DB
- [ ] Step 2: Discover all entry points
- [ ] Step 3: Rank by attack value
- [ ] Step 4: Generate entrypoints.json
- [ ] Step 5: Review and analyze top targets
```

**Step 1**: Find the module DB

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py appinfo.dll
```

**Step 2**: Discover all entry points

```bash
python .agent/skills/map-attack-surface/scripts/discover_entrypoints.py <db_path>
```

**Step 3**: Rank by attack value

```bash
python .agent/skills/map-attack-surface/scripts/rank_entrypoints.py <db_path> --top 20
```

**Step 4**: Generate entrypoints.json

```bash
python .agent/skills/map-attack-surface/scripts/generate_entrypoints_json.py <db_path> -o entrypoints.json
```

**Step 5**: For each high-ranked entry point, drill deeper using other skills:

```bash
# Trace the call chain from the entry point
python .agent/skills/callgraph-tracer/scripts/chain_analysis.py <db_path> <function> --depth 3

# Classify what the function does
python .agent/skills/classify-functions/scripts/classify_function.py <db_path> <function>

# Lift the function for manual review
python .agent/skills/decompiled-code-extractor/scripts/extract_function_data.py <db_path> <function>
```

### Workflow 2: "Find hidden entry points beyond exports"

Focus on non-obvious attack surface.

```bash
# Discover then filter to non-export types
python .agent/skills/map-attack-surface/scripts/discover_entrypoints.py <db_path> --type COM_METHOD --type RPC_HANDLER --type CALLBACK_REGISTRATION --type WINDOW_PROC --type TLS_CALLBACK --type NAMED_PIPE_HANDLER --type TCP_UDP_HANDLER --type IPC_DISPATCHER
```

### Workflow 3: "Generate fuzzing targets"

Produce a prioritized list for fuzzing harness generation.

```bash
# Top 15 targets with score >= 0.3, deep callgraph analysis
python .agent/skills/map-attack-surface/scripts/generate_entrypoints_json.py <db_path> -o fuzz_targets.json --top 15 --min-score 0.3 --depth 15
```

The `tainted_arguments` field in each entry point tells the fuzzer which parameters to mutate.

### Workflow 4: "Compare attack surface across modules"

```bash
# Generate entrypoints for each module
python .agent/skills/map-attack-surface/scripts/generate_entrypoints_json.py extracted_dbs/appinfo_dll_*.db -o appinfo_ep.json
python .agent/skills/map-attack-surface/scripts/generate_entrypoints_json.py extracted_dbs/cmd_exe_*.db -o cmd_ep.json
```

Compare the `attack_surface_summary` sections for relative exposure.

## Integration with Other Skills

| Task                              | Skill to Use                                                             |
| --------------------------------- | ------------------------------------------------------------------------ |
| Trace call chain from entry point | [callgraph-tracer](../callgraph-tracer/SKILL.md)                         |
| Classify function purpose         | [classify-functions](../classify-functions/SKILL.md)                     |
| Lift entry point code for review  | [code-lifting](../code-lifting/SKILL.md)                                 |
| Reconstruct COM interfaces        | [com-interface-reconstruction](../com-interface-reconstruction/SKILL.md) |
| Trace data flow from entry args   | [data-flow-tracer](../data-flow-tracer/SKILL.md)                         |
| Reconstruct struct types          | [reconstruct-types](../reconstruct-types/SKILL.md)                       |
| Deep research on entry point      | [deep-research-prompt](../deep-research-prompt/SKILL.md)                 |

## Direct Helper Module Access

For advanced queries not covered by the scripts:

```python
from helpers import open_individual_analysis_db, open_analyzed_files_db

with open_individual_analysis_db("extracted_dbs/module.db") as db:
    fi = db.get_file_info()
    exports = fi.parsed_exports      # list of export dicts
    entries = fi.parsed_entry_point   # list of entry point dicts
    tls = fi.parsed_tls_callbacks     # TLS callback metadata

    # Find functions calling specific APIs
    funcs = db.search_functions(has_dangerous_apis=True)
```

## Performance

| Operation                 | Typical Time | Notes                                     |
| ------------------------- | ------------ | ----------------------------------------- |
| Discover entry points     | ~5-10s       | Full module export/vtable/callback scan   |
| Rank entry points         | ~10-20s      | Requires call graph reachability analysis |
| Generate entrypoints.json | ~1-2s        | Serialization of discovery results        |

## Additional Resources

- For entry point type taxonomy and scoring details, see [reference.md](reference.md)
- For DB schema and JSON field formats, see [data_format_reference.md](../../docs/data_format_reference.md)
- For file_info.json schema, see [file_info_format_reference.md](../../docs/file_info_format_reference.md)
