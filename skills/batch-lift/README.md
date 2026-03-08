# Batch / Contextual Code Lifting

Answer: **"Lift related function groups together with shared context, not one at a time."**

Lifting one function at a time loses context -- struct definitions are incomplete, constants are defined in isolation, and cross-references between related functions are missed. This skill orchestrates batch lifting: it collects related function sets (C++ class methods, call chains, export subtrees), builds shared struct definitions accumulated across ALL functions, determines dependency order (callees first), and produces a single coordinated output.

## Quick Start

```bash
# 1. Find the module DB
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py appinfo.dll

# 2. Collect all methods of a C++ class
python .agent/skills/batch-lift/scripts/collect_functions.py extracted_dbs/appinfo_dll_e98d25a9e8.db --class LUATelemetry

# 3. Collect a call chain from a function, 3 levels deep
python .agent/skills/batch-lift/scripts/collect_functions.py extracted_dbs/cmd_exe_6d109a3a00.db --chain BatLoop --depth 3

# 4. Full pipeline: collect -> lift plan
python .agent/skills/batch-lift/scripts/collect_functions.py extracted_dbs/appinfo_dll_e98d25a9e8.db --class LUATelemetry --json > funcs.json
python .agent/skills/batch-lift/scripts/prepare_batch_lift.py --from-json funcs.json --summary
```

## Scripts

| Script | Purpose |
|--------|---------|
| `collect_functions.py` | Multi-mode function set collection with dependency ordering (class, chain, export-down) |
| `prepare_batch_lift.py` | Batch data extraction, struct scanning across all functions, dependency-ordered lift plan |

## Collection Modes

| Mode | Flag | Description |
|------|------|-------------|
| Class methods | `--class ClassName` | All methods by mangled name + functions referencing the class in their signature |
| Call chain | `--chain FuncName --depth N` | BFS from a function through internal calls, N levels deep |
| Export-down | `--export ExportName --depth N` | Same as chain but starts from a named export |

## Example Output

### collect_functions.py (class mode)

```
================================================================================
  Class: LUATelemetry  (appinfo.dll)
  Functions collected: 14
  DB: extracted_dbs/appinfo_dll_e98d25a9e8.db
================================================================================

Lift order (callees first -> callers last):
----------------------------------------------------------------------
    1. [     ok] LUATelemetry::LUATelemetry  [constructor]
       private: LUATelemetry::LUATelemetry(void)
    2. [     ok] LUATelemetry::Instance  [method]
       protected: static class LUATelemetry * LUATelem...
    3. [     ok] LUATelemetry::QueryLUARegValue  [method]
       private: static unsigned long LUATelemetry::Que...
    ...
```

### prepare_batch_lift.py --summary

```
Batch lift summary: 35 functions from coredpus.dll

Shared struct definitions (1):
  CSyncMLCmd: 37 fields, from 24 function(s)

Lift order (callees first):
    1. CSyncMLCmd::SetCmdBypassResult  (ID=621, 5L code, 1L asm)
    2. CSyncMLCmd::SetBypassResult  (ID=619, 9L code, 7L asm)
    3. CSyncMLCmd::CSyncMLCmd  (ID=576, 27L code, 28L asm)
    ...
```

### prepare_batch_lift.py --structs-only

```cpp
// Accumulated struct definitions from batch scan

#pragma once
#include <stdint.h>

// Base parameter: CDomNode
// Source: CDomNode::CDomNode, CDomNode::~CDomNode, CDomNode::SetStatus, ...
/**
 * CDomNode -- Reconstructed from 29 function(s)
 * Field names are placeholders; rename during lifting.
 */
struct CDomNode {
    uint64_t field_00;                  // +0x00 (8B)
    uint64_t field_08;                  // +0x08 (8B)
    uint64_t field_10;                  // +0x10 (8B)
    uint64_t field_18;                  // +0x18 (8B)
    uint64_t field_20;                  // +0x20 (8B)
    uint64_t field_28;                  // +0x28 (8B)
    uint8_t _unknown_30[0x30];     // +0x30 .. +0x5F
    uint64_t field_60;                  // +0x60 (8B)
    ...
};  // total known size >= 0xC8 (200 bytes)
```

## Key Features

- **Dependency ordering** -- Topological sort puts callees before callers so struct definitions and constants accumulate naturally upward
- **Shared struct scanning** -- Regex-based scanner detects `*(TYPE*)(base + offset)` patterns across ALL functions, merges fields, and consolidates entries with the same inferred type
- **Progressive accumulation** -- `--structs-only` mode lets you check accumulated structs at any point during lifting
- **Three output modes** -- Full plan (with code + assembly), `--summary` (compact), `--structs-only` (just type definitions)
- **Pipeline design** -- `collect_functions.py --json | prepare_batch_lift.py --from-json` for composable two-step workflow
- **Direct ID mode** -- `prepare_batch_lift.py <db_path> --ids 42,43,44` for ad-hoc function sets

## Common Workflows

**Lift all methods of a C++ class:**
```bash
python .agent/skills/batch-lift/scripts/collect_functions.py <db_path> --class ClassName --json > funcs.json
python .agent/skills/batch-lift/scripts/prepare_batch_lift.py --from-json funcs.json
```

**Lift a call chain from a function:**
```bash
python .agent/skills/batch-lift/scripts/collect_functions.py <db_path> --chain FuncName --depth 2 --json > funcs.json
python .agent/skills/batch-lift/scripts/prepare_batch_lift.py --from-json funcs.json --summary
```

**Lift from an export down 3 levels:**
```bash
python .agent/skills/batch-lift/scripts/collect_functions.py <db_path> --export ExportName --depth 3 --json > funcs.json
python .agent/skills/batch-lift/scripts/prepare_batch_lift.py --from-json funcs.json
```

**Check accumulated structs only (for progressive refinement):**
```bash
python .agent/skills/batch-lift/scripts/prepare_batch_lift.py --from-json funcs.json --structs-only
```

**Lift an ad-hoc set of functions by ID:**
```bash
python .agent/skills/batch-lift/scripts/prepare_batch_lift.py <db_path> --ids 45,54,75,89 --summary
```

## Files

```
batch-lift/
├── SKILL.md              # Agent skill instructions (read by Cursor)
├── reference.md          # Algorithms, struct scanning, dependency ordering, API reference
├── README.md             # This file
└── scripts/
    ├── _common.py            # Shared: workspace root, JSON helpers, mangled name parsing,
    │                         #   struct access pattern scanner, merge/format, topo sort
    ├── collect_functions.py  # Multi-mode function set collection (class/chain/export)
    └── prepare_batch_lift.py # Batch data extraction, struct scanning, lift plan generation
```

## Dependencies

- Python 3.10+
- `.agent/helpers/` module (workspace root) -- provides `open_individual_analysis_db`, `open_analyzed_files_db`
- SQLite analysis databases from DeepExtractIDA

## Related Skills

- [code-lifting](../code-lifting/SKILL.md) -- Per-function lifting workflow (the core lifting rules this skill orchestrates)
- [reconstruct-types](../reconstruct-types/SKILL.md) -- Deep struct/class reconstruction with assembly-backed scanning
- [callgraph-tracer](../callgraph-tracer/SKILL.md) -- Call graph analysis and cross-module chain tracing
- [classify-functions](../classify-functions/SKILL.md) -- Categorize functions to identify which ones to batch-lift
- [analyze-ida-decompiled](../analyze-ida-decompiled/SKILL.md) -- Understand decompiled code and module metadata
