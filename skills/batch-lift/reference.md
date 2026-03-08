# Batch Lift -- Technical Reference

Detailed reference for function collection algorithms, struct accumulation strategy, dependency ordering, and script internals.

---

## Function Collection Algorithms

### Class Method Collection

The `--class` mode finds methods via two strategies:

**1. Mangled name prefix matching:**
Scans ALL functions in the module DB for mangled names that encode the class:

| Prefix | Role |
|--------|------|
| `??0ClassName@@` | Constructor |
| `??1ClassName@@` | Destructor |
| `??_GClassName@@` | Scalar deleting destructor |
| `?Method@ClassName@@` | Regular method |
| `??_7ClassName@@6B@` | VFTable (included for context) |

**2. Signature reference matching:**
Functions whose `function_signature` or `function_signature_extended` reference `ClassName` as a parameter type (e.g., `void func(CSecurityDescriptor *)`). This catches standalone functions that operate on the class but aren't class methods.

### Call Chain Collection (BFS)

The `--chain` mode performs BFS from a starting function using `simple_outbound_xrefs`:

1. Start with the named function (or ID)
2. Parse `simple_outbound_xrefs` for each function in the queue
3. Follow xrefs where `function_id` is NOT null (internal calls only)
4. Skip `module_name == "data"` (function_type=4) and `module_name == "vtable"` (function_type=8)
5. Track depth; stop at `--depth` limit
6. Result: all reachable internal functions up to depth N

**Depth semantics**: Depth 0 = starting function only. Depth 1 = starting function + its direct callees. Depth 3 = starting function + 3 levels of callees.

### Export-Down Collection

Same as call chain, but first verifies the starting function is in the module's export table (from `file_info.exports`). Proceeds with chain BFS regardless (warns if not a confirmed export).

---

## Dependency Ordering

### Algorithm: Reverse Topological Sort (Kahn's)

Functions are ordered so callees come before callers (bottom-up):

1. Build directed graph: edges from caller -> callee (using `simple_outbound_xrefs` where both `function_id` values are in the set)
2. Run Kahn's topological sort (processes nodes with in-degree 0 first = callers first)
3. **Reverse** the result: callees come first, callers come last

**Why callees first?**
- Callee signatures are known when lifting the caller
- Struct definitions accumulate from leaf functions upward
- Constants discovered in callees propagate to callers

### Handling Cycles

Mutually recursive functions (SCCs) are appended after the topological order. The agent should lift them together, treating the cycle as a single unit.

---

## Struct Access Pattern Scanning

The `prepare_batch_lift.py` scanner detects three patterns in decompiled code:

### Pattern 1: Indexed access
```
*((_QWORD *)a1 + 14)     -> base=a1, type=_QWORD, index=14, offset=14*8=112
*((_DWORD *)this + 32)    -> base=this, type=_DWORD, index=32, offset=32*4=128
```

### Pattern 2: Direct byte offset
```
*(_BYTE *)(a1 + 20)      -> base=a1, type=_BYTE, offset=20
*(_DWORD *)(this + 0x38) -> base=this, type=_DWORD, offset=0x38
```

### Pattern 3: Zero-offset access
```
*(_DWORD *)a1             -> base=a1, type=_DWORD, offset=0
```

### Merge Strategy

When the same offset is accessed in multiple functions:
- **Larger type wins**: If function A accesses offset 0x10 as `_DWORD` (4B) and function B accesses it as `_QWORD` (8B), the merged field is `uint64_t` (8B)
- **Gaps are padded**: Unknown regions between known fields get `uint8_t _unknown_XX[size]`
- **Source tracking**: Each field notes which functions access it

### Limitations

The built-in scanner is regex-based on decompiled code only. For assembly-backed accuracy (ground truth sizes), use the reconstruct-types skill:
```bash
python .agent/skills/reconstruct-types/scripts/scan_struct_fields.py <db_path> --class ClassName
```

---

## Script Architecture

### Workspace Layout

```
{workspace_root}/
├── extracted_dbs/
│   ├── analyzed_files.db
│   └── {module}_{hash}.db
├── extracted_code/
│   └── {module_name}/
├── .agent/helpers/
│   ├── analyzed_files_db/
│   └── individual_analysis_db/
└── .agent/skills/
    ├── batch-lift/            ← THIS SKILL
    │   ├── SKILL.md
    │   ├── reference.md
    │   └── scripts/
    │       ├── _common.py
    │       ├── collect_functions.py
    │       └── prepare_batch_lift.py
    ├── decompiled-code-extractor/  (reused: find_module_db.py, extract_function_data.py)
    ├── callgraph-tracer/      (reused: chain_analysis.py, build_call_graph.py)
    └── reconstruct-types/     (reused: scan_struct_fields.py, generate_header.py)
```

### Common Module (`_common.py`)

All scripts import from `_common.py` which provides:

| Function | Purpose |
|----------|---------|
| `parse_json_safe(raw)` | Safe JSON parse, returns None on failure |
| `resolve_db_path(path)` | Resolve relative to workspace root |
| `parse_class_from_mangled(name)` | Extract class/method info from mangled name |
| `scan_struct_accesses(code)` | Regex-based struct pattern detection |
| `merge_struct_fields(accesses)` | Merge patterns across functions |
| `format_struct_definition(name, fields)` | Generate C struct definition |
| `topological_sort_functions(funcs, ids)` | Dependency-ordered sort (callees first) |

### Pipeline Pattern

The recommended usage is a two-step pipeline:

```bash
# Step 1: Collect function set -> JSON manifest
python .agent/skills/batch-lift/scripts/collect_functions.py <db_path> --class ClassName --json > funcs.json

# Step 2: Generate lift plan from manifest
python .agent/skills/batch-lift/scripts/prepare_batch_lift.py --from-json funcs.json
```

The JSON manifest from Step 1 includes `dependency_order` (pre-computed topological sort), so Step 2 can skip recomputation.

---

## Helper Module API (Quick Reference)

### AnalyzedFilesDB

```python
from helpers import open_analyzed_files_db

with open_analyzed_files_db() as db:
    db.get_complete()                 # All modules with status=COMPLETE
    db.get_by_file_name("cmd.exe")    # Find by filename
```

### IndividualAnalysisDB

```python
from helpers import open_individual_analysis_db

with open_individual_analysis_db("extracted_dbs/module.db") as db:
    db.get_function_by_id(42)                  # By ID
    db.get_function_by_name("FuncName")        # By name (case-insensitive)
    db.search_functions(name_contains="Bat")   # Partial search
    db.get_all_functions()                     # All functions
    db.get_file_info()                         # Module metadata
```

### FunctionRecord Key Fields

| Field | Parsed Property | Use |
|-------|----------------|-----|
| `decompiled_code` | (direct) | Structural base for lifting |
| `assembly_code` | (direct) | Ground truth verification |
| `simple_outbound_xrefs` | `parsed_simple_outbound_xrefs` | Call graph edges |
| `simple_inbound_xrefs` | `parsed_simple_inbound_xrefs` | Caller identification |
| `mangled_name` | (direct) | Class/method role detection |
| `vtable_contexts` | `parsed_vtable_contexts` | Class hierarchy |

---

## Xref Classification for Batch Context

When displaying outbound xrefs in the lift plan, calls are classified relative to the batch set:

| Category | Meaning | Action |
|----------|---------|--------|
| **Within lift set** | Callee is one of the functions being batch-lifted | Reference by lifted name |
| **Other internal** | Same module but not in the lift set | Note as context |
| **External** | Different module | Use Windows API documentation |

---

## IDA Type -> C Type Mapping

| IDA Type | Size | C Type |
|----------|------|--------|
| `_BYTE` | 1 | `uint8_t` |
| `_WORD` | 2 | `uint16_t` |
| `_DWORD` | 4 | `uint32_t` |
| `_QWORD` | 8 | `uint64_t` |
| `HRESULT` | 4 | `HRESULT` |
| `LONG` | 4 | `LONG` |

---

## Performance Notes

| Operation | Typical Time |
|-----------|-------------|
| Collect class methods (50 methods) | <1s |
| Collect call chain (depth 3, ~100 functions) | <2s |
| Extract batch data (50 functions) | 1-3s |
| Struct scanning (50 functions) | <1s |
| Full lift plan generation | 2-5s |

For very large sets (>200 functions), use `--summary` first to assess scope before generating the full plan.
