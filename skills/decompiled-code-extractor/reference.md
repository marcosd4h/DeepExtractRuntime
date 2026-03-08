# Decompiled Code Extractor -- Technical Reference

## FunctionRecord Fields

Every function extracted from an analysis DB is represented as a `FunctionRecord` dataclass (from `helpers.individual_analysis_db.records`). Fields marked JSON are stored as JSON strings and can be parsed via the `parsed_*` cached properties.

| Field | Type | Description |
|-------|------|-------------|
| `function_id` | int | Unique numeric identifier within the DB |
| `function_name` | str | Demangled function name |
| `function_signature` | str | Demangled signature (parameter types, return type) |
| `function_signature_extended` | str | Extended signature with IDA type annotations |
| `mangled_name` | str | MSVC mangled name (encodes class, namespace, types) |
| `decompiled_code` | str | Hex-Rays decompiled C++ source |
| `assembly_code` | str | Raw x64 assembly listing |
| `inbound_xrefs` | JSON | Detailed inbound cross-references (callers) |
| `outbound_xrefs` | JSON | Detailed outbound cross-references (callees) |
| `simple_inbound_xrefs` | JSON | Simplified inbound xrefs (name, ID, type) |
| `simple_outbound_xrefs` | JSON | Simplified outbound xrefs (name, ID, type) |
| `vtable_contexts` | JSON | Vtable slot assignments and class hierarchy |
| `global_var_accesses` | JSON | Global variable reads and writes |
| `dangerous_api_calls` | JSON | Security-relevant API calls detected |
| `string_literals` | JSON | String constants referenced by the function |
| `stack_frame` | JSON | Stack layout, security cookie, frame pointer usage |
| `loop_analysis` | JSON | Loop count, complexity, nesting depth |
| `analysis_errors` | JSON | Any errors encountered during extraction |
| `created_at` | str | Timestamp of extraction |

### Parsed Properties

`FunctionRecord` provides `@cached_property` accessors that parse JSON fields on demand:

- `parsed_inbound_xrefs` -- parsed `inbound_xrefs`
- `parsed_outbound_xrefs` -- parsed `outbound_xrefs`
- `parsed_simple_inbound_xrefs` -- parsed `simple_inbound_xrefs`
- `parsed_simple_outbound_xrefs` -- parsed `simple_outbound_xrefs`
- `parsed_vtable_contexts` -- parsed `vtable_contexts`
- `parsed_global_var_accesses` -- parsed `global_var_accesses`
- `parsed_dangerous_api_calls` -- parsed `dangerous_api_calls`
- `parsed_string_literals` -- parsed `string_literals`
- `parsed_stack_frame` -- parsed `stack_frame`
- `parsed_loop_analysis` -- parsed `loop_analysis`

## Database Tables

### `functions` Table

Primary table. One row per function. Columns correspond to `FunctionRecord` fields above.

### `file_info` Table

Module-level metadata. One row per DB. Contains PE metadata, imports, exports, security features, sections, and the function summary. Accessed via `FileInfoRecord` dataclass.

Key sections: `basic_file_info`, `pe_version_info`, `pe_metadata`, `imports`, `exports`, `security_features`, `sections`, `entry_points`, `function_summary`.

### `schema_version` Table

Single row tracking the DB schema version for compatibility checks.

## Helper API for Extraction

### Opening Databases

```python
from helpers import open_individual_analysis_db, open_analyzed_files_db

with open_individual_analysis_db("extracted_dbs/module_hash.db") as db:
    func = db.get_function_by_name("FunctionName")
    func = db.get_function_by_id(42)
    funcs = db.search_functions_by_pattern("Check.*")
    file_info = db.get_file_info()

with open_analyzed_files_db("extracted_dbs/analyzed_files.db") as tracking:
    records = tracking.get_all_records()
    record = tracking.find_by_module_name("appinfo.dll")
```

### Function Resolution

```python
from helpers import resolve_function, search_functions_by_pattern

func = resolve_function(db, name="AiCheckLUA")
func = resolve_function(db, function_id=42)
matches = search_functions_by_pattern(db, "AiCheck.*")
```

### Path Resolution

```python
from helpers import resolve_db_path, resolve_tracking_db

db_path = resolve_db_path("appinfo.dll")
tracking_path = resolve_tracking_db()
```

## Simple Xref Format

The `simple_outbound_xrefs` and `simple_inbound_xrefs` JSON fields contain arrays of objects:

```json
[
  {
    "target_name": "CreateFileW",
    "target_id": null,
    "xref_type": 3,
    "module": "kernel32.dll"
  },
  {
    "target_name": "AiIsSystemApplication",
    "target_id": 128,
    "xref_type": 1,
    "module": null
  }
]
```

Xref types: `1` = internal call, `2` = jump/indirect, `3` = external import.

## Script Argument Reference

### find_module_db.py

| Argument | Type | Description |
|----------|------|-------------|
| `module_name` | positional (optional) | Module name to search for |
| `--ext` | string | Filter by file extension (e.g., `.dll`) |
| `--list` | flag | List all analyzed modules |
| `--json` | flag | JSON output mode |

### list_functions.py

| Argument | Type | Description |
|----------|------|-------------|
| `db_path` | positional | Path to analysis database |
| `--search` | string | Filter functions by name pattern |
| `--has-decompiled` | flag | Only functions with decompiled code |
| `--with-signatures` | flag | Include function signatures in output |
| `--limit` | int | Maximum number of results |
| `--json` | flag | JSON output mode |

### extract_function_data.py

| Argument | Type | Description |
|----------|------|-------------|
| `db_path` | positional | Path to analysis database |
| `function_name` | positional (optional) | Function name to extract |
| `--id` | int | Function ID to extract |
| `--search` | string | Search pattern for function names |
| `--json` | flag | JSON output mode |
