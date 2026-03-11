# Import/Export Resolution -- Technical Reference

## Data Model

### ExportEntry

| Field | Type | Description |
|-------|------|-------------|
| `name` | str | Exported function name |
| `module` | str | Module that exports this function |
| `ordinal` | int? | Export ordinal number |
| `is_forwarded` | bool | Whether the export is a forwarder |
| `forwarded_to` | str? | Target of the forwarder (e.g. `ntdll.RtlAllocateHeap`) |

### ImportEntry

| Field | Type | Description |
|-------|------|-------------|
| `importing_module` | str | Module that imports the function |
| `source_module` | str | DLL the function is imported from |
| `function_name` | str | Imported function name |
| `is_delay_loaded` | bool | Whether the import is delay-loaded |
| `ordinal` | int? | Import ordinal (if by ordinal) |

### ImportExportIndex

Singleton cross-module index built from `analyzed_files.db` and per-module `file_info.imports`/`file_info.exports` JSON columns. Auto-cached after first build.

| Property | Type | Description |
|----------|------|-------------|
| `module_count` | int | Number of indexed modules |
| `total_exports` | int | Total export entries across all modules |
| `total_imports` | int | Total import entries across all modules |
| `forwarded_count` | int | Number of forwarded exports |
| `unique_export_names` | int | Distinct export function names |
| `unique_import_names` | int | Distinct import function names |

### PE Import Table Entry (source JSON)

```json
{ "module_name": "ntdll.dll",
  "functions": [{ "function_name": "NtCreateFile", "is_delay_loaded": false, "ordinal": null }] }
```

### PE Export Table Entry (source JSON)

```json
{ "function_name": "HeapAlloc", "ordinal": 123,
  "is_forwarded": true, "forwarded_to": "ntdll.RtlAllocateHeap" }
```

## Output Schemas

### build_index.py

```json
{ "status": "ok", "module_count": N, "total_exports": N, "total_imports": N,
  "forwarded_count": N, "unique_export_names": N, "unique_import_names": N,
  "_meta": { "tracking_db": "...", "generated": "ISO8601" } }
```

### query_function.py

```json
{ "status": "ok", "function": "CreateProcessW", "direction": "both",
  "exporters": [{ "module": "kernel32.dll", "ordinal": N, "is_forwarded": false, "forwarded_to": null }],
  "importers": [{ "importing_module": "cmd.exe", "source_module": "kernel32.dll", "is_delay_loaded": false }],
  "_meta": { ... } }
```

### module_deps.py

**Suppliers mode** (`--module X`):

```json
{ "status": "ok", "mode": "suppliers", "target_module": "appinfo.dll",
  "suppliers": { "ntdll.dll": ["NtCreateFile", "RtlAllocateHeap", ...], ... },
  "supplier_count": N, "_meta": { ... } }
```

**Consumers mode** (`--module X --consumers`):

```json
{ "status": "ok", "mode": "consumers", "target_module": "ntdll.dll",
  "consumers": { "kernel32.dll": ["HeapAlloc", ...], ... },
  "consumer_count": N, "_meta": { ... } }
```

**Full graph mode** (no `--module`):

```json
{ "status": "ok", "mode": "full_graph",
  "graph": { "appinfo.dll": ["ntdll.dll", "kernel32.dll"], ... },
  "module_count": N, "edge_count": N, "_meta": { ... } }
```

Mermaid diagram output available via `--diagram`.

### resolve_forwarders.py

**Single chain** (`--module X --function Y`):

```json
{ "status": "ok", "mode": "single", "start_module": "kernel32.dll",
  "start_function": "HeapAlloc", "chain_length": 2,
  "chain": [{ "module": "kernel32.dll", "function": "HeapAlloc" },
            { "module": "ntdll.dll", "function": "RtlAllocateHeap" }],
  "_meta": { ... } }
```

**All forwarded** (`--module X --all`):

```json
{ "status": "ok", "mode": "all_forwarded", "module": "kernel32.dll",
  "forwarded_count": N,
  "forwarded_exports": [{ "export": "HeapAlloc", "forwarded_to": "ntdll.RtlAllocateHeap",
    "chain": [{ "module": "...", "function": "..." }, ...] }],
  "_meta": { ... } }
```

Forwarder chains are bounded to `max_depth=5` to prevent infinite loops.

## Dependency Graph Structure

The graph is a `dict[str, set[str]]` mapping each importing module to its set of supplier modules. Built from PE import tables, not code-level xrefs. API-set names (e.g. `api-ms-win-core-*`) are resolved to real DLL names during indexing.

## Error Handling

| Condition | Behavior |
|-----------|----------|
| Tracking DB missing | `emit_error()` with `NOT_FOUND` |
| Module has no imports/exports JSON | Module skipped with warning; indexing continues |
| Forwarded target not in analyzed set | Chain reports endpoint; notes target is unanalyzed |
| Malformed JSON in file_info | `parse_json_safe` returns None; module skipped |
| `--consumers` without `--module` | `emit_error()` with `INVALID_ARGS` |
| `--function` without `--module` (resolve_forwarders) | `emit_error()` with `INVALID_ARGS` |
