---
name: import-export-resolver
description: >-
  Resolve PE-level import and export relationships across all analyzed
  modules in a DeepExtractIDA workspace. Answers which module exports a
  given function, which modules import it, builds PE-level module
  dependency graphs, and follows forwarded export chains. Use when the
  user asks which DLL exports a function, who imports a function, what
  a module depends on at the loader level, wants PE import/export
  tables (not code xrefs), asks about forwarded exports, needs
  cross-module dependency mapping from import tables, or wants to know
  all consumers of a given DLL.
cacheable: true
depends_on: ["decompiled-code-extractor"]
---

# Import/Export Resolution

## Purpose

Resolve PE-level import and export relationships across all analyzed
modules. This skill works from the PE import/export tables stored in
`file_info.imports` and `file_info.exports` -- the authoritative record
of what the Windows loader resolves at load time.

This is distinct from code-level xrefs (`simple_outbound_xrefs`) that
`callgraph-tracer` uses. PE tables are ground truth for loader-level
dependencies; xrefs capture what IDA found in the disassembly. Use this
skill for loader-level questions, `callgraph-tracer` for code-level
call chains.

## When NOT to Use

- Tracing code-level call chains or cross-module execution paths -- use **callgraph-tracer**
- Categorizing imports by API type (file I/O, crypto, network, etc.) -- use **generate-re-report** (`analyze_imports.py`)
- Mapping attack surface or ranking entry points by risk -- use **map-attack-surface**
- General function explanation or decompiled code analysis -- use **re-analyst** or `/explain`
- Understanding cross-module data flow (taint propagation, parameter tracing) -- use **taint-analysis** or **data-flow-tracer**

## Data Sources

### SQLite Databases (primary)

- `file_info.imports` -- PE import table (JSON). Each entry has
  `module_name`, `functions[]` with `function_name`, `is_delay_loaded`,
  `ordinal`. API-set names are resolved to real DLLs.
- `file_info.exports` -- PE export table (JSON). Each entry has
  `function_name`, `ordinal`, `is_forwarded`, `forwarded_to`.
- `analyzed_files.db` -- tracking DB for module discovery.

See [data_format_reference.md](../docs/data_format_reference.md) and
[file_info_format_reference.md](../docs/file_info_format_reference.md)
for full JSON schemas.

### Finding a Module DB

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py --list
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py appinfo.dll
```

## Utility Scripts

### query_function.py -- Resolve Function Importers/Exporters (Start Here)

Find which modules export a function and which modules import it.

```bash
python .agent/skills/import-export-resolver/scripts/query_function.py --function CreateProcessW

python .agent/skills/import-export-resolver/scripts/query_function.py --function CreateProcessW --direction export --json

python .agent/skills/import-export-resolver/scripts/query_function.py --function HeapAlloc --direction both --json
```

Output includes: list of exporting modules (with ordinal and forwarder
info) and list of importing modules (with source DLL and delay-load
status).

### build_index.py -- Build Cross-Module Import/Export Index

Build and cache the cross-module PE import/export index. Other scripts
invoke this automatically; run it directly to see index statistics.

```bash
python .agent/skills/import-export-resolver/scripts/build_index.py

python .agent/skills/import-export-resolver/scripts/build_index.py --json

python .agent/skills/import-export-resolver/scripts/build_index.py --no-cache
```

Output includes: module count, total exports, total imports, forwarded
export count, unique name counts.

### module_deps.py -- PE-Level Module Dependency Graph

Build a module dependency graph from PE import tables. Optionally focus
on a single module or show reverse dependencies (consumers).

```bash
python .agent/skills/import-export-resolver/scripts/module_deps.py

python .agent/skills/import-export-resolver/scripts/module_deps.py --module ntdll.dll --consumers --json

python .agent/skills/import-export-resolver/scripts/module_deps.py --module appinfo.dll --json

python .agent/skills/import-export-resolver/scripts/module_deps.py --diagram
```

### resolve_forwarders.py -- Follow Forwarded Export Chains

Follow forwarded export chains across DLLs (e.g.
`kernel32!HeapAlloc` -> `ntdll!RtlAllocateHeap`).

```bash
python .agent/skills/import-export-resolver/scripts/resolve_forwarders.py --module kernel32.dll --function HeapAlloc

python .agent/skills/import-export-resolver/scripts/resolve_forwarders.py --module kernel32.dll --all --json
```

## Workflows

### Workflow 1: "Which module exports CreateProcessW?"

Import/Export Resolution Progress:
- [ ] Step 1: Build or load the import/export index
- [ ] Step 2: Query for exporters

**Step 1**: Build the index (auto-cached).

```bash
python .agent/skills/import-export-resolver/scripts/build_index.py
```

**Step 2**: Query for the function.

```bash
python .agent/skills/import-export-resolver/scripts/query_function.py --function CreateProcessW --direction export --json
```

### Workflow 2: "What does appinfo.dll import and from where?"

Import/Export Resolution Progress:
- [ ] Step 1: Build the index
- [ ] Step 2: Query module suppliers

**Step 1**: Build the index.

```bash
python .agent/skills/import-export-resolver/scripts/build_index.py
```

**Step 2**: Get the module's import dependencies.

```bash
python .agent/skills/import-export-resolver/scripts/module_deps.py --module appinfo.dll --json
```

### Workflow 3: "Show all modules that depend on ntdll.dll"

Import/Export Resolution Progress:
- [ ] Step 1: Build the index
- [ ] Step 2: Query consumers

**Step 1**: Build the index.

```bash
python .agent/skills/import-export-resolver/scripts/build_index.py
```

**Step 2**: Find consumers of ntdll.dll.

```bash
python .agent/skills/import-export-resolver/scripts/module_deps.py --module ntdll.dll --consumers --json
```

## Step Dependencies

- `build_index.py` is a prerequisite for all other scripts (auto-invoked
  by the `ImportExportIndex` helper when needed).
- `query_function.py`, `module_deps.py`, and `resolve_forwarders.py`
  are independent of each other.

## Prompt Patterns

### Pattern A: Function resolution

> "which DLL exports CreateProcessW?"

- Run: `query_function.py --function CreateProcessW --direction export --json`

### Pattern B: Module dependency

> "what does appinfo.dll depend on?"

- Run: `module_deps.py --module appinfo.dll --json`

### Pattern C: Reverse dependency

> "who imports from ntdll.dll?"

- Run: `module_deps.py --module ntdll.dll --consumers --json`

## Exclusions

- Does NOT trace code-level xrefs or call chains. Use
  `callgraph-tracer` for that.
- Does NOT classify imports by API category (file I/O, crypto, etc.).
  Use `generate-re-report` (`analyze_imports.py`) for that.
- Does NOT analyze individual function behavior. Use
  `decompiled-code-extractor` or `security-dossier`.

## Degradation Paths

1. **Tracking DB missing** -- Report error with `NOT_FOUND`. Suggest
   `find_module_db.py --list` to verify available modules.
2. **Module has no imports/exports JSON** -- Skip module, log warning,
   continue indexing remaining modules.
3. **Forwarded export target not in analyzed set** -- Report chain
   endpoint and note the target module is not analyzed.
4. **Malformed JSON in file_info** -- `parse_json_safe` returns None;
   module is skipped with a warning. No crash.

## Integration with Other Skills

| Task | Recommended Skill |
|------|-------------------|
| Code-level call chain tracing | callgraph-tracer |
| Import categorization by API type | generate-re-report |
| Exports as attack entry points | map-attack-surface |
| Cross-module taint propagation | taint-analysis |

## Direct Helper Module Access

For programmatic use without the script wrappers:

- `helpers.ImportExportIndex(tracking_db)` -- build cross-module index
- `index.who_exports(name)` -- find all exporters
- `index.who_imports(name, from_module=...)` -- find all importers
- `index.module_consumers(name)` -- reverse dependency lookup
- `index.module_suppliers(name)` -- forward dependency lookup
- `index.resolve_forwarder_chain(module, function)` -- follow forwarders
- `index.dependency_graph()` -- full module dependency graph

## Performance

| Operation | Typical Time | Notes |
|---|---|---|
| Build full index (50 modules) | ~2-5s | Scales with total import/export count |
| Single function query | <0.1s | Index lookup after build |
| Module dependency graph | ~1s | Reuses cached index |
| Forwarder chain resolution | <0.5s | Bounded by max_depth=5 |

## Additional Resources

- [README.md](README.md) -- CLI usage examples and output format
- [data_format_reference.md](../docs/data_format_reference.md) -- DB schema
- [file_info_format_reference.md](../docs/file_info_format_reference.md) -- PE imports/exports JSON schema
- Related: [callgraph-tracer](../callgraph-tracer/SKILL.md) (code xrefs),
  [generate-re-report](../generate-re-report/SKILL.md) (import categorization),
  [map-attack-surface](../map-attack-surface/SKILL.md) (exports as entry points)
