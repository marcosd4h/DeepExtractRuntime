# Helpers Library

Shared Python modules for querying DeepExtractIDA analysis outputs. Every
skill script, agent script, hook, and command in the runtime imports from
this library. It is the single source of truth for database access, function
resolution, classification, error handling, and all other cross-cutting
infrastructure.

> **Rule: never reimplement what helpers already provide.** Before writing any
> utility code in a new script, check this reference. Using helpers ensures
> consistency, prevents divergent implementations, and lets every script
> benefit when a helper is improved.

---

## When to Use Helpers

Use the helpers library whenever you are developing:

- **Skill scripts** (`skills/<name>/scripts/*.py`) -- import via `_common.py`
- **Agent scripts** (`agents/<name>/scripts/*.py`) -- import via `_common.py`
- **Hook scripts** (`hooks/*.py`) -- import after adding `.agent` to `sys.path`
- **Inline Python** in command workflows -- run from `.agent/` working directory
- **Tests** (`tests/*.py`) -- import directly since `conftest.py` handles paths

If your code touches an analysis database, resolves a function, classifies an
API, emits JSON output, reports an error, or does anything listed in the
categories below -- there is a helper for it.

---

## Import Patterns

### From skill/agent scripts (recommended)

Route through your `scripts/_common.py` which handles workspace bootstrap:

```python
# scripts/_common.py
from skills._shared import bootstrap, make_db_resolvers

WORKSPACE_ROOT = bootstrap(__file__)
resolve_db_path, resolve_tracking_db = make_db_resolvers(WORKSPACE_ROOT)

from helpers import (  # noqa: E402
    open_individual_analysis_db,
    emit_error,
    resolve_function,
)
```

Then in your script:

```python
import sys
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT_DIR))

from _common import resolve_db_path, open_individual_analysis_db, emit_error
from helpers.callgraph import CallGraph          # additional helpers not in _common
from helpers.errors import db_error_handler      # submodule imports
```

### From hook scripts

Hooks add `.agent` to `sys.path` manually:

```python
AGENT_DIR = Path(__file__).resolve().parent.parent  # .agent/
sys.path.insert(0, str(AGENT_DIR))

from helpers.analyzed_files_db import open_analyzed_files_db
from helpers.session_utils import resolve_session_id
```

### From inline Python in commands

Run from the `.agent/` directory so `helpers` is importable:

```bash
cd <workspace>/.agent && python -c "
from helpers.validation import validate_workspace_data
status = validate_workspace_data('..')
print(status)
"
```

### Import style

Two styles are supported. Both work; use whichever is clearest:

```python
# Style A: top-level re-exports (concise, most common)
from helpers import open_individual_analysis_db, resolve_function, emit_error

# Style B: submodule imports (explicit provenance)
from helpers.errors import emit_error, db_error_handler
from helpers.json_output import emit_json
from helpers.callgraph import CallGraph
```

Style A uses the 170+ symbols re-exported by `helpers/__init__.py`. Style B
is preferred when you need symbols not in the top-level re-exports, or when
you want the import to show which module a symbol comes from.

---

## Helper Categories

### Database Access

Open and query the read-only SQLite databases produced by DeepExtractIDA.
All connections enforce `PRAGMA query_only = ON`.

| Operation | Helper | Module |
|-----------|--------|--------|
| Open per-module analysis DB | `open_individual_analysis_db(db_path)` | `individual_analysis_db` |
| Open tracking DB (module index) | `open_analyzed_files_db(db_path)` | `analyzed_files_db` |
| Resolve DB path from module name | `resolve_db_path_auto(db_path)` | `db_paths` |
| Resolve tracking DB path | `resolve_tracking_db_auto(workspace)` | `db_paths` |
| Windows long-path support | `safe_long_path(path)` | `db_paths` |

**Key types:** `IndividualAnalysisDB`, `FunctionRecord`, `FileInfoRecord`,
`AnalyzedFilesDB`, `AnalyzedFileRecord`.

### Function Resolution

Look up, search, filter, and batch-resolve functions.

| Operation | Helper | Module |
|-----------|--------|--------|
| Resolve by name or ID | `resolve_function(db, name_or_id)` | `function_resolver` |
| Search by regex pattern | `search_functions_by_pattern(db, pattern)` | `function_resolver` |
| Load function index from JSON | `load_function_index_for_db(db_path)` | `function_index` |
| Lookup in index | `lookup_function(index, name)` | `function_index` |
| Batch resolve multiple functions | `batch_resolve_functions(db, ids)` | `batch_operations` |
| Batch extract function data | `batch_extract_function_data(db, ids)` | `batch_operations` |
| Filter application-only functions | `filter_application_functions(index)` | `function_index` |
| Check if function is library code | `is_library_function(entry)` | `function_index` |

### API and String Classification

Classify Win32/NT APIs and string literals by category and security relevance.

| Operation | Helper | Module |
|-----------|--------|--------|
| Classify API by functional area | `classify_api(api_name)` | `api_taxonomy` |
| Classify API for security impact | `classify_api_security(api_name)` | `api_taxonomy` |
| Get API fingerprint for a set | `classify_api_fingerprint(api_list)` | `api_taxonomy` |
| Get dangerous API set | `get_dangerous_api_set()` | `api_taxonomy` |
| Categorize a string literal | `categorize_string(string)` | `string_taxonomy` |
| Full string taxonomy | `STRING_TAXONOMY` | `string_taxonomy` |
| Full API taxonomy (17 categories) | `API_TAXONOMY` | `api_taxonomy` |
| Security API categories (11 cats) | `SECURITY_API_CATEGORIES` | `api_taxonomy` |

### Call Graph and Cross-Module Analysis

Build, traverse, and query directed call graphs.

| Operation | Helper | Module |
|-----------|--------|--------|
| Build call graph | `CallGraph.from_functions(functions)` | `callgraph` |
| Reachable from a node | `graph.reachable_from(func_id)` | `callgraph` |
| Find path between functions | `graph.bfs_path(src, dst)` | `callgraph` |
| Strongly connected components | `graph.strongly_connected_components()` | `callgraph` |
| Cross-module graph | `CrossModuleGraph(...)` | `cross_module_graph` |
| Module resolver for xrefs | `ModuleResolver(...)` | `cross_module_graph` |

### Module Profiles

Query pre-computed module fingerprints (noise ratio, API surface, complexity).

| Operation | Helper | Module |
|-----------|--------|--------|
| Load profile for a DB | `load_profile_for_db(db_path)` | `module_profile` |
| Load all module profiles | `load_all_profiles(workspace)` | `module_profile` |
| Get noise ratio (library %) | `get_noise_ratio(profile)` | `module_profile` |
| Get technology flags | `get_technology_flags(profile)` | `module_profile` |
| Get canary coverage | `get_canary_coverage(profile)` | `module_profile` |

### param_risk

Parameter-type risk scoring from C-style function signatures. Relocated from
`map-attack-surface` skill to enable cross-skill reuse.

| Symbol | Type | Description |
|--------|------|-------------|
| `score_parameter_risk(signature)` | function | Returns `(risk_score: float, reasons: list[str])` |
| `HIGH_RISK_PARAM_PATTERNS` | list | 11 regex patterns with risk scores for parameter types |
| `BUFFER_SIZE_PAIR_PATTERNS` | list | 3 compiled regexes detecting buffer+size parameter pairs |

The risk score is 0.0-1.0: weighted combination of max parameter type risk and
average across all parameters, with bonus for parameter count.

### winrt_index

WinRT server index built from extraction data across four access contexts.

- **WinrtIndex** -- queryable index over WinRT server registrations
  - `load(data_root)` -- load all four access contexts
  - `get_servers_for_module(name)` -> list[WinrtServer]
  - `get_servers_by_class(class_name)` -> WinrtServer | None
  - `get_procedures_for_module(name)` -> list[str]
  - `is_winrt_procedure(module, func_name)` -> bool
  - `get_interfaces_for_module(name)` -> list[WinrtInterface]
  - `get_methods_for_class(class_name)` -> list[WinrtMethod]
  - `search_methods(pattern)` -> list[WinrtMethod]
  - `get_access_contexts_for_class(class_name)` -> set[WinrtAccessContext]
  - `get_privileged_surface(caller_il)` -> list[WinrtServer]
  - `get_servers_by_risk(tier)` -> list[WinrtServer]
  - `get_all_classes()` -> list[str]
  - `get_all_modules()` -> list[str]
  - `summary()` -> dict
- **WinrtServer**(dataclass) -- server class metadata with risk tier computation
- **WinrtInterface**(dataclass) -- interface with GUID, methods, pseudo-IDL
- **WinrtMethod**(dataclass) -- method with name, access type, binary file
- **WinrtAccessContext**(enum) -- HIGH_IL_ALL, HIGH_IL_PRIVILEGED, MEDIUM_IL_ALL, MEDIUM_IL_PRIVILEGED
- **get_winrt_index**() -> WinrtIndex -- cached singleton
- **invalidate_winrt_index**() -- clear cached index

### com_index

COM server index built from extraction data across four access contexts.

- **ComIndex** -- queryable index over COM server registrations
  - `load(data_root)` -- load all four access contexts
  - `get_servers_for_module(name)` -> list[ComServer]
  - `get_server_by_clsid(clsid)` -> ComServer | None
  - `get_procedures_for_module(name)` -> list[str]
  - `is_com_procedure(module, func_name)` -> bool
  - `get_interfaces_for_module(name)` -> list[ComInterface]
  - `get_methods_for_clsid(clsid)` -> list[ComMethod]
  - `search_methods(pattern)` -> list[ComMethod]
  - `get_access_contexts_for_clsid(clsid)` -> set[ComAccessContext]
  - `get_privileged_surface(caller_il)` -> list[ComServer]
  - `get_servers_by_risk(tier)` -> list[ComServer]
  - `get_elevatable_servers()` -> list[ComServer]
  - `get_servers_by_service(name)` -> list[ComServer]
  - `find_servers_for_interface(iid)` -> list[ComServer]
  - `get_all_clsids()` -> list[str]
  - `get_all_modules()` -> list[str]
  - `get_all_services()` -> list[str]
  - `summary()` -> dict
- **ComServer**(dataclass) -- CLSID metadata with risk tier computation, elevation/DCOM/marshalling flags
- **ComInterface**(dataclass) -- interface with GUID, methods, pseudo-IDL
- **ComMethod**(dataclass) -- method with name, access type, binary file, interface name
- **ComAccessContext**(enum) -- HIGH_IL_ALL, HIGH_IL_PRIVILEGED, MEDIUM_IL_ALL, MEDIUM_IL_PRIVILEGED
- **get_com_index**() -> ComIndex -- cached singleton
- **invalidate_com_index**() -- clear cached index

### rpc_index

RPC server index loader and query engine. Loads ground-truth RPC interface data
from `config/assets/rpc_data/rpc_servers.json`.

| Symbol | Type | Description |
|--------|------|-------------|
| `RpcIndex` | class | Queryable index of RPC interfaces and procedures |
| `RpcInterface` | dataclass | Single RPC interface with UUID, procedures, endpoints |
| `get_rpc_index()` | function | Return global singleton `RpcIndex` (lazy-loaded) |
| `invalidate_rpc_index()` | function | Clear cached singleton (for testing) |

Key query methods on `RpcIndex`:
- `get_procedures_for_module(name)` -- confirmed RPC procedure names for a binary
- `is_rpc_procedure(module, func)` -- exact match against known procedures
- `get_interface_for_procedure(module, func)` -- returns the owning `RpcInterface`
- `get_interfaces_for_module(module)` -- all interfaces registered in a binary
- `compute_blast_radius(uuid)` -- co-hosted sibling interfaces in same process

### Error Handling and Output

Structured error reporting, JSON output, and progress feedback. All scripts
must use these rather than raw `print()` or `sys.exit()`.

| Operation | Helper | Module |
|-----------|--------|--------|
| Fatal error (exit 1) | `emit_error(msg, code)` | `errors` |
| Raise in library code | `raise ScriptError(msg, code)` | `errors` |
| Non-fatal warning | `log_warning(msg, code)` | `errors` |
| DB error context manager | `db_error_handler(db_path, op)` | `errors` |
| Emit JSON to stdout | `emit_json(data)` | `json_output` |
| Emit JSON list wrapper | `emit_json_list(key, items)` | `json_output` |
| Check if JSON mode forced | `should_force_json()` | `json_output` |
| Progress status to stderr | `status_message(msg)` | `progress` |
| Progress iterator | `progress_iter(items, label)` | `progress` |
| Class-based progress | `ProgressReporter(total, label)` | `progress` |

**Error codes:** `NOT_FOUND`, `INVALID_ARGS`, `DB_ERROR`, `PARSE_ERROR`,
`NO_DATA`, `AMBIGUOUS`, `UNKNOWN`.

### Caching

Filesystem cache with 24-hour TTL validated by database modification time.

| Operation | Helper | Module |
|-----------|--------|--------|
| Check cache | `get_cached(db_path, key, params)` | `cache` |
| Store in cache | `cache_result(db_path, key, data, params)` | `cache` |
| Clear module cache | `clear_cache(module, operation)` | `cache` |
| Clear cache by DB path | `clear_cache_for_db(db_path, operation)` | `cache` |

### Validation

Pre-flight checks and argument validation.

| Operation | Helper | Module |
|-----------|--------|--------|
| Validate workspace data exists | `validate_workspace_data(workspace)` | `validation` |
| Validate analysis DB integrity | `validate_analysis_db(db_path)` | `validation` |
| Quick-validate a DB | `quick_validate(db_path)` | `validation` |
| Validate function ID format | `validate_function_id(func_id)` | `validation` |
| Validate positive integer | `validate_positive_int(value)` | `validation` |

### Parsing and Type Utilities

Helpers for parsing decompiled code, assembly, mangled names, and types.

| Operation | Helper | Module |
|-----------|--------|--------|
| Parse class from mangled name | `parse_class_from_mangled(name)` | `mangled_names` |
| Extract function calls from source | `extract_function_calls(source)` | `decompiled_parser` |
| Split function arguments | `split_arguments(arg_string)` | `decompiled_parser` |
| Find parameter usage in calls | `find_param_in_calls(source, param)` | `decompiled_parser` |
| Scan struct accesses (decompiled) | `scan_decompiled_struct_accesses(src)` | `struct_scanner` |
| Scan struct accesses (assembly) | `scan_assembly_struct_accesses(asm)` | `struct_scanner` |
| Batch struct scanning | `scan_batch_struct_accesses(funcs)` | `struct_scanner` |
| Merge scanned struct fields | `merge_scanned_struct_fields(fields)` | `struct_scanner` |
| Get assembly metrics | `get_asm_metrics(asm_text)` | `asm_metrics` |
| x64 assembly regex patterns | `ASM_CALL_RE`, `ASM_BRANCH_RE`, etc. | `asm_patterns` |
| x64 calling convention tables | `PARAM_REGISTERS`, `REGISTER_TO_PARAM` | `calling_conventions` |
| IDA type to C type mapping | `IDA_TO_C_TYPE`, `TYPE_SIZES` | `type_constants` |
| Classify guard conditions | `classify_guard(condition)` | `guard_classifier` |

### Script Runner (Inter-Skill Calls)

Execute skill and agent scripts as subprocesses.

| Operation | Helper | Module |
|-----------|--------|--------|
| Find a skill script path | `find_skill_script(skill, script)` | `script_runner` |
| Run a skill script | `run_skill_script(skill, script, args)` | `script_runner` |
| Load a skill module in-process | `load_skill_module(skill, module)` | `script_runner` |
| Get workspace root path | `get_workspace_root()` | `script_runner` |
| Get workspace args | `get_workspace_args()` | `script_runner` |

### Pipeline Planning and Execution

Parse YAML batch pipeline definitions, resolve modules, and execute headless
multi-module analysis runs.

| Operation | Helper | Module |
|-----------|--------|--------|
| Load pipeline YAML | `load_pipeline(yaml_path)` | `pipeline_schema` |
| Validate pipeline definition | `validate_pipeline(definition, root)` | `pipeline_schema` |
| Resolve module list | `resolve_modules(modules, root)` | `pipeline_schema` |
| Render output directory | `render_output_path(template, name, root)` | `pipeline_schema` |
| Step registry | `STEP_REGISTRY` | `pipeline_schema` |
| Execute one module | `execute_module(module, steps, settings, batch_dir)` | `pipeline_executor` |
| Execute batch pipeline | `execute_pipeline(definition, root)` | `pipeline_executor` |
| Write batch manifest | `write_batch_manifest(batch_dir, definition, progress)` | `pipeline_executor` |
| Write batch summary | `write_batch_summary(batch_dir, result)` | `pipeline_executor` |

### Workspace and Orchestration

Multi-step workflow handoff and agent orchestration.

| Operation | Helper | Module |
|-----------|--------|--------|
| List workspace runs | `list_runs(module=None, goal=None, limit=10)` | `workspace` |
| Prepare workspace step | `prepare_step(run_dir, step)` | `workspace_bootstrap` |
| Complete workspace step | `complete_step(run_dir, step, data)` | `workspace_bootstrap` |
| Validate workspace run | `validate_workspace_run(run_dir)` | `workspace_validation` |
| Resolve session ID | `resolve_session_id()` | `session_utils` |
| Get scratchpad path | `scratchpad_path(session_id)` | `session_utils` |
| Agent base class | `AgentBase` | `agent_common` |
| Agent orchestrator | `AgentOrchestrator` | `agent_common` |
| Hierarchical config loader | `load_config()` | `config` |

### Standalone Scripts

Run directly from the command line (not imported as modules):

| Script | Purpose | Usage |
|--------|---------|-------|
| `unified_search.py` | Search across functions, strings, APIs, classes, exports | `python .agent/helpers/unified_search.py <db> --query <term> [--json]` |
| `cleanup_workspace.py` | Clean old workspace run directories | `python .agent/helpers/cleanup_workspace.py [--older-than DAYS] [--dry-run]` |
| `pipeline_cli.py` | Headless batch pipeline CLI (run, validate, list-steps) | `python .agent/helpers/pipeline_cli.py run <yaml> [--json]` |

> **Programmatic search**: Skill scripts that need to combine search with other
> logic should import `run_search` directly instead of spawning a subprocess:
>
> ```python
> from helpers.unified_search import run_search
> results = run_search(db_path, "CreateProcess", dimensions=["name", "api"])
> for hit in results.matches:
>     print(hit.function_name, hit.relevance_score)
> ```
>
> This avoids subprocess overhead and gives direct access to `UnifiedSearchResults`
> with per-hit relevance scoring.  The CLI entrypoint remains available for
> agent-level use via command workflows.

---

## Common Anti-Patterns

These are the most frequent mistakes when developing scripts. All are avoided
by using the appropriate helper.

| Anti-Pattern | Use Instead |
|-------------|-------------|
| Raw `sqlite3.connect()` | `open_individual_analysis_db(db_path)` |
| `SELECT * FROM functions WHERE ...` | `resolve_function(db, name_or_id)` |
| Manual path joining for DBs | `resolve_db_path_auto(workspace, module)` |
| `print(json.dumps(...))` for output | `emit_json(data)` |
| `sys.exit(1)` with print to stderr | `emit_error(msg, code)` |
| Hand-parsing function/class names | `parse_class_from_mangled(name)` |
| Custom API categorization | `classify_api(name)` or `classify_api_security(name)` |
| `print("Processing...")` to stdout | `status_message("Processing...")` (writes to stderr) |
| Ad-hoc string classification | `categorize_string(s)` |
| Manual cache file management | `get_cached()` / `cache_result()` |

---

## Developing a New Helper

If you need shared logic that does not fit any existing module, consider adding
a new helper. Follow these steps:

1. Create `helpers/<module_name>.py` with a module docstring.
2. Keep the module focused on one functional area.
3. Add public symbols to `helpers/__init__.py` re-exports and `__all__`.
4. Update this README with the new module in the appropriate category table.
5. Add tests in `.agent/tests/` covering the public API.
6. Use `ScriptError` for recoverable errors; let callers decide how to handle.
7. Never write to databases -- all helpers are read-only.

---

## Subpackage Documentation

Detailed documentation for the database subpackages:

- [`analyzed_files_db/README.md`](analyzed_files_db/README.md) -- tracking database API
- [`individual_analysis_db/README.md`](individual_analysis_db/README.md) -- per-binary analysis database API
- [`function_index/`](function_index/) -- JSON index for fast function-to-file resolution

## Further Reading

| Document | Description |
|----------|-------------|
| [Helper API Reference](../docs/helper_api_reference.md) | Full public API for all 30+ modules |
| [Skill Authoring Guide](../docs/skill_authoring_guide.md) | Section 7: Helper Integration Reference |
| [Command Authoring Guide](../docs/command_authoring_guide.md) | Section 4: Python Execution Context |
| [Agent Authoring Guide](../docs/agent_authoring_guide.md) | Section 4: Shared Utilities |
| [Error Handling Convention](../../.cursor/rules/error-handling-convention.mdc) | Layered error handling rules |
| [JSON Output Convention](../../.cursor/rules/json-output-convention.mdc) | stdout/stderr separation rules |
