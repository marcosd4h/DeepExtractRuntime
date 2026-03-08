# Helper API Reference -- DeepExtractIDA Agent Analysis Runtime

This reference documents the public API for the 35+ modules in `.agent/helpers/`. These modules provide the foundational data access, analysis taxonomies, and infrastructure used by skills, agents, and commands.

## 1. Database Access

### individual_analysis_db
Provides read-only access to per-binary analysis SQLite databases.

- **IndividualAnalysisDB**(db_path: str)
  - `get_file_info()` -> FileInfoRecord
  - `get_function_by_id(func_id: int)` -> FunctionRecord
  - `get_function_by_name(name: str)` -> FunctionRecord
  - `search_functions(name_contains: str, limit: int = 50, offset: int = 0)` -> Page[FunctionRecord]
  - `get_all_functions(limit: int = 100, offset: int = 0)` -> Page[FunctionRecord]
- **FunctionRecord**(dataclass)
  - Fields: `id`, `name`, `mangled_name`, `signature`, `decompiled_code`, `assembly_code`, `inbound_xrefs`, `outbound_xrefs`, `strings`, `globals`, `dangerous_api_calls`, `loop_analysis`, `stack_frame`
- **FileInfoRecord**(dataclass)
  - Fields: `file_name`, `file_hash`, `architecture`, `security_features`, `exports`, `entry_points`, `tls_callbacks`
- **parse_json_safe**(data: str | dict | None) -> dict | list | None
  - Parses JSON strings from DB columns into Python objects.

### analyzed_files_db
Manages the tracking database for all analyzed modules.

- **AnalyzedFilesDB**(db_path: str)
  - `get_by_file_name(name: str)` -> list[AnalyzedFileRecord]
  - `get_complete()` -> list[AnalyzedFileRecord]
  - `get_by_hash(file_hash: str)` -> AnalyzedFileRecord | None
- **AnalyzedFileRecord**(dataclass)
  - Fields: `file_name`, `file_hash`, `analysis_db_path`, `status`, `created_at`

### db_paths
Centralized resolution for database file paths.

- `resolve_db_path(db_path: str, workspace_root: Path)` -> str
  - Resolves a DB path relative to *workspace_root*, falling back to `extracted_dbs/`.
- `resolve_db_path_auto(db_path: str)` -> str
  - Same as above but auto-detects workspace root from helpers/ location.
- `resolve_module_db(module_name_or_path: str, workspace_root: Path, *, require_complete: bool = True)` -> str | None
  - Resolves a module name or `.db` path to an absolute DB path.
- `resolve_module_db_auto(module_name_or_path: str, *, require_complete: bool = True)` -> str | None
  - Same as above but auto-detects workspace root.
- `resolve_tracking_db(workspace_root: Path)` -> str | None
  - Returns the path to `analyzed_files.db` (checks `extracted_dbs/` then root).
- `resolve_tracking_db_auto()` -> str | None
  - Same as above but auto-detects workspace root.

## 2. Function Resolution

### function_index
High-performance function-to-file resolution using `function_index.json`.

- `load_function_index(module_name: str)` -> dict
  - Loads the function index for a specific module.
- `lookup_function(index: dict, name: str)` -> dict | None
  - Resolves a function name to its metadata (file, library tag, ID).
- `filter_by_library(index: dict, functions: list[str])` -> list[str]
  - Filters out functions tagged as library code (WIL, STL, CRT, etc.).
- `is_application_function(index: dict, name: str)` -> bool
  - Returns True if the function is not tagged as library code.

### function_resolver
Unified function lookup across multiple modules.

- `resolve_function(db: IndividualAnalysisDB, identifier: str | int)` -> FunctionRecord | None
  - Resolves a function by its name or integer ID.
- `search_functions_by_pattern(db: IndividualAnalysisDB, pattern: str)` -> list[FunctionRecord]
  - Searches functions using substring or regex patterns.

### unified_search
Multi-dimensional search across module databases.

- **unified_search.py** (Standalone Script)
  - Dimensions: `name`, `signature`, `string`, `api`, `dangerous`, `class`, `export`
  - Match Modes: `substring`, `regex`, `fuzzy`
  - Usage: `python .agent/helpers/unified_search.py <db> --query <term>`

## 3. Analysis Taxonomies

### api_taxonomy
Classification of Win32/NT APIs into functional and security categories.

- `classify_api(api_name: str)` -> str | None
  - Returns the functional category (e.g., `file_io`, `registry`, `network`).
- `classify_api_security(api_name: str)` -> str | None
  - Returns the security impact category (e.g., `privilege_escalation`, `data_leakage`).
- `classify_api_fingerprint(api_name: str)` -> str | None
  - Returns a coarse fingerprint bucket (`"com"`, `"rpc"`, `"security"`, `"crypto"`) for module-level density counting.
- `get_dangerous_api_set()` -> set[str]
  - Returns a set of all APIs classified as security-sensitive.
- `DISPATCH_KEYWORDS`: tuple of function-name substrings suggesting dispatch/routing behaviour.

### string_taxonomy
Categorization of string literals using regex patterns.

- `categorize_string(s: str)` -> str
  - Categorizes a string (e.g., `file_path`, `registry_key`, `url`, `guid`).
- `categorize_strings(strings: list[str])` -> dict[str, list[str]]
  - Batch categorizes a list of strings.

### type_constants
Mappings for C/C++ type sizes and IDA-to-C type conversions.

- `TYPE_SIZES`: dict[str, int] (e.g., `BYTE: 1`, `DWORD: 4`)
- `IDA_TO_C_TYPE`: dict[str, str] (e.g., `_BYTE: unsigned char`)
- `SIZE_TO_C_TYPE`: dict[int, str] (e.g., `4: uint32_t`)

## 4. Graph & Topology

### callgraph
Directed graph construction and traversal for function xrefs.

- **CallGraph**
  - `from_functions(functions: list[FunctionRecord])` -> CallGraph
  - `reachable_from(func_id: int, max_depth: int = 5)` -> set[int]
  - `callers_of(func_id: int, max_depth: int = 5)` -> set[int]
  - `find_path(start_id: int, end_id: int)` -> list[int] | None
  - `get_stats()` -> dict (node count, edge count, SCC count)

### cross_module_graph
Resolution of external function calls across analyzed modules.

- **CrossModuleGraph**(tracking_db: AnalyzedFilesDB)
  - `resolve_external_call(caller_module: str, callee_name: str)` -> FunctionWithModuleInfo | None
  - `build_cross_module_chain(start_func: str, start_module: str, depth: int = 3)` -> list

## 5. Infrastructure

### cache
Filesystem-based result caching with DB mtime validation.

- `get_cached(db_path: str, operation: str, params: dict = None)` -> dict | None
  - Retrieves a cached result if the DB mtime matches and TTL is valid.
- `cache_result(db_path: str, operation: str, data: dict, params: dict = None)` -> None
  - Atomically writes a result to the cache directory.
- `clear_cache(module_name: str = None)` -> None
  - Clears the cache for a specific module or the entire runtime.

### script_runner
Subprocess management and dynamic module loading.

- `run_skill_script(skill: str, script: str, args: list[str])` -> dict
  - Executes a skill script as a subprocess and returns the parsed JSON output.
- `load_skill_module(skill: str, script: str)` -> module
  - Dynamically imports a skill script as a Python module.
- `find_skill_script(skill: str, script: str)` -> Path
  - Resolves the absolute path to a skill script.

### json_output
Standardized JSON output for skill scripts.

- `emit_json(data: dict, *, status: str = "ok")` -> None
  - Writes a dict to stdout wrapped with a `"status"` key.
- `emit_json_list(key: str, items: list, *, extra: dict = None)` -> None
  - Writes a list payload under *key*, wrapped with `"status"`.
- `should_force_json(args)` -> bool
  - Returns `True` when `--json` was passed or `--workspace-dir` is set.

### errors
Structured JSON error reporting to stderr.

- `emit_error(message: str, code: str)` -> None
  - Writes `{"error": message, "code": code}` to stderr and exits with code 1.
- `log_error(message: str, code: str)` -> None
  - Writes the error JSON to stderr without exiting.
- `log_warning(message: str)` -> None
  - Writes a warning message to stderr.

### progress
Throttled progress reporting for long-running operations.

- **ProgressReporter**(total: int, operation: str)
  - `update(current: int)` -> None
  - `status_message(msg: str)` -> None
- `progress_iter(iterable, total: int = None, operation: str = "")` -> iterator
  - Wraps an iterable with automatic progress reporting.

## 6. Utilities

### mangled_names
Parsing of Microsoft C++ mangled names.

- `parse_class_from_mangled(mangled_name: str)` -> dict | None
  - Extracts `class_name`, `method_name`, `namespaces`, and `role` (e.g., `constructor`).

### module_profile
Access to pre-computed module fingerprints.

- `load_module_profile(module_name: str)` -> dict
- `get_noise_ratio(profile: dict)` -> float
- `get_technology_flags(profile: dict)` -> dict[str, bool] (e.g., `com`, `rpc`, `security`)

### batch_operations
Efficient loading of multiple function records.

- `batch_extract_function_data(db: IndividualAnalysisDB, func_ids: list[int])` -> list[dict]
- `batch_resolve_functions(db: IndividualAnalysisDB, identifiers: list[str | int])` -> list[FunctionRecord]

## 7. WinRT Index

### winrt_index
WinRT server index built from extraction data across four access contexts (caller IL x server privilege).

- **WinrtAccessContext**(enum) -- `HIGH_IL_ALL`, `HIGH_IL_PRIVILEGED`, `MEDIUM_IL_ALL`, `MEDIUM_IL_PRIVILEGED`
- **WinrtMethod**(dataclass) -- `access`, `type`, `name`, `file`; properties: `short_name`, `class_name`, `binary_name`
- **WinrtInterface**(dataclass) -- `name`, `guid`, `methods: list[WinrtMethod]`, `pseudo_idl: list[str]`; property: `method_count`
- **WinrtServer**(dataclass) -- server class metadata with computed properties:
  - `is_out_of_process`, `is_in_process`, `runs_as_system`, `has_permissive_sddl`, `is_remote_activatable`, `is_base_trust`
  - `risk_tier(context)` -> str -- compute risk tier for a given access context
  - `best_risk_tier` -> str -- highest risk across all contexts
  - `to_dict()` -> dict
- **WinrtIndex** -- queryable index:
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
  - `summary()` -> dict
- **get_winrt_index**(force_reload: bool = False) -> WinrtIndex -- cached singleton
- **invalidate_winrt_index**() -- clear cached index

### com_index
COM server index built from extraction data across four access contexts (caller IL x server privilege).

- **ComAccessContext**(enum) -- `HIGH_IL_ALL`, `HIGH_IL_PRIVILEGED`, `MEDIUM_IL_ALL`, `MEDIUM_IL_PRIVILEGED`
- **ComMethod**(dataclass) -- `access`, `type`, `name`, `file`, `interface_name`; properties: `short_name`, `class_name`, `binary_name`
- **ComInterface**(dataclass) -- `name`, `guid`, `methods: list[ComMethod]`, `pseudo_idl: list[str]`; property: `method_count`
- **ComServer**(dataclass) -- CLSID metadata with computed properties:
  - `is_out_of_process` (includes DLL surrogate), `is_in_process`, `runs_as_system`, `has_permissive_launch`, `has_permissive_access`
  - `is_remote_activatable`, `is_trusted_marshaller`, `can_elevate`, `auto_elevation`
  - `risk_tier(context)` -> str -- compute risk tier for a given access context
  - `best_risk_tier` -> str -- highest risk across all contexts
  - `to_dict()` -> dict
- **ComIndex** -- queryable index:
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
  - `summary()` -> dict
- **get_com_index**(force_reload: bool = False) -> ComIndex -- cached singleton
- **invalidate_com_index**() -- clear cached index

## 8. Validation & Sessions

### validation
Integrity checking for analysis databases.

- `validate_analysis_db(db_path: str)` -> ValidationResult
- `quick_validate(db_path: str)` -> bool

### session_utils
Session ID resolution and scratchpad path management.

- `resolve_session_id(stdin_data: dict)` -> str
  - Resolves the current session ID from environment variables or the hook
    protocol's stdin JSON payload. Resolution priority:
    1. `AGENT_SESSION_ID` env var
    2. `conversation_id` from stdin (Cursor)
    3. `session_id` from stdin (Claude Code)
    4. UUID4 fallback
- `scratchpad_path(session_id: str)` -> Path
  - Returns the path to the session-scoped scratchpad file.
