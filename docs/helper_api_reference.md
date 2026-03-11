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

## 9. Decompiled Code Parsing

### decompiled_parser
Regex-based extraction of function calls, arguments, and parameter usage from IDA decompiled C/C++ code.

- `extract_function_calls(code: str, *, keywords: frozenset[str] = _DEFAULT_KEYWORDS)` -> list[dict]
  - Extracts call sites from decompiled code. Handles multi-line calls by joining lines when parentheses are unbalanced. Each dict has: `function_name`, `line_number`, `line`, `arguments`, `result_var`.
- `discover_calls_with_xrefs(code: str, xrefs: list[dict], *, keywords: frozenset[str] = _DEFAULT_KEYWORDS)` -> list[dict]
  - Uses DB `simple_outbound_xrefs` as ground truth for call discovery, enriches with argument expressions from the regex parser. Preferred over `extract_function_calls` alone.
- `split_arguments(args_str: str)` -> list[str]
  - Splits comma-delimited argument strings while respecting nested `()` and `[]`.
- `find_param_in_calls(code: str, param_name: str, *, keywords: frozenset[str] = _DEFAULT_KEYWORDS)` -> list[dict]
  - Finds calls where a named parameter appears in an argument expression. Each dict has: `function_name`, `arg_position`, `arg_expression`, `line_number`, `is_direct`.
- `extract_balanced_parens(text: str, start: int = 0)` -> str | None
  - Extracts content from balanced parentheses starting at `text[start]`.

### guard_classifier
Classifies conditional guards (if/while conditions) in decompiled code by type and attacker influence.

- **Guard**(dataclass)
  - Fields: `guard_type`, `line_number`, `condition_text`, `attacker_controllable`, `bypass_difficulty`, `api_in_condition`, `tainted_vars_in_condition`, `role`, `on_path_to_sink`
- `classify_guard(condition: str, tainted_vars: set[str])` -> Guard
  - Classifies a single condition string. Guard types: `auth_check`, `error_check`, `validation`, `function_check`, `null_check`, `bounds_check`, `comparison`. Bypass difficulty: `easy`, `medium`, `hard`, `unknown`.
- `find_guards_between(code: str, source_line: int, sink_line: int, tainted_vars: set[str], *, path_aware: bool = True)` -> list[Guard]
  - Scans lines between source and sink for `if`/`while` guards. When `path_aware=True`, annotates each guard with role (`protects`, `enables`, `sibling`) and excludes off-path guards.
- `AUTH_CHECK_APIS`: tuple of security-check API name prefixes.
- `VALIDATION_API_PREFIXES`: tuple of validation function prefixes.
- `ERROR_CHECK_MACROS`: tuple of HRESULT/NTSTATUS check macros.

### struct_scanner
Scans decompiled and assembly code for struct/class field accesses to infer memory layouts.

- `scan_decompiled_struct_accesses(code: str, type_sizes: dict[str, int])` -> list[dict]
  - Scans decompiled code for `*(_TYPE *)(base + offset)` and `base->field` patterns. Returns dicts with: `base`, `offset`, `size`, `type_name`, `pattern`.
- `scan_assembly_struct_accesses(asm: str)` -> list[dict]
  - Scans x64 assembly for `[reg+offset]` memory access patterns with ptr-size inference.
- `scan_batch_struct_accesses(code: str, type_sizes: dict[str, int])` -> list[dict]
  - Batch-lift style scanning: returns `base`, `offset`, `size`, `type_name`, `pattern` for indexed, direct, and zero-offset accesses.
- `merge_struct_fields(fields: list[dict])` -> list[dict]
  - Merges overlapping field accesses from multiple functions into a unified layout sorted by offset.
- `parse_signature_params(signature: str)` -> dict[str, str]
  - Parses C-style function signature parameter names and types into a `{name: type}` dict.

## 10. Taint & Data Flow Analysis

### def_use_chain
Lightweight def-use chain analysis with scope-aware taint propagation for IDA Hex-Rays output.

- **VarDef**(dataclass) -- Variable definition (assignment target).
  - Fields: `var`, `line`, `rhs_expr`, `rhs_vars`, `block_idx`, `rhs_call`
- **VarUse**(dataclass) -- Variable use site.
  - Fields: `var`, `line`, `context` (`call_arg`, `condition`, `return`, `array_index`, `struct_write`, `assignment_rhs`), `target_func`, `arg_position`
- **TaintResult**(dataclass) -- Result of taint propagation.
  - Fields: `tainted_vars`, `tainted_calls`, `tainted_conditions`, `tainted_returns`, `tainted_struct_writes`
  - `to_dict()` -> dict
- **TaintSummary**(dataclass) -- Procedure summary for inter-procedural taint.
  - Fields: `function_name`, `tainted_params`, `returns_tainted_from`, `sinks_reached`
- **TaintVar** -- Type alias: `str | tuple[str, str]` (plain variable or field-qualified).
- `parse_def_use(code: str)` -> tuple[list[VarDef], list[VarUse]]
  - Parses decompiled code into variable definitions and uses.
- `propagate_taint(defs, uses, initial_tainted, max_iterations=50, *, scope_aware=True, field_sensitive=False, sanitizer_kill=True)` -> TaintResult
  - Fixed-point taint propagation through def-use chains. Supports scope-aware propagation, field-sensitive taint (`a1->buffer` vs `a1->length`), and sanitizer-kill.
- `analyze_taint(code: str, initial_tainted: set[str], *, scope_aware=True, field_sensitive=False, sanitizer_kill=True)` -> TaintResult
  - One-shot convenience: parses code and propagates taint.
- `build_taint_summary(code: str, param_count: int, function_name: str = "")` -> TaintSummary
  - Runs `analyze_taint` for each parameter and builds an inter-procedural summary.
- `SANITIZER_APIS`: frozenset of APIs that produce trusted output from tainted input.

### constraint_collector
Extracts path constraints from guard conditions on taint paths for feasibility checking.

- **Constraint**(dataclass)
  - Fields: `variable`, `operator` (`==`, `!=`, `<`, `<=`, `>`, `>=`, `is_null`, `not_null`, `in_set`, `not_in_set`), `value`, `source_line`, `raw_condition`, `negated`
  - `to_dict()` -> dict
- **ConstraintSet**(dataclass) -- Constraints that must hold simultaneously.
  - Fields: `constraints`, `disjuncts` (list of ConstraintSet for OR branches), `source_guards`, `unparsed_guards`
  - `add(c: Constraint)` -> None
  - `to_dict()` -> dict
- `collect_constraints(guards: list[Guard])` -> ConstraintSet
  - Extracts variable constraints (comparisons, null checks, range checks) from a list of guard conditions. Handles `&&` conjuncts and top-level `||` disjuncts.

### constraint_solver
Pattern-based constraint satisfiability checker for taint path feasibility.

- **FeasibilityResult**(dataclass)
  - Fields: `feasible` (True | False | None for unknown), `conflicts`, `reason`, `constraints_checked`, `constraints_decidable`
  - `to_dict()` -> dict
- `check_feasibility(constraint_set: ConstraintSet)` -> FeasibilityResult
  - Checks whether constraints can be simultaneously satisfied using range intersections, null/non-null conflicts, equality conflicts, and symbolic equivalence via union-find. Returns `feasible=None` for patterns beyond its capability.

## 11. Finding Normalization & Merging

### finding_schema
Unified finding schema for normalizing results across all vulnerability scanners (taint, memory corruption, logic).

- **Finding**(dataclass) -- Scanner-agnostic vulnerability finding.
  - Fields: `function_name`, `function_id`, `module`, `source_type`, `source_category`, `sink`, `sink_category`, `severity`, `score`, `exploitability_score`, `exploitability_rating`, `verification_status`, `guards`, `path`, `evidence_lines`, `summary`, `extra`
  - `to_dict()` -> dict
  - `dedup_key` (property) -> str -- Deduplication key: `function_id::sink::source_category`.
  - `path_signature` (property) -> str -- SHA-256 hash prefix of sorted path elements.
- `from_taint_finding(finding: dict, func_info: dict | None = None)` -> Finding
  - Converts a taint-analysis finding dict to a unified Finding.
- `from_memory_finding(finding: dict)` -> Finding
  - Converts a MemCorruptionFinding dict to a unified Finding.
- `from_logic_finding(finding: dict)` -> Finding
  - Converts a LogicFinding dict to a unified Finding.
- `from_verified_finding(verified: dict)` -> Finding
  - Converts a VerificationResult dict to a unified Finding (handles both memory and logic verified outputs).
- `normalize_scanner_output(data: dict, source_type: str)` -> list[Finding]
  - Extracts findings from a scanner's JSON output and normalizes them. Handles both raw and verified finding lists.
- `graduated_reachability_score(entry_type: str | None, hops: int)` -> float
  - Computes a graduated reachability score (0.0-1.0) based on entry type and hop distance.

### finding_merge
Merges, deduplicates, and ranks findings across multiple scanner outputs.

- `merge_findings(*scanner_outputs: tuple[dict, str])` -> list[Finding]
  - Merges findings from multiple scanners. Each arg is `(data_dict, source_type)`. Returns deduplicated, score-sorted list.
- `deduplicate(findings: list[Finding], *, max_per_key: int = 3)` -> list[Finding]
  - Removes duplicate findings (same function + sink + category). Keeps up to `max_per_key` distinct paths per dedup key, sorted by score.
- `rank(findings: list[Finding])` -> list[Finding]
  - Sorts findings by composite score descending. Uses exploitability_score if available, severity as tiebreaker.
- `findings_summary(findings: list[Finding])` -> dict
  - Produces summary: total count, by_severity, by_source, top_score.

## 12. Assembly Analysis

### asm_patterns
Shared x64 assembly regex patterns consolidated from multiple skills.

- `ASM_CALL_RE` -- Compiled regex matching `call` instructions.
- `ASM_BRANCH_RE` -- Compiled regex matching conditional/unconditional branch instructions (je, jne, jmp, loop, etc.).
- `ASM_RET_RE` -- Compiled regex matching `ret`/`retn` instructions.
- `ASM_SYSCALL_RE` -- Compiled regex matching `syscall` and `int 2Eh`.
- `IMP_PREFIX_RE` -- Compiled regex stripping `__imp_`/`_imp_`/`j_` prefixes.
- `CALL_TARGET_RE` -- Compiled regex extracting call instruction targets.
- `ASM_MEM_OFFSET_RE` -- Compiled regex matching `[base+offset]` memory references (handles SIB addressing).
- `ASM_PTR_RE` -- Compiled regex matching ptr size qualifiers (`byte ptr`, `dword ptr`, etc.).
- `ASM_LOAD_RE` -- Compiled regex extracting destination register from mov/lea/cmp/test.
- `ASM_PROLOGUE_SAVE_RE` -- Compiled regex matching prologue saves of parameter registers.
- `ASM_GLOBAL_RE` -- Compiled regex matching IDA global variable names (`dword_XXXX`, `qword_XXXX`, etc.).
- `strip_import_prefix(api_name: str)` -> str
  - Removes IDA import-thunk prefixes (`__imp_`, `_imp_`, `j_`, `cs:`) from an API name.

### asm_metrics
Structural metrics extraction from x64 assembly code.

- **AsmMetrics**(dataclass)
  - Fields: `instruction_count`, `call_count`, `branch_count`, `ret_count`, `has_syscall`, `is_leaf`, `is_tiny`
- `get_asm_metrics(assembly_code: str | None)` -> AsmMetrics
  - Extracts structural metrics from IDA-formatted assembly text.
- `count_asm_instructions(assembly_code: str | None)` -> int
  - Counts non-empty, non-comment lines in assembly text.
- `count_asm_calls(assembly_code: str | None)` -> int
  - Counts call instructions in assembly text.

### calling_conventions
x64 fastcall register mappings and assembly width constants.

- `PARAM_REGISTERS`: dict[int, set[str]] -- Parameter number (1-based) to register alias set (e.g., `1: {"rcx", "ecx", "cx", "cl", "ch"}`).
- `REGISTER_TO_PARAM`: dict[str, int] -- Reverse lookup: register name to parameter number.
- `PARAM_REGS_X64` -- Backward-compatible alias for `REGISTER_TO_PARAM`.
- `ASM_REG_SIZES`: dict[str, int] -- Register name to byte width (e.g., `"rax": 8`, `"eax": 4`).
- `ASM_PTR_SIZES`: dict[str, int] -- Instruction operand width qualifiers (e.g., `"byte": 1`, `"qword": 8`).
- `STACK_REGS`: frozenset[str] -- Stack/frame registers excluded from struct-field inference.
- `param_name_for(param_number: int)` -> str
  - Returns IDA-style positional parameter name (`a1`, `a2`, ...).

## 13. Security Analysis Helpers

### param_risk
Parameter-type risk scoring from C-style function signatures.

- `score_parameter_risk(signature: str | None)` -> tuple[float, list[str]]
  - Scores how dangerous a function's parameters look (0.0-1.0). Returns `(risk_score, reasons)`. Weighted combination of max parameter type risk, average risk, and parameter count bonus.
- `HIGH_RISK_PARAM_PATTERNS`: list[tuple[str, float]] -- 11 regex patterns with risk scores for parameter types (buffer pointers, handles, COM interfaces, size parameters).
- `BUFFER_SIZE_PAIR_PATTERNS`: list[re.Pattern] -- 3 compiled regexes detecting buffer+size parameter pair combinations.

### sddl_parser
SDDL ACE parsing with Deny support and effective permission computation.

- **ParsedACE**(dataclass)
  - Fields: `ace_type` (`"A"` Allow or `"D"` Deny), `flags`, `rights`, `object_guid`, `inherit_object_guid`, `account_sid`
- `parse_sddl_aces(sddl: str)` -> list[ParsedACE]
  - Parses all ACEs from an SDDL string in evaluation order.
- `effective_permissions_for_sid(sddl: str, sid: str, *, permissive_sids: set[str] | None = None)` -> tuple[bool, str]
  - Determines whether a SID has effective access after Deny evaluation. Returns `(has_access, reason)`.
- `is_permissive_sddl(sddl: str)` -> bool
  - Checks whether any permissive SID (WD, AC, AU, IU) has effective access. Correctly handles Deny overrides.
- `PERMISSIVE_SIDS`: frozenset of well-known permissive SID abbreviations.

## 14. Command & Pipeline Infrastructure

### command_validation
Pre-execution validation for slash command arguments.

- **CommandValidationResult**(dataclass)
  - Fields: `ok`, `errors`, `error_codes`, `warnings`, `resolved`
  - `add_error(msg: str, code: ErrorCode | str)` -> None
  - `add_warning(msg: str)` -> None
- `validate_module(module_name: str, workspace_root: Path | None = None, *, allow_code_only: bool = False)` -> CommandValidationResult
  - Validates module existence and DB accessibility. On success, `result.resolved["db_path"]` contains the absolute DB path.
- `validate_function_arg(db_path: str, function_ref: str)` -> CommandValidationResult
  - Validates that a function reference resolves in the given DB. On success, `result.resolved["function"]` contains the resolved record.
- `validate_depth_param(value: Any, max_depth: int = 20)` -> CommandValidationResult
  - Validates a depth parameter is a positive integer within bounds.
- `validate_command_args(command_name: str, args: dict[str, Any], workspace_root: Path | None = None)` -> CommandValidationResult
  - Dispatches to per-command validators based on `command_name`. Validates module, function, depth, and command-specific flags.
- `command_preflight(command_name: str, module: str | None = None, function: str | None = None, **kwargs)` -> CommandValidationResult
  - Convenience wrapper: validates and resolves all arguments in one call.

### pipeline_schema
Schema parsing and validation for headless batch pipeline YAML definitions.

- **StepConfig**(dataclass, frozen) -- Metadata for a supported pipeline step.
  - Fields: `name`, `kind` (StepKind), `description`, `goal`, `valid_options`
- **StepDef**(dataclass, frozen) -- A parsed step entry from the YAML file.
  - Fields: `name`, `options`, `config`
- **PipelineSettings**(dataclass, frozen) -- Execution settings after config/YAML merge.
  - Fields: `continue_on_error`, `max_workers`, `step_timeout`, `parallel_modules`, `max_module_workers`, `no_cache`
  - `module_workers` (property) -> int
- **PipelineDef**(dataclass, frozen) -- Fully parsed pipeline definition.
  - Fields: `name`, `source_path`, `modules`, `steps`, `settings`, `output`
- **ResolvedModule**(dataclass, frozen) -- Module name resolved to a concrete DB path.
  - Fields: `module_name`, `db_path`
- `STEP_REGISTRY`: dict[str, StepConfig] -- Registry of all supported pipeline step names.
- `load_pipeline(yaml_path: str | Path)` -> PipelineDef
  - Parses a YAML pipeline definition file into a typed `PipelineDef`.
- `resolve_modules(modules: list[str] | Literal["all"], workspace_root: Path)` -> list[ResolvedModule]
  - Resolves module names (or `"all"`) to concrete DB paths.
- `validate_pipeline(definition: PipelineDef, workspace_root: Path)` -> ValidationResult
  - Validates a parsed pipeline: checks steps exist in registry, modules resolve, options are valid.
- `render_output_path(template: str, module_name: str, workspace_root: Path)` -> str
  - Renders an output directory path from a template with `{module}`, `{timestamp}` placeholders.

### pipeline_executor
Execution engine for headless batch pipelines.

- **StepResult**(dataclass) -- Outcome of one pipeline step.
  - Fields: `step_name`, `status`, `elapsed_seconds`, `workspace_path`, `error`, `data`
- **ModuleResult**(dataclass) -- Execution summary for a single module.
  - Fields: `module_name`, `db_path`, `status`, `elapsed_seconds`, `step_results`, `errors`
- **BatchResult**(dataclass) -- Execution summary for a full batch run.
  - Fields: `pipeline_name`, `source_path`, `output_dir`, `status`, `dry_run`, `settings`, `modules`, `total_elapsed_seconds`
- `execute_module(module: ResolvedModule, steps: list[StepDef], settings: PipelineSettings, batch_dir: str | Path)` -> ModuleResult
  - Executes all pipeline steps for a single module.
- `execute_pipeline(definition: PipelineDef, workspace_root: Path)` -> BatchResult
  - Executes a full batch pipeline: resolves modules, dispatches steps (with optional module-level parallelism), writes manifest and summary.
- `dispatch_goal_step(step: StepDef, module: ResolvedModule, settings: PipelineSettings, batch_dir: Path)` -> StepResult
  - Dispatches a goal-type step (triage, security) to the triage-coordinator agent.
- `dispatch_scan_step(step: StepDef, module: ResolvedModule, settings: PipelineSettings, batch_dir: Path)` -> StepResult
  - Dispatches a security-scan step (memory, logic scanners).
- `dispatch_skill_step(step: StepDef, module: ResolvedModule, settings: PipelineSettings, batch_dir: Path)` -> StepResult
  - Dispatches a skill-group step (classify, callgraph, taint, dossiers, entrypoints).
- `write_batch_manifest(batch_dir: str | Path, definition: PipelineDef, progress: dict)` -> None
  - Writes/updates the batch manifest file with current progress.
- `write_batch_summary(batch_dir: str | Path, batch_result: BatchResult)` -> str
  - Writes the final batch summary JSON and returns its path.

## 15. Workspace & Orchestration

### workspace
Run-directory I/O primitives for multi-step workflow handoff.

- `create_run_dir(module_name: str, goal: str)` -> str
  - Creates and returns a new workspace run directory path under `.agent/workspace/`.
- `list_runs(module: str | None = None, goal: str | None = None, limit: int | None = 10)` -> list[dict]
  - Lists workspace runs, optionally filtered by module or goal. Returns manifest metadata per run.
- `write_results(run_dir: str | Path, step_name: str, full_data: Any, summary_data: Any)` -> dict[str, str]
  - Writes full `results.json` and `summary.json` for a step. Returns paths dict.
- `read_results(run_dir: str | Path, step_name: str)` -> Any
  - Reads and returns full results JSON for a step (with workspace envelope).
- `read_step_payload(run_dir: str | Path, step_name: str)` -> Any
  - Reads and returns the unwrapped skill output payload (envelope stripped).
- `read_summary(run_dir: str | Path, step_name: str)` -> Any
  - Reads and returns summary JSON for a step.
- `get_step_paths(run_dir: str | Path, step_name: str)` -> dict[str, str]
  - Returns paths for a step's results and summary files (no I/O).
- `update_manifest(run_dir: str | Path, step_name: str, status: str, summary_path: str | Path)` -> None
  - Updates the manifest with step status and summary path reference.
- `summarize_json_payload(payload: Any)` -> dict
  - Produces a compact preview of a JSON payload (key counts, list lengths, scalar truncation).
- `utc_iso()` -> str -- Returns current UTC time as ISO-8601 string.
- `safe_name(value: str, fallback: str = "item")` -> str -- Sanitizes a string for use in file paths.
- `coerce_path(value: str | Path)` -> Path -- Resolves a path to absolute.
- `MANIFEST_FILE`, `RESULTS_FILE`, `SUMMARY_FILE` -- Filename constants.

### workspace_bootstrap
Workspace step setup bootstrap reducing boilerplate for skill scripts.

- `prepare_step(run_dir: str | Path, step_name: str)` -> dict[str, str]
  - Creates step subdirectory and returns paths for output files (`step_name`, `step_path`, `results_path`, `summary_path`).
- `complete_step(run_dir: str | Path, step_name: str, full_data: Any, summary_data: Any, status: str = "success")` -> dict[str, str]
  - Writes step results + summary and updates the manifest in one call.

### workspace_validation
Validates workspace handoff compliance for run directories.

- **WorkspaceValidationResult**(dataclass)
  - Fields: `valid`, `run_dir`, `issues`, `manifest`, `step_count`
  - `to_dict()` -> dict
- `validate_workspace_run(run_dir: str | Path)` -> WorkspaceValidationResult
  - Validates: run directory exists, manifest.json is valid, steps have status and summary_path, referenced files exist, each step directory has results.json and summary.json.

### agent_common
Shared orchestration helpers for agent scripts.

- **AgentStep**(dataclass, frozen) -- Description of a skill-script invocation.
  - Fields: `name`, `skill_name`, `script_name`, `args`, `timeout`, `json_output`, `workspace_dir`, `workspace_step`, `max_retries`
- **AgentStepResult**(dataclass) -- Execution result for one step.
  - Fields: `name`, `skill_name`, `script_name`, `success`, `elapsed_seconds`, `exit_code`, `error`, `stdout`, `stderr`, `json_data`
  - `to_dict()` -> dict
- **AgentBase** -- Shared runner wrapper for agent skill invocations.
  - `run_skill_script_result(skill_name, script_name, args, *, timeout, json_output, workspace_dir, workspace_step, max_retries, warn_on_failure)` -> dict
  - `run_skill_script(skill_name, script_name, args, *, timeout, workspace_dir, workspace_step, max_retries)` -> dict | list | None
- **AgentOrchestrator** -- Lightweight step execution with retry and circuit-breaker.
  - `__init__(runner: AgentBase | None, *, max_workers: int = 4, failure_threshold: int | None = None)`
  - `run_step(step: AgentStep)` -> AgentStepResult
  - `results` (property) -> list[AgentStepResult]
  - `summary()` -> dict -- Aggregate statistics: total, failed, elapsed, steps.

## 16. Cross-Module Indexes

### import_export_index
PE import/export table index across all analyzed modules for loader-level dependency resolution.

- **ExportEntry**(dataclass, frozen)
  - Fields: `module`, `db_path`, `name`, `ordinal`, `is_forwarded`, `forwarded_to`
- **ImportEntry**(dataclass, frozen)
  - Fields: `importing_module`, `source_module`, `function_name`, `is_delay_loaded`, `ordinal`
- **ImportExportIndex** -- Queryable index (context manager).
  - `__init__(tracking_db: str | None = None, workspace_root: str | Path | None = None, *, max_workers: int = 8)`
  - `who_exports(function_name: str)` -> list[ExportEntry] -- Modules whose PE export table contains the function.
  - `who_imports(function_name: str, *, source_module: str | None = None)` -> list[ImportEntry] -- Modules that import the function.
  - `module_consumers(module_name: str)` -> dict[str, list[str]] -- Modules that import from *module_name*, grouped by importing module.
  - `module_suppliers(module_name: str)` -> dict[str, list[str]] -- Modules that *module_name* imports from, grouped by supplier.
  - `resolve_forwarder_chain(module: str, function_name: str)` -> list[ExportEntry] -- Follows PE forwarded export chains to the final implementation.
  - `dependency_graph()` -> dict[str, set[str]] -- Module-to-module dependency edges from PE import tables.
  - `module_export_list(module_name: str)` -> list[ExportEntry] -- All exports for a module.
  - `summary()` -> dict -- Aggregate statistics (module count, export count, import count).
  - Context manager: `with ImportExportIndex() as idx: ...`

### string_taxonomy (expanded)
Canonical string categorization with regex patterns consolidated from multiple skills. Expands the brief entry in section 3.

- `STRING_TAXONOMY`: list[tuple[re.Pattern, str, str]] -- Ordered list of `(regex, category, description)` tuples. 16 categories covering file paths, registry keys, URLs, RPC endpoints, named pipes, ALPC paths, service accounts, certificates, credentials, embedded commands, source paths, ETW providers, GUIDs, error messages, format strings, debug traces.
- `CATEGORIES`: list[str] -- All canonical category names in definition order.
- `CATEGORY_RISK`: dict[str, str] -- Security risk level per category (`HIGH`, `MEDIUM`, `LOW`).
- `TAXONOMY_TO_CLASSIFICATION`: dict[str, str] -- Maps taxonomy categories to classify-functions scoring buckets.
- `categorize_string(s: str)` -> tuple[str, str] | None
  - Categorizes a string literal. Returns `(category, description)` for the first matching pattern, or `None`.
- `categorize_string_simple(s: str)` -> str
  - Returns only the category name (or `"other"` if no match). Backward-compatible with the old `categorize_string` return type.
- `categorize_strings(strings: list[str])` -> dict[str, list[str]]
  - Batch categorizes strings into `{category: [strings]}` buckets.

### type_constants (expanded)
IDA type size mappings and C type translation tables. Expands the brief entry in section 3.

- `TYPE_SIZES`: dict[str, int] -- IDA type name to byte size (e.g., `"_BYTE": 1`, `"DWORD": 4`, `"_QWORD": 8`). Covers `_BYTE`, `BYTE`, `char`, `_WORD`, `WORD`, `short`, `_DWORD`, `DWORD`, `int`, `LONG`, `HRESULT`, `_QWORD`, `QWORD`, `__int64`, and unsigned variants.
- `IDA_TO_C_TYPE`: dict[str, str] -- IDA type name to C standard type for header generation (e.g., `"_DWORD": "uint32_t"`, `"HRESULT": "HRESULT"`).
- `SIZE_TO_C_TYPE`: dict[int, str] -- Field byte-size to default C type (e.g., `1: "uint8_t"`, `4: "uint32_t"`, `8: "uint64_t"`).

## 17. Low-Level Utilities

### sql_utils
Shared SQL utilities for safe LIKE queries.

- `escape_like(value: str)` -> str
  - Escapes SQL LIKE meta-characters (`\`, `%`, `_`) so the value is matched literally. Callers must append `ESCAPE '\'` to the LIKE clause.
- `LIKE_ESCAPE`: str -- The SQL `ESCAPE '\'` clause fragment to append to LIKE expressions.

### logging_config
Centralized logging configuration for the runtime.

- `configure_logging()` -> None
  - Sets up the `helpers` logger hierarchy with a stderr handler. Safe to call multiple times. Level controlled by `DEEPEXTRACT_LOG_LEVEL` environment variable (default `WARNING`).
