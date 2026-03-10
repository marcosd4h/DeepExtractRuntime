"""Helpers for querying DeepExtract analysis outputs.

Modules:
    analyzed_files_db   -- Tracking DB (module index, status, hashes)
    individual_analysis_db -- Per-binary analysis DB (functions, file_info)
    function_index      -- JSON index for fast function-to-file resolution
    api_taxonomy        -- Win32/NT API prefix classification
    module_profile      -- Pre-computed module fingerprints (library, API, complexity)
    db_paths            -- Centralized DB path resolution (resolve_db_path, resolve_tracking_db)
    session_utils       -- Session ID resolution and scratchpad path utilities
    batch_operations    -- Bulk function loading by ID/name list
    cross_module_graph  -- Cross-module call graph resolution and traversal
    progress            -- Progress indicators for long-running operations
    validation          -- DB schema validation and integrity checking
    config              -- Hierarchical configuration with env-var overrides
    asm_metrics         -- Assembly instruction metric extraction heuristics
    logging_config      -- Centralized logging configuration for debug/trace output
    module_discovery    -- Canonical module/DB directory scanning (iter_module_dirs, iter_module_dbs)
    workspace           -- Workspace run-directory I/O primitives (create_run_dir, list_runs, write_results, ...)
    workspace_bootstrap -- Convenience wrappers for workspace step setup (prepare_step, complete_step)

Standalone scripts:
    unified_search.py   -- Multi-dimension search across a module DB.
                           Run directly:  python .agent/helpers/unified_search.py <db> --query <term>
                           Searches: function names, signatures, strings, APIs, classes, exports.
    cleanup_workspace.py -- Cleanup old workspace run directories and stale state files.
                           Run directly:  python .agent/helpers/cleanup_workspace.py [--older-than DAYS] [--dry-run]
    pipeline_cli.py     -- Headless batch pipeline CLI (run, validate, list-steps).
                           Run directly:  python .agent/helpers/pipeline_cli.py run <yaml> [--json]
    qa_runner.py        -- QA test runner for automated quality checks.
                           Run directly:  python .agent/helpers/qa_runner.py [options]
    health_check.py     -- Workspace health check (extraction data, DBs, registries, config).
                           Run directly:  python .agent/helpers/health_check.py [--quick|--full] [--json]
    select_audit_callees.py -- Select callees for deep extraction during /audit (Steps 3h + 3i).
                           Run directly:  python .agent/helpers/select_audit_callees.py <db_path> --dossier <path> [--json]
    select_backward_traces.py -- Select backward trace targets for /audit Step 3c.
                           Run directly:  python .agent/helpers/select_backward_traces.py --dossier <path> [--json]

All public symbols are lazily imported on first access to avoid loading
all 30+ submodules when only a few are needed.
"""

from __future__ import annotations

import importlib
from typing import Any

# Mapping: public_name -> (submodule, real_attribute_name)
# When real_attribute_name is None, the public_name is the same as the attribute.
_LAZY_IMPORTS: dict[str, tuple[str, str | None]] = {
    # analyzed_files_db
    "AnalyzedFileRecord": (".analyzed_files_db", None),
    "AnalyzedFilesDB": (".analyzed_files_db", None),
    "open_analyzed_files_db": (".analyzed_files_db", None),
    # individual_analysis_db
    "FileInfoRecord": (".individual_analysis_db", None),
    "FunctionRecord": (".individual_analysis_db", None),
    "FunctionWithModuleInfo": (".individual_analysis_db", None),
    "IndividualAnalysisDB": (".individual_analysis_db", None),
    "LIKE_ESCAPE": (".individual_analysis_db", None),
    "Page": (".individual_analysis_db", None),
    "RECOMMENDED_FUNCTION_INDEXES": (".individual_analysis_db", None),
    "escape_like": (".individual_analysis_db", None),
    "open_individual_analysis_db": (".individual_analysis_db", None),
    "parse_json_safe": (".individual_analysis_db", None),
    # function_index
    "add_app_only_argument": (".function_index", None),
    "build_id_map": (".function_index", None),
    "compute_stats": (".function_index", None),
    "filter_application_functions": (".function_index", None),
    "filter_decompiled": (".function_index", None),
    "filter_by_library": (".function_index", None),
    "get_function_id": (".function_index", None),
    "get_library_tag_for_function": (".function_index", None),
    "has_assembly": (".function_index", None),
    "has_decompiled": (".function_index", None),
    "is_application_function": (".function_index", None),
    "is_library_function": (".function_index", None),
    "list_extracted_modules": (".function_index", None),
    "load_all_function_indexes": (".function_index", None),
    "load_function_index": (".function_index", None),
    "load_function_index_for_db": (".function_index", None),
    "lookup_function": (".function_index", None),
    "search_index": (".function_index", None),
    "resolve_function_file": (".function_index", None),
    "resolve_module_dir": (".function_index", None),
    # api_taxonomy
    "API_TAXONOMY": (".api_taxonomy", None),
    "DISPATCH_KEYWORDS": (".api_taxonomy", None),
    "SECURITY_API_CATEGORIES": (".api_taxonomy", None),
    "classify_api": (".api_taxonomy", None),
    "classify_api_fingerprint": (".api_taxonomy", None),
    "classify_api_security": (".api_taxonomy", None),
    "classify_from_json": (".api_taxonomy", None),
    "get_dangerous_api_prefixes": (".api_taxonomy", None),
    "get_dangerous_api_set": (".api_taxonomy", None),
    "is_in_dangerous_apis_json": (".api_taxonomy", None),
    # db_paths
    "_resolve_db_path": (".db_paths", "resolve_db_path"),
    "resolve_db_path_auto": (".db_paths", None),
    "_resolve_module_db": (".db_paths", "resolve_module_db"),
    "resolve_module_db_auto": (".db_paths", None),
    "_resolve_tracking_db": (".db_paths", "resolve_tracking_db"),
    "resolve_tracking_db_auto": (".db_paths", None),
    "safe_long_path": (".db_paths", None),
    "safe_makedirs": (".db_paths", None),
    # function_resolver
    "resolve_function": (".function_resolver", None),
    "search_functions_by_pattern": (".function_resolver", None),
    # string_taxonomy
    "STRING_CATEGORIES_LIST": (".string_taxonomy", "CATEGORIES"),
    "STRING_TAXONOMY": (".string_taxonomy", None),
    "TAXONOMY_TO_CLASSIFICATION": (".string_taxonomy", None),
    "_categorize_string": (".string_taxonomy", "categorize_string"),
    "_categorize_string_simple": (".string_taxonomy", "categorize_string_simple"),
    "_categorize_strings": (".string_taxonomy", "categorize_strings"),
    # type_constants
    "IDA_TO_C_TYPE": (".type_constants", None),
    "SIZE_TO_C_TYPE": (".type_constants", None),
    "TYPE_SIZES": (".type_constants", None),
    # mangled_names
    "parse_class_from_mangled": (".mangled_names", None),
    # errors
    "ScriptError": (".errors", None),
    "ErrorCode": (".errors", None),
    "db_error_handler": (".errors", None),
    "emit_error": (".errors", None),
    "log_error": (".errors", None),
    "log_warning": (".errors", None),
    # json_output
    "emit_json": (".json_output", None),
    "emit_json_list": (".json_output", None),
    "should_force_json": (".json_output", None),
    # cache
    "cache_result": (".cache", None),
    "clear_cache": (".cache", None),
    "clear_cache_for_db": (".cache", None),
    "evict_stale": (".cache", None),
    "get_cached": (".cache", None),
    # callgraph
    "CallGraph": (".callgraph", None),
    # script_runner
    "find_agent_script": (".script_runner", None),
    "find_skill_script": (".script_runner", None),
    "get_agents_dir": (".script_runner", None),
    "get_skills_dir": (".script_runner", None),
    "get_workspace_args": (".script_runner", None),
    "get_workspace_root": (".script_runner", None),
    "load_skill_module": (".script_runner", None),
    "run_skill_script": (".script_runner", None),
    # pipeline_schema
    "OptionSpec": (".pipeline_schema", None),
    "PipelineDef": (".pipeline_schema", None),
    "PipelineSettings": (".pipeline_schema", None),
    "ResolvedModule": (".pipeline_schema", None),
    "STEP_REGISTRY": (".pipeline_schema", None),
    "StepConfig": (".pipeline_schema", None),
    "StepDef": (".pipeline_schema", None),
    "load_pipeline": (".pipeline_schema", None),
    "render_output_path": (".pipeline_schema", None),
    "resolve_modules": (".pipeline_schema", None),
    "validate_pipeline": (".pipeline_schema", None),
    # pipeline_executor
    "BatchResult": (".pipeline_executor", None),
    "ModuleResult": (".pipeline_executor", None),
    "StepResult": (".pipeline_executor", None),
    "dispatch_goal_step": (".pipeline_executor", None),
    "dispatch_skill_step": (".pipeline_executor", None),
    "execute_module": (".pipeline_executor", None),
    "execute_pipeline": (".pipeline_executor", None),
    "write_batch_manifest": (".pipeline_executor", None),
    "write_batch_summary": (".pipeline_executor", None),
    # module_profile
    "load_module_profile": (".module_profile", None),
    "load_all_profiles": (".module_profile", None),
    "load_profile_for_db": (".module_profile", None),
    "get_noise_ratio": (".module_profile", None),
    "get_technology_flags": (".module_profile", None),
    "get_canary_coverage": (".module_profile", None),
    # session_utils
    "resolve_session_id": (".session_utils", None),
    "scratchpad_path": (".session_utils", None),
    "SCRATCHPADS_DIR": (".session_utils", None),
    # batch_operations
    "batch_extract_function_data": (".batch_operations", None),
    "batch_resolve_functions": (".batch_operations", None),
    "batch_resolve_xref_targets": (".batch_operations", None),
    "load_all_functions_slim": (".batch_operations", None),
    "load_function_record": (".batch_operations", None),
    "severity_label": (".batch_operations", None),
    "DEFAULT_SEVERITY_BANDS": (".batch_operations", None),
    # cross_module_graph
    "CrossModuleGraph": (".cross_module_graph", None),
    "ModuleResolver": (".cross_module_graph", None),
    # import_export_index
    "ExportEntry": (".import_export_index", None),
    "ImportEntry": (".import_export_index", None),
    "ImportExportIndex": (".import_export_index", None),
    # param_risk
    "HIGH_RISK_PARAM_PATTERNS": (".param_risk", None),
    "BUFFER_SIZE_PAIR_PATTERNS": (".param_risk", None),
    "score_parameter_risk": (".param_risk", None),
    # progress
    "ProgressReporter": (".progress", None),
    "progress_iter": (".progress", None),
    "status_message": (".progress", None),
    # validation
    "ValidationResult": (".validation", None),
    "WorkspaceDataStatus": (".validation", None),
    "validate_analysis_db": (".validation", None),
    "validate_depth": (".validation", None),
    "validate_tracking_db": (".validation", None),
    "validate_function_index": (".validation", None),
    "validate_function_id": (".validation", None),
    "validate_positive_int": (".validation", None),
    "validate_workspace_data": (".validation", None),
    "quick_validate": (".validation", None),
    # agent_common
    "AgentBase": (".agent_common", None),
    "AgentOrchestrator": (".agent_common", None),
    "AgentStep": (".agent_common", None),
    "AgentStepResult": (".agent_common", None),
    # asm_patterns
    "ASM_BRANCH_RE": (".asm_patterns", None),
    "ASM_CALL_RE": (".asm_patterns", None),
    "ASM_GLOBAL_RE": (".asm_patterns", None),
    "ASM_LOAD_RE": (".asm_patterns", None),
    "ASM_MEM_OFFSET_RE": (".asm_patterns", None),
    "ASM_PROLOGUE_SAVE_RE": (".asm_patterns", None),
    "ASM_PTR_RE": (".asm_patterns", None),
    "ASM_RET_RE": (".asm_patterns", None),
    "ASM_SYSCALL_RE": (".asm_patterns", None),
    "CALL_TARGET_RE": (".asm_patterns", None),
    "IMP_PREFIX_RE": (".asm_patterns", None),
    "IDA_PARAM_RE": (".asm_patterns", None),
    "strip_import_prefix": (".asm_patterns", None),
    # calling_conventions
    "ASM_PTR_SIZES": (".calling_conventions", None),
    "ASM_REG_SIZES": (".calling_conventions", None),
    "PARAM_REGISTERS": (".calling_conventions", None),
    "PARAM_REGS_X64": (".calling_conventions", None),
    "REGISTER_TO_PARAM": (".calling_conventions", None),
    "STACK_REGS": (".calling_conventions", None),
    "param_name_for": (".calling_conventions", None),
    # decompiled_parser
    "extract_balanced_parens": (".decompiled_parser", None),
    "extract_function_calls": (".decompiled_parser", None),
    "find_param_in_calls": (".decompiled_parser", None),
    "split_arguments": (".decompiled_parser", None),
    # struct_scanner
    "merge_scanned_struct_fields": (".struct_scanner", "merge_struct_fields"),
    "parse_signature_params": (".struct_scanner", None),
    "scan_assembly_struct_accesses": (".struct_scanner", None),
    "scan_batch_struct_accesses": (".struct_scanner", None),
    "scan_decompiled_struct_accesses": (".struct_scanner", None),
    # workspace_validation
    "WorkspaceValidationResult": (".workspace_validation", None),
    "validate_workspace_run": (".workspace_validation", None),
    # module_discovery
    "ModuleDir": (".module_discovery", None),
    "ModuleDb": (".module_discovery", None),
    "iter_module_dirs": (".module_discovery", None),
    "iter_module_dbs": (".module_discovery", None),
    "db_stem_from_filename": (".module_discovery", None),
    "dir_name_to_file_name": (".module_discovery", None),
    "normalize_module_name": (".module_discovery", None),
    "get_tracking_db_path": (".module_discovery", None),
    # workspace (run-directory I/O primitives)
    "create_run_dir": (".workspace", None),
    "list_runs": (".workspace", None),
    "write_results": (".workspace", None),
    "read_results": (".workspace", None),
    "read_step_payload": (".workspace", None),
    "read_summary": (".workspace", None),
    "get_step_paths": (".workspace", None),
    "update_manifest": (".workspace", None),
    # workspace_bootstrap
    "prepare_step": (".workspace_bootstrap", None),
    "complete_step": (".workspace_bootstrap", None),
    # guard_classifier
    "Guard": (".guard_classifier", None),
    "classify_guard": (".guard_classifier", None),
    "find_guards_between": (".guard_classifier", None),
    # def_use_chain
    "TaintResult": (".def_use_chain", None),
    "VarDef": (".def_use_chain", None),
    "VarUse": (".def_use_chain", None),
    "analyze_taint": (".def_use_chain", None),
    "parse_def_use": (".def_use_chain", None),
    "propagate_taint": (".def_use_chain", None),
    # constraint_collector
    "Constraint": (".constraint_collector", None),
    "ConstraintSet": (".constraint_collector", None),
    "collect_constraints": (".constraint_collector", None),
    # constraint_solver
    "FeasibilityResult": (".constraint_solver", None),
    "check_feasibility": (".constraint_solver", None),
    # command_validation
    "CommandValidationResult": (".command_validation", None),
    "command_preflight": (".command_validation", None),
    "validate_command_args": (".command_validation", None),
    "validate_function_arg": (".command_validation", None),
    "validate_module": (".command_validation", None),
    # asm_metrics
    "AsmMetrics": (".asm_metrics", None),
    "count_asm_calls": (".asm_metrics", None),
    "count_asm_instructions": (".asm_metrics", None),
    "get_asm_metrics": (".asm_metrics", None),
    # finding_schema
    "Finding": (".finding_schema", None),
    "from_taint_finding": (".finding_schema", None),
    "from_memory_finding": (".finding_schema", None),
    "from_logic_finding": (".finding_schema", None),
    "normalize_scanner_output": (".finding_schema", None),
    # finding_merge
    "merge_findings": (".finding_merge", None),
    "deduplicate": (".finding_merge", "deduplicate"),
    "findings_summary": (".finding_merge", None),
    # rpc_index
    "RpcIndex": (".rpc_index", None),
    "RpcInterface": (".rpc_index", None),
    "get_rpc_index": (".rpc_index", None),
    "invalidate_rpc_index": (".rpc_index", None),
    # rpc_stub_parser
    "RpcParameter": (".rpc_stub_parser", None),
    "RpcProcedureSignature": (".rpc_stub_parser", None),
    "RpcStubFile": (".rpc_stub_parser", None),
    "parse_stub_file": (".rpc_stub_parser", None),
    "load_stubs_from_directory": (".rpc_stub_parser", None),
    # rpc_procedure_classifier
    "ProcedureClassification": (".rpc_procedure_classifier", None),
    "classify_procedure": (".rpc_procedure_classifier", None),
    "classify_procedures": (".rpc_procedure_classifier", None),
    "summarize_classifications": (".rpc_procedure_classifier", None),
    # winrt_index
    "WinrtIndex": (".winrt_index", None),
    "WinrtServer": (".winrt_index", None),
    "WinrtInterface": (".winrt_index", None),
    "WinrtMethod": (".winrt_index", None),
    "WinrtAccessContext": (".winrt_index", None),
    "get_winrt_index": (".winrt_index", None),
    "invalidate_winrt_index": (".winrt_index", None),
    # com_index
    "ComIndex": (".com_index", None),
    "ComServer": (".com_index", None),
    "ComInterface": (".com_index", None),
    "ComMethod": (".com_index", None),
    "ComAccessContext": (".com_index", None),
    "get_com_index": (".com_index", None),
    "invalidate_com_index": (".com_index", None),
}

__all__ = list(_LAZY_IMPORTS.keys())


def __getattr__(name: str) -> Any:
    entry = _LAZY_IMPORTS.get(name)
    if entry is None:
        raise AttributeError(f"module 'helpers' has no attribute {name!r}")
    module_path, real_name = entry
    mod = importlib.import_module(module_path, __package__)
    attr = getattr(mod, real_name if real_name is not None else name)
    globals()[name] = attr
    return attr
