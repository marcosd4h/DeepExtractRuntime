# Compare Modules

## Overview

Cross-module analysis of two or more DeepExtractIDA-analyzed modules -- comparing dependency relationships, import/export overlap, function classification distributions, and cross-module call chains.

The text after `/compare-modules` lists **two or more module names**:
- `/compare-modules appinfo.dll cmd.exe`
- `/compare-modules explorer.exe shell32.dll ntdll.dll`
- `/compare-modules --all` -- compare all analyzed modules at a high level (capped at 200 modules; see Scale Limits)

If fewer than two modules are specified, list available modules and ask.

## Scale Limits

The `--all` flag is capped at 200 modules (configurable via `scale.max_modules_compare` in `.agent/config/defaults.json`). If there are more than 200 modules, `--all` compares the first 200 and warns the user. For targeted comparison of specific modules, always list them explicitly.

With 100+ modules, pairwise analysis becomes O(N^2). Use `--all` only for high-level overviews; use explicit module lists for detailed comparison.

## IMPORTANT: Execution Model

**This is an execute-immediately command. Do NOT present anything for user confirmation.** Run and write the final comparison report straight to the chat as your response. The user expects to see the completed report.

## Execution Context

> **IMPORTANT**: Any inline Python that imports `helpers.*` must run with `cd <workspace>/.agent`
> (so the `.agent/` directory is on `sys.path`), **not** from the workspace root.
> Script invocations like `python .agent/skills/.../script.py` can be run from the workspace root
> because those scripts manage their own path setup.

## Workspace Protocol

For multi-module comparison:

1. Create a top-level run directory under `.agent/workspace/` for the command.
2. Create per-module sub-runs (for example, `<run_dir>/<moduleA>/`, `<run_dir>/<moduleB>/`) to avoid collisions.
3. Pass `--workspace-dir <module_run_dir>` and `--workspace-step <step_name>` to every skill invocation.
4. Keep only compact summaries in context; avoid inlining full JSON across modules.
5. Read detailed data on demand from `<module_run_dir>/<step_name>/results.json` and use each run's `manifest.json` for traceability.

## Steps

### Step 0: Preflight Validation

Validate arguments using `helpers.command_validation.validate_command_args("compare-modules", {"module": "<module_A>"})`.
If validation fails, report the errors and stop. On success, use `result.resolved["db_path"]` for subsequent script calls.

1. **Find all module DBs**
   Use the **decompiled-code-extractor** skill (`find_module_db.py`) for each module. With `--all`, use `--list` to enumerate everything. Verify all have COMPLETE status.
   `list_extracted_modules()` from helpers or `python .agent/skills/function-index/scripts/index_functions.py --all --stats` provides instant enumeration with app/library breakdown. The session context "Module Profiles" section already has per-module noise ratios, library breakdowns, and technology surface flags for quick comparison.
   The enriched `function_index.json` now includes `function_id`, `has_decompiled`, and `has_assembly` (and may include `file: null` entries). Use index metadata first; avoid DB name lookups for basic function identity/status checks.

> **Tip:** All skill scripts support `--json` for machine-readable output. Use `--json` when parsing script output programmatically.

2. **Cross-module dependency overview**
   Use the **callgraph-tracer** skill (`module_dependencies.py --overview`) to get the high-level dependency map: all modules, function counts, and which modules call into which.

3. **Pairwise dependency analysis**
   Use the **callgraph-tracer** skill (`module_dependencies.py --module <name>`) for each module's inbound/outbound dependencies. Then use `module_dependencies.py --shared-functions <A> <B>` to find specific function calls between each pair.

4. **PE-level import/export dependency analysis**
   Use the **import-export-resolver** skill (`module_deps.py --module <name> --json`) for each module to surface PE-level dependencies, forwarding chains, and shared consumers. Then use `resolve_forwarders.py --module <name> --json` to identify export forwarders that mask the true implementation module. This complements the call-graph-based dependency analysis from Step 3 with loader-level ground truth.

5. **API surface comparison**
   Use the **generate-re-report** skill (`analyze_imports.py --exports --include-delay-load`) for each module. Compare: which import categories each module uses, whether one module's exports are consumed by the other, and shared imported DLLs.

6. **String intelligence comparison**
   Use the **generate-re-report** skill (`analyze_strings.py`) per module to get categorized string literals (file paths, registry keys, URLs, RPC endpoints, error messages). Compare: shared strings across modules, unique string categories per module, and notable clusters that reveal shared data or communication patterns.

7. **Function classification comparison**
   Use `module_profile.json` per module for side-by-side app vs library comparison (noise ratio, library breakdown). Fall back to `compute_stats()` if profiles are missing. Use `--app-only` to normalize classification to application code only.
   Prefer `function_id` from index entries when fetching full function rows (`db.get_function_by_id`) instead of `db.get_function_by_name`.
   Use the **classify-functions** skill (`triage_summary.py`) for each module. Compare: category distributions (what each module primarily does), interesting function counts, and noise ratios.

8. **Cross-module call chain analysis**
   For the most interesting inter-module function calls (from Step 3), use the **callgraph-tracer** skill (`chain_analysis.py --follow <target> --depth 2`) to trace execution across module boundaries.

9. **Generate cross-module diagram**
   Use the **callgraph-tracer** skill (`generate_diagram.py --cross-module`) to produce a Mermaid diagram of inter-module relationships.

10. **Synthesize comparison report**
   Combine all findings:

   - **Module Profiles**: side-by-side table from `module_profile.json` (functions, exports, imports, noise ratio, library breakdown, dangerous API categories)
   - **Dependency Mapping**: direction of dependencies (provider/consumer), Mermaid diagram
   - **Shared Function Calls**: table of caller -> callee -> type for cross-module calls
   - **Import/Export Overlap**: shared import sources, export/import matching between modules
   - **Capability Comparison**: classification distributions side-by-side, unique capabilities per module
   - **Cross-Module Call Chains**: narrative for the most interesting inter-module execution paths
   - **Architectural Observations**: role relationships, coupling tightness, shared data (registry keys, file paths, strings). Function_index `group_by_library()` per module reveals architectural differences -- e.g., heavy WRL usage = COM-focused, heavy CRT = C runtime-focused.
   - **Recommended Cross-Module Analysis**: interesting cross-boundary functions to audit, shared attack surface

## Step Dependencies

- Step 1 is the starting point (no dependencies).
- Step 2 depends on Step 1. Step 3 depends on Step 2.
- Step 4 depends on Step 1 (needs module DBs resolved).
- Steps 5 + 6 + 7 + 8 are independent per-module operations -- run them concurrently for each module.
- Step 9 depends on Step 3 (needs inter-module function calls to select targets).
- Step 10 depends on Step 9 (needs cross-module relationship data).
- Step 10 depends on all previous steps.

## Output

Present the comparison report in chat. Always save to `extracted_code/reports/compare_modules_<moduleA>_<moduleB>_<timestamp>.md` (using `YYYYMMDD_HHMM` for timestamp). Create the `reports/` directory if needed.

All saved files must include a provenance header: generation date, workspace run directory path, module names, DB paths, and comparison scope.

**Follow-up suggestions**:

- `/audit <module> <export>` -- security audit on an interesting cross-module export (includes cross-module resolution)
- `/audit <module> <function>` -- security audit on shared attack surface functions
- `/data-flow-cross forward <module> <function> --param N` -- trace data flow across module boundaries
- `/explain <module> <function>` -- understand a function that appears in cross-module call chains

## Error Handling

- **Module not found**: List available modules via `find_module_db.py --list` and ask the user to choose
- **Only one module available**: Report that comparison requires at least 2 modules
- **DB access failure**: Report the error with the DB path and suggest running `/health`
- **Tracking DB missing**: Report that cross-module comparison requires the tracking DB
- **Partial module failure**: If analysis succeeds for some modules but fails for others, report the successful portions and clearly state which modules could not be analyzed. Continue with available data rather than aborting entirely.
