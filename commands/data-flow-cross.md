# Cross-Module Data Flow Trace

## Overview

Trace how data moves across module boundaries (e.g., from `appinfo.dll` to `ntdll.dll`). Answers questions like "where does this parameter end up after being passed to another DLL?" or "where did this argument come from before it was passed into this module?"

Usage:

- `/data-flow-cross forward appinfo.dll AiLaunchProcess --param 1` -- trace where parameter 1 flows, including calls into other DLLs
- `/data-flow-cross backward cmd.exe BatLoop --target CreateProcessW` -- trace where CreateProcessW arguments come from, following back into callers in other modules

## IMPORTANT: Execution Model

**This is an execute-immediately command. Do NOT present anything for user confirmation.** Run and write the final cross-module trace results straight to the chat as your response. The user expects to see the completed output.

## Workspace Protocol

This command traces across multiple modules using multiple skills (data-flow-tracer + callgraph-tracer):

1. Create `.agent/workspace/<module>_data_flow_cross_<timestamp>/`.
2. Pass `--workspace-dir <run_dir>` and `--workspace-step <step_name>` to each skill invocation.
3. Keep only summary output in context; do not inline full trace JSON in chat.
4. Read full payloads from `<run_dir>/<step_name>/results.json` when synthesizing the cross-module report.
5. Use `<run_dir>/manifest.json` to track which module traces completed successfully.

## Execution Context

> **IMPORTANT**: Any inline Python that imports `helpers.*` must run with `cd <workspace>/.agent`
> (so the `.agent/` directory is on `sys.path`), **not** from the workspace root.
> Script invocations like `python .agent/skills/.../script.py` can be run from the workspace root
> because those scripts manage their own path setup.

## Steps

### Step 0: Preflight Validation

Validate arguments using `helpers.command_validation.validate_command_args("data-flow-cross", {"module": "<module>", "function": "<function>"})`.
If validation fails, report the errors and stop. On success, use `result.resolved["db_path"]` for subsequent script calls.

1. **Locate the starting point**

> **Tip:** All skill scripts support `--json` for machine-readable output. Use `--json` when parsing script output programmatically.

   - Resolve the initial module DB using `python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py <module>` (run from workspace root).
   - After resolving the target function, use the returned `function_id` for all subsequent skill script invocations (e.g., `--id <function_id>`) to avoid re-resolution ambiguity.
   - Check whether it is library boilerplate (WIL/CRT/STL/WRL/ETW) using `is_library_function()` from function_index. Flag library functions in the output and deprioritize them in trace narratives.
   - Resolve the tracking database by running `cd <workspace>/.agent && python -c "from helpers.db_paths import resolve_tracking_db; print(resolve_tracking_db('..'))"` or by using the skill script.

2. **Run cross-module trace**

   **Forward trace** (across DLL boundaries):
   - Use the **data-flow-tracer** skill to trace within the first module.
   - For every external call found, first try the **import-export-resolver** skill (`query_function.py --function <callee> --direction export`) to resolve the implementing module via PE import/export tables. This correctly handles API-set forwarders (e.g., `api-ms-win-*` -> `kernelbase.dll`).
   - Fall back to the **callgraph-tracer** skill (`cross_module_resolve.py`) if import-export resolution fails.
   - If the target module is analyzed, continue the trace in that module using its DB.
   - Repeat until the specified `--depth` is reached.

   **Backward trace** (across DLL boundaries):
   - Use the **data-flow-tracer** skill to trace within the current module.
   - If the origin is a function parameter, first try the **import-export-resolver** skill (`query_function.py --function <func> --direction import`) to find importing modules, then use the **callgraph-tracer** skill (`chain_analysis.py`) for caller resolution within those modules.
   - For each caller found in another analyzed module, continue the backward trace in that module.
   - Repeat until the specified `--depth` is reached.

3. **Synthesize cross-module report**
   - **Trace Path**: Present an indented tree or list showing the data flow across modules.
   - **Module Transitions**: Clearly mark where the flow crosses from one DLL to another.
   - **Argument/Parameter Mapping**: Show how parameter N in Module A becomes argument M in Module B.

## Output

Present the cross-module trace results in chat. Always save to `extracted_code/<starting_module_folder>/reports/data_flow_cross_<function>_<timestamp>.md` (using `YYYYMMDD_HHMM` for timestamp). Create the `reports/` directory if needed.

All saved files must include a provenance header: generation date, starting module and function, trace direction, depth, modules traversed, and workspace run directory path.

**Follow-up suggestions**:

- `/audit <module> <function>` -- full security audit (includes cross-module resolution).
- `/taint <module> <function>` -- targeted taint trace on functions in the cross-module flow path.

## Error Handling

- **Module not found**: List available modules via `find_module_db.py --list` and ask the user to choose
- **Function not found**: Run a fuzzy search and suggest close matches
- **Tracking DB missing**: Report that cross-module tracing requires the tracking DB; suggest checking extraction
- **DB access failure**: Report the error with the DB path and suggest running `/health`
- **Partial trace failure**: If the trace succeeds in some modules but fails in others, report the successful portion and clearly state which module transitions could not be followed and why
