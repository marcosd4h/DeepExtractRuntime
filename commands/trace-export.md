# Trace Export

## Overview

Trace a module's exported function through its full call chain -- documenting each function's purpose, following cross-module transitions, and generating a visual call graph diagram. Follows execution flow from a public API entry point deep into the module's internals.

The text after `/trace-export` specifies the **export name** and optionally the **module**:

- `/trace-export AiLaunchProcess` -- searches all modules
- `/trace-export appinfo.dll AiLaunchProcess` -- targets specific module
- `/trace-export appinfo.dll --list` -- list all exports first

Default trace depth is 3 levels. Override with `--depth N`.

## IMPORTANT: Execution Model

**This is an execute-immediately command. Do NOT present anything for user confirmation.** Run and write the final trace report straight to the chat as your response. The user expects to see the completed report.

## Execution Context

> **IMPORTANT**: Any inline Python that imports `helpers.*` must run with `cd <workspace>/.agent`
> (so the `.agent/` directory is on `sys.path`), **not** from the workspace root.
> Script invocations like `python .agent/skills/.../script.py` can be run from the workspace root
> because those scripts manage their own path setup.

## Workspace Protocol

For trace pipelines with multiple skills:

1. Create `.agent/workspace/<module>_trace_export_<timestamp>/`.
2. Pass `--workspace-dir <run_dir>` and `--workspace-step <step_name>` to each skill script.
3. Keep only summary output in context/chat.
4. Pull full chain/classification payloads only from `<run_dir>/<step_name>/results.json` when writing the final trace narrative.
5. Reference `<run_dir>/manifest.json` to verify which steps completed successfully.

## Steps

### Step 0: Preflight Validation

Validate arguments using `helpers.command_validation.validate_command_args("trace-export", {"module": "<module>", "function": "<export_name>"})`.
If validation fails, report the errors and stop. On success, use `result.resolved["db_path"]` for subsequent script calls.

1. **Find the module DB**
   Use the **decompiled-code-extractor** skill (`find_module_db.py`) to resolve the module name to its DB path.
   If module is unknown, `python .agent/skills/function-index/scripts/lookup_function.py <export_name>` finds it across all modules instantly.
   For broader discovery (e.g., finding which functions reference an API or contain a string), use `python .agent/helpers/unified_search.py <db_path> --query <term> --dimensions name,export,api`.
   Use the index-returned `function_id` for follow-up DB access (`db.get_function_by_id`) and treat `has_decompiled=false` / `file=null` as valid indexed entries.

> **Tip:** All skill scripts support `--json` for machine-readable output. Use `--json` when parsing script output programmatically.

2. **Verify the export exists**
   Use the **generate-re-report** skill (`analyze_imports.py --exports`) to list the module's exports and confirm the target function is actually exported. If not, inform the user and offer to trace it as an internal function.

3. **Get the compact call tree**
   Use the **callgraph-tracer** skill (`chain_analysis.py --depth 3 --summary`) to see the full tree structure without code. This reveals internal callees, resolvable cross-module callees, and unresolvable external calls.
   Use the user's `--depth` value if provided instead of the default 3.

4. **Classify key functions in the chain**
   Use `is_library_function()` from function_index to skip classifying WIL/WRL/STL boilerplate callees. Focus the '5-8 most interesting callees' selection on application code only.
   When resolving chain nodes, use `function_id` from function_index first (index-first resolution), and only fall back to name search if not indexed.
   Use the **classify-functions** skill (`classify_function.py`) for the export itself plus the 5-8 most interesting callees (those with dangerous APIs, high complexity, or security relevance). Do not classify every function -- focus on the significant ones.

5. **Security dossier for the export** (if the export has dangerous callees or high attack score)
   Use the **security-dossier** skill (`build_dossier.py`) to gather security context for the export itself and optionally the top 1-2 most dangerous callees:

   ```bash
   python .agent/skills/security-dossier/scripts/build_dossier.py <db_path> <export_name> --json
   ```

   This returns attack reachability, data flow exposure, dangerous operations, resource patterns, and complexity metrics in a single call. Feed results into the Dangerous Operations Reachable section.

6. **Deep trace with code**
   `resolve_function_file()` from helpers provides direct .cpp paths for reading callee source code.
   Use the **callgraph-tracer** skill (`chain_analysis.py --depth 2`) with full code output for the most interesting paths. For specific callees identified in Step 3, use `--follow <callee>` to trace selectively rather than blind high-depth recursion.

7. **Data flow trace for key parameters**
   Use the **data-flow-tracer** skill (`forward_trace.py`) to trace the export's key parameters through the call chain:

   ```bash
   python .agent/skills/data-flow-tracer/scripts/forward_trace.py <db_path> <export_name> --param 1 --depth 2
   ```

   Run for the 1-2 most security-relevant parameters (e.g., user-controlled inputs, handles, buffer pointers). This provides concrete evidence for the Data Flow Summary rather than relying on inference from the call tree.

7b. **Taint analysis** (conditional on step 5 showing dangerous callees or high attack score)
   Use the **taint-analysis** skill (`taint_function.py`) to trace the export's parameters to dangerous sinks:
   ```bash
   python .agent/skills/taint-analysis/scripts/taint_function.py <db_path> <export_name> --depth 2 --json \
       --workspace-dir <run_dir> --workspace-step taint_export
   ```
   Reports which parameters reach which sinks, severity scoring, guards on the path with bypass difficulty, and logic effects. Feed results into the Taint Summary subsection of the trace report.

8. **Cross-module resolution**
   First try the **import-export-resolver** skill (`query_function.py --function <callee> --direction export`) to resolve external callees via PE import/export tables (handles API-set forwarders like `api-ms-win-*` -> `kernelbase.dll`). Fall back to the **callgraph-tracer** skill (`cross_module_resolve.py --from-function`) for callees not resolvable via import tables. For each resolvable cross-module callee, run `chain_analysis.py` starting from that callee's module DB.

9. **Generate visual diagram**
   Use the **callgraph-tracer** skill (`generate_diagram.py --function <export> --depth 3`) to produce a Mermaid call graph diagram.

10. **Synthesize trace report**
   Combine all findings into a structured narrative:
   - **Export Identity**: signature, mangled name, ordinal/named/forwarded, classification
   - **Call Tree Overview**: Mermaid diagram from Step 9
   - **Execution Flow Narrative**: walk through each level (Level 0: export, Level 1: direct callees, etc.) documenting purpose, parameters, key operations, and calls made. Note cross-module transitions clearly.
   - **Cross-Module Transitions**: table of source function -> external callee -> target module -> resolved?
   - **Dangerous Operations Reachable**: each dangerous API with the path from the export (e.g., `export -> func_A -> func_B -> CreateProcessW at depth 3`)
   - **Taint Summary** (when step 7b produced results): which parameters reach which dangerous sinks, severity scores, guards on the path with bypass difficulty, logic effects (branch steering, array indexing, size arguments)
   - **Data Flow Summary**: from Step 7 data flow traces -- what enters through parameters, where it flows, what external effects the export can produce
   - **Notable Patterns**: recursive calls, dispatch tables, COM/RPC interactions, string constants (registry keys, file paths, URLs)

   When including observations from reading the code beyond what automated scripts report (e.g., in the Execution Flow Narrative), limit to 3 significant observations per function, require specific code/variable references, and label as `"Manual review -- not from automated analysis"` to distinguish from reproducible script output.

## Step Dependencies

- Steps 1 -> 2 are sequential (resolve then verify).
- Steps 3 + 4 are independent and can run concurrently (call tree structure + function classification).
- Steps 5 + 6 + 7 + 7b + 8 + 9 depend on Steps 3 + 4, but are independent of each other -- run concurrently after the first batch completes. Step 7b is conditional on step 5 results.
- Step 10 depends on all previous steps.

## Output

Present the trace report in chat. Always save to `extracted_code/<module_folder>/reports/trace_export_<export_name>_<timestamp>.md` (using `YYYYMMDD_HHMM` for timestamp).

All saved files must include a provenance header: generation date, workspace run directory path, module name, export name, trace depth used, and DB path.

**Follow-up suggestions**:

- `/audit <module> <function>` -- security audit on dangerous functions found in the trace
- `/taint <module> <function>` -- deeper taint analysis on functions with dangerous sinks
- `/explain <module> <function>` -- understand what a specific callee in the chain does
- `/data-flow forward <module> <export> --param N` -- trace where a specific parameter flows
- `/lift-class <module> <class>` -- lift classes whose methods appear in the call chain

## Error Handling

- **Module not found**: List available modules via `find_module_db.py --list` and ask the user to choose
- **Export not found**: Run `--list` to show available exports and suggest close matches
- **DB access failure**: Report the error with the DB path and suggest running `/health`
- **Missing decompiled code**: Report which functions in the call chain lack decompiled output
