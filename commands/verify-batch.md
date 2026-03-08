# Verify Batch Decompiler Accuracy

## Overview

Verify Hex-Rays decompiled output for a list of specific functions or an entire class, leveraging the **verifier** subagent for automated, iterative verification.

Usage:

- `/verify-batch appinfo.dll AiCheckSecureApplicationDirectory AiCreateApplicationContext` -- specific functions
- `/verify-batch appinfo.dll CSecurityDescriptor` -- all methods of a class

## IMPORTANT: Execution Model

**This is an execute-immediately command. Do NOT present anything for user confirmation.** Run and write the final verification report straight to the chat as your response. The user expects to see the completed report.

## Workspace Protocol

This command orchestrates N verifier subagent launches:

1. Create `.agent/workspace/<module>_verify_batch_<timestamp>/`.
2. Store per-function verification results in `<run_dir>/<function_name>/results.json`.
3. Keep only pass/fail summaries in context; read full verification details on demand.
4. Use `<run_dir>/manifest.json` to track which functions have been verified and their status.

## Execution Context

> **IMPORTANT**: Any inline Python that imports `helpers.*` must run with `cd <workspace>/.agent`
> (so the `.agent/` directory is on `sys.path`), **not** from the workspace root.
> Script invocations like `python .agent/skills/.../script.py` can be run from the workspace root
> because those scripts manage their own path setup.

## Steps

### Step 0: Preflight Validation

Validate arguments using `helpers.command_validation.validate_command_args("verify-batch", {"module": "<module>"})`.
If validation fails, report the errors and stop. On success, use `result.resolved["db_path"]` for subsequent script calls.

1. **Initialize the verification batch**

> **Tip:** All skill scripts support `--json` for machine-readable output. Use `--json` when parsing script output programmatically.

   - Resolve the module DB using `python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py <module>`.
   - Resolve the target functions using layered resolution:
     - **Quick lookup first**: Use `python .agent/skills/function-index/scripts/lookup_function.py <function_name>` for instant resolution across all modules. Use the returned `function_id` for all subsequent operations.
     - **Fallback**: If lookup returns no match, use `python .agent/skills/decompiled-code-extractor/scripts/list_functions.py <db_path> --search <name>` for fuzzy search.
     - If a class name is provided, use `python .agent/skills/reconstruct-types/scripts/list_types.py <db_path> --class <class_name>` to get all method IDs.
   - After resolving target functions, check each against `is_library_function()` from function_index. If any are library boilerplate (WIL/CRT/STL/WRL/ETW), warn the user and suggest focusing verification on application code instead.
   - Create a **session-scoped scratchpad** at `.agent/hooks/scratchpads/{session_id}.md` to track progress.

2. **Run verification loop**
   - For each function in the batch:
     - Launch the **verifier** subagent with `readonly: true` and a descriptive name (e.g., `"Verify decompiler accuracy for AiCheckLockdown (appinfo.dll)"`):
       ```bash
       # verifier subagent prompt
       Verify the accuracy of the decompiled code for function <function_name> in <module>.
       Compare it against the assembly ground truth and report any inaccuracies.
       ```
     - The subagent will use the `verify-decompiled` skill to perform deep analysis.
     - Update the scratchpad as each function is completed.

### Step Dependencies

- Step 1 is sequential (resolve module and functions).
- Step 2: Individual function verifications are independent -- run up to 3-4 verifier subagents concurrently (subject to agent limits).
- Step 3 depends on Step 2 completion (all verifications must finish before synthesis).

3. **Synthesize batch report**
   - Once all functions are verified, summarize the findings:
     - **Batch Summary**: Total functions verified, count of Accurate vs. Inaccurate.
     - **Critical Findings**: Highlight any functions with CRITICAL or HIGH severity issues.
     - **Detailed Results**: A table or list showing each function and its verification status.

## Output

Present the batch verification report in chat. Always save to `extracted_code/<module_folder>/reports/verify_batch_<target>_<timestamp>.md` (using `YYYYMMDD_HHMM` for timestamp, `<target>` is class name or function list). Create the `reports/` directory if needed.

All saved files must include a provenance header: generation date, module name, DB path, functions verified, and workspace run directory path.

**Follow-up suggestions**:

- `/lift-class <module> <class>` -- lift the class methods, incorporating fixes for verified issues.
- `/audit <module> <function>` -- perform a full security audit on functions with significant inaccuracies.

## Error Handling

- **Module not found**: List available modules via `find_module_db.py --list` and ask the user to choose
- **Function(s) not found**: Report which functions were not found; verify the ones that exist
- **Class not found**: List available classes and suggest close matches
- **DB access failure**: Report the error with the DB path and suggest running `/health`
- **Missing assembly code**: Report which functions lack assembly; mark as `SKIP` in results
- **Partial verification failure**: If some functions verify successfully but others fail (subagent error, timeout), report the successful verifications and clearly list which functions could not be verified and why. A partial report is more useful than an error message.
