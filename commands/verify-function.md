# Verify Decompiler Accuracy

## Overview

Quickly verify whether Hex-Rays decompiled output is accurate for a specific function, or scan an entire module for decompiler issues -- without running a full `/audit` pipeline.

The text after `/verify` specifies the **function name** and optionally the **module**:
- `/verify AiCheckSecureApplicationDirectory` -- searches all modules
- `/verify appinfo.dll AiCheckSecureApplicationDirectory` -- targets specific module
- `/verify appinfo.dll` -- scans the entire module for decompiler issues (no function = module scan)
- `/verify appinfo.dll --top 10` -- module scan, show top 10 results

If a function is specified, runs per-function deep verification. If only a module is specified, runs a module-wide scan ranking functions by issue severity.

## IMPORTANT: Execution Model

**This is an execute-immediately command. Do NOT present anything for user confirmation.** Run and write the final verification report straight to the chat as your response. The user expects to see the completed output.

## Execution Context

> **IMPORTANT**: Any inline Python that imports `helpers.*` must run with `cd <workspace>/.agent`
> (so the `.agent/` directory is on `sys.path`), **not** from the workspace root.
> Script invocations like `python .agent/skills/.../script.py` can be run from the workspace root
> because those scripts manage their own path setup.

## Steps

### Step 0: Preflight Validation

Validate arguments using `helpers.command_validation.validate_command_args("verify", {"module": "<module>"})`.
If validation fails, report the errors and stop. On success, use `result.resolved["db_path"]` for subsequent script calls.

1. **Locate the target**
   - If a function name is provided:
     **Quick lookup**: Use `python .agent/skills/function-index/scripts/lookup_function.py <function_name>` to locate the function across all modules instantly.
     Otherwise, use the **decompiled-code-extractor** skill (`find_module_db.py` then `list_functions.py --search`) to resolve the module DB and exact function name.
   - After resolution, check whether the target is library boilerplate (WIL/CRT/STL/WRL/ETW) using `is_library_function()` from function_index. If so, note this in the output -- library code is lower-priority for verification.
   - If only a module name is provided:
     Use `python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py <module>` to resolve the DB path.

> **Tip:** All skill scripts support `--json` for machine-readable output. Use `--json` when parsing script output programmatically.

2. **Run verification**

   **Per-function verification** (function name provided):
   Use the **verify-decompiled** skill (`verify_function.py`) to compare decompiled output against assembly ground truth:

   ```bash
   python .agent/skills/verify-decompiled/scripts/verify_function.py <db_path> <function_name>
   python .agent/skills/verify-decompiled/scripts/verify_function.py <db_path> --id <function_id>
   ```

   **Module-wide scan** (no function name):
   Use the **verify-decompiled** skill (`scan_module.py`) to scan all functions and rank by severity:

   ```bash
   python .agent/skills/verify-decompiled/scripts/scan_module.py <db_path>
   python .agent/skills/verify-decompiled/scripts/scan_module.py <db_path> --min-severity HIGH --top 20
   ```

   Use the user's `--top` value if provided, otherwise default to `--top 20`.

3. **Present findings**

   **For per-function verification**, present:
   - **Accuracy Summary**: overall assessment (ACCURATE / MINOR ISSUES / SIGNIFICANT ISSUES)
   - **Issue List**: each finding with severity, description, affected line, and assembly evidence
   - **Impact**: whether the issues affect understanding of the function's behavior
   - **Recommendation**: whether the decompiled output can be trusted as-is, or needs correction before further analysis

   **Severity criteria for decompiler issues** (each level has a concrete, falsifiable definition):

   | Level    | Definition                                                                              |
   |----------|-----------------------------------------------------------------------------------------|
   | CRITICAL | Wrong control flow: missed branch, wrong loop condition, or incorrect exception handler |
   | HIGH     | Wrong access size or type that changes semantic meaning (e.g., DWORD read as BYTE)      |
   | MODERATE | Missing NULL guard, collapsed operation, or elided cast that could mislead analysis     |
   | LOW      | Cosmetic issue (variable naming, type width) that does not affect behavioral understanding |

   **For module-wide scan**, present:
   - **Scan Summary**: total functions scanned, issue distribution by severity
   - **Top Issues**: ranked list of functions with the most/worst decompiler issues
   - **Recommended Next Steps**: suggest `/verify <module> <function>` for the top hits, or `/audit` for security-critical functions

## Output

Present the verification report in chat. This is a lightweight retrieval command; file output is on-request only. When saving, use `extracted_code/<module_folder>/reports/verify_<function>_<timestamp>.md` and include a provenance header (generation date, module, function, DB path, scan mode).

**Follow-up suggestions**:
- `/audit <module> <function>` -- full security audit on functions with CRITICAL issues
- `/explain <module> <function>` -- understand what a flagged function does
- `/verify <module> <function>` -- deep-dive a specific function from a module scan

## Error Handling

- **Module not found**: List available modules via `find_module_db.py --list` and ask the user to choose
- **Function not found**: Run a fuzzy search and suggest close matches
- **DB access failure**: Report the error with the DB path and suggest running `/health`
- **Missing assembly code**: Cannot verify without assembly ground truth; report as `SKIP`
- **Missing decompiled code**: Cannot verify; report as `SKIP` with explanation
- **Partial scan failure** (module-wide mode): If some functions scan successfully but others fail, report the successful scans and list which functions could not be scanned. Continue presenting results for the portion that completed.
