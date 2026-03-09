# Lift Class

## Overview

Batch-lift all methods of a C++ class with shared type context, producing a single cohesive `.cpp` output file with struct definitions, constants, and all methods in dependency order. Uses assembly as ground truth to ensure 100% functional equivalence.

**Primary mechanism: code-lifter subagent.** This command delegates to the `code-lifter` subagent, which maintains shared struct definitions, naming conventions, accumulated constants, and already-lifted code in its context across all methods. The grind loop is a fallback for edge cases (see below).

The text after `/lift-class` specifies the **class name** and optionally the **module**:

- `/lift-class CSecurityDescriptor` -- searches all modules
- `/lift-class appinfo.dll CSecurityDescriptor` -- targets specific module
- `/lift-class cmd.exe --list` -- list all detected classes first

## IMPORTANT: Execution Model

**This is an execute-immediately command. Do NOT present anything for user confirmation.** Run and write the final lifted code and summary straight to the chat as your response. The user expects to see the completed output.

## Execution Context

> **IMPORTANT**: Any inline Python that imports `helpers.*` must run with `cd <workspace>/.agent`
> (so the `.agent/` directory is on `sys.path`), **not** from the workspace root.
> Script invocations like `python .agent/skills/.../script.py` can be run from the workspace root
> because those scripts manage their own path setup.

## Workspace Protocol

Apply filesystem handoff for all intermediate artifacts:

1. Create `.agent/workspace/<module>_lift_class_<timestamp>/`.
2. For any supporting skill/script invocations, pass:
   - `--workspace-dir <run_dir>`
   - `--workspace-step <step_name>`
3. Keep only summaries in context; read full intermediate data from `<run_dir>/<step_name>/results.json` when needed.
4. For fallback grind-loop runs, use the session-scoped scratchpad `.agent/hooks/scratchpads/{session_id}.md` for loop state, but store intermediate script outputs in the workspace run directory.

## Steps

### Step 0: Preflight Validation

Validate arguments using `helpers.command_validation.validate_command_args("lift-class", {"module": "<module>", "class": "<class_name>"})`.
If validation fails, report the errors and stop. On success, use `result.resolved["db_path"]` for subsequent script calls.

1. **Find the module DB**
   Use the **decompiled-code-extractor** skill (`find_module_db.py`) to resolve the module. To browse available classes, use the **reconstruct-types** skill (`list_types.py` or `extract_class_hierarchy.py`).

> **Tip:** All skill scripts support `--json` for machine-readable output. Use `--json` when parsing script output programmatically.

2. **Collect and preview the class methods**
   Use the **code-lifter** subagent's `batch_extract.py` to preview what will be lifted:

   ```bash
   python .agent/agents/code-lifter/scripts/batch_extract.py <db_path> --class <ClassName> --summary
   ```

   Review: method count, which have decompiled code, dependency order, initial struct scan.
   If the class has many methods (>15), ask the user if they want to lift all or a subset.

   Use `--app-only` on `collect_functions.py` or `--skip-library` to exclude WIL/WRL boilerplate methods that sometimes appear in class groups. `resolve_module_dir()` from helpers provides the extracted_code path for output.

3. **Delegate to the code-lifter subagent**
   Launch the `code-lifter` subagent with a descriptive name (e.g., `"Lift CSecurityDescriptor methods (appinfo.dll)"`) and a prompt that includes:
   - The DB path
   - The class name
   - The function count and any user preferences (e.g., subset selection)
   - Any specific instructions from the user

   The code-lifter subagent will:
   - Run `batch_extract.py --init-state` to extract all data and initialize shared state
   - Optionally run deep struct scanning via `scan_struct_fields.py`
   - Lift each function in dependency order (constructors first)
   - Track shared state (struct fields, constants, naming) across all methods
   - Assemble the final `.cpp` output
   - Return results (lifted code, struct definition, progress summary)

4. **Handle results from the subagent**
   The code-lifter returns:
   - The assembled `.cpp` file path
   - Summary: methods lifted vs skipped, struct coverage, constants found
   - Any issues or warnings

   Save the output to `extracted_code/<module_folder>/lifted_<ClassName>.cpp`.

5. **Optional: Verify with the verifier subagent**
   For critical functions, launch the `verifier` subagent with `readonly: true` to independently check that the lifted code matches assembly ground truth. The verifier operates in a separate context (preventing confirmation bias) and must never modify lifted outputs.

6. **Summary**
   Report: methods lifted vs skipped, struct field coverage, decompiler issues found.

**Follow-up suggestions**:

- `/reconstruct-types <module> <class>` -- refine struct/class definitions with full module context
- `/explain <module> <method>` -- understand a specific method's behavior in detail
- `/trace-export <module> <export>` -- trace the call chain if any lifted methods are exports

## Step Dependencies

- Steps 1 -> 2 are sequential (resolve then preview).
- Step 3 depends on Steps 1 + 2 (needs DB path, class info, user preferences).
- Step 4 depends on Step 3 (waits for subagent results).
- Step 5 (optional verify) depends on Step 4. For classes with many methods, individual method verifications can run concurrently.
- Step 6 depends on Step 4 (or Step 5 if verification was run).

## Fallback: Grind Loop

If the code-lifter subagent is unavailable or hits context limits (rare with <20 methods), fall back to the grind-loop approach:

1. Create `.agent/hooks/scratchpads/{session_id}.md` with one checkbox per method
2. Lift methods one at a time using the **code-lifting** and **batch-lift** skills
3. Track shared state manually via `track_shared_state.py`
4. Set Status to `DONE` when finished

The code-lifter subagent is strongly preferred because the grind loop **loses context** between iterations -- struct definitions, naming maps, and constants cannot propagate across methods.

## Output

Save the `.cpp` file to `extracted_code/<module_folder>/lifted_<ClassName>.cpp`. Also present a summary in chat showing the struct definition and lifted function signatures.

All saved files must include a provenance header comment: generation date, module name and DB path, class name, methods lifted, and workspace run directory path.

## Error Handling

- **Module not found**: List available modules via `find_module_db.py --list` and ask the user to choose
- **Class not found**: Run `--list` to show available classes and suggest close matches
- **DB access failure**: Report the error with the DB path and suggest running `/health`
- **Missing decompiled code**: Report which class methods lack decompiled output; lift available methods only
- **State file corruption**: Create a fresh state file; warn that accumulated context was lost
