# Reconstruct Types

## Overview

Reconstruct C/C++ struct and class definitions from a module's decompiled code by scanning memory access patterns, vtable contexts, and mangled names across all functions. Generates compilable C++ header files with per-field confidence annotations.

The text after `/reconstruct-types` specifies a **module** and optionally a **class name**:

- `/reconstruct-types appinfo.dll` -- reconstruct all types in the module
- `/reconstruct-types appinfo.dll CSecurityDescriptor` -- reconstruct a specific class
- `/reconstruct-types appinfo.dll --include-com` -- include COM interface reconstruction
- `/reconstruct-types appinfo.dll --validate` -- validate generated header against assembly

## IMPORTANT: Execution Model

**This is an execute-immediately command. Do NOT present anything for user confirmation.** Run and write the final reconstructed types straight to the chat as your response. The user expects to see the completed output.

## Workspace Protocol

This command uses the **type-reconstructor** agent's `reconstruct_all.py` pipeline, plus optional validation:

1. Create `.agent/workspace/<module>_reconstruct_types_<timestamp>/`.
2. Pass `--workspace-dir <run_dir>` and `--workspace-step reconstruct` to the `reconstruct_all.py` invocation.
3. Keep only summary output in context; read full intermediate data from `<run_dir>/reconstruct/results.json` when presenting results.
4. Use `<run_dir>/manifest.json` to track completed/failed steps.

## Execution Context

> **IMPORTANT**: Any inline Python that imports `helpers.*` must run with `cd <workspace>/.agent`
> (so the `.agent/` directory is on `sys.path`), **not** from the workspace root.
> Script invocations like `python .agent/skills/.../script.py` can be run from the workspace root
> because those scripts manage their own path setup.

## Steps

### Step 0: Preflight Validation

Validate arguments using `helpers.command_validation.validate_command_args("reconstruct-types", {"module": "<module>"})`.
If validation fails, report the errors and stop. On success, use `result.resolved["db_path"]` for subsequent script calls.

1. **Find the module DB**
   Use the **decompiled-code-extractor** skill (`find_module_db.py`) to resolve the module name to its DB path.

> **Tip:** All skill scripts support `--json` for machine-readable output. Use `--json` when parsing script output programmatically.

2. **Reconstruct types via type-reconstructor**
   Use the **type-reconstructor** agent's `reconstruct_all.py` to run the full reconstruction pipeline in one call. This covers: type discovery, class hierarchy extraction, struct field scanning, evidence merging (conflict resolution, padding inference, confidence scoring), and header generation.

   ```bash
   # Single class
   python .agent/agents/type-reconstructor/scripts/reconstruct_all.py <db_path> --class <ClassName> --json

   # Full module
   python .agent/agents/type-reconstructor/scripts/reconstruct_all.py <db_path> --json

   # With COM interface reconstruction
   python .agent/agents/type-reconstructor/scripts/reconstruct_all.py <db_path> --include-com --json

   # With output file
   python .agent/agents/type-reconstructor/scripts/reconstruct_all.py <db_path> --output <path> --json
   ```

   If the user requests `--include-com`, pass `--include-com` to `reconstruct_all.py`. If the user requests `--output`, pass `--output <path>`.

3. **Optional: Validate against assembly**
   If the user requests `--validate`, use the **type-reconstructor** agent's `validate_layout.py`:

   ```bash
   python .agent/agents/type-reconstructor/scripts/validate_layout.py <db_path> --header <header_path>
   ```

### Step Dependencies

- Step 1 is the starting point.
- Step 2 depends on Step 1 (needs DB path). It runs the full pipeline internally (discover -> hierarchy -> scan -> merge -> COM -> header).
- Step 3 is optional and depends on Step 2 (needs the generated header to validate).
- Step 4 depends on all previous steps.

4. **Present results**
   - **Type Summary**: total classes/structs found, inheritance graph
   - **Struct Definitions**: C++ header with field names, types, offsets, and confidence per field
   - **Confidence Overview**: high/medium/low confidence field counts
   - **Validation Results** (if `--validate`): matches, mismatches, missing fields
   - **Recommendations**: fields that need manual review, assembly evidence for low-confidence fields

## Output

Present the reconstructed types in chat. Always save the header file to `extracted_code/<module_folder>/reports/reconstructed_types_<module>_<timestamp>.h` (using `YYYYMMDD_HHMM` for timestamp). Create the `reports/` directory if needed.

All saved files must include a provenance header comment: generation date, module name, DB path, class count, and field confidence distribution.

**Follow-up suggestions**:

- `/lift-class <module> <ClassName>` -- lift all methods of a reconstructed class

## Error Handling

- **Module not found**: List available modules via `find_module_db.py --list` and ask the user to choose
- **Class not found**: List available classes/structs and suggest close matches
- **DB access failure**: Report the error with the DB path and suggest running `/health`
- **Insufficient evidence**: Report which types have low confidence and why (few source functions, no assembly verification)
- **Partial step failure**: If some steps fail (e.g., hierarchy extraction fails but field scanning succeeds), continue with available data and clearly state which steps produced results and which did not
