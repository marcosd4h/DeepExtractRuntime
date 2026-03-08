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

This command invokes multiple scripts (list_types, extract_class_hierarchy, scan_struct_fields, generate_header, optionally COM + validate):

1. Create `.agent/workspace/<module>_reconstruct_types_<timestamp>/`.
2. Pass `--workspace-dir <run_dir>` and `--workspace-step <step_name>` to each skill invocation.
3. Keep only summary output in context; read full intermediate data from `<run_dir>/<step_name>/results.json` when generating the final header.
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

2. **Discover types**
   Use the **reconstruct-types** skill (`list_types.py`) to list all classes and struct candidates in the module:

   ```bash
   python .agent/skills/reconstruct-types/scripts/list_types.py <db_path>
   python .agent/skills/reconstruct-types/scripts/list_types.py <db_path> --json
   ```

   If a specific class is requested, confirm it exists in the output.

3. **Extract class hierarchy**
   Use the **reconstruct-types** skill (`extract_class_hierarchy.py`) to find inheritance relationships:

   ```bash
   python .agent/skills/reconstruct-types/scripts/extract_class_hierarchy.py <db_path>
   python .agent/skills/reconstruct-types/scripts/extract_class_hierarchy.py <db_path> --class <ClassName>
   ```

4. **Scan struct fields**
   Use the **reconstruct-types** skill (`scan_struct_fields.py`) to scan all functions for memory access patterns:

   ```bash
   python .agent/skills/reconstruct-types/scripts/scan_struct_fields.py <db_path> --all-classes
   python .agent/skills/reconstruct-types/scripts/scan_struct_fields.py <db_path> --class <ClassName>
   python .agent/skills/reconstruct-types/scripts/scan_struct_fields.py <db_path> --all-classes --app-only
   ```

   For a single class, use `--class`. For the whole module, use `--all-classes`. Add `--app-only` to skip library functions.

5. **Generate header**
   Use the **reconstruct-types** skill (`generate_header.py`) to produce a compilable C++ header:

   ```bash
   python .agent/skills/reconstruct-types/scripts/generate_header.py <db_path> --all-classes
   python .agent/skills/reconstruct-types/scripts/generate_header.py <db_path> --class <ClassName> --output <path>
   ```

6. **Optional: COM interface reconstruction**
   If the user requests `--include-com` or the module has COM/WRL interfaces:

   ```bash
   python .agent/skills/com-interface-reconstruction/scripts/scan_com_interfaces.py <db_path>
   ```

7. **Optional: Validate against assembly**
   If the user requests `--validate`, use the **type-reconstructor** agent's `validate_layout.py`:

   ```bash
   python .agent/agents/type-reconstructor/scripts/validate_layout.py <db_path> --header <header_path>
   ```

### Step Dependencies

- Step 1 is the starting point.
- Steps 2 + 3 are independent and can run concurrently (type listing + hierarchy extraction).
- Step 4 depends on Step 1 (needs DB path; does not depend on Steps 2-3).
- Step 5 depends on Step 4 (needs scanned field data).
- Step 6 is optional and depends on Step 1 (needs DB path; operates on the DB directly, not the generated header). Step 7 is optional and depends on Step 5 (needs the generated header to validate). Steps 6 + 7 are independent of each other.
- Step 8 depends on all previous steps.

8. **Present results**
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
- `/verify <module> <function>` -- verify decompiler output for functions with suspicious struct access

## Error Handling

- **Module not found**: List available modules via `find_module_db.py --list` and ask the user to choose
- **Class not found**: List available classes/structs and suggest close matches
- **DB access failure**: Report the error with the DB path and suggest running `/health`
- **Insufficient evidence**: Report which types have low confidence and why (few source functions, no assembly verification)
- **Partial step failure**: If some steps fail (e.g., hierarchy extraction fails but field scanning succeeds), continue with available data and clearly state which steps produced results and which did not
