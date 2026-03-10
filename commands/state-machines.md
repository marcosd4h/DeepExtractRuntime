# State Machines

## Overview

Extract state machines, dispatch tables, and switch/case command dispatchers from decompiled functions. Reconstructs state transition graphs and generates visual diagrams.

The text after `/state-machines` specifies a **module** and optionally a **function**:

- `/state-machines appinfo.dll` -- scan module for all dispatch tables and state machines
- `/state-machines cmd.exe FParseWork` -- extract dispatch table from a specific function
- `/state-machines cmd.exe FParseWork --diagram` -- generate a Mermaid diagram
- `/state-machines appinfo.dll --detect` -- detect all dispatcher functions in the module

## IMPORTANT: Execution Model

**This is an execute-immediately command. Do NOT present anything for user confirmation.** Run and write the final analysis straight to the chat as your response. The user expects to see the completed output.

## Workspace Protocol

For module-wide detection (which invokes detect_dispatchers + per-function extraction + diagram generation):

1. Create `.agent/workspace/<module>_state_machines_<timestamp>/`.
2. Pass `--workspace-dir <run_dir>` and `--workspace-step <step_name>` to each skill invocation.
3. Keep only summary output in context; read full dispatch table/state machine data from `<run_dir>/<step_name>/results.json` when presenting results.
4. Use `<run_dir>/manifest.json` to track completed/failed extractions.

For single-function analysis, workspace protocol is optional (few steps, small payloads).

## Execution Context

> **IMPORTANT**: Any inline Python that imports `helpers.*` must run with `cd <workspace>/.agent`
> (so the `.agent/` directory is on `sys.path`), **not** from the workspace root.
> Script invocations like `python .agent/skills/.../script.py` can be run from the workspace root
> because those scripts manage their own path setup.

## Steps

### Step 0: Preflight Validation

Validate arguments using `helpers.command_validation.validate_command_args("state-machines", {"module": "<module>"})`.
If validation fails, report the errors and stop. On success, use `result.resolved["db_path"]` for subsequent script calls.

1. **Find the module DB**
   Use the **decompiled-code-extractor** skill (`find_module_db.py`) to resolve the module name to its DB path.

> **Tip:** All skill scripts support `--json` for machine-readable output. Use `--json` when parsing script output programmatically.

2. **Detect or target dispatchers**

   When presenting results, check each detected dispatcher against `is_library_function()` from function_index. Flag library boilerplate dispatchers (WIL/CRT/STL/WRL/ETW) in the output and rank application-code dispatchers higher.

   **Module-wide detection** (no function specified, or `--detect`):
   Use the **state-machine-extractor** skill (`detect_dispatchers.py`) to find all dispatcher functions:

   ```bash
   python .agent/skills/state-machine-extractor/scripts/detect_dispatchers.py <db_path>
   python .agent/skills/state-machine-extractor/scripts/detect_dispatchers.py <db_path> --json
   ```

   This scans all functions for switch/case statements, if-chains with numeric comparisons, and loop-with-dispatch patterns. Results are ranked by dispatch complexity.

   **Specific function** (function name provided):
   Proceed directly to Step 3.

3. **Extract dispatch table**
   Use the **state-machine-extractor** skill (`extract_dispatch_table.py`) to extract the case-value-to-handler mapping:

   ```bash
   python .agent/skills/state-machine-extractor/scripts/extract_dispatch_table.py <db_path> <function_name>
   python .agent/skills/state-machine-extractor/scripts/extract_dispatch_table.py <db_path> --id <function_id>
   python .agent/skills/state-machine-extractor/scripts/extract_dispatch_table.py <db_path> <function_name> --json
   ```

   Output includes: switch variable, case values, handler function names/addresses, default handler, and source type (switch vs if-chain).

4. **Reconstruct state machine** (if loop-with-dispatch pattern detected)
   Use the **state-machine-extractor** skill (`extract_state_machine.py`) to reconstruct state transitions:

   ```bash
   python .agent/skills/state-machine-extractor/scripts/extract_state_machine.py <db_path> <function_name>
   python .agent/skills/state-machine-extractor/scripts/extract_state_machine.py <db_path> <function_name> --with-code
   python .agent/skills/state-machine-extractor/scripts/extract_state_machine.py <db_path> <function_name> --json
   ```

   This identifies the state variable, loop structure, and transitions between states.

5. **Generate diagram** (if `--diagram` requested, or always for state machines)
   Use the **state-machine-extractor** skill (`generate_state_diagram.py`) to produce a visual diagram:

   ```bash
   python .agent/skills/state-machine-extractor/scripts/generate_state_diagram.py <db_path> <function_name>
   python .agent/skills/state-machine-extractor/scripts/generate_state_diagram.py <db_path> <function_name> --format mermaid
   python .agent/skills/state-machine-extractor/scripts/generate_state_diagram.py <db_path> <function_name> --format dot
   python .agent/skills/state-machine-extractor/scripts/generate_state_diagram.py <db_path> <function_name> --mode state-machine
   ```

   Default format is Mermaid. Mode auto-detects between dispatch table and state machine.

### Step Dependencies

- Steps 1 -> 2 are sequential. Step 3 depends on Step 2 (or Step 1 directly when a specific function is given).
- Steps 4 + 5 both depend on Step 3 and are independent -- run concurrently if both apply.
- For module-wide detection: Steps 3-5 can run per-dispatcher in parallel after Step 2 identifies targets.
- Step 6 depends on all previous steps.

6. **Present results**

   **For module-wide detection**, present:
   - **Dispatcher Summary**: total dispatchers found, by type (switch, if-chain, state machine)
   - **Top Dispatchers**: ranked by complexity (case count, nesting depth)
   - **Recommendations**: suggest `/state-machines <module> <function>` for the top hits

   **For dispatch table extraction**, present:
   - **Table Overview**: function name, switch variable, total cases, has default
   - **Case Mapping**: table of case value -> handler function -> handler description
   - **Handler Details**: for each handler, brief classification (what it does)
   - **Mermaid Diagram** (if `--diagram`): visual flowchart of the dispatch

   **For state machine reconstruction**, present:
   - **State Machine Overview**: state variable, total states, loop structure
   - **State Transitions**: table of from_state -> condition -> to_state
   - **State Descriptions**: for each state, the handler code summary
   - **Mermaid Diagram**: state transition diagram (always included for state machines)

## Output

Present the analysis in chat. Include Mermaid diagrams inline. This is a lightweight retrieval command; file output is on-request only. When saving, use `extracted_code/<module_folder>/reports/state_machines_<function>_<timestamp>.md` and include a provenance header (generation date, module, function, dispatcher type).

**Follow-up suggestions**:

- `/explain <module> <handler_function>` -- understand what a specific handler does
- `/data-flow forward <module> <function> --param 1` -- trace state variable flow
- `/audit <module> <export> --diagram` -- full security audit with call graph from the parent export

## Error Handling

- **Module not found**: List available modules via `find_module_db.py --list` and ask the user to choose
- **Function not found**: Run a fuzzy search and suggest close matches
- **DB access failure**: Report the error with the DB path and suggest running `/health`
- **No dispatch tables found**: Report that no switch/case dispatchers were detected in the target
- **Partial extraction failure**: If detection succeeds but extraction fails for some dispatchers, report the successful extractions and list which dispatchers could not be processed and why
