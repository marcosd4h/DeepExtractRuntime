# Data Flow Trace

## Overview

Trace how data moves through a binary -- forward parameter flow, backward argument origin, global variable producer/consumer maps, and string literal usage chains. Answers questions like "where does this parameter end up?" and "where does this argument come from?"

The text after `/data-flow` specifies the **direction**, **function**, and **target**:

- `/data-flow forward appinfo.dll AiLaunchProcess --param 1` -- trace where parameter 1 flows
- `/data-flow backward appinfo.dll AiLaunchProcess --target CreateProcessW` -- trace where CreateProcessW arguments come from
- `/data-flow string appinfo.dll --string "CreateProcess"` -- find all functions referencing a string
- `/data-flow string cmd.exe --function eComSrv` -- show all strings used by a function
- `/data-flow globals appinfo.dll` -- map all global variable readers/writers

Default trace depth is 1 (direct callees/callers only). Override with `--depth N`.

## IMPORTANT: Execution Model

**This is an execute-immediately command. Do NOT present anything for user confirmation.** Run and write the final trace results straight to the chat as your response. The user expects to see the completed output.

## Execution Context

> **IMPORTANT**: Any inline Python that imports `helpers.*` must run with `cd <workspace>/.agent`
> (so the `.agent/` directory is on `sys.path`), **not** from the workspace root.
> Script invocations like `python .agent/skills/.../script.py` can be run from the workspace root
> because those scripts manage their own path setup.

## Steps

### Step 0: Preflight Validation

Validate arguments using `helpers.command_validation.validate_command_args("data-flow", {"module": "<module>", "function": "<function>"})`.
If validation fails, report the errors and stop. On success, use `result.resolved["db_path"]` for subsequent script calls.

1. **Find the module DB**
   Use the **decompiled-code-extractor** skill (`find_module_db.py`) to resolve the module name to its DB path.
   If module is unknown, `python .agent/skills/function-index/scripts/lookup_function.py <function_name>` finds it across all modules.
   After resolving the target function, use the returned `function_id` for all subsequent skill script invocations (e.g., `--id <function_id>`) to avoid re-resolution ambiguity.
   Check whether it is library boilerplate (WIL/CRT/STL/WRL/ETW) using `is_library_function()` from function_index. Flag library functions in the output so the user knows the trace targets infrastructure code.

> **Tip:** All skill scripts support `--json` for machine-readable output. Use `--json` when parsing script output programmatically.

2. **Run the appropriate trace**

   **Forward trace** (where does a parameter go?):

   ```bash
   python .agent/skills/data-flow-tracer/scripts/forward_trace.py <db_path> <function_name> --param N
   python .agent/skills/data-flow-tracer/scripts/forward_trace.py <db_path> <function_name> --param N --depth 2
   python .agent/skills/data-flow-tracer/scripts/forward_trace.py <db_path> <function_name> --param N --assembly
   ```

   **Backward trace** (where does an argument come from?):

   ```bash
   python .agent/skills/data-flow-tracer/scripts/backward_trace.py <db_path> <function_name> --target <API_name>
   python .agent/skills/data-flow-tracer/scripts/backward_trace.py <db_path> <function_name> --target <API_name> --arg N
   python .agent/skills/data-flow-tracer/scripts/backward_trace.py <db_path> <function_name> --target <API_name> --callers --depth 2
   ```

   **String trace** (who uses this string?):

   ```bash
   python .agent/skills/data-flow-tracer/scripts/string_trace.py <db_path> --string <text>
   python .agent/skills/data-flow-tracer/scripts/string_trace.py <db_path> --function <name>
   python .agent/skills/data-flow-tracer/scripts/string_trace.py <db_path> --string <text> --callers --depth 2
   python .agent/skills/data-flow-tracer/scripts/string_trace.py <db_path> --list-strings --limit 50
   ```

   **Global variable map**:

   ```bash
   python .agent/skills/data-flow-tracer/scripts/global_state_map.py <db_path>
   python .agent/skills/data-flow-tracer/scripts/global_state_map.py <db_path> --function <name>
   python .agent/skills/data-flow-tracer/scripts/global_state_map.py <db_path> --address <hex_addr>
   ```

3. **Present results**

   **For forward traces**, present:
   - **Parameter Identity**: parameter name, type, register (x64 convention)
   - **Flow Map**: each callee that receives the parameter, at which argument position
   - **Side Effects**: global variable writes, return value propagation
   - **Depth visualization**: indented tree showing parameter flow across call depth

   **For backward traces**, present:
   - **Target Call**: the API call and its full argument list
   - **Argument Origins**: for each argument, classify as: function parameter, return value of another call, global variable, constant, or complex expression
   - **Caller Chain** (if `--callers`): what each caller passes at each call site

   **For string traces**, present:
   - **String References**: all functions that reference the string, with code context
   - **Caller Chain** (if `--callers`): execution paths that lead to the string's use
   - **Categorization**: file path, registry key, URL, RPC endpoint, etc.

   **For global variable maps**, present:
   - **Variable Summary**: address, readers, writers, read-write functions
   - **Access Patterns**: which functions read vs write the variable

## Output

Present the trace results in chat. This is a lightweight retrieval command; file output is on-request only. When saving, use `extracted_code/<module_folder>/reports/data_flow_<function>_<timestamp>.md` and include a provenance header (generation date, module, function, trace direction, depth).

**Follow-up suggestions**:

- `/audit <module> <function> --diagram` -- full security audit with call graph from an export
- `/audit <module> <function>` -- security audit on functions in the data flow path
- `/explain <module> <function>` -- understand what a function in the chain does

## Error Handling

- **Module not found**: List available modules via `find_module_db.py --list` and ask the user to choose
- **Function not found**: Run a fuzzy search and suggest close matches
- **DB access failure**: Report the error with the DB path and suggest running `/health`
- **No xref data available**: Report that the function has no outbound/inbound xrefs for tracing
- **Missing decompiled code**: Report which functions lack decompiled output along the trace
- **Partial trace failure**: If the trace succeeds for some depth levels but fails at deeper levels, report the successful portion and clearly state where the trace was truncated and why
