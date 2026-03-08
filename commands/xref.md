# Cross-Reference Lookup

## Overview

Quick cross-reference lookup for a function: show who calls it (inbound xrefs) and what it calls (outbound xrefs) in a compact table format. Lightweight alternative to `/trace-export` for when you just need to see a function's immediate neighborhood.

Usage:

- `/xref appinfo.dll AiLaunchProcess` -- show callers and callees
- `/xref AiLaunchProcess` -- auto-detect module
- `/xref appinfo.dll AiLaunchProcess --depth 2` -- show 2 levels of callers/callees
- `/xref appinfo.dll --search "Check*"` -- xrefs for functions matching a pattern

## IMPORTANT: Execution Model

**This is an execute-immediately command. Do NOT present anything for user confirmation.** Run and write the cross-reference results straight to the chat as your response. The user expects to see the completed output.

## Execution Context

> **IMPORTANT**: Any inline Python that imports `helpers.*` must run with `cd <workspace>/.agent`
> (so the `.agent/` directory is on `sys.path`), **not** from the workspace root.
> Script invocations like `python .agent/skills/.../script.py` can be run from the workspace root
> because those scripts manage their own path setup.

## Steps

### Step 0: Preflight Validation

Validate arguments using `helpers.command_validation.validate_command_args("xref", {"module": "<module>", "function": "<function>"})`.
If validation fails, report the errors and stop. On success, use `result.resolved["db_path"]` for subsequent script calls.

### 1. Locate the function

> **Tip:** All skill scripts support `--json` for machine-readable output. Use `--json` when parsing script output programmatically.

Use the **function-index** skill for fast lookup:

```bash
python .agent/skills/function-index/scripts/lookup_function.py <function_name> --json
```

Or find the module DB first:

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py <module_name>
```

Once located, note `function_id` and `db_path`. Use `--id <function_id>` in all subsequent calls.

### 2. Extract cross-references

Use the **callgraph-tracer** skill to get detailed xref data:

```bash
python .agent/skills/callgraph-tracer/scripts/analyze_detailed_xrefs.py <db_path> --id <fid> --json
```

For deeper analysis (2+ levels):

```bash
python .agent/skills/callgraph-tracer/scripts/build_call_graph.py <db_path> --neighbors <function_name> --json
```

For cross-module xref resolution:

```bash
python .agent/skills/callgraph-tracer/scripts/cross_module_resolve.py <function_name> --json
```

### 3. Present results

**Inbound Cross-References (Callers):**

| # | Caller | Module | Xref Type |
|---|--------|--------|-----------|
| 1 | FunctionA | (internal) | call |
| 2 | FunctionB | kernel32.dll | import |

**Outbound Cross-References (Callees):**

| # | Callee | Module | Category |
|---|--------|--------|----------|
| 1 | CreateProcessW | kernel32.dll | command_execution |
| 2 | HeapAlloc | ntdll.dll | memory_alloc |
| 3 | InternalHelper | (internal) | -- |

For internal callees, note if they are application code or library boilerplate.
For external callees, classify using `classify_api_security()` categories when applicable.

**Summary line:**
- N inbound / M outbound xrefs
- N internal / M external callees
- Dangerous callees flagged

## Output

Present the xref table directly in chat. No file is saved for this lightweight command.

**Follow-up suggestions:**

- `/explain <module> <callee>` -- understand what a callee does
- `/trace-export <module> <function>` -- full call chain trace
- `/audit <module> <function>` -- security audit on the function
- `/data-flow forward <module> <function> --param N` -- trace parameter into callees
- `/taint <module> <function>` -- check if tainted data reaches dangerous callees

## Error Handling

- **Module not found**: List available modules via `find_module_db.py --list` and ask user to choose
- **Function not found**: Run a fuzzy search and suggest close matches
- **No xrefs found**: Report explicitly -- isolated functions with no callers or callees are a data point
- **DB access failure**: Report the error with the DB path and suggest running `/health`
