# Taint Analysis

## Overview

Trace attacker-controlled function inputs forward to dangerous sinks and backward to caller origins, highlighting what sensitive functions are reached, what guards must be bypassed, and how tainted data affects internal logic. Designed for vulnerability research.

The text after `/taint` specifies the **module**, **function**, and optional flags:

- `/taint appinfo.dll AiLaunchProcess` -- trace all params forward (default)
- `/taint appinfo.dll AiLaunchProcess --params 1,3` -- trace specific params
- `/taint appinfo.dll AiLaunchProcess --params 1 --depth 3` -- deeper recursion
- `/taint appinfo.dll AiLaunchProcess --direction both` -- forward + backward
- `/taint appinfo.dll AiLaunchProcess --direction backward` -- caller origins only
- `/taint appinfo.dll AiLaunchProcess --cross-module` -- trace across DLL boundaries
- `/taint appinfo.dll AiLaunchProcess --cross-module --cross-depth 3` -- deeper cross-module
- `/taint appinfo.dll AiLaunchProcess --cross-module --cross-depth 2` -- full context with trust analysis
- `/taint appinfo.dll --from-entrypoints` -- auto-discover top entry points and taint-trace each across modules
- `/taint appinfo.dll --from-entrypoints --top 10 --min-score 0.4` -- top 10 above 0.4 attack score

If no function is specified (and `--from-entrypoints` is not used), ask the user.

## IMPORTANT: Execution Model

**This is an execute-immediately command. Do NOT present anything for user confirmation.** Run and write the final taint report straight to the chat as your response. The user expects to see the completed analysis.

## Execution Context

> **IMPORTANT**: Any inline Python that imports `helpers.*` must run with `cd <workspace>/.agent`
> (so the `.agent/` directory is on `sys.path`), **not** from the workspace root.
> Script invocations like `python .agent/skills/.../script.py` can be run from the workspace root
> because those scripts manage their own path setup.

## Steps

### Step 0: Preflight Validation

Validate arguments using `helpers.command_validation.validate_command_args("taint", {"module": "<module>", "function": "<function>"})`.
If validation fails, report the errors and stop. On success, use `result.resolved["db_path"]` for subsequent script calls.

### 1. Locate the function

Use the **function-index** skill for fast lookup:

```bash
python .agent/skills/function-index/scripts/lookup_function.py <function_name> --json
```

Or find the module DB first:

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py <module_name>
```

Once located, note `function_id` and `db_path`.

### 2. Run taint analysis

```bash
# Forward (default) -- where does tainted data go?
python .agent/skills/taint-analysis/scripts/taint_function.py <db_path> --id <fid> --json

# Forward with specific params and depth
python .agent/skills/taint-analysis/scripts/taint_function.py <db_path> --id <fid> --params 1,3 --depth 3 --json

# Both directions
python .agent/skills/taint-analysis/scripts/taint_function.py <db_path> --id <fid> --direction both --json

# Backward only -- where does tainted data come from?
python .agent/skills/taint-analysis/scripts/taint_function.py <db_path> --id <fid> --direction backward --json

# Cross-module -- trace tainted data across DLL boundaries
python .agent/skills/taint-analysis/scripts/taint_function.py <db_path> --id <fid> --cross-module --json

# Cross-module with deeper recursion (2 DLL hops)
python .agent/skills/taint-analysis/scripts/taint_function.py <db_path> --id <fid> --cross-module --cross-depth 2 --json

# Dedicated cross-module orchestrator (groups findings by boundary, trust analysis, COM/RPC)
python .agent/skills/taint-analysis/scripts/trace_taint_cross_module.py <db_path> --id <fid> --cross-depth 2 --json

# Disable trust analysis or COM vtable resolution
python .agent/skills/taint-analysis/scripts/trace_taint_cross_module.py <db_path> --id <fid> --no-trust-analysis --json
python .agent/skills/taint-analysis/scripts/trace_taint_cross_module.py <db_path> --id <fid> --no-com-resolve --json

# Batch: auto-discover top entry points and taint-trace each across modules
python .agent/skills/taint-analysis/scripts/trace_taint_cross_module.py <db_path> --from-entrypoints --json
python .agent/skills/taint-analysis/scripts/trace_taint_cross_module.py <db_path> --from-entrypoints --top 10 --min-score 0.4 --json
```

### 3. Present results

Parse the JSON output and present:

**For each forward finding:**

- Sink name and category (command_execution, memory_unsafe, etc.)
- Severity score and label (CRITICAL/HIGH/MEDIUM/LOW)
- Call path from tainted parameter to the sink
- Guards on the path: type, condition text, whether attacker-controllable, bypass difficulty
- Logic effects: branch steering, array indexing, loop bounds, size arguments

**For backward callers:**

- Each caller and what they pass for the tainted parameters
- Origin classification (parameter, call_result, global, constant, etc.)
- Risk level (HIGH if origin is an export parameter, MEDIUM if call_result/global, NONE if constant)

**For cross-module findings (when --cross-module is used):**

- Boundary type (dll_import, com_vtable, rpc) and parameter mapping across each crossing
- Trust boundary transitions: source trust level -> target trust level, privilege escalation flags
- Accumulated guard chain across all modules in the path
- Return-value back-propagation: variables tainted via callee return values
- Trust-escalated findings (score boosted 1.25x when taint crosses to a higher-trust module)

**Summary line:**

- Total sinks reached, severity breakdown, number of callers, high-risk origins
- Cross-module: boundary counts, trust escalations, return-tainted variables

## Output

Present the taint report in chat. When the user asks to save, write to `extracted_code/<module_folder>/reports/taint_<function_name>_<timestamp>.md`.

**Follow-up suggestions:**

- `/audit <module> <function>` -- full security audit on flagged functions
- `/data-flow forward <module> <function> --param N` -- deeper data flow trace
- `/explain <module> <callee>` -- understand what a flagged callee does
- `/lift-class <module> <function>` -- lift flagged function to clean code for review

## Error Handling

- **Module not found**: List available modules via `find_module_db.py --list` and ask user to choose
- **Function not found**: Run a fuzzy search and suggest close matches
- **No decompiled code**: Report the gap and suggest `--assembly` traces if available
- **Subprocess timeout**: Report partial results from completed parameter traces
- **No sinks found**: Report explicitly -- "no dangerous sinks reached" is a valid (good) result
