---
name: data-flow-tracer
description: Trace how data moves through decompiled binaries -- forward parameter flow, backward argument origin, global variable producer/consumer maps, and string literal usage chains. Use when the user asks to trace a parameter, find where an argument comes from, map global variable readers/writers, trace string usage, understand data flow between functions, or asks what happens to a specific value in a function.
---

# Data Flow & Taint Tracing

## Purpose

Trace how specific data moves through extracted Windows PE binaries. Follows parameter values forward through outbound calls, traces API call arguments backward to their origin, maps global variable producers/consumers, and tracks string literal usage chains. Uses `simple_outbound_xrefs`, `simple_inbound_xrefs`, `global_var_accesses`, `string_literals`, decompiled code parsing, and assembly as ground truth.

**This is about understanding data relationships, not security.** Do not add vulnerability annotations or security assessments.

## Data Sources

- **Individual analysis DBs** (`extracted_dbs/{module}_{hash}.db`): Per-function decompiled code, assembly, xrefs, globals, strings
- **Tracking DB** (`extracted_dbs/analyzed_files.db`): Maps module names to their analysis DB paths
- **Decompiled code**: Parsed for function calls, argument expressions, variable assignments
- **Assembly code**: Ground truth for register propagation and memory access verification

For data format details, see [data_format_reference.md](../../docs/data_format_reference.md).

### Finding a Module DB

Reuse the decompiled-code-extractor skill's `find_module_db.py`:

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py --list
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py appinfo.dll
```

### Quick Cross-Dimensional Search

To search across function names, signatures, strings, APIs, classes, and exports in one call:

```bash
python .agent/helpers/unified_search.py <db_path> --query "SearchTerm"
python .agent/helpers/unified_search.py <db_path> --query "SearchTerm" --json
```

## Utility Scripts

All scripts are in the `scripts/` subdirectory. Auto-resolve workspace root and `.agent/helpers/` imports. Run from the workspace root.

### forward_trace.py -- Parameter Forward Trace (Start Here)

Track where a function parameter flows: which calls receive it, which globals it's written to, whether it's returned.

```bash
# Where does parameter 1 of AiLaunchProcess go?
python .agent/skills/data-flow-tracer/scripts/forward_trace.py <db_path> <function> --param 1

# Recursive: follow into callees up to depth 2
python .agent/skills/data-flow-tracer/scripts/forward_trace.py <db_path> <function> --param 2 --depth 2

# Include assembly register tracking
python .agent/skills/data-flow-tracer/scripts/forward_trace.py <db_path> <function> --param 1 --assembly

# By function ID
python .agent/skills/data-flow-tracer/scripts/forward_trace.py <db_path> --id 42 --param 1
```

Output includes:

- All decompiled code lines referencing the parameter
- Function calls receiving the parameter (with argument position and xref classification)
- Global variable writes involving the parameter
- Whether the parameter is returned
- Assembly register aliases (with `--assembly`)
- Recursive callee follow (with `--depth > 1`)

### backward_trace.py -- Argument Origin Trace

Find where a target API call's arguments originate: from a parameter, another call's return value, a global, or a constant.

```bash
# Where do CreateFileW's arguments come from in this function?
python .agent/skills/data-flow-tracer/scripts/backward_trace.py <db_path> <function> --target CreateFileW

# Trace just argument 1, then show what each caller passes
python .agent/skills/data-flow-tracer/scripts/backward_trace.py <db_path> <function> --target CreateProcessW --arg 1 --callers

# Deep caller trace
python .agent/skills/data-flow-tracer/scripts/backward_trace.py <db_path> <function> --target CreateProcessW --arg 2 --callers --depth 2
```

Output includes:

- The API call line in decompiled code
- Each argument classified (parameter, call_result, constant, global, local_variable, expression)
- Variable assignment chain tracing for local variables
- Caller context when `--callers` is used (what each caller passes at the traced parameter position)

### global_state_map.py -- Global Variable Producer/Consumer Map

Build a map of which functions read and write each global variable.

```bash
# Full producer/consumer map
python .agent/skills/data-flow-tracer/scripts/global_state_map.py <db_path>

# Focus on a specific global
python .agent/skills/data-flow-tracer/scripts/global_state_map.py <db_path> --global dword_18005C380

# Summary: counts and top shared variables
python .agent/skills/data-flow-tracer/scripts/global_state_map.py <db_path> --summary

# Only globals with both readers and writers
python .agent/skills/data-flow-tracer/scripts/global_state_map.py <db_path> --shared-only

# Only globals that are written
python .agent/skills/data-flow-tracer/scripts/global_state_map.py <db_path> --writers-only

# JSON output
python .agent/skills/data-flow-tracer/scripts/global_state_map.py <db_path> --json
```

### string_trace.py -- String Origin Tracking

Trace how string literals flow through the binary: which functions reference them, the decompiled code context, and caller chains.

```bash
# Find all functions referencing a string
python .agent/skills/data-flow-tracer/scripts/string_trace.py <db_path> --string "CreateProcess"

# Include caller chain for each referencing function
python .agent/skills/data-flow-tracer/scripts/string_trace.py <db_path> --string "COMSPEC" --callers --depth 2

# Show all strings used by a specific function
python .agent/skills/data-flow-tracer/scripts/string_trace.py <db_path> --function eComSrv --callers

# Show all strings used by a function (by ID)
python .agent/skills/data-flow-tracer/scripts/string_trace.py <db_path> --id <function_id>

# List all unique strings in the module
python .agent/skills/data-flow-tracer/scripts/string_trace.py <db_path> --list-strings --limit 50

# Include assembly context for string references
python .agent/skills/data-flow-tracer/scripts/string_trace.py <db_path> --string "PATH" --assembly
```

## Workflows

### Workflow 1: "What happens to parameter 2 of function X?"

Forward trace a parameter through the function and its callees.

```
Forward Trace Progress:
- [ ] Step 1: Find the module DB
- [ ] Step 2: Run forward_trace.py with --param N
- [ ] Step 3: Review which calls receive the parameter
- [ ] Step 4: Follow interesting callees with --depth 2
- [ ] Step 5: Check assembly register propagation if needed
```

**Step 1**: Find the module DB

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py appinfo.dll
```

**Step 2**: Run the forward trace

```bash
python .agent/skills/data-flow-tracer/scripts/forward_trace.py <db_path> <function> --param 2
```

**Step 3**: Review the output -- it shows:

- Every line where the parameter appears
- Which function calls receive it (with the argument position in the callee)
- Whether it's stored to a global variable
- Whether it's returned

**Step 4**: For interesting callees, re-run with `--depth 2` to follow the parameter into those functions:

```bash
python .agent/skills/data-flow-tracer/scripts/forward_trace.py <db_path> <function> --param 2 --depth 2
```

**Step 5**: If decompiled code is ambiguous, add `--assembly` to see register-level tracking.

### Workflow 2: "Where does the 3rd argument to CreateFileW come from?"

Backward trace an API call's argument to its origin.

```
Backward Trace Progress:
- [ ] Step 1: Find the module DB containing the function
- [ ] Step 2: Run backward_trace.py with --target and --arg
- [ ] Step 3: Review the origin classification
- [ ] Step 4: If origin is a parameter, trace callers with --callers
- [ ] Step 5: Optionally recurse with --depth
```

**Step 1**: Find the DB

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py appinfo.dll
```

**Step 2**: Trace the argument origin

```bash
python .agent/skills/data-flow-tracer/scripts/backward_trace.py <db_path> <function> --target CreateFileW --arg 3
```

**Step 3**: The output classifies the argument as one of:

- **parameter**: comes directly from the function's own parameter (e.g., `a1`)
- **call_result**: comes from another function's return value
- **constant**: hardcoded value
- **global**: from a global variable
- **local_variable**: from a local -- the tracer follows assignment chains automatically

**Step 4**: If the origin is a parameter, use `--callers` to see what each caller passes:

```bash
python .agent/skills/data-flow-tracer/scripts/backward_trace.py <db_path> <function> --target CreateFileW --arg 3 --callers
```

**Step 5**: For deeper chains (caller's caller), add `--depth 2`.

### Workflow 3: "Which functions read/write this global variable?"

Map the producers and consumers of global state.

```
Global State Map Progress:
- [ ] Step 1: Find the module DB
- [ ] Step 2: Run global_state_map.py
- [ ] Step 3: Focus on specific globals of interest
```

**Step 1**: Find the DB

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py cmd.exe
```

**Step 2**: Get the summary first, then drill down

```bash
# Overview
python .agent/skills/data-flow-tracer/scripts/global_state_map.py <db_path> --summary

# Shared globals (read + written = shared state)
python .agent/skills/data-flow-tracer/scripts/global_state_map.py <db_path> --shared-only
```

**Step 3**: Focus on a specific global

```bash
python .agent/skills/data-flow-tracer/scripts/global_state_map.py <db_path> --global dword_18005C380
```

### Workflow 4: "Where is this string used and who provides the context?"

Trace string literal usage through the call chain.

```
String Trace Progress:
- [ ] Step 1: Find the module DB
- [ ] Step 2: Search for the string
- [ ] Step 3: Review code context and callers
```

**Step 1**: Find the DB

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py cmd.exe
```

**Step 2**: Search for the string

```bash
python .agent/skills/data-flow-tracer/scripts/string_trace.py <db_path> --string "COMSPEC"
```

**Step 3**: Add callers to understand the execution paths

```bash
python .agent/skills/data-flow-tracer/scripts/string_trace.py <db_path> --string "COMSPEC" --callers --depth 2
```

To see all strings a function uses:

```bash
python .agent/skills/data-flow-tracer/scripts/string_trace.py <db_path> --function eComSrv
```

## Direct Helper Module Access

For custom data-flow queries not covered by scripts:

```python
from helpers import open_individual_analysis_db, open_analyzed_files_db

with open_individual_analysis_db("extracted_dbs/module.db") as db:
    func = db.get_function_by_name("FunctionName")[0]

    # Global accesses
    globals_list = func.parsed_global_var_accesses  # list of {address, name, access_type}

    # String literals
    strings = func.parsed_string_literals  # list of strings

    # Outbound xrefs (callees)
    callees = func.parsed_simple_outbound_xrefs

    # Inbound xrefs (callers)
    callers = func.parsed_simple_inbound_xrefs
```

**Library filtering**: Use `from helpers import get_library_tag_for_function, load_function_index_for_db` to check if a callee is library boilerplate during trace analysis. Library-tagged callees (WIL/STL/WRL) can be deprioritized in trace output.

See [reference.md](reference.md) for full API details and field formats.

## Integration with Other Skills

| Task | Recommended Skill |
|------|-------------------|
| Trace call chains to follow data across functions | callgraph-tracer |
| Classify functions that produce or consume data | classify-functions |
| Build security dossier for functions handling sensitive data | security-dossier |
| Reconstruct struct types for traced data structures | reconstruct-types |
| Lift functions involved in critical data paths | code-lifting / batch-lift |

## Performance

| Operation | Typical Time | Notes |
|-----------|-------------|-------|
| Forward/backward trace | ~2-5s | Single function, depends on call depth |
| Global state map | ~10-30s | Full module scan of all global accesses |
| String trace | ~1-3s | Single string or function |

## Additional Resources

- For DB schema and JSON field formats, see [data_format_reference.md](../../docs/data_format_reference.md)
- For call graph tracing across modules, see [callgraph-tracer](../callgraph-tracer/SKILL.md)
- For code lifting with struct reconstruction, see [code-lifting](../code-lifting/SKILL.md)
- For type reconstruction from memory access patterns, see [reconstruct-types](../reconstruct-types/SKILL.md)
- For code analysis and navigation, see [analyze-ida-decompiled](../analyze-ida-decompiled/SKILL.md)
