# Call Graph

## Overview

Build, query, and visualize call graphs for a module or function. Shows topology statistics, strongly connected components, hub functions, root/leaf nodes, and generates Mermaid diagrams.

Usage:

- `/callgraph appinfo.dll` -- module-wide stats (node/edge counts, hubs, connectivity)
- `/callgraph appinfo.dll --scc` -- strongly connected components (recursive call clusters)
- `/callgraph appinfo.dll --roots` -- functions with no callers (entry points by graph structure)
- `/callgraph appinfo.dll --leaves` -- functions that call nothing (leaf/utility functions)
- `/callgraph appinfo.dll AiLaunchProcess` -- neighborhood graph for a specific function
- `/callgraph appinfo.dll AiLaunchProcess --diagram` -- Mermaid diagram of the function's call neighborhood
- `/callgraph appinfo.dll --path FuncA FuncB` -- find call path between two functions
- `/callgraph appinfo.dll --reachable FuncA` -- all functions reachable from FuncA

## IMPORTANT: Execution Model

**This is an execute-immediately command. Do NOT present anything for user confirmation.** Run and write the call graph analysis straight to the chat as your response. The user expects to see the completed output.

## Execution Context

> **IMPORTANT**: Any inline Python that imports `helpers.*` must run with `cd <workspace>/.agent`
> (so the `.agent/` directory is on `sys.path`), **not** from the workspace root.
> Script invocations like `python .agent/skills/.../script.py` can be run from the workspace root
> because those scripts manage their own path setup.

## Steps

### Step 0: Preflight Validation

Validate arguments using `helpers.command_validation.validate_command_args("callgraph", {"module": "<module>"})`.
If validation fails, report the errors and stop. On success, use `result.resolved["db_path"]` for subsequent script calls.

### 1. Find the module DB

Use the **decompiled-code-extractor** skill (`find_module_db.py`) to resolve the module name to its DB path.

> **Tip:** All skill scripts support `--json` for machine-readable output. Use `--json` when parsing script output programmatically.

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py <module_name> --json
```

### 2. Build or query the call graph

**Module-wide statistics** (default when no function is specified):

```bash
python .agent/skills/callgraph-tracer/scripts/build_call_graph.py <db_path> --stats --json
```

**Strongly connected components** (`--scc`):

```bash
python .agent/skills/callgraph-tracer/scripts/build_call_graph.py <db_path> --scc --json
```

**Root nodes** (`--roots`) -- functions with no callers:

```bash
python .agent/skills/callgraph-tracer/scripts/build_call_graph.py <db_path> --roots --json
```

**Leaf nodes** (`--leaves`) -- functions that call nothing:

```bash
python .agent/skills/callgraph-tracer/scripts/build_call_graph.py <db_path> --leaves --json
```

**Function neighborhood** (specific function):

```bash
python .agent/skills/callgraph-tracer/scripts/build_call_graph.py <db_path> --neighbors <function_name> --json
```

**Path between two functions** (`--path`):

```bash
python .agent/skills/callgraph-tracer/scripts/build_call_graph.py <db_path> --path <funcA> <funcB> --json
```

**Reachable functions** (`--reachable`):

```bash
python .agent/skills/callgraph-tracer/scripts/build_call_graph.py <db_path> --reachable <function_name> --json
```

### 3. Generate diagram (if requested or for function neighborhoods)

Use the **callgraph-tracer** skill (`generate_diagram.py`) to produce a Mermaid diagram:

```bash
python .agent/skills/callgraph-tracer/scripts/generate_diagram.py <db_path> --function <function_name>
python .agent/skills/callgraph-tracer/scripts/generate_diagram.py <db_path> --path <funcA> <funcB> --format mermaid
```

### 4. Present results

**For module-wide stats**, present:
- **Graph Overview**: total nodes, total edges, density
- **Hub Functions**: top functions by caller+callee count (highest connectivity)
- **Strongly Connected Components** (if `--scc`): component count, largest SCC members
- **Root/Leaf Summary** (if `--roots` or `--leaves`): listed with classification when available

**For function neighborhood**, present:
- **Direct Callers**: who calls this function
- **Direct Callees**: what this function calls
- **Mermaid Diagram** (if `--diagram`): visual call neighborhood

**For path queries**, present:
- **Call Path**: ordered list of functions from source to destination
- **Mermaid Diagram**: path visualization

## Output

Present the analysis in chat. Include Mermaid diagrams inline when requested. This is a lightweight retrieval command; no workspace protocol is needed.

**Follow-up suggestions:**

- `/xref <module> <function>` -- detailed cross-references for a specific function
- `/audit <module> <export> --diagram` -- full security audit with call graph from an export
- `/explain <module> <function>` -- understand what a hub function does
- `/taint <module> <function>` -- check if tainted data flows through a hub

## Error Handling

- **Module not found**: List available modules via `find_module_db.py --list` and ask user to choose
- **Function not found**: Run a fuzzy search and suggest close matches
- **No path found**: Report that no call path exists between the two functions
- **DB access failure**: Report the error with the DB path and suggest running `/health`
