---
name: state-machine-extractor
description: Extract state machines, dispatch tables, and switch/case command dispatchers from IDA Pro decompiled binaries. Use when the user asks to find dispatch tables, extract switch/case mappings, reconstruct state machines, identify command handlers, map case values to handler functions, generate state diagrams, or analyze command dispatchers in decompiled Windows PE binaries.
---

# State Machine & Dispatch Table Extraction

## Purpose

Detect and reconstruct command dispatchers, switch/case dispatch tables, and state machines from DeepExtractIDA analysis databases. Scans decompiled code for switch statements and if-else chains, correlates with jump table targets from outbound xrefs, and uses loop analysis to identify state machine patterns. Produces structured dispatch tables (case value -> handler function) and state transition models with Mermaid/DOT diagram output.

## Data Sources

### SQLite Databases (primary)

Individual analysis DBs in `extracted_dbs/` contain per-function data:

- `decompiled_code` -- parse switch/case statements and if-else dispatch chains
- `outbound_xrefs` (detailed) -- jump table targets with `is_jump_table_target`, confidence, detection method
- `simple_outbound_xrefs` -- handler resolution (internal vs. external, function IDs)
- `loop_analysis` -- loops containing dispatch logic indicate state machines
- `string_literals` -- command/state names associated with case values
- `assembly_code` -- jump table patterns (indirect jumps, cmp+ja guard sequences)

### Finding a Module DB

Reuse the decompiled-code-extractor skill's `find_module_db.py`:

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py --list
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py cmd.exe
```

### Quick Cross-Dimensional Search

To search across function names, signatures, strings, APIs, classes, and exports in one call:

```bash
python .agent/helpers/unified_search.py <db_path> --query "SearchTerm"
python .agent/helpers/unified_search.py <db_path> --query "SearchTerm" --json
```

## Utility Scripts

All scripts are in `scripts/`. Auto-resolve workspace root and `.agent/helpers/` imports. Run from workspace root.

### detect_dispatchers.py -- Scan Module for Dispatch Functions (Start Here)

Find all functions containing dispatch tables, switch/case, or state machine patterns.

```bash
# Scan entire module (default min 3 cases)
python .agent/skills/state-machine-extractor/scripts/detect_dispatchers.py <db_path>

# Require at least 5 cases
python .agent/skills/state-machine-extractor/scripts/detect_dispatchers.py <db_path> --min-cases 5

# Only show state machine candidates (dispatch inside loops)
python .agent/skills/state-machine-extractor/scripts/detect_dispatchers.py <db_path> --with-loops

# JSON output
python .agent/skills/state-machine-extractor/scripts/detect_dispatchers.py <db_path> --json
```

Use `--app-only` filtering (via function_index) to skip WIL/STL/CRT switch statements that are noise in module-wide dispatcher scans.

Output classifies each candidate as:

- **loop_switch**: Switch inside a loop (state machine candidate)
- **loop_if_chain**: If-chain inside a loop (state machine candidate)
- **switch**: Simple switch/case dispatch
- **if_chain**: If-else chain comparing same variable against constants
- **jump_table**: Jump table targets detected in xrefs

### extract_dispatch_table.py -- Extract Case->Handler Mapping

Extract the full dispatch table from a specific function.

```bash
# By function name
python .agent/skills/state-machine-extractor/scripts/extract_dispatch_table.py <db_path> <function_name>

# By function ID
python .agent/skills/state-machine-extractor/scripts/extract_dispatch_table.py <db_path> --id <function_id>

# Search for functions
python .agent/skills/state-machine-extractor/scripts/extract_dispatch_table.py <db_path> --search "Dispatch"

# JSON output
python .agent/skills/state-machine-extractor/scripts/extract_dispatch_table.py <db_path> <function_name> --json
```

Output includes:

- Case value (decimal and hex)
- Handler function name and ID
- Whether handler is internal (same module) or external
- String label if found near the case
- Source (decompiled switch, if-chain, or jump table)
- Confidence score

### extract_state_machine.py -- Reconstruct State Machine

Build a state machine model from functions with dispatch-in-loop patterns.

```bash
# Reconstruct state machine
python .agent/skills/state-machine-extractor/scripts/extract_state_machine.py <db_path> <function_name>

# By function ID
python .agent/skills/state-machine-extractor/scripts/extract_state_machine.py <db_path> --id <function_id>

# Include decompiled code in output
python .agent/skills/state-machine-extractor/scripts/extract_state_machine.py <db_path> <function_name> --with-code

# JSON output
python .agent/skills/state-machine-extractor/scripts/extract_state_machine.py <db_path> <function_name> --json
```

Output includes:

- State variable name
- All states with IDs, names, handler functions
- Initial and terminal state identification
- State transitions (from -> to) with triggering conditions
- Loop characteristics (complexity, block count, exit conditions)

### generate_state_diagram.py -- Mermaid/DOT Diagrams

Generate visual diagrams for dispatch tables or state machines.

```bash
# Auto-detect mode (state machine if loops present, dispatch otherwise)
python .agent/skills/state-machine-extractor/scripts/generate_state_diagram.py <db_path> --function <name>

# Force dispatch table diagram
python .agent/skills/state-machine-extractor/scripts/generate_state_diagram.py <db_path> --function <name> --mode dispatch

# Force state machine diagram
python .agent/skills/state-machine-extractor/scripts/generate_state_diagram.py <db_path> --function <name> --mode state-machine

# DOT format (for Graphviz rendering)
python .agent/skills/state-machine-extractor/scripts/generate_state_diagram.py <db_path> --function <name> --format dot

# By function ID
python .agent/skills/state-machine-extractor/scripts/generate_state_diagram.py <db_path> --id <function_id>
```

Paste Mermaid output into GitHub, Mermaid Live Editor, or VS Code Mermaid extension.

## Workflows

### Workflow 1: "Find all dispatchers in a module"

```
Progress:
- [ ] Step 1: Find the module DB
- [ ] Step 2: Scan for dispatch functions
- [ ] Step 3: Extract dispatch tables for interesting candidates
- [ ] Step 4: Generate diagrams
```

**Step 1**: Find the module

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py cmd.exe
```

**Step 2**: Scan for dispatchers

```bash
python .agent/skills/state-machine-extractor/scripts/detect_dispatchers.py <db_path>
```

**Step 3**: Extract the dispatch table for the most interesting candidate

```bash
python .agent/skills/state-machine-extractor/scripts/extract_dispatch_table.py <db_path> <function_name>
```

**Step 4**: Generate a diagram

```bash
python .agent/skills/state-machine-extractor/scripts/generate_state_diagram.py <db_path> --function <function_name>
```

### Workflow 2: "Reconstruct a state machine"

```
Progress:
- [ ] Step 1: Find the module DB
- [ ] Step 2: Scan for state machine candidates (dispatch inside loops)
- [ ] Step 3: Reconstruct the state machine
- [ ] Step 4: Generate state diagram
- [ ] Step 5: Cross-reference handlers with call graph
```

**Step 1**: Find the module

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py <module>
```

**Step 2**: Find state machine candidates

```bash
python .agent/skills/state-machine-extractor/scripts/detect_dispatchers.py <db_path> --with-loops
```

**Step 3**: Reconstruct the state machine

```bash
python .agent/skills/state-machine-extractor/scripts/extract_state_machine.py <db_path> <function_name>
```

**Step 4**: Generate diagram

```bash
python .agent/skills/state-machine-extractor/scripts/generate_state_diagram.py <db_path> --function <function_name> --mode state-machine
```

**Step 5**: Trace handler implementations using the call graph tracer

```bash
python .agent/skills/callgraph-tracer/scripts/chain_analysis.py <db_path> <handler_name>
```

### Workflow 3: "Map command IDs to handlers"

For command-line tools, protocol handlers, or message dispatchers:

**Step 1**: Scan for the dispatch function

```bash
python .agent/skills/state-machine-extractor/scripts/detect_dispatchers.py <db_path> --min-cases 5
```

**Step 2**: Extract the command ID -> handler table

```bash
python .agent/skills/state-machine-extractor/scripts/extract_dispatch_table.py <db_path> <dispatch_func> --json
```

**Step 3**: For each handler, get its implementation

```bash
python .agent/skills/decompiled-code-extractor/scripts/extract_function_data.py <db_path> <handler_name>
```

## Detection Strategies

The skill combines three detection approaches:

### 1. Decompiled Code Parsing

- **Switch/case**: Regex extraction of `switch(var) { case N: ... }` blocks
- **If-else chains**: Detect sequences of `if (var == CONST)` comparing the same variable against 4+ constants (common Hex-Rays output for small switches)
- **Handler extraction**: Parse function calls within each case block to identify the handler

### 2. Jump Table Resolution from Xrefs

- Filter `outbound_xrefs` entries with `is_jump_table_target: true`
- Use `jump_table_detection_confidence` and `jump_table_detection_method` for quality
- Correlates with assembly indirect jump patterns

### 3. State Machine Reconstruction

- Identify loops (from `loop_analysis`) containing dispatch logic
- Track assignments to the switch variable within case blocks as state transitions
- Mark states as initial (assigned before the loop) or terminal (return without transition)
- Use `string_literals` to name states and commands

## Direct Helper Module Access

For custom queries not covered by scripts:

```python
from helpers import open_individual_analysis_db

with open_individual_analysis_db("extracted_dbs/module.db") as db:
    # Find functions with large switch statements
    funcs = db.get_all_functions()
    for f in funcs:
        if f.decompiled_code and "switch" in f.decompiled_code:
            print(f.function_name)
```

See [reference.md](reference.md) for technical details on detection algorithms, data formats, and output structures.

## Integration with Other Skills

| Task | Recommended Skill |
|------|-------------------|
| Trace call chains from dispatch handlers | callgraph-tracer |
| Classify dispatch handler functions by purpose | classify-functions |
| Build security dossier for command handlers | security-dossier |
| Trace data flow through state transitions | data-flow-tracer |
| Lift dispatch handler functions to clean code | code-lifting / batch-lift |

## Performance

| Operation | Typical Time | Notes |
|-----------|-------------|-------|
| Detect dispatchers | ~5-10s | Full module switch/case scan |
| Extract dispatch table | ~2-5s | Single function analysis |
| Extract state machine | ~3-5s | Single function with state tracking |
| Generate state diagram | ~1-2s | Mermaid/DOT rendering |

## Additional Resources

- For DB schema and JSON field formats, see [data_format_reference.md](../../docs/data_format_reference.md)
- For file_info.json schema, see [file_info_format_reference.md](../../docs/file_info_format_reference.md)
- For code analysis, see [analyze-ida-decompiled](../analyze-ida-decompiled/SKILL.md)
- For call graph tracing (follow handlers across modules), see [callgraph-tracer](../callgraph-tracer/SKILL.md)
- For code lifting (clean up handler implementations), see [code-lifting](../code-lifting/SKILL.md)
