# State Machine & Dispatch Table Extraction -- Technical Reference

Detailed reference for detection algorithms, data formats, output structures, and helper module APIs.

---

## Detection Algorithms

### Switch/Case Parsing (Decompiled Code)

The scanner applies regex patterns against `decompiled_code`:

1. **`RE_SWITCH`**: Matches `switch ( expression )` -- captures the switch variable
2. **`RE_CASE`**: Matches `case 0x1A:` or `case 42:` -- captures integer values (hex/decimal/negative)
3. **`RE_DEFAULT`**: Matches `default:` -- indicates presence of fallback handler
4. **Brace-balanced extraction**: Extracts the full switch body by tracking `{}` nesting depth

After parsing:
- Case values are converted to integers
- The body is split per-case using `RE_CASE` positions
- Function calls within each case block are extracted via `RE_FUNCTION_CALL`
- The first "significant" call in each case is selected as the handler (internal named > internal sub_ > external)

### If-Else Chain Detection

Many small switches compile to if-else chains in Hex-Rays. The scanner detects:

```cpp
if ( v5 == 3 )      // branch 1
    handler_3();
else if ( v5 == 7 )  // branch 2
    handler_7();
else if ( v5 == 12 ) // branch 3
    handler_12();
// ...
```

**Algorithm**:
1. `RE_IF_EQ_CONST` extracts all `if (var == CONST)` comparisons
2. Comparisons are grouped by variable name
3. Groups with >= `min_branches` (default 4) comparisons are reported as dispatch candidates
4. Each branch's handler is resolved from function calls in the subsequent block

### Jump Table Resolution (Outbound Xrefs)

The detailed `outbound_xrefs` JSON field contains jump table metadata:

```json
{
    "function_name": "handler_case_5",
    "is_jump_table_target": true,
    "jump_table_detection_confidence": 85,
    "jump_table_detection_method": "ida_switch_info",
    "source_instruction_ea": "0x1400012A0",
    "target_ea": "0x140001300"
}
```

The scanner filters for `is_jump_table_target == true` entries. These appear when:
- IDA's switch info (`idaapi.get_switch_info()`) identifies the jump table
- Manual fallback detection finds indirect jumps with computed targets

Jump table confidence thresholds (from the extractor):
- >= 80: High confidence (IDA switch info confirmed)
- 50-80: Medium confidence (pattern-matched)
- 30-50: Low confidence (heuristic, may be false positive)

### Assembly Pattern Detection

Complements decompiled-code parsing for validation:

- **`RE_ASM_JUMP_TABLE`**: Matches `jmp qword ptr [reg+reg*8]` or `jmp off_XXXX` patterns
- **`RE_ASM_SWITCH_CMP`**: Matches `cmp reg, CONST` instructions that guard switch range checks

The `cmp` values often indicate the maximum case value (the `ja default` pattern).

---

## State Machine Reconstruction

A **state machine** is detected when a dispatch pattern (switch or if-chain) appears inside a loop. The reconstruction algorithm:

### Detection Criteria

1. Function has at least one switch or if-chain with >= 3 cases
2. `loop_analysis` reports at least one loop
3. The switch variable is assigned to new values within case blocks (state transitions)

### State Identification

- Each case value becomes a state
- State name = string literal from that case block, or `STATE_<value>`
- Handler = primary function called in that case

### Transition Detection

The scanner searches for assignments to the switch variable within case blocks:

```cpp
case 3:
    result = process_data(ctx);
    if (result < 0)
        state = 7;    // transition: 3 -> 7 (error)
    else
        state = 4;    // transition: 3 -> 4 (success)
    break;
```

`RE_STATE_ASSIGN` matches `variable = CONST;` patterns. When the assigned variable matches the switch variable and the new value differs from the current case, it's recorded as a transition.

### Initial State Detection

1. Search the function prologue (code before the first loop) for assignments to the state variable
2. If `state_var = N;` found before the loop, state N is marked initial
3. Fallback: first case value is assumed initial

### Terminal State Detection

A state is terminal when its case block:
- Contains a `return` statement
- Does NOT reassign the state variable
- This indicates the function exits the loop from that state

---

## Output Data Structures

### DispatchTable

```json
{
    "function_name": "Dispatch",
    "function_id": 42,
    "switch_variable": "v5",
    "source_type": "switch",
    "total_cases": 15,
    "has_default": true,
    "cases": [
        {
            "case_value": 0,
            "case_value_hex": "0",
            "handler_name": "HandleInit",
            "handler_id": 55,
            "is_internal": true,
            "handler_module": "internal",
            "label": "init",
            "source": "decompiled",
            "confidence": 100.0
        }
    ],
    "string_labels": { "0": "init", "5": "process" }
}
```

### StateMachine

```json
{
    "function_name": "BatLoop",
    "function_id": 42,
    "state_variable": "v5",
    "state_count": 8,
    "loop_info": {
        "complexity": 45,
        "block_count": 120,
        "instruction_count": 800,
        "has_function_calls": true,
        "is_infinite": false,
        "exit_condition_count": 3,
        "nesting_level": 0
    },
    "states": [
        {
            "state_id": 0,
            "state_name": "STATE_0",
            "handler_name": "Initialize",
            "handler_id": 55,
            "is_initial": true,
            "is_terminal": false,
            "transition_count": 2
        }
    ],
    "all_transitions": [
        {
            "from_state": 0,
            "to_state": 1,
            "action": "if ( result >= 0 )",
            "assignment": "v5 = 1"
        }
    ]
}
```

---

## Script Architecture

All scripts follow the same pattern used by other skills:

1. Resolve workspace root (4 levels up from `scripts/`)
2. Add workspace root to `sys.path`
3. Import from `helpers` package
4. Resolve DB paths relative to workspace root
5. Use `open_individual_analysis_db()` for DB access

### Directory Layout

```
.agent/skills/state-machine-extractor/
├── SKILL.md                       # Main instructions
├── reference.md                   # This file
└── scripts/
    ├── _common.py                 # Shared: regex, data structures, JSON parsing
    ├── detect_dispatchers.py      # Module-wide scan for dispatch functions
    ├── extract_dispatch_table.py  # Single-function dispatch table extraction
    ├── extract_state_machine.py   # State machine reconstruction
    └── generate_state_diagram.py  # Mermaid/DOT diagram generation
```

### Script Dependencies

```
detect_dispatchers.py    <- _common.py, helpers
extract_dispatch_table.py <- _common.py, helpers
extract_state_machine.py <- _common.py, extract_dispatch_table.py, helpers
generate_state_diagram.py <- _common.py, extract_dispatch_table.py, extract_state_machine.py, helpers
```

---

## Relevant DB Fields

### functions table -- Key Fields for Dispatch Detection

| Field | Use |
|-------|-----|
| `decompiled_code` | Parse switch/case, if-chains |
| `outbound_xrefs` (detailed) | Jump table targets with `is_jump_table_target` |
| `simple_outbound_xrefs` | Handler name/ID resolution |
| `string_literals` | Command/state name labels |
| `loop_analysis` | Detect dispatch-in-loop (state machine) |
| `assembly_code` | Validate jump table patterns |

### outbound_xrefs -- Jump Table Fields

| Field | Type | Description |
|-------|------|-------------|
| `is_jump_table_target` | bool | True if this xref is a jump table entry |
| `jump_table_detection_confidence` | int | 0-100 confidence score |
| `jump_table_detection_method` | str | `"ida_switch_info"`, `"manual_detection"`, etc. |
| `source_instruction_ea` | str | Hex address of the dispatching instruction |
| `target_ea` | str | Hex address of the jump target |

### loop_analysis -- State Machine Loop Fields

| Field | Type | Description |
|-------|------|-------------|
| `complexity` | int | McCabe cyclomatic complexity |
| `block_count` | int | Number of basic blocks in the loop |
| `instruction_count` | int | Total instructions in the loop |
| `has_function_calls` | bool | True if loop calls functions (dispatch target indicator) |
| `is_infinite` | bool | True for `while(1)` / `for(;;)` patterns |
| `exit_condition_count` | int | Number of loop exit conditions |
| `nesting_level` | int | Loop nesting depth |

---

## Common Dispatch Patterns in Windows Binaries

### Command-line Dispatch (cmd.exe pattern)

```cpp
while (1) {
    cmd_type = get_next_command(ctx);
    switch (cmd_type) {
        case CMD_IF:     result = eIf(ctx); break;
        case CMD_FOR:    result = eFor(ctx); break;
        case CMD_GOTO:   result = eGoto(ctx); break;
        // ...
    }
}
```
Characteristics: loop + switch, state variable assigned from a function return value, each case calls one handler.

### Message Dispatcher (WndProc pattern)

```cpp
switch (uMsg) {
    case WM_CREATE:   return OnCreate(hWnd, wParam, lParam);
    case WM_DESTROY:  return OnDestroy(hWnd);
    case WM_PAINT:    return OnPaint(hWnd);
    default:          return DefWindowProc(hWnd, uMsg, wParam, lParam);
}
```
Characteristics: single switch (no loop), message IDs as cases, handler-per-case, default handler.

### Protocol State Machine

```cpp
state = INITIAL;
while (state != DONE) {
    switch (state) {
        case INITIAL:
            if (handshake_ok()) state = AUTHENTICATED;
            else state = ERROR;
            break;
        case AUTHENTICATED:
            process_request();
            state = DONE;
            break;
        case ERROR:
            log_error();
            state = DONE;
            break;
    }
}
```
Characteristics: loop + switch, state variable directly assigned within cases, clear initial/terminal states.

### If-Chain Dispatch (small switch Hex-Rays output)

```cpp
if ( v5 == 1 )
    handler_1(ctx);
else if ( v5 == 2 )
    handler_2(ctx);
else if ( v5 == 3 )
    handler_3(ctx);
```
Characteristics: Hex-Rays sometimes decompiles small switches as if-chains, especially with non-contiguous case values.

---

## Helper Module API Reference

### IndividualAnalysisDB (per-module)

```python
from helpers import open_individual_analysis_db

with open_individual_analysis_db("extracted_dbs/module.db") as db:
    db.get_function_by_id(42)                   # FunctionRecord by ID
    db.get_function_by_name("Dispatch")         # list[FunctionRecord]
    db.search_functions(name_contains="Handle") # partial search
    db.get_all_functions()                      # all FunctionRecords
    db.get_function_names()                     # list of names
    db.execute_query("SELECT ...")              # custom SQL
```

### FunctionRecord -- Key Parsed Properties

| Property | Returns | Use |
|----------|---------|-----|
| `parsed_simple_outbound_xrefs` | list[dict] | Handler function resolution |
| `parsed_outbound_xrefs` | list[dict] | Jump table target detection |
| `parsed_string_literals` | list[str] | Case/state labeling |
| `parsed_loop_analysis` | dict | State machine detection |

---

## Diagram Format Reference

### Mermaid Dispatch Diagram

Generated with `graph LR` (left-to-right flowchart):
- Blue diamond: dispatcher function
- Green boxes: internal handlers (same module)
- Yellow rounded boxes: external handlers (imports/APIs)
- Red octagon: default handler

### Mermaid State Diagram

Generated with `stateDiagram-v2`:
- `[*] -->` marks initial state
- `--> [*]` marks terminal states
- Transition labels show triggering conditions
- `direction LR` for left-to-right layout

### DOT Format

Standard `digraph` with `rankdir=LR`. Render with:
```bash
dot -Tpng output.dot -o output.png
dot -Tsvg output.dot -o output.svg
```

---

## Limitations

1. **Indirect dispatch**: Function pointer tables (`void (*handlers[])(ctx)`) are not directly parsed from decompiled code. Use `outbound_xrefs` with `is_indirect_call` for these.
2. **Computed state transitions**: When the next state is computed (e.g., `state = lookup_table[input]`), individual transitions cannot be extracted from static analysis alone.
3. **Nested switches**: Only the outermost switch per variable is reconstructed as a dispatch table. Nested switches (different variables) produce separate tables.
4. **Optimized switches**: Compiler-optimized binary search trees for large switches may not be fully reconstructed from decompiled code; assembly + jump table data helps.
