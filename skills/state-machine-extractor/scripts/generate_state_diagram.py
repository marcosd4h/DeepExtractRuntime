#!/usr/bin/env python3
"""Generate Mermaid or DOT state diagrams from dispatch tables and state machines.

Usage:
    python generate_state_diagram.py <db_path> --function <name>
    python generate_state_diagram.py <db_path> --function <name> --format dot
    python generate_state_diagram.py <db_path> --function <name> --mode dispatch
    python generate_state_diagram.py <db_path> --function <name> --mode state-machine
    python generate_state_diagram.py <db_path> --id <function_id>

Examples:
    python .agent/skills/state-machine-extractor/scripts/generate_state_diagram.py extracted_dbs/cmd_exe_6d109a3a00.db --function Dispatch
    python .agent/skills/state-machine-extractor/scripts/generate_state_diagram.py extracted_dbs/cmd_exe_6d109a3a00.db --function BatLoop --mode state-machine
    python .agent/skills/state-machine-extractor/scripts/generate_state_diagram.py extracted_dbs/cmd_exe_6d109a3a00.db --id 42 --format dot

Output:
    Mermaid or DOT diagram source code. Paste Mermaid output into any
    compatible renderer (GitHub, Mermaid Live Editor, VS Code extension).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

from _common import (
    WORKSPACE_ROOT,
    emit_error,
    format_int,
    resolve_db_path,
)

from extract_dispatch_table import build_dispatch_table
from extract_state_machine import reconstruct_state_machine

from helpers import (
    FunctionRecord,
    load_function_index_for_db,
    open_individual_analysis_db,
    resolve_function,
)
from helpers.errors import ErrorCode, db_error_handler, safe_parse_args
from helpers.json_output import emit_json


def generate_dispatch_mermaid(func: FunctionRecord, db) -> str:
    """Generate a Mermaid flowchart for a dispatch table."""
    tables = build_dispatch_table(func, db)
    if not tables:
        return f"graph LR\n    note[No dispatch table found in {func.function_name}]"

    func_name = _sanitize_mermaid_id(func.function_name or f"sub_{func.function_id}")
    lines = ["graph LR"]

    for ti, table in enumerate(tables):
        prefix = f"T{ti}_" if len(tables) > 1 else ""
        switch_label = table.switch_variable or "dispatch"

        # Dispatcher node
        disp_id = f"{prefix}DISP"
        disp_label = f"{func_name}\\nswitch({switch_label})"
        lines.append(f'    {disp_id}["{disp_label}"]')

        # Case nodes
        for case in table.cases:
            case_id = f"{prefix}C{_safe_id(case.case_value)}"
            handler = case.handler_name or "(inline)"
            label_text = case.label or ""
            if label_text:
                label_text = f"\\n{_escape_mermaid(label_text[:40])}"

            node_label = f"{_escape_mermaid(handler)}{label_text}"
            edge_label = f"|case {format_int(case.case_value)}|"

            # Color based on type
            if case.is_internal:
                lines.append(f'    {case_id}["{node_label}"]')
                lines.append(f"    style {case_id} fill:#d4edda,stroke:#28a745")
            else:
                lines.append(f'    {case_id}(["{node_label}"])')
                lines.append(f"    style {case_id} fill:#fff3cd,stroke:#ffc107")

            lines.append(f"    {disp_id} --{edge_label}--> {case_id}")

        # Default case
        if table.has_default:
            def_id = f"{prefix}DEF"
            def_handler = table.default_handler or "(default)"
            lines.append(f'    {def_id}{{{{"{_escape_mermaid(def_handler)}"}}}}')
            lines.append(f"    {disp_id} --|default|--> {def_id}")
            lines.append(f"    style {def_id} fill:#f8d7da,stroke:#dc3545")

        lines.append(f"    style {disp_id} fill:#cce5ff,stroke:#004085")

    return "\n".join(lines)


def generate_state_machine_mermaid(func: FunctionRecord, db) -> str:
    """Generate a Mermaid stateDiagram for a reconstructed state machine."""
    sm = reconstruct_state_machine(func, db)
    if sm is None:
        # Fall back to dispatch diagram
        return generate_dispatch_mermaid(func, db)

    lines = ["stateDiagram-v2"]

    # Direction
    lines.append("    direction LR")

    # States
    for state in sm.states:
        sid = _state_id(state.state_id)
        name = _escape_mermaid(state.state_name)
        handler_info = ""
        if state.handler_name:
            handler_info = f" : {_escape_mermaid(state.handler_name)}"

        if state.is_initial:
            lines.append(f"    [*] --> {sid}")

        lines.append(f"    {sid} : {name}{handler_info}")

        if state.is_terminal:
            lines.append(f"    {sid} --> [*]")

    # Transitions
    for state in sm.states:
        for t in state.transitions:
            from_id = _state_id(t["from_state"])
            to_id = _state_id(t["to_state"])
            action = t.get("action") or t.get("assignment", "")
            if action:
                action = _escape_mermaid(action[:60])
                lines.append(f"    {from_id} --> {to_id} : {action}")
            else:
                lines.append(f"    {from_id} --> {to_id}")

    # If no transitions found, add self-loops as hints
    if not any(state.transitions for state in sm.states):
        lines.append("")
        lines.append("    note right of [*]")
        lines.append("        No explicit transitions detected.")
        lines.append("        State variable may be modified")
        lines.append("        through function calls.")
        lines.append("    end note")

    return "\n".join(lines)


def generate_dispatch_dot(func: FunctionRecord, db) -> str:
    """Generate a DOT digraph for a dispatch table."""
    tables = build_dispatch_table(func, db)
    if not tables:
        return f'digraph dispatch {{ label="No dispatch table found" }}'

    func_name = func.function_name or f"sub_{func.function_id}"
    lines = [
        f'digraph dispatch {{',
        f'    rankdir=LR;',
        f'    label="{_escape_dot(func_name)} dispatch table";',
        f'    node [shape=box, style=filled, fontname="Consolas"];',
    ]

    for ti, table in enumerate(tables):
        prefix = f"T{ti}_" if len(tables) > 1 else ""
        switch_label = table.switch_variable or "dispatch"

        disp_id = f"{prefix}DISP"
        lines.append(
            f'    {disp_id} [label="{_escape_dot(func_name)}\\nswitch({_escape_dot(switch_label)})", '
            f'fillcolor="#cce5ff", shape=diamond];'
        )

        for case in table.cases:
            case_id = f"{prefix}C{_safe_id(case.case_value)}"
            handler = case.handler_name or "(inline)"
            label = case.label or ""
            node_label = f"{_escape_dot(handler)}"
            if label:
                node_label += f"\\n{_escape_dot(label[:40])}"

            color = "#d4edda" if case.is_internal else "#fff3cd"
            lines.append(f'    {case_id} [label="{node_label}", fillcolor="{color}"];')
            lines.append(
                f'    {disp_id} -> {case_id} [label="case {format_int(case.case_value)}"];'
            )

        if table.has_default:
            def_id = f"{prefix}DEF"
            lines.append(f'    {def_id} [label="default", fillcolor="#f8d7da", shape=octagon];')
            lines.append(f'    {disp_id} -> {def_id} [label="default"];')

    lines.append("}")
    return "\n".join(lines)


def generate_state_machine_dot(func: FunctionRecord, db) -> str:
    """Generate a DOT digraph for a reconstructed state machine."""
    sm = reconstruct_state_machine(func, db)
    if sm is None:
        return generate_dispatch_dot(func, db)

    func_name = func.function_name or f"sub_{func.function_id}"
    lines = [
        f'digraph state_machine {{',
        f'    rankdir=LR;',
        f'    label="{_escape_dot(func_name)} state machine";',
        f'    node [shape=box, style="filled,rounded", fontname="Consolas"];',
    ]

    # Start/end nodes
    lines.append('    __START__ [label="", shape=circle, fillcolor=black, width=0.3];')
    lines.append('    __END__ [label="", shape=doublecircle, fillcolor=black, width=0.3];')

    for state in sm.states:
        sid = _state_id(state.state_id)
        label = f"{_escape_dot(state.state_name)}"
        if state.handler_name:
            label += f"\\n{_escape_dot(state.handler_name)}"

        color = "#cce5ff"
        if state.is_initial:
            color = "#d4edda"
            lines.append(f'    __START__ -> {sid};')
        if state.is_terminal:
            color = "#f8d7da"
            lines.append(f'    {sid} -> __END__;')

        lines.append(f'    {sid} [label="{label}", fillcolor="{color}"];')

    for state in sm.states:
        for t in state.transitions:
            from_id = _state_id(t["from_state"])
            to_id = _state_id(t["to_state"])
            action = t.get("action") or t.get("assignment", "")
            if action:
                lines.append(f'    {from_id} -> {to_id} [label="{_escape_dot(action[:50])}"];')
            else:
                lines.append(f'    {from_id} -> {to_id};')

    lines.append("}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sanitize_mermaid_id(name: str) -> str:
    """Make a name safe for Mermaid node IDs."""
    return "".join(c if c.isalnum() or c == "_" else "_" for c in name)


def _escape_mermaid(text: str) -> str:
    """Escape text for Mermaid labels."""
    return text.replace('"', "'").replace("\n", "\\n").replace("#", "&#35;")


def _escape_dot(text: str) -> str:
    """Escape text for DOT labels."""
    return text.replace('"', '\\"').replace("\n", "\\n").replace("\\", "\\\\")


def _safe_id(val: int) -> str:
    """Convert an integer to a safe identifier part."""
    if val < 0:
        return f"neg{abs(val)}"
    return str(val)


def _state_id(val: int) -> str:
    """Create a state node ID from an integer."""
    if val < 0:
        return f"S_neg{abs(val)}"
    return f"S_{val}"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate state/dispatch diagrams (Mermaid or DOT).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("db_path", help="Path to the individual analysis DB")
    func_group = parser.add_mutually_exclusive_group(required=True)
    func_group.add_argument("--function", dest="function_name", help="Function name to diagram")
    func_group.add_argument("--id", "--function-id", type=int, dest="function_id", help="Function ID to diagram")
    parser.add_argument(
        "--format", choices=["mermaid", "dot"], default="mermaid",
        help="Output format (default: mermaid)",
    )
    parser.add_argument(
        "--mode", choices=["dispatch", "state-machine", "auto"], default="auto",
        help="Diagram mode: dispatch table, state machine, or auto-detect (default: auto)",
    )
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = safe_parse_args(parser)

    db_path = resolve_db_path(args.db_path)
    function_index = load_function_index_for_db(db_path)

    with db_error_handler(db_path, "generating state diagram"):
        with open_individual_analysis_db(db_path) as db:
            func, err = resolve_function(
                db, name=args.function_name, function_id=args.function_id,
                function_index=function_index,
            )
            if err:
                emit_error(f"[{Path(db_path).stem}] {err}", ErrorCode.NOT_FOUND)

            # Auto mode: try state machine first, fall back to dispatch
            mode = args.mode
            if mode == "auto":
                from _common import parse_json_safe
                loops = parse_json_safe(func.loop_analysis)
                has_loops = (
                    loops
                    and isinstance(loops, dict)
                    and len(loops.get("loops", [])) > 0
                )
                mode = "state-machine" if has_loops else "dispatch"

            # Generate
            if mode == "state-machine":
                if args.format == "mermaid":
                    output = generate_state_machine_mermaid(func, db)
                else:
                    output = generate_state_machine_dot(func, db)
            else:
                if args.format == "mermaid":
                    output = generate_dispatch_mermaid(func, db)
                else:
                    output = generate_dispatch_dot(func, db)

            if args.json:
                emit_json({
                    "status": "ok",
                    "format": args.format,
                    "mode": mode,
                    "function_name": func.function_name,
                    "diagram": output,
                })
            else:
                print(output)


if __name__ == "__main__":
    main()
