#!/usr/bin/env python3
"""Reconstruct state machines from functions with dispatch-inside-loop patterns.

Analyzes functions that contain switch/case or if-chain dispatch logic within
loops, extracting states, transitions, and actions to build a state machine model.

Usage:
    python extract_state_machine.py <db_path> <function_name>
    python extract_state_machine.py <db_path> --id <function_id>
    python extract_state_machine.py <db_path> <function_name> --json
    python extract_state_machine.py <db_path> <function_name> --with-code

Examples:
    python .agent/skills/state-machine-extractor/scripts/extract_state_machine.py extracted_dbs/cmd_exe_6d109a3a00.db BatLoop
    python .agent/skills/state-machine-extractor/scripts/extract_state_machine.py extracted_dbs/cmd_exe_6d109a3a00.db --id 42 --json
    python .agent/skills/state-machine-extractor/scripts/extract_state_machine.py extracted_dbs/cmd_exe_6d109a3a00.db Dispatch --with-code

Output:
    Reconstructed state machine model: states, transitions, initial/terminal
    states, loop characteristics, and associated handler functions.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any, Optional

from _common import (
    DispatchTable,
    StateInfo,
    StateMachine,
    WORKSPACE_ROOT,
    emit_error,
    format_int,
    parse_json_safe,
    parse_string_compare_chain,
    parse_switch_cases,
    parse_if_chain,
    extract_case_handlers,
    RE_FUNCTION_CALL,
    RE_STRING_CMP_CALL,
    resolve_db_path,
)

from extract_dispatch_table import build_dispatch_table

from helpers import (
    FunctionRecord,
    load_function_index_for_db,
    open_individual_analysis_db,
    resolve_function,
    validate_function_id,
)
from helpers.cache import get_cached, cache_result
from helpers.errors import ErrorCode, db_error_handler, safe_parse_args
from helpers.json_output import emit_json


# Patterns for detecting state variable assignments in decompiled code
# Matches: state_var = CONST;  or  state_var = expr;
RE_STATE_ASSIGN = re.compile(
    r'\b(\w+)\s*=\s*(-?(?:0[xX][0-9a-fA-F]+|\d+))\s*;',
)

# Detect break/return/goto patterns that indicate terminal transitions
RE_BREAK = re.compile(r'\bbreak\s*;')
RE_RETURN_VAL = re.compile(r'\breturn\s+(.+?)\s*;')
RE_CONTINUE = re.compile(r'\bcontinue\s*;')

# Word-boundary match for loop keywords to avoid false positives from
# identifiers like "format", "double", "done", "before", etc.
RE_LOOP_KW = re.compile(r'\b(?:while|for)\s*\(|\bdo\s*\{')


def reconstruct_state_machine(
    func: FunctionRecord,
    db,
    include_code: bool = False,
) -> Optional[StateMachine]:
    """Reconstruct a state machine from a function with dispatch-in-loop pattern.

    Returns a StateMachine object or None if no state machine pattern detected.
    """
    decompiled = func.decompiled_code or ""
    func_name = func.function_name or f"sub_{func.function_id}"

    # Step 1: Get dispatch tables
    tables = build_dispatch_table(func, db)
    if not tables:
        return None

    # Use the largest dispatch table
    primary_table = max(tables, key=lambda t: t.total_cases)

    # Step 2: Get loop analysis
    loops = parse_json_safe(func.loop_analysis)
    loop_info = None
    if loops and isinstance(loops, dict):
        loop_list = loops.get("loops", [])
        if loop_list:
            # Find the most complex loop (likely the main state loop)
            loop_info = max(loop_list, key=lambda l: l.get("complexity", 0))

    # Step 3: Determine the state variable
    state_var = primary_table.switch_variable

    # Pre-parse switches once to avoid redundant regex work in
    # _extract_transitions and per-state _is_terminal_state calls.
    parsed_switches = parse_switch_cases(decompiled)

    # Step 4: Analyze transitions -- find where the state variable is reassigned
    transitions = _extract_transitions(decompiled, state_var, primary_table,
                                       parsed_switches=parsed_switches)

    # Step 5: Build state model
    sm = StateMachine(
        function_name=func_name,
        function_id=func.function_id,
        state_variable=state_var,
        dispatch_table=primary_table,
        loop_info=loop_info,
    )

    # Build states from dispatch table cases
    known_states = set()
    for case in primary_table.cases:
        if case.case_label:
            state_name = case.case_label
        elif case.label:
            state_name = case.label
        else:
            state_name = f"STATE_{format_int(case.case_value)}"

        state = StateInfo(
            state_id=case.case_value,
            state_name=state_name,
            handler_name=case.handler_name,
            handler_id=case.handler_id,
        )

        # Determine if terminal (handler returns or breaks out of loop)
        state.is_terminal = _is_terminal_state(
            case.case_value, state_var, decompiled, primary_table,
            parsed_switches=parsed_switches,
        )

        # Attach transitions FROM this state
        state.transitions = [
            t for t in transitions if t["from_state"] == case.case_value
        ]

        known_states.add(case.case_value)
        sm.states.append(state)

    # Detect initial state
    _mark_initial_state(sm, decompiled, state_var)

    # Add transition targets that aren't in the dispatch table (implicit states)
    for t in transitions:
        target = t.get("to_state")
        if target is not None and target not in known_states:
            state = StateInfo(
                state_id=target,
                state_name=f"STATE_{format_int(target)}",
                is_terminal=False,
            )
            sm.states.append(state)
            known_states.add(target)

    # Sort states by ID
    sm.states.sort(key=lambda s: s.state_id)

    return sm


def _extract_transitions(
    decompiled: str,
    state_var: Optional[str],
    table: DispatchTable,
    *,
    parsed_switches: Optional[list[dict[str, Any]]] = None,
) -> list[dict[str, Any]]:
    """Find state transitions by detecting assignments to the state variable.

    Returns list of {from_state, to_state, condition, action}.
    """
    if not state_var:
        return []

    transitions = []

    switches = parsed_switches if parsed_switches is not None else parse_switch_cases(decompiled)
    for sw in switches:
        if sw["switch_variable"] != state_var:
            continue

        body = sw["body_text"]
        # Split into case blocks
        case_blocks = _split_case_blocks(body)

        for case_val, block_text in case_blocks.items():
            # Find assignments to the state variable in this case block
            for match in RE_STATE_ASSIGN.finditer(block_text):
                var_name = match.group(1)
                assigned_val = match.group(2)

                # Check if this assigns to the state variable
                if var_name == state_var:
                    to_state = _parse_int_safe(assigned_val)
                    if to_state is not None and to_state != case_val:
                        # Find what action/condition triggers this transition
                        context = block_text[:match.start()]
                        action = _extract_action_context(context, block_text)

                        transitions.append({
                            "from_state": case_val,
                            "to_state": to_state,
                            "action": action,
                            "assignment": f"{state_var} = {assigned_val}",
                        })

    # Also check if-chains
    if_chains = parse_if_chain(decompiled, min_branches=3)
    for chain in if_chains:
        if chain["variable"] != state_var:
            continue
        for comp in chain["comparisons"]:
            case_val = comp["value"]
            pos = comp["start_pos"]
            # Get the if block
            block_end = decompiled.find("\n}", pos)
            if block_end == -1:
                block_end = min(pos + 500, len(decompiled))
            block = decompiled[pos:block_end]

            for match in RE_STATE_ASSIGN.finditer(block):
                var_name = match.group(1)
                assigned_val = match.group(2)
                if var_name == state_var:
                    to_state = _parse_int_safe(assigned_val)
                    if to_state is not None and to_state != case_val:
                        transitions.append({
                            "from_state": case_val,
                            "to_state": to_state,
                            "action": None,
                            "assignment": f"{state_var} = {assigned_val}",
                        })

    # String-compare dispatch: no numeric state transitions -- keywords are
    # matched sequentially, and unmatched input falls through.  Skip.

    return transitions


def _split_case_blocks(switch_body: str) -> dict[int, str]:
    """Split a switch body into individual case blocks.

    Returns {case_value: block_text}.
    """
    blocks: dict[int, str] = {}
    case_pattern = re.compile(r'^\s*case\s+(-?(?:0[xX][0-9a-fA-F]+|\d+))\s*:', re.MULTILINE)

    matches = list(case_pattern.finditer(switch_body))
    for i, match in enumerate(matches):
        case_val = _parse_int_safe(match.group(1))
        if case_val is None:
            continue
        start = match.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(switch_body)
        blocks[case_val] = switch_body[start:end]

    return blocks


def _is_terminal_state(
    case_val: int,
    state_var: Optional[str],
    decompiled: str,
    table: DispatchTable,
    *,
    parsed_switches: Optional[list[dict[str, Any]]] = None,
) -> bool:
    """Check if a state is terminal (returns or exits the loop without transition)."""
    # For string-compare tables, check the block around the keyword match
    if table.source_type == "string_compare":
        case_entry = next((c for c in table.cases if c.case_value == case_val), None)
        if case_entry and case_entry.case_label:
            kw = case_entry.case_label
            idx = decompiled.find(f'"{kw}"')
            if idx != -1:
                block_end = decompiled.find("\n}", idx)
                if block_end == -1:
                    block_end = min(idx + 500, len(decompiled))
                block = decompiled[idx:block_end]
                has_return = bool(RE_RETURN_VAL.search(block))
                if has_return:
                    return True
        return False

    switches = parsed_switches if parsed_switches is not None else parse_switch_cases(decompiled)
    for sw in switches:
        if sw["switch_variable"] != state_var:
            continue
        blocks = _split_case_blocks(sw["body_text"])
        block = blocks.get(case_val, "")

        # Terminal if it returns without setting the state variable
        has_return = bool(RE_RETURN_VAL.search(block))
        has_state_assign = state_var and state_var in block and RE_STATE_ASSIGN.search(block)

        if has_return and not has_state_assign:
            return True

    return False


def _mark_initial_state(sm: StateMachine, decompiled: str, state_var: Optional[str]) -> None:
    """Try to determine which state is initial based on variable initialization."""
    if not state_var or not sm.states:
        if sm.states:
            sm.states[0].is_initial = True
        return

    # Look for initialization: state_var = VALUE before the loop
    # Heuristic: find the first assignment to state_var before the switch/while
    init_pattern = re.compile(
        rf'\b{re.escape(state_var)}\s*=\s*(-?(?:0[xX][0-9a-fA-F]+|\d+))\s*;'
    )

    # Search in the function prologue (before first loop construct)
    loop_match = RE_LOOP_KW.search(decompiled)
    loop_pos = loop_match.start() if loop_match else None

    if loop_pos is not None:
        prologue = decompiled[:loop_pos]
    else:
        prologue = decompiled[:200]  # first 200 chars as fallback

    for match in init_pattern.finditer(prologue):
        init_val = _parse_int_safe(match.group(1))
        if init_val is not None:
            for state in sm.states:
                if state.state_id == init_val:
                    state.is_initial = True
                    return

    # Fallback: first case value
    if sm.states:
        sm.states[0].is_initial = True


def _extract_action_context(before_assign: str, full_block: str) -> Optional[str]:
    """Extract action/condition that triggers a state transition."""
    # Look for the most recent if-condition or function call before assignment
    lines = before_assign.strip().splitlines()
    for line in reversed(lines):
        line = line.strip()
        if line.startswith("if"):
            return line
        if RE_FUNCTION_CALL.search(line):
            return line.strip()

    return None


def _parse_int_safe(s: str) -> Optional[int]:
    try:
        s = s.strip()
        if s.startswith(("-0x", "-0X")):
            return -int(s[1:], 16)
        if s.startswith(("0x", "0X")):
            return int(s, 16)
        return int(s)
    except (ValueError, TypeError):
        return None


def _sm_to_cacheable(sm: StateMachine) -> dict:
    """Serialize a StateMachine to a JSON-safe dict for caching."""
    output = {
        "function_name": sm.function_name,
        "function_id": sm.function_id,
        "state_variable": sm.state_variable,
        "state_count": len(sm.states),
        "loop_info": sm.loop_info,
        "states": [],
        "all_transitions": [],
    }
    for state in sm.states:
        output["states"].append({
            "state_id": state.state_id,
            "state_name": state.state_name,
            "handler_name": state.handler_name,
            "handler_id": state.handler_id,
            "is_initial": state.is_initial,
            "is_terminal": state.is_terminal,
            "transition_count": len(state.transitions),
        })
        for t in state.transitions:
            output["all_transitions"].append(t)
    return output


def _sm_from_cached(d: dict) -> StateMachine:
    """Reconstruct a StateMachine from a cached dict."""
    sm = StateMachine(
        function_name=d["function_name"],
        function_id=d["function_id"],
        state_variable=d.get("state_variable"),
        loop_info=d.get("loop_info"),
    )
    all_transitions = d.get("all_transitions", [])
    for s in d.get("states", []):
        state = StateInfo(
            state_id=s["state_id"],
            state_name=s.get("state_name", ""),
            handler_name=s.get("handler_name"),
            handler_id=s.get("handler_id"),
            is_terminal=s.get("is_terminal", False),
            is_initial=s.get("is_initial", False),
            transitions=[t for t in all_transitions
                         if t.get("from_state") == s["state_id"]],
        )
        sm.states.append(state)
    return sm


def print_state_machine(
    sm: Optional[StateMachine],
    func: FunctionRecord,
    include_code: bool = False,
    as_json: bool = False,
) -> None:
    if as_json:
        if sm is None:
            emit_error("No state machine pattern detected", ErrorCode.NO_DATA)
            return

        emit_json(_sm_to_cacheable(sm))
        return

    if sm is None:
        print(f"No state machine pattern detected in {func.function_name or func.function_id}.")
        print("Tip: Use detect_dispatchers.py --with-loops to find state machine candidates.")
        return

    func_name = func.function_name or f"sub_{func.function_id}"
    sig = func.function_signature or ""

    print(f"\n{'#' * 80}")
    print(f"  STATE MACHINE RECONSTRUCTION")
    print(f"  Function: {func_name}")
    print(f"  ID: {func.function_id}")
    if sig:
        print(f"  Signature: {sig}")
    print(f"  State variable: {sm.state_variable or '(unknown)'}")
    print(f"  States: {len(sm.states)}")
    print(f"{'#' * 80}")

    # Loop info
    if sm.loop_info:
        li = sm.loop_info
        print(f"\n{'=' * 80}")
        print(f"  LOOP CHARACTERISTICS")
        print(f"{'=' * 80}")
        print(f"  Complexity:       {li.get('complexity', '?')}")
        print(f"  Block count:      {li.get('block_count', '?')}")
        print(f"  Instruction count: {li.get('instruction_count', '?')}")
        print(f"  Has function calls: {li.get('has_function_calls', '?')}")
        print(f"  Is infinite:      {li.get('is_infinite', '?')}")
        print(f"  Exit conditions:  {li.get('exit_condition_count', '?')}")
        print(f"  Nesting level:    {li.get('nesting_level', '?')}")

    # State table
    print(f"\n{'=' * 80}")
    print(f"  STATES")
    print(f"{'=' * 80}\n")

    initial = [s for s in sm.states if s.is_initial]
    terminal = [s for s in sm.states if s.is_terminal]

    print(f"  Initial state(s): {', '.join(s.state_name for s in initial) or '(unknown)'}")
    print(f"  Terminal state(s): {', '.join(s.state_name for s in terminal) or '(none detected)'}")
    print()

    print(f"  {'ID':>10}  {'State Name':<30}  {'Handler':<30}  {'Flags':<15}  {'Transitions':>5}")
    print(f"  {'-' * 10}  {'-' * 30}  {'-' * 30}  {'-' * 15}  {'-' * 5}")

    for state in sm.states:
        sid = format_int(state.state_id)
        sname = state.state_name
        if len(sname) > 30:
            sname = sname[:27] + "..."
        handler = state.handler_name or "(inline)"
        if len(handler) > 30:
            handler = handler[:27] + "..."
        flags = []
        if state.is_initial:
            flags.append("INIT")
        if state.is_terminal:
            flags.append("TERM")
        flag_str = ",".join(flags) or "-"
        trans_count = str(len(state.transitions))
        print(f"  {sid:>10}  {sname:<30}  {handler:<30}  {flag_str:<15}  {trans_count:>5}")

    # Transitions
    all_transitions = [t for s in sm.states for t in s.transitions]
    if all_transitions:
        print(f"\n{'=' * 80}")
        print(f"  TRANSITIONS ({len(all_transitions)} found)")
        print(f"{'=' * 80}\n")

        print(f"  {'From':>12}  {'->':>3}  {'To':<12}  {'Action/Condition'}")
        print(f"  {'-' * 12}  {'-' * 3}  {'-' * 12}  {'-' * 50}")

        for t in all_transitions:
            from_s = format_int(t["from_state"])
            to_s = format_int(t["to_state"])
            action = t.get("action") or t.get("assignment", "")
            if len(action) > 50:
                action = action[:47] + "..."
            print(f"  {from_s:>12}  ->  {to_s:<12}  {action}")
    else:
        print(f"\n  No explicit transitions detected.")
        print(f"  (State variable may be modified through function calls or indirect means)")

    if include_code and func.decompiled_code:
        print(f"\n{'=' * 80}")
        print(f"  DECOMPILED CODE")
        print(f"{'=' * 80}\n")
        print(func.decompiled_code)

    # Mermaid hint
    print(f"\n{'=' * 80}")
    print(f"  Use generate_state_diagram.py to produce a Mermaid/DOT diagram.")
    print(f"{'=' * 80}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Reconstruct state machines from dispatch-in-loop functions.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("db_path", help="Path to the individual analysis DB")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--function", "--name", dest="function_name", metavar="NAME",
                       help="Function name to analyze")
    group.add_argument("--id", "--function-id", type=int, dest="function_id", help="Function ID")
    parser.add_argument("function_name_pos", nargs="?", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--with-code", action="store_true", help="Include decompiled code in output")
    parser.add_argument("--no-cache", action="store_true", help="Bypass cache and force fresh analysis")
    args = safe_parse_args(parser)
    if args.function_name_pos and not args.function_name:
        args.function_name = args.function_name_pos

    if args.function_id is not None:
        args.function_id = validate_function_id(args.function_id)

    db_path = resolve_db_path(args.db_path)
    function_index = load_function_index_for_db(db_path)

    with db_error_handler(db_path, "extracting state machine"):
        with open_individual_analysis_db(db_path) as db:
            if not args.function_name and args.function_id is None:
                parser.error("Provide a function name or --id")

            func, err = resolve_function(
                db, name=args.function_name, function_id=args.function_id,
                function_index=function_index,
            )
            if err:
                if "Multiple matches" in err:
                    if args.json:
                        emit_error(err, ErrorCode.AMBIGUOUS)
                    print(err)
                    return
                emit_error(f"[{Path(db_path).stem}] {err}", ErrorCode.NOT_FOUND)

            cache_params = {"function_id": func.function_id}
            if not args.no_cache:
                cached = get_cached(db_path, "state_machine", params=cache_params)
                if cached is not None:
                    if args.json:
                        emit_json(cached)
                    else:
                        sm = _sm_from_cached(cached)
                        print_state_machine(
                            sm,
                            func,
                            include_code=args.with_code,
                            as_json=False,
                        )
                    return

            sm = reconstruct_state_machine(func, db, include_code=args.with_code)
            if sm is not None:
                cache_result(
                    db_path,
                    "state_machine",
                    _sm_to_cacheable(sm),
                    params=cache_params,
                )
            print_state_machine(sm, func, include_code=args.with_code, as_json=args.json)


if __name__ == "__main__":
    main()
