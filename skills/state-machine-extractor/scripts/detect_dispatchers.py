#!/usr/bin/env python3
"""Scan a module for functions containing dispatch tables, switch/case, or state machines.

Usage:
    python detect_dispatchers.py <db_path>
    python detect_dispatchers.py <db_path> --min-cases 3
    python detect_dispatchers.py <db_path> --with-loops
    python detect_dispatchers.py <db_path> --json

Examples:
    python .agent/skills/state-machine-extractor/scripts/detect_dispatchers.py extracted_dbs/cmd_exe_6d109a3a00.db
    python .agent/skills/state-machine-extractor/scripts/detect_dispatchers.py extracted_dbs/cmd_exe_6d109a3a00.db --min-cases 5 --with-loops
    python .agent/skills/state-machine-extractor/scripts/detect_dispatchers.py extracted_dbs/cmd_exe_6d109a3a00.db --json

Output:
    Lists candidate dispatcher functions ranked by case count, with metadata
    about switch statements, if-chains, jump tables, and loop presence.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from _common import (
    WORKSPACE_ROOT,
    detect_asm_switch_patterns,
    emit_error,
    extract_jump_table_targets,
    parse_if_chain,
    parse_json_safe,
    parse_string_compare_chain,
    parse_switch_cases,
    resolve_db_path,
)

from helpers import load_function_index_for_db, open_individual_analysis_db
from helpers.cache import get_cached, cache_result
from helpers.errors import ErrorCode, db_error_handler, safe_parse_args
from helpers.json_output import emit_json_list


def scan_module(db_path: str, min_cases: int = 3, with_loops: bool = False, app_only: bool = False, no_cache: bool = False) -> list[dict]:
    """Scan all functions in a module for dispatch/switch patterns.

    Returns list of candidate dicts sorted by total_cases descending.
    """
    cache_params = {"min_cases": min_cases}
    if with_loops:
        cache_params["with_loops"] = True
    if app_only:
        cache_params["app_only"] = True

    if not no_cache:
        cached = get_cached(db_path, "detect_dispatchers", params=cache_params)
        if cached is not None:
            return cached

    candidates = []
    function_index = load_function_index_for_db(db_path)
    library_names = set()
    if function_index and app_only:
        library_names = {k for k, v in function_index.items() if v.get("library") is not None}

    with db_error_handler(db_path, "scanning module for dispatchers"):
        with open_individual_analysis_db(db_path) as db:
            functions = db.get_all_functions()

        for func in functions:
            if app_only and library_names and (func.function_name or "") in library_names:
                continue
            if not func.decompiled_code:
                continue

            decompiled = func.decompiled_code
            result = {
                "function_id": func.function_id,
                "function_name": func.function_name or f"sub_{func.function_id}",
                "function_signature": func.function_signature or "",
                "switches": [],
                "if_chains": [],
                "string_compare_chains": [],
                "jump_table_targets": 0,
                "asm_has_jump_table": False,
                "has_loops": False,
                "loop_count": 0,
                "total_cases": 0,
                "dispatch_type": "none",
                "is_state_machine_candidate": False,
            }

            # 1. Detect switch/case in decompiled code
            switches = parse_switch_cases(decompiled)
            for sw in switches:
                result["switches"].append({
                    "variable": sw["switch_variable"],
                    "case_count": len(sw["cases"]),
                    "has_default": sw["has_default"],
                    "case_values": sw["cases"][:20],  # cap for output
                })
                result["total_cases"] += len(sw["cases"])

            # 2. Detect if-else chains
            if_chains = parse_if_chain(decompiled, min_branches=min_cases)
            for chain in if_chains:
                values = [c["value"] for c in chain["comparisons"]]
                result["if_chains"].append({
                    "variable": chain["variable"],
                    "branch_count": len(chain["comparisons"]),
                    "values": values[:20],
                })
                result["total_cases"] += len(chain["comparisons"])

            # 2b. Detect string-compare dispatch chains
            str_chains = parse_string_compare_chain(decompiled, min_branches=min_cases)
            for chain in str_chains:
                keywords = [kw["keyword"] for kw in chain["keywords"]]
                result["string_compare_chains"].append({
                    "compare_function": chain["compare_function"],
                    "variable": chain["variable"],
                    "branch_count": len(chain["keywords"]),
                    "keywords": keywords[:20],
                })
                result["total_cases"] += len(chain["keywords"])

            # 3. Detect jump table targets from detailed outbound xrefs
            detailed_xrefs = parse_json_safe(func.outbound_xrefs)
            if detailed_xrefs and isinstance(detailed_xrefs, list):
                jt_targets = extract_jump_table_targets(detailed_xrefs)
                result["jump_table_targets"] = len(jt_targets)
                if jt_targets and not switches:
                    # Jump table without visible switch in decompiled code
                    result["total_cases"] += len(jt_targets)

            # 4. Check assembly for switch patterns
            if func.assembly_code:
                asm_info = detect_asm_switch_patterns(func.assembly_code)
                result["asm_has_jump_table"] = asm_info["has_jump_table"]

            # 5. Check loop analysis
            loops = parse_json_safe(func.loop_analysis)
            if loops and isinstance(loops, dict):
                loop_list = loops.get("loops", [])
                result["loop_count"] = len(loop_list)
                result["has_loops"] = len(loop_list) > 0

            # Skip if below threshold
            if result["total_cases"] < min_cases:
                continue

            # Classify dispatch type
            if result["switches"] and result["has_loops"]:
                result["dispatch_type"] = "loop_switch"
                result["is_state_machine_candidate"] = True
            elif result["switches"]:
                result["dispatch_type"] = "switch"
            elif result["if_chains"] and result["has_loops"]:
                result["dispatch_type"] = "loop_if_chain"
                result["is_state_machine_candidate"] = True
            elif result["if_chains"]:
                result["dispatch_type"] = "if_chain"
            elif result["string_compare_chains"] and result["has_loops"]:
                result["dispatch_type"] = "loop_string_compare"
                result["is_state_machine_candidate"] = True
            elif result["string_compare_chains"]:
                result["dispatch_type"] = "string_compare"
            elif result["jump_table_targets"] > 0:
                result["dispatch_type"] = "jump_table"
            else:
                result["dispatch_type"] = "mixed"

            # State machine = dispatch inside loop
            if result["has_loops"] and result["total_cases"] >= min_cases:
                result["is_state_machine_candidate"] = True

            candidates.append(result)

    # Filter to only with-loops if requested
    if with_loops:
        candidates = [c for c in candidates if c["has_loops"]]

    # Sort by total cases descending
    candidates.sort(key=lambda c: c["total_cases"], reverse=True)

    cache_result(db_path, "detect_dispatchers", candidates, params=cache_params)
    return candidates


def print_results(candidates: list[dict], as_json: bool = False) -> None:
    if as_json:
        emit_json_list("candidates", candidates)
        return

    if not candidates:
        print("No dispatch/switch functions found matching criteria.")
        return

    state_machines = [c for c in candidates if c["is_state_machine_candidate"]]
    dispatchers = [c for c in candidates if not c["is_state_machine_candidate"]]

    if state_machines:
        print(f"\n{'=' * 80}")
        print(f"  STATE MACHINE CANDIDATES ({len(state_machines)} found)")
        print(f"  Functions with dispatch logic inside loops")
        print(f"{'=' * 80}\n")
        _print_table(state_machines)

    if dispatchers:
        print(f"\n{'=' * 80}")
        print(f"  DISPATCH TABLE FUNCTIONS ({len(dispatchers)} found)")
        print(f"  Functions with switch/case or if-chain dispatch")
        print(f"{'=' * 80}\n")
        _print_table(dispatchers)

    print(f"\nTotal candidates: {len(candidates)}")
    print(f"  State machine candidates: {len(state_machines)}")
    print(f"  Dispatch-only functions:  {len(dispatchers)}")
    print(f"\nUse extract_dispatch_table.py to get the full case->handler mapping.")
    print(f"Use extract_state_machine.py to reconstruct state machines.")


def _print_table(items: list[dict]) -> None:
    print(f"{'ID':>6}  {'Cases':>5}  {'Type':<14}  {'Loops':>5}  {'JT':>3}  {'Function Name'}")
    print(f"{'-' * 6}  {'-' * 5}  {'-' * 14}  {'-' * 5}  {'-' * 3}  {'-' * 50}")
    for c in items:
        loops_str = str(c["loop_count"]) if c["has_loops"] else "-"
        jt_str = str(c["jump_table_targets"]) if c["jump_table_targets"] else "-"
        name = c["function_name"]
        if len(name) > 50:
            name = name[:47] + "..."
        print(f"{c['function_id']:>6}  {c['total_cases']:>5}  {c['dispatch_type']:<14}  {loops_str:>5}  {jt_str:>3}  {name}")

        # Show switch details
        for sw in c["switches"]:
            vals = ", ".join(str(v) for v in sw["case_values"][:8])
            more = f" +{len(sw['case_values']) - 8} more" if len(sw["case_values"]) > 8 else ""
            default = " +default" if sw["has_default"] else ""
            print(f"          switch({sw['variable']}): {sw['case_count']} cases [{vals}{more}]{default}")

        # Show if-chain details
        for ic in c["if_chains"]:
            vals = ", ".join(str(v) for v in ic["values"][:8])
            more = f" +{len(ic['values']) - 8} more" if len(ic["values"]) > 8 else ""
            print(f"          if-chain({ic['variable']}): {ic['branch_count']} branches [{vals}{more}]")

        # Show string-compare chain details
        for sc in c.get("string_compare_chains", []):
            kws = ", ".join(f'"{k}"' for k in sc["keywords"][:6])
            more = f" +{len(sc['keywords']) - 6} more" if len(sc["keywords"]) > 6 else ""
            print(f"          str-cmp({sc['variable']}): {sc['branch_count']} keywords [{kws}{more}]")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan a module for dispatch/switch functions and state machines.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("db_path", help="Path to the individual analysis DB")
    parser.add_argument(
        "--min-cases", type=int, default=3,
        help="Minimum number of cases/branches to report (default: 3)",
    )
    parser.add_argument(
        "--with-loops", action="store_true",
        help="Only show functions that also contain loops (state machine candidates)",
    )
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--app-only", action="store_true", help="Skip library-tagged functions (from function_index)")
    parser.add_argument("--no-cache", action="store_true", help="Bypass cache and force fresh analysis")
    args = safe_parse_args(parser)

    db_path = resolve_db_path(args.db_path)
    try:
        candidates = scan_module(db_path, min_cases=args.min_cases, with_loops=args.with_loops, app_only=args.app_only, no_cache=args.no_cache)
    except FileNotFoundError as e:
        emit_error(str(e), ErrorCode.NOT_FOUND)
    print_results(candidates, as_json=args.json)


if __name__ == "__main__":
    main()
