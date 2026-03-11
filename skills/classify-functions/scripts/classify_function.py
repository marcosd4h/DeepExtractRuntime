#!/usr/bin/env python3
"""Classify a single function with detailed reasoning.

Usage:
    python classify_function.py <db_path> <function_name>
    python classify_function.py <db_path> --id <function_id>
    python classify_function.py <db_path> --search <pattern>

Examples:
    python classify_function.py extracted_dbs/appinfo_dll_e98d25a9e8.db AiCheckSecureApplicationDirectory
    python classify_function.py extracted_dbs/cmd_exe_6d109a3a00.db --id 42
    python classify_function.py extracted_dbs/appinfo_dll_e98d25a9e8.db --search "Check"

Output:
    Detailed classification with all signals, scores, and reasoning for
    why the function was assigned its primary category.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from _common import (
    WORKSPACE_ROOT,
    ClassificationResult,
    classify_api,
    classify_function,
    emit_error,
    parse_json_safe,
    resolve_db_path,
)

from helpers import (
    load_function_index_for_db,
    open_individual_analysis_db,
    resolve_function,
    search_functions_by_pattern,
    validate_function_id,
)
from helpers.errors import emit_error, ErrorCode, db_error_handler, safe_parse_args
from helpers.json_output import emit_json


def _section(title: str) -> None:
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}")


def print_detailed_classification(db_path: str, func, result: ClassificationResult) -> None:
    """Print detailed classification reasoning for a single function."""
    print(f"{'#' * 70}")
    print(f"  FUNCTION CLASSIFICATION DETAIL")
    print(f"  Function: {func.function_name}")
    print(f"  ID: {func.function_id}")
    print(f"  DB: {db_path}")
    print(f"{'#' * 70}")

    # Primary result
    _section("CLASSIFICATION RESULT")
    print(f"  Primary Category:   {result.primary_category}")
    if result.secondary_categories:
        print(f"  Secondary:          {', '.join(result.secondary_categories)}")
    print(f"  Interest Score:     {result.interest_score}/10")

    # Scores breakdown
    _section("CATEGORY SCORES (all categories with score > 0)")
    if result.scores:
        sorted_scores = sorted(result.scores.items(), key=lambda x: -x[1])
        for cat, score in sorted_scores:
            if score <= 0:
                continue
            marker = " <-- PRIMARY" if cat == result.primary_category else ""
            print(f"  {cat:<25} {score:>6.1f}{marker}")
    else:
        print("  (no scores -- function could not be classified)")

    # Signals breakdown
    _section("CLASSIFICATION SIGNALS (evidence)")
    if result.signals:
        for cat, sigs in sorted(result.signals.items()):
            if not sigs:
                continue
            print(f"\n  [{cat}]")
            for sig in sigs:
                print(f"    - {sig}")
    else:
        print("  (no signals detected)")

    # Assembly metrics
    _section("STRUCTURAL METRICS")
    if result.asm_metrics:
        m = result.asm_metrics
        print(f"  Assembly instructions: {m.instruction_count}")
        print(f"  Call instructions:     {m.call_count}")
        print(f"  Branch instructions:   {m.branch_count}")
        print(f"  Return instructions:   {m.ret_count}")
        print(f"  Is leaf function:      {m.is_leaf}")
        print(f"  Is tiny (<10 instr):   {m.is_tiny}")
        print(f"  Has syscall:           {m.has_syscall}")
    else:
        print("  (no assembly code available)")
    print(f"  Loop count:            {result.loop_count}")
    print(f"  Has decompiled code:   {result.has_decompiled}")

    # API calls
    _section("OUTBOUND API CALLS")
    outbound = parse_json_safe(func.simple_outbound_xrefs) or []
    if outbound and isinstance(outbound, list):
        for xref in outbound:
            if not isinstance(xref, dict):
                continue
            ftype = xref.get("function_type", 0)
            if ftype in (4, 8):
                continue
            api_name = xref.get("function_name", "?")
            module = xref.get("module_name", "")
            fid = xref.get("function_id")
            cat = classify_api(api_name)
            cat_label = f" [{cat}]" if cat else ""
            loc = f" (in {module})" if module else ""
            internal = f" [internal ID={fid}]" if fid else ""
            print(f"  -> {api_name}{cat_label}{loc}{internal}")
    else:
        print("  (none)")

    # Dangerous APIs
    dangerous = parse_json_safe(func.dangerous_api_calls)
    if dangerous and isinstance(dangerous, list) and len(dangerous) > 0:
        _section(f"DANGEROUS APIs ({len(dangerous)})")
        for api in dangerous:
            print(f"  ! {api}")

    # String literals (first 20)
    strings = parse_json_safe(func.string_literals)
    if strings and isinstance(strings, list) and len(strings) > 0:
        shown = strings[:20]
        _section(f"STRING LITERALS ({len(strings)} total, showing first {len(shown)})")
        for s in shown:
            if isinstance(s, str):
                display = s[:100] + "..." if len(s) > 100 else s
                print(f"  \"{display}\"")
        if len(strings) > 20:
            print(f"  ... and {len(strings) - 20} more")

    # Signatures
    _section("FUNCTION IDENTITY")
    print(f"  Name:      {func.function_name}")
    print(f"  Signature: {func.function_signature or '(none)'}")
    if func.function_signature_extended and func.function_signature_extended != func.function_signature:
        print(f"  Extended:  {func.function_signature_extended}")
    print(f"  Mangled:   {func.mangled_name or '(none)'}")


def search_and_classify(db_path: str, pattern: str, *, as_json: bool = False) -> None:
    """Search for functions and show brief classification for each match."""
    function_index = load_function_index_for_db(db_path)
    with db_error_handler(db_path, "searching functions for classification"):
        with open_individual_analysis_db(db_path) as db:
            results = search_functions_by_pattern(
                db,
                pattern,
                function_index=function_index,
            )
            if not results:
                if as_json:
                    emit_json({"match_count": 0, "matches": [], "pattern": pattern})
                else:
                    print(f"No functions matching '{pattern}' found.")
                return

            if as_json:
                matches = []
                for func in results:
                    cr = classify_function(func)
                    matches.append({
                        "function_id": func.function_id,
                        "function_name": func.function_name,
                        "signature": func.function_signature or "",
                        "interest_score": cr.interest_score,
                        "primary_category": cr.primary_category,
                    })
                emit_json({"match_count": len(matches), "matches": matches, "pattern": pattern})
                return

            print(f"Found {len(results)} function(s) matching '{pattern}':\n")
            print(f"{'ID':>6}  {'Interest':>8}  {'Category':<22}  {'Function Name'}")
            print(f"{'-' * 6}  {'-' * 8}  {'-' * 22}  {'-' * 40}")
            for func in results:
                cr = classify_function(func)
                name = func.function_name or "(unnamed)"
                if len(name) > 40:
                    name = name[:37] + "..."
                print(f"{func.function_id:>6}  {cr.interest_score:>8}  {cr.primary_category:<22}  {name}")

            print(f"\nUse --id <ID> to see detailed classification for a specific function.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Classify a single function with detailed reasoning.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("db_path", help="Path to the individual analysis DB")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--function", "--name", dest="function_name", metavar="NAME",
                       help="Function name to classify")
    group.add_argument("--id", "--function-id", type=int, dest="function_id", help="Function ID")
    group.add_argument("--search", dest="search_pattern", help="Search for functions matching a pattern")
    parser.add_argument("function_name_pos", nargs="?", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--json", action="store_true", help="Output classification as JSON")
    args = safe_parse_args(parser)
    if args.function_name_pos and not args.function_name:
        args.function_name = args.function_name_pos

    if args.function_id is not None:
        args.function_id = validate_function_id(args.function_id)

    db_path = resolve_db_path(args.db_path)
    function_index = load_function_index_for_db(db_path)

    if args.search_pattern:
        search_and_classify(db_path, args.search_pattern, as_json=args.json)
        return

    with db_error_handler(db_path, "loading function for classification"):
        with open_individual_analysis_db(db_path) as db:
            if not args.function_name and args.function_id is None:
                emit_error("Provide a function name, --id, or --search", ErrorCode.INVALID_ARGS)

            func, err = resolve_function(
                db,
                name=args.function_name,
                function_id=args.function_id,
                function_index=function_index,
            )
            if err:
                if "Multiple matches" in err and args.json:
                    emit_error(f"[{Path(db_path).stem}] {err}", ErrorCode.AMBIGUOUS)
                if "Multiple matches" in err:
                    print(err)
                    return
                emit_error(f"[{Path(db_path).stem}] {err}", ErrorCode.NOT_FOUND)

            result = classify_function(func)

            if args.json:
                emit_json(result.to_dict())
            else:
                print_detailed_classification(db_path, func, result)


if __name__ == "__main__":
    main()
