#!/usr/bin/env python3
"""Extract all data needed for code lifting from an individual analysis DB.

Usage:
    python extract_function_data.py <db_path> <function_name>
    python extract_function_data.py <db_path> --id <function_id>
    python extract_function_data.py <db_path> --search <pattern>

Examples:
    python extract_function_data.py extracted_dbs/appinfo_dll_e98d25a9e8.db AiCheckSecureApplicationDirectory
    python extract_function_data.py extracted_dbs/cmd_exe_6d109a3a00.db --id 42
    python extract_function_data.py extracted_dbs/cmd_exe_6d109a3a00.db --search "BatLoop"

Output:
    Prints all function data needed for lifting in labeled sections:
    - Signatures (base, extended, mangled)
    - Decompiled C++ code
    - Assembly code
    - String literals, outbound/inbound xrefs, vtable contexts
    - Global variable accesses, stack frame, loop analysis

    With --search, prints matching function names and IDs for selection.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from _common import (
    emit_error,
    filter_decompiled,
    load_function_index_for_db,
    open_individual_analysis_db,
    parse_json_safe,
    resolve_db_path,
)
from helpers import resolve_function, search_functions_by_pattern
from helpers.errors import ErrorCode, db_error_handler, safe_parse_args
from helpers.json_output import emit_json


def _format_json(obj: object) -> str:
    if obj is None:
        return "(none)"
    return json.dumps(obj, indent=2, ensure_ascii=False)


def _print_section(title: str, content: str | None, max_lines: int = 0) -> None:
    print(f"\n{'=' * 80}")
    print(f"  {title}")
    print(f"{'=' * 80}")
    if content is None or content.strip() == "":
        print("(none)")
        return
    if max_lines > 0:
        lines = content.splitlines()
        if len(lines) > max_lines:
            for line in lines[:max_lines]:
                print(line)
            print(f"\n... ({len(lines) - max_lines} more lines, {len(lines)} total)")
            return
    print(content)


def search_functions(db_path: str, pattern: str, *, as_json: bool = False) -> None:
    function_index = load_function_index_for_db(db_path)
    with db_error_handler(db_path, "searching functions"):
        with open_individual_analysis_db(db_path) as db:
            decompiled_index = (
                filter_decompiled(function_index, decompiled=True)
                if function_index else None
            )
            results = [
                func for func in search_functions_by_pattern(
                    db,
                    pattern,
                    function_index=decompiled_index,
                )
                if func.decompiled_code
            ]
            if not results:
                if as_json:
                    emit_json({"match_count": 0, "matches": [], "pattern": pattern})
                else:
                    print(f"No functions matching '{pattern}' with decompiled code found.")
                return

            if as_json:
                matches = [
                    {
                        "function_id": func.function_id,
                        "function_name": func.function_name,
                        "signature": func.function_signature or "",
                    }
                    for func in results
                ]
                emit_json({"match_count": len(matches), "matches": matches, "pattern": pattern})
                return

            print(f"Found {len(results)} function(s) matching '{pattern}':\n")
            print(f"{'ID':>6}  {'Function Name':<50}  {'Signature'}")
            print(f"{'-' * 6}  {'-' * 50}  {'-' * 60}")
            for func in results:
                name = func.function_name or "(unnamed)"
                sig = func.function_signature or ""
                if len(sig) > 60:
                    sig = sig[:57] + "..."
                print(f"{func.function_id:>6}  {name:<50}  {sig}")

            print(f"\nUse --id <ID> to extract full data for a specific function.")


def _build_function_dict(func, db_path: str) -> dict:
    """Build a JSON-serialisable dict with all lifting data for a function."""
    return {
        "function_id": func.function_id,
        "function_name": func.function_name,
        "function_signature": func.function_signature,
        "function_signature_extended": func.function_signature_extended,
        "mangled_name": func.mangled_name,
        "decompiled_code": func.decompiled_code,
        "assembly_code": func.assembly_code,
        "string_literals": parse_json_safe(func.string_literals),
        "outbound_xrefs": parse_json_safe(func.simple_outbound_xrefs),
        "inbound_xrefs": parse_json_safe(func.simple_inbound_xrefs),
        "vtable_contexts": parse_json_safe(func.vtable_contexts),
        "global_var_accesses": parse_json_safe(func.global_var_accesses),
        "stack_frame": parse_json_safe(func.stack_frame),
        "loop_analysis": parse_json_safe(func.loop_analysis),
        "db_path": db_path,
    }


def extract_function(db_path: str, function_name: str | None = None, function_id: int | None = None, as_json: bool = False) -> None:
    function_index = load_function_index_for_db(db_path)
    # Pre-filter index to decompiled-only for partial matching
    decompiled_index = filter_decompiled(function_index, decompiled=True) if function_index else None
    with db_error_handler(db_path, "extracting function data"):
        with open_individual_analysis_db(db_path) as db:
            func, err = resolve_function(
                db,
                name=function_name,
                function_id=function_id,
                function_index=decompiled_index,
            )
            if err:
                if "Multiple matches" in err and as_json:
                    emit_error(f"[{Path(db_path).stem}] {err}", ErrorCode.AMBIGUOUS)
                if "Multiple matches" in err:
                    print(err)
                    return
                emit_error(f"[{Path(db_path).stem}] {err}", ErrorCode.NOT_FOUND)

            assert func is not None

            if as_json:
                emit_json(_build_function_dict(func, db_path))
                return

        # Header
        print(f"{'#' * 80}")
        print(f"  FUNCTION DATA FOR LIFTING")
        print(f"  Function: {func.function_name}")
        print(f"  ID: {func.function_id}")
        print(f"  DB: {db_path}")
        print(f"{'#' * 80}")

        # Signatures
        _print_section("FUNCTION SIGNATURE (demangled)", func.function_signature)
        _print_section("FUNCTION SIGNATURE (extended)", func.function_signature_extended)
        _print_section("MANGLED NAME", func.mangled_name)

        # Primary inputs
        _print_section("DECOMPILED C++ CODE", func.decompiled_code)
        _print_section("ASSEMBLY CODE", func.assembly_code)

        # Context data
        strings = parse_json_safe(func.string_literals)
        _print_section("STRING LITERALS", _format_json(strings))

        outbound = parse_json_safe(func.simple_outbound_xrefs)
        if outbound and isinstance(outbound, list):
            lines = []
            for xref in outbound:
                name = xref.get("function_name", "?")
                module = xref.get("module_name", "")
                ftype = xref.get("function_type", 0)
                fid = xref.get("function_id")
                loc = f" (in {module})" if module else ""
                internal = f" [internal, ID={fid}]" if fid else ""
                lines.append(f"  -> {name}{loc}{internal}  type={ftype}")
            _print_section("OUTBOUND CALLS (functions called)", "\n".join(lines))
        else:
            _print_section("OUTBOUND CALLS (functions called)", "(none)")

        inbound = parse_json_safe(func.simple_inbound_xrefs)
        if inbound and isinstance(inbound, list):
            lines = []
            for xref in inbound:
                name = xref.get("function_name", "?")
                fid = xref.get("function_id")
                internal = f" [internal, ID={fid}]" if fid else ""
                lines.append(f"  <- {name}{internal}")
            _print_section("INBOUND CALLERS (called by)", "\n".join(lines))
        else:
            _print_section("INBOUND CALLERS (called by)", "(none)")

        vtables = parse_json_safe(func.vtable_contexts)
        _print_section("VTABLE CONTEXTS", _format_json(vtables))

        globals_acc = parse_json_safe(func.global_var_accesses)
        _print_section("GLOBAL VARIABLE ACCESSES", _format_json(globals_acc))

        stack = parse_json_safe(func.stack_frame)
        _print_section("STACK FRAME", _format_json(stack))

        loops = parse_json_safe(func.loop_analysis)
        _print_section("LOOP ANALYSIS", _format_json(loops))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract function data for code lifting from an analysis DB.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("db_path", help="Path to the individual analysis DB (e.g., extracted_dbs/module_hash.db)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--function", "--name", dest="function_name", metavar="NAME",
                       help="Function name to look up")
    group.add_argument("--id", "--function-id", type=int, dest="function_id", help="Function ID to look up")
    group.add_argument("--search", dest="search_pattern", help="Search for functions matching a pattern")
    parser.add_argument("function_name_pos", nargs="?", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = safe_parse_args(parser)
    if args.function_name_pos and not args.function_name:
        args.function_name = args.function_name_pos

    db_path = resolve_db_path(args.db_path)

    if args.search_pattern:
        search_functions(db_path, args.search_pattern, as_json=args.json)
    elif args.function_id is not None:
        extract_function(db_path, function_id=args.function_id, as_json=args.json)
    elif args.function_name:
        extract_function(db_path, function_name=args.function_name, as_json=args.json)
    else:
        parser.error("Provide a function name, --id, or --search")


if __name__ == "__main__":
    main()
