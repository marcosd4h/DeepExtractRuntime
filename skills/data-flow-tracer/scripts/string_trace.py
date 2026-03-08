#!/usr/bin/env python3
"""String origin tracking: trace how string literals flow through the binary.

Given a string literal, finds all functions that reference it, shows the
decompiled code context where the string appears, and optionally traces
callers to understand what execution paths lead to the string's use.

Usage:
    python string_trace.py <db_path> --string <text>
    python string_trace.py <db_path> --function <name>
    python string_trace.py <db_path> --id <function_id>
    python string_trace.py <db_path> --string <text> --callers --depth 2
    python string_trace.py <db_path> --list-strings [--limit N]
    python string_trace.py <db_path> --string <text> --json

Examples:
    # Find all functions referencing a specific string
    python string_trace.py extracted_dbs/appinfo_dll_e98d25a9e8.db --string "CreateProcess"

    # Show code context for functions using a string, plus their callers
    python string_trace.py extracted_dbs/cmd_exe_6d109a3a00.db --string "COMSPEC" --callers

    # Find strings referenced by a specific function and their usage chains
    python string_trace.py extracted_dbs/cmd_exe_6d109a3a00.db --function eComSrv --callers

    # List all unique strings in the module
    python string_trace.py extracted_dbs/appinfo_dll_e98d25a9e8.db --list-strings --limit 50

    # Full caller chain depth 2
    python string_trace.py extracted_dbs/cmd_exe_6d109a3a00.db --string "PATH" --callers --depth 2

    # JSON output
    python string_trace.py extracted_dbs/appinfo_dll_e98d25a9e8.db --string "CreateProcess" --json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

from _common import (
    WORKSPACE_ROOT,
    emit_error,
    parse_json_safe,
    resolve_db_path,
)

from helpers import (
    load_function_index_for_db,
    open_individual_analysis_db,
    resolve_function,
    search_functions_by_pattern,
)
from helpers.cache import get_cached, cache_result
from helpers.errors import ErrorCode, db_error_handler, emit_error, safe_parse_args
from helpers.json_output import emit_json


# ---------------------------------------------------------------------------
# Data retrieval helpers
# ---------------------------------------------------------------------------


def _find_string_references(db_path: str, search_text: str) -> list[dict]:
    """Find all functions that reference a string matching the search text.

    Returns list of dicts:
      function_id, function_name, function_signature, matched_strings,
      decompiled_code, inbound_xrefs
    """
    results = []
    search_lower = search_text.lower()

    with db_error_handler(db_path, "finding string references"):
        with open_individual_analysis_db(db_path) as db:
            functions = db.get_all_functions()

    for func in functions:
        strings = parse_json_safe(func.string_literals)
        if not strings or not isinstance(strings, list):
            continue

        matched = [s for s in strings if isinstance(s, str) and search_lower in s.lower()]
        if not matched:
            continue

        results.append({
            "function_id": func.function_id,
            "function_name": func.function_name or f"sub_{func.function_id}",
            "function_signature": func.function_signature,
            "matched_strings": matched,
            "decompiled_code": func.decompiled_code or "",
            "assembly_code": func.assembly_code or "",
            "inbound_xrefs": parse_json_safe(func.simple_inbound_xrefs) or [],
            "outbound_xrefs": parse_json_safe(func.simple_outbound_xrefs) or [],
        })

    return results


def _find_function_strings(db_path: str, function_name: str | None = None,
                           function_id: int | None = None) -> list[dict]:
    """Get all strings referenced by a specific function."""
    function_index = load_function_index_for_db(db_path)
    with db_error_handler(db_path, "loading function strings"):
        with open_individual_analysis_db(db_path) as db:
            if function_id is not None:
                func, err = resolve_function(
                    db, function_id=function_id, function_index=function_index,
                )
                funcs = [func] if func else []
                if not funcs:
                    return []
            else:
                funcs = search_functions_by_pattern(
                    db, function_name, function_index=function_index,
                )
                if not funcs:
                    return []

    results = []
    for func in funcs:
        strings = parse_json_safe(func.string_literals)
        if not strings:
            strings = []
        results.append({
            "function_id": func.function_id,
            "function_name": func.function_name or f"sub_{func.function_id}",
            "function_signature": func.function_signature,
            "all_strings": strings,
            "decompiled_code": func.decompiled_code or "",
            "assembly_code": func.assembly_code or "",
            "inbound_xrefs": parse_json_safe(func.simple_inbound_xrefs) or [],
        })
    return results


def _list_all_strings(db_path: str, limit: int = 100) -> dict[str, list[str]]:
    """List all unique strings across the module with referencing functions.

    Returns dict: string -> list of function names.
    """
    string_map: dict[str, list[str]] = defaultdict(list)

    with db_error_handler(db_path, "listing all strings"):
        with open_individual_analysis_db(db_path) as db:
            functions = db.get_all_functions()

    for func in functions:
        strings = parse_json_safe(func.string_literals)
        if not strings or not isinstance(strings, list):
            continue
        fname = func.function_name or f"sub_{func.function_id}"
        for s in strings:
            if isinstance(s, str):
                string_map[s].append(fname)

    return dict(string_map)


def _find_string_in_code(code: str, search_text: str) -> list[dict]:
    """Find lines in decompiled code that reference a string.

    Returns list of {line_number, line} dicts.
    """
    results = []
    search_lower = search_text.lower()
    for i, line in enumerate(code.splitlines(), 1):
        if search_lower in line.lower():
            results.append({"line_number": i, "line": line.strip()})
    return results


def _find_string_in_assembly(assembly: str, search_text: str) -> list[dict]:
    """Find lines in assembly that reference a string (via comments or operands)."""
    results = []
    search_lower = search_text.lower()
    for i, line in enumerate(assembly.splitlines(), 1):
        if search_lower in line.lower():
            results.append({"line_number": i, "line": line.strip()})
    return results


def _collect_callers(
    func_info: dict,
    db_path: str,
    max_depth: int = 1,
    current_depth: int = 0,
    visited: set = None,
) -> list[dict]:
    """Collect the caller chain for a function.

    Returns list of caller dicts with recursive structure.
    """
    if visited is None:
        visited = set()

    inbound = func_info.get("inbound_xrefs", [])
    if not inbound:
        return []

    callers = []
    for xref in inbound:
        if not isinstance(xref, dict):
            continue
        caller_name = xref.get("function_name", "?")
        caller_id = xref.get("function_id")
        module = xref.get("module_name", "")

        visit_key = (db_path, caller_name)
        if visit_key in visited:
            callers.append({
                "function_name": caller_name,
                "function_id": caller_id,
                "status": "cycle",
            })
            continue

        if caller_id is None:
            callers.append({
                "function_name": caller_name,
                "function_id": None,
                "status": "external",
                "module_name": module,
            })
            continue

        entry = {
            "function_name": caller_name,
            "function_id": caller_id,
            "status": "internal",
        }

        # Recurse into callers
        if current_depth < max_depth:
            visited.add(visit_key)
            with db_error_handler(db_path, "loading caller data"):
                with open_individual_analysis_db(db_path) as db:
                    caller_func = db.get_function_by_id(caller_id)
            if caller_func:
                caller_info = {
                    "function_name": caller_func.function_name,
                    "function_id": caller_func.function_id,
                    "inbound_xrefs": parse_json_safe(caller_func.simple_inbound_xrefs) or [],
                }
                entry["callers"] = _collect_callers(
                    caller_info, db_path,
                    max_depth=max_depth, current_depth=current_depth + 1,
                    visited=visited,
                )

        callers.append(entry)

    return callers


# ---------------------------------------------------------------------------
# Core trace logic (returns structured data)
# ---------------------------------------------------------------------------


def trace_string(
    db_path: str,
    search_text: str,
    show_callers: bool = False,
    max_depth: int = 1,
    show_assembly: bool = False,
) -> dict:
    """Main string trace: find references and return structured result."""
    result = {
        "mode": "string_trace",
        "search_text": search_text,
        "db": Path(db_path).name,
    }

    refs = _find_string_references(db_path, search_text)
    result["function_count"] = len(refs)

    if not refs:
        result["functions"] = []
        return result

    functions = []
    for func_info in sorted(refs, key=lambda x: x["function_name"]):
        func_data = {
            "function_id": func_info["function_id"],
            "function_name": func_info["function_name"],
            "function_signature": func_info["function_signature"],
            "matched_strings": func_info["matched_strings"],
        }

        # Code context
        code = func_info["decompiled_code"]
        if code:
            func_data["code_context"] = _find_string_in_code(code, search_text)
        else:
            func_data["code_context"] = []

        # Assembly context
        if show_assembly and func_info["assembly_code"]:
            func_data["assembly_context"] = _find_string_in_assembly(
                func_info["assembly_code"], search_text,
            )
        else:
            func_data["assembly_context"] = []

        # Callers
        if show_callers:
            func_data["callers"] = _collect_callers(
                func_info, db_path, max_depth=max_depth,
            )

        functions.append(func_data)

    result["functions"] = functions
    return result


def trace_function_strings(
    db_path: str,
    function_name: str | None = None,
    show_callers: bool = False,
    max_depth: int = 1,
    function_id: int | None = None,
) -> dict:
    """Show all strings used by a function. Returns structured result."""
    result = {
        "mode": "function_strings",
        "function_name": function_name or f"ID={function_id}",
        "db": Path(db_path).name,
    }

    results = _find_function_strings(db_path, function_name=function_name,
                                     function_id=function_id)
    if not results:
        result["status"] = "not_found"
        result["functions"] = []
        return result

    result["status"] = "ok"
    functions = []
    for func_info in results:
        func_data = {
            "function_id": func_info["function_id"],
            "function_name": func_info["function_name"],
            "function_signature": func_info["function_signature"],
            "string_count": len(func_info["all_strings"]),
            "strings": [],
        }

        for i, s in enumerate(func_info["all_strings"], 1):
            string_entry = {
                "index": i,
                "value": s,
                "code_context": [],
            }

            # Show where in code this string appears
            if func_info["decompiled_code"] and isinstance(s, str) and len(s) > 2:
                fragment = s[:40]
                string_entry["code_context"] = _find_string_in_code(
                    func_info["decompiled_code"], fragment,
                )

            func_data["strings"].append(string_entry)

        if show_callers:
            func_data["callers"] = _collect_callers(
                func_info, db_path, max_depth=max_depth,
            )

        functions.append(func_data)

    result["functions"] = functions
    return result


def list_strings(db_path: str, limit: int = 100) -> dict:
    """List all unique strings in the module. Returns structured result."""
    print(f"Scanning strings in {Path(db_path).name}...", file=sys.stderr)
    string_map = _list_all_strings(db_path, limit)

    result = {
        "mode": "list_strings",
        "db": Path(db_path).name,
        "total_unique": len(string_map),
        "limit": limit,
    }

    if not string_map:
        result["strings"] = []
        return result

    sorted_strings = sorted(string_map.items(), key=lambda x: len(x[1]), reverse=True)

    strings_data = []
    for s, funcs in sorted_strings[:limit]:
        strings_data.append({
            "value": s,
            "reference_count": len(funcs),
            "functions": funcs,
        })

    result["strings"] = strings_data
    result["truncated"] = len(sorted_strings) > limit
    return result


# ---------------------------------------------------------------------------
# Text rendering (human-readable output)
# ---------------------------------------------------------------------------


def _print_callers(callers: list[dict], indent: str = "") -> None:
    """Print caller chain as human-readable text."""
    if not callers:
        print(f"{indent}  (no callers recorded)")
        return

    for caller in callers:
        name = caller["function_name"]
        cid = caller.get("function_id")
        status = caller["status"]

        if status == "cycle":
            print(f"{indent}  <- {name} [CYCLE]")
        elif status == "external":
            module = caller.get("module_name", "")
            print(f"{indent}  <- {name}  ({module})  [external]")
        else:
            print(f"{indent}  <- {name}  [ID={cid}]")
            if "callers" in caller:
                _print_callers(caller["callers"], indent + "  ")


def _print_trace_string(result: dict) -> None:
    """Print string trace result as human-readable text."""
    search_text = result["search_text"]
    db_name = result["db"]

    print(f"String Trace: \"{search_text}\"")
    print(f"{'=' * 60}")
    print(f"Searching in {db_name}...")

    functions = result.get("functions", [])
    if not functions:
        print(f"\nNo functions reference a string matching \"{search_text}\".")
        return

    print(f"Found {len(functions)} function(s) referencing matching strings.\n")

    for func_data in functions:
        fname = func_data["function_name"]
        sig = func_data.get("function_signature") or "(unknown)"
        matched = func_data["matched_strings"]

        print(f"\n{'-' * 60}")
        print(f"Function: {fname}  [ID={func_data['function_id']}]")
        print(f"Signature: {sig}")
        print(f"Matched strings ({len(matched)}):")
        for ms in matched[:10]:
            display = ms[:80] + "..." if len(ms) > 80 else ms
            print(f"  \"{display}\"")
        if len(matched) > 10:
            print(f"  ... ({len(matched) - 10} more)")

        # Show decompiled code context
        context_lines = func_data.get("code_context", [])
        if context_lines:
            print(f"\nDecompiled code context ({len(context_lines)} lines):")
            for cl in context_lines[:10]:
                print(f"  L{cl['line_number']:>4}: {cl['line']}")
            if len(context_lines) > 10:
                print(f"  ... ({len(context_lines) - 10} more lines)")

        # Show assembly context
        asm_lines = func_data.get("assembly_context", [])
        if asm_lines:
            print(f"\nAssembly context ({len(asm_lines)} lines):")
            for al in asm_lines[:5]:
                print(f"  L{al['line_number']:>4}: {al['line']}")

        # Show callers
        if "callers" in func_data:
            print(f"\nCaller chain:")
            _print_callers(func_data["callers"])


def _print_function_strings(result: dict) -> None:
    """Print function strings result as human-readable text."""
    if result.get("status") == "not_found":
        print(f"Function '{result['function_name']}' not found in {result['db']}.")
        return

    for func_data in result.get("functions", []):
        fname = func_data["function_name"]
        sig = func_data.get("function_signature") or "(unknown)"
        strings = func_data.get("strings", [])

        print(f"Strings in {fname}")
        print(f"{'=' * 60}")
        print(f"Signature: {sig}")
        print(f"Total strings: {func_data.get('string_count', len(strings))}")

        if not strings:
            print("(no string literals)")
            continue

        for s_entry in strings:
            display = s_entry["value"]
            if isinstance(display, str) and len(display) > 100:
                display = display[:100] + "..."
            print(f"\n  [{s_entry['index']}] \"{display}\"")

            for cl in s_entry.get("code_context", [])[:3]:
                print(f"       L{cl['line_number']}: {cl['line']}")

        if "callers" in func_data:
            print(f"\nCaller chain for {fname}:")
            _print_callers(func_data["callers"])


def _print_list_strings(result: dict) -> None:
    """Print list-strings result as human-readable text."""
    strings_data = result.get("strings", [])

    if not strings_data:
        print("No string literals found.")
        return

    total = result.get("total_unique", len(strings_data))
    limit = result.get("limit", 100)

    print(f"Unique strings: {total}")
    print(f"{'=' * 60}")
    print(f"{'Refs':>4}  {'String':<60}  Functions")
    print(f"{'-' * 4}  {'-' * 60}  {'-' * 30}")

    for s_entry in strings_data:
        s = s_entry["value"]
        funcs = s_entry["functions"]
        display = s[:58] + ".." if len(s) > 60 else s
        func_display = ", ".join(funcs[:3])
        if len(funcs) > 3:
            func_display += f" +{len(funcs) - 3}"
        print(f"{s_entry['reference_count']:>4}  \"{display}\"  {func_display}")

    if result.get("truncated"):
        print(f"\n... ({total - limit} more strings, use --limit to see more)")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="String origin tracking: trace how string literals flow through the binary.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("db_path", help="Path to the module's analysis DB")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--string", dest="search_string", help="String text to search for (partial match)")
    group.add_argument("--function", dest="function_name", help="Show all strings used by this function")
    group.add_argument("--id", "--function-id", dest="function_id", type=int,
                       help="Show all strings used by this function (by ID, preferred after initial lookup)")
    group.add_argument("--list-strings", action="store_true", help="List all unique strings in the module")
    parser.add_argument("--callers", action="store_true", help="Show caller chain for each referencing function")
    parser.add_argument("--depth", type=int, default=1, help="Max caller chain depth (default: 1)")
    parser.add_argument("--limit", type=int, default=100, help="Limit for --list-strings (default: 100)")
    parser.add_argument("--assembly", action="store_true", help="Include assembly context")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--app-only", action="store_true", help="Skip library-tagged functions (from function_index)")
    parser.add_argument("--no-cache", action="store_true", help="Bypass cache and force fresh analysis")
    args = safe_parse_args(parser)

    db_path = resolve_db_path(args.db_path)

    if args.list_strings:
        cache_params = {"mode": "list", "limit": args.limit}
        if not args.no_cache:
            cached = get_cached(db_path, "string_trace", params=cache_params)
            if cached is not None:
                if args.json:
                    emit_json(cached)
                else:
                    _print_list_strings(cached)
                return

        result = list_strings(db_path, limit=args.limit)
        cache_result(db_path, "string_trace", result, params=cache_params)
        if args.json:
            emit_json(result)
        else:
            _print_list_strings(result)

    elif args.search_string:
        cache_params = {
            "mode": "string",
            "string": args.search_string,
            "callers": args.callers,
            "depth": args.depth,
        }
        if args.assembly:
            cache_params["assembly"] = True
        if not args.no_cache:
            cached = get_cached(db_path, "string_trace", params=cache_params)
            if cached is not None:
                if args.json:
                    emit_json(cached)
                else:
                    _print_trace_string(cached)
                return

        result = trace_string(
            db_path=db_path,
            search_text=args.search_string,
            show_callers=args.callers,
            max_depth=args.depth,
            show_assembly=args.assembly,
        )
        cache_result(db_path, "string_trace", result, params=cache_params)
        if args.json:
            emit_json(result)
        else:
            _print_trace_string(result)

    elif args.function_name or args.function_id:
        cache_key = args.function_name or f"id:{args.function_id}"
        cache_params = {
            "mode": "function",
            "function": cache_key,
            "callers": args.callers,
            "depth": args.depth,
        }
        if not args.no_cache:
            cached = get_cached(db_path, "string_trace", params=cache_params)
            if cached is not None:
                if args.json:
                    emit_json(cached)
                else:
                    _print_function_strings(cached)
                return

        result = trace_function_strings(
            db_path=db_path,
            function_name=args.function_name,
            function_id=args.function_id,
            show_callers=args.callers,
            max_depth=args.depth,
        )

        if args.json and result.get("status") == "not_found":
            fname = args.function_name or f"ID={args.function_id}"
            emit_error(f"Function '{fname}' not found", ErrorCode.NOT_FOUND)

        cache_result(db_path, "string_trace", result, params=cache_params)
        if args.json:
            emit_json(result)
        else:
            _print_function_strings(result)


if __name__ == "__main__":
    main()
