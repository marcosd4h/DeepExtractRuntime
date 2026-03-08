#!/usr/bin/env python3
"""Categorize and aggregate string literals across a module or single function.

Usage:
    python analyze_strings_deep.py <db_path>
    python analyze_strings_deep.py <db_path> --json
    python analyze_strings_deep.py <db_path> --id <func_id>
    python analyze_strings_deep.py <db_path> --function <name>
    python analyze_strings_deep.py <db_path> --top 20 --category file_path
"""

from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT_DIR))

from _common import (
    categorize_string,
    emit_error,
    open_individual_analysis_db,
    parse_json_safe,
    resolve_db_path,
)

from helpers.cache import cache_result, get_cached
from helpers.errors import ErrorCode, db_error_handler, safe_parse_args
from helpers.json_output import emit_json
from helpers.function_resolver import resolve_function
from helpers.validation import validate_function_id


def _truncate(s: str, max_len: int = 100) -> str:
    if len(s) <= max_len:
        return s
    return s[: max_len - 3] + "..."


def analyze_strings(
    db_path: str,
    *,
    function_id: int | None = None,
    function_name: str | None = None,
    no_cache: bool = False,
) -> dict:
    """Collect strings and categorize them.

    If *function_id* or *function_name* is given, only that function's
    strings are analyzed. Otherwise scans all functions in the module.
    """
    cache_key = "string_analysis"
    cache_params = {}
    if function_id is not None:
        cache_params["function_id"] = function_id
    elif function_name is not None:
        cache_params["function_name"] = function_name

    if not no_cache and not cache_params:
        cached = get_cached(db_path, cache_key, cache_params or None)
        if cached is not None:
            return cached

    with db_error_handler(db_path, "analyzing strings"):
        with open_individual_analysis_db(db_path) as db:
            if function_id is not None or function_name is not None:
                func, err = resolve_function(
                    db, name=function_name, function_id=function_id,
                )
                if err:
                    emit_error(f"[{Path(db_path).stem}] {err}", ErrorCode.NOT_FOUND)
                funcs = [func]
            else:
                funcs = db.get_all_functions()

    string_index: dict[str, dict] = {}
    total_refs = 0

    for func in funcs:
        strings = parse_json_safe(func.string_literals) or []
        if not isinstance(strings, list):
            continue

        fname = func.function_name or f"sub_{func.function_id}"

        for s in strings:
            if not isinstance(s, str) or not s.strip():
                continue
            if len(s) > 500:
                continue

            total_refs += 1
            s_key = s.strip()

            if s_key not in string_index:
                cat_result = categorize_string(s_key)
                string_index[s_key] = {
                    "string": s_key,
                    "category": cat_result[0] if cat_result else "uncategorized",
                    "description": cat_result[1] if cat_result else "",
                    "functions": set(),
                }
            string_index[s_key]["functions"].add(fname)

    categories: dict[str, list[dict]] = defaultdict(list)
    uncategorized: list[str] = []

    for s_key, info in string_index.items():
        entry = {
            "string": info["string"],
            "functions": sorted(info["functions"]),
            "count": len(info["functions"]),
            "description": info["description"],
        }
        if info["category"] == "uncategorized":
            uncategorized.append(s_key)
        else:
            categories[info["category"]].append(entry)

    for cat in categories:
        categories[cat].sort(key=lambda x: -x["count"])

    summary = {cat: len(entries) for cat, entries in categories.items()}
    summary = dict(sorted(summary.items(), key=lambda x: -x[1]))

    all_entries = []
    for cat, entries in categories.items():
        for e in entries:
            all_entries.append({**e, "category": cat})
    all_entries.sort(key=lambda x: -x["count"])

    result = {
        "status": "ok",
        "categories": dict(sorted(categories.items(), key=lambda x: -len(x[1]))),
        "summary": summary,
        "total_unique_strings": len(string_index),
        "total_string_refs": total_refs,
        "uncategorized_count": len(uncategorized),
        "uncategorized_sample": uncategorized[:50],
        "top_referenced": all_entries[:30],
        "_meta": {
            "db": str(db_path),
            "generated": datetime.now(timezone.utc).isoformat(),
            "params": {
                "function_id": function_id,
                "function_name": function_name,
            },
        },
    }

    if not cache_params:
        cache_result(db_path, cache_key, result, cache_params or None)

    return result


def _print_text(result: dict, top_n: int = 10, category_filter: str | None = None) -> None:
    """Print human-readable string analysis."""
    total_unique = result.get("total_unique_strings", 0)
    total_refs = result.get("total_string_refs", 0)
    uncat = result.get("uncategorized_count", 0)

    print(f"\n=== String Intelligence ===\n")
    print(f"{total_unique:,} unique strings across {total_refs:,} references "
          f"({uncat:,} uncategorized)\n")

    summary = result.get("summary", {})
    if summary:
        print(f"{'Category':<22} {'Unique Strings':>14}")
        print(f"{'-' * 22} {'-' * 14}")
        for cat, count in summary.items():
            print(f"{cat:<22} {count:>14}")
        print()

    categories = result.get("categories", {})
    for cat, entries in categories.items():
        if category_filter and cat != category_filter:
            continue
        print(f"--- {cat} ({len(entries)} strings) ---\n")
        for e in entries[:top_n]:
            s = _truncate(e["string"], 80)
            funcs = e["functions"][:5]
            func_str = ", ".join(funcs)
            if len(e["functions"]) > 5:
                func_str += f" +{len(e['functions']) - 5} more"
            print(f"  [{e['count']:>3} refs] {s}")
            print(f"           {func_str}")
        if len(entries) > top_n:
            print(f"  ... and {len(entries) - top_n} more")
        print()

    top = result.get("top_referenced", [])
    if top and not category_filter:
        print(f"--- Most Widely Referenced ---\n")
        for e in top[:top_n]:
            s = _truncate(e["string"], 60)
            print(f"  [{e['count']:>3} refs] [{e['category']}] {s}")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="Deep string analysis for security-relevant patterns",
    )
    parser.add_argument("db_path", help="Path to the individual analysis database")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--id", type=int, dest="function_id", help="Function ID")
    group.add_argument("--function", dest="function_name", help="Function name")
    parser.add_argument("--json", action="store_true", help="JSON output mode")
    parser.add_argument("--top", type=int, default=10, help="Top N per category (default: 10)")
    parser.add_argument("--category", type=str, default=None, help="Filter to one category")
    parser.add_argument("--no-cache", action="store_true", help="Bypass result cache")
    args = safe_parse_args(parser)

    db_path = resolve_db_path(args.db_path)
    if args.function_id is not None:
        args.function_id = validate_function_id(args.function_id)

    result = analyze_strings(
        db_path,
        function_id=args.function_id,
        function_name=args.function_name,
        no_cache=args.no_cache,
    )

    if args.json:
        emit_json(result, default=str)
    else:
        _print_text(result, top_n=args.top, category_filter=args.category)


if __name__ == "__main__":
    main()
