#!/usr/bin/env python3
"""Categorize and aggregate all string literals across a module.

Usage:
    python .agent/skills/generate-re-report/scripts/analyze_strings.py <db_path>
    python .agent/skills/generate-re-report/scripts/analyze_strings.py <db_path> --json
    python .agent/skills/generate-re-report/scripts/analyze_strings.py <db_path> --top 20
    python .agent/skills/generate-re-report/scripts/analyze_strings.py <db_path> --category file_path
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import (
    open_analysis_db,
    parse_json_safe,
    resolve_db_path,
    truncate_string,
)
from helpers.cache import get_cached, cache_result
from helpers.errors import db_error_handler, safe_parse_args
from helpers.json_output import emit_json


def analyze_strings(db_path: str, *, no_cache: bool = False) -> dict:
    """Collect all strings across all functions and categorize them.

    Returns dict with keys:
        categories: {category: [{string, functions: [name], count}]}
        summary: {category: unique_string_count}
        total_unique_strings: int
        total_string_refs: int (sum of all function-string references)
        uncategorized_sample: [string] (first 50 uncategorized)
        top_referenced: [{string, category, function_count}] (most widely referenced)
    """
    if not no_cache:
        cached = get_cached(db_path, "analyze_strings")
        if cached is not None:
            return cached

    with db_error_handler(db_path, "analyzing strings"):
        with open_analysis_db(db_path) as db:
            all_funcs = db.get_all_functions()

    # Map: string -> {functions: set, category, description}
    string_index: dict[str, dict] = {}
    total_refs = 0

    for func in all_funcs:
        strings = parse_json_safe(func.string_literals) or []
        if not isinstance(strings, list):
            continue

        fname = func.function_name or f"sub_{func.function_id}"

        for s in strings:
            if not isinstance(s, str) or not s.strip():
                continue
            # Skip very long strings (likely data blobs)
            if len(s) > 500:
                continue

            total_refs += 1
            s_key = s.strip()

            if s_key not in string_index:
                string_index[s_key] = {
                    "string": s_key,
                    "category": "uncategorized",
                    "description": "",
                    "functions": set(),
                }
            string_index[s_key]["functions"].add(fname)

    # Group by category
    categories: dict[str, list[dict]] = defaultdict(list)
    uncategorized: list[str] = []

    for s_key, info in string_index.items():
        entry = {
            "string": info["string"],
            "functions": sorted(info["functions"]),
            "count": len(info["functions"]),
        }
        if info["category"] == "uncategorized":
            uncategorized.append(s_key)
        else:
            categories[info["category"]].append(entry)

    # Sort each category by reference count
    for cat in categories:
        categories[cat].sort(key=lambda x: -x["count"])

    # Summary
    summary = {cat: len(entries) for cat, entries in categories.items()}
    summary = dict(sorted(summary.items(), key=lambda x: -x[1]))

    # Top referenced strings (across all categories)
    all_entries = []
    for cat, entries in categories.items():
        for e in entries:
            all_entries.append({**e, "category": cat})
    all_entries.sort(key=lambda x: -x["count"])

    result = {
        "categories": dict(sorted(categories.items(), key=lambda x: -len(x[1]))),
        "summary": summary,
        "total_unique_strings": len(string_index),
        "total_string_refs": total_refs,
        "uncategorized_count": len(uncategorized),
        "uncategorized_sample": uncategorized[:50],
        "top_referenced": all_entries[:30],
    }

    cache_result(db_path, "analyze_strings", result)
    return result


def format_string_report(result: dict, top_n: int = 10, category_filter: str | None = None) -> str:
    """Format string analysis as markdown."""
    lines = []
    lines.append("## String Intelligence\n")

    total_unique = result.get("total_unique_strings", 0)
    total_refs = result.get("total_string_refs", 0)
    uncat = result.get("uncategorized_count", 0)

    lines.append(f"**{total_unique:,} unique strings** across **{total_refs:,} references**")
    lines.append(f"({uncat:,} uncategorized)\n")

    # Summary table
    summary = result.get("summary", {})
    if summary:
        lines.append("| Category | Unique Strings |")
        lines.append("|---|---|")
        for cat, count in summary.items():
            lines.append(f"| {cat} | {count} |")
        lines.append("")

    # Per-category details
    categories = result.get("categories", {})
    for cat, entries in categories.items():
        if category_filter and cat != category_filter:
            continue
        lines.append(f"### {cat} ({len(entries)} strings)\n")

        shown = entries[:top_n]
        for e in shown:
            s = truncate_string(e["string"], 100)
            funcs = e["functions"][:5]
            func_str = ", ".join(f"`{f}`" for f in funcs)
            if len(e["functions"]) > 5:
                func_str += f" _+{len(e['functions']) - 5} more_"
            lines.append(f"- `{s}` ({e['count']} refs: {func_str})")

        if len(entries) > top_n:
            lines.append(f"- _... and {len(entries) - top_n} more_")
        lines.append("")

    # Top referenced strings
    top = result.get("top_referenced", [])
    if top and not category_filter:
        lines.append("### Most Widely Referenced Strings\n")
        lines.append("| String | Category | Referenced By |")
        lines.append("|---|---|---|")
        for e in top[:top_n]:
            s = truncate_string(e["string"], 60)
            lines.append(f"| `{s}` | {e['category']} | {e['count']} functions |")
        lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Categorize all string literals in a module")
    parser.add_argument("db_path", help="Path to individual analysis DB")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--top", type=int, default=10, help="Show top N per category (default: 10)")
    parser.add_argument("--category", type=str, default=None, help="Filter to one category")
    parser.add_argument("--no-cache", action="store_true", help="Bypass result cache")
    args = safe_parse_args(parser)

    result = analyze_strings(args.db_path, no_cache=args.no_cache)

    if args.json:
        emit_json(result, default=str)
    else:
        print(format_string_report(result, top_n=args.top, category_filter=args.category))


if __name__ == "__main__":
    main()
