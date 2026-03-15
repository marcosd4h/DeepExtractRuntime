#!/usr/bin/env python3
"""Generate a high-level triage summary for a module.

Usage:
    python triage_summary.py <db_path>
    python triage_summary.py <db_path> --json
    python triage_summary.py <db_path> --top 20

Examples:
    python triage_summary.py extracted_dbs/appinfo_dll_e98d25a9e8.db
    python triage_summary.py extracted_dbs/cmd_exe_6d109a3a00.db --top 20
    python triage_summary.py extracted_dbs/coredpus_dll_319f60b0a5.db --json

Output:
    High-level module overview: category distribution, API usage breakdown,
    complexity metrics, and top-N most interesting functions to investigate.
    Designed for quick triage of 1000+ function binaries.
"""

from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from pathlib import Path

from _common import (
    WORKSPACE_ROOT,
    CATEGORIES,
    LOW_INTEREST_CATEGORIES,
    ClassificationResult,
    classify_function,
    parse_json_safe,
    resolve_db_path,
)

from helpers import open_individual_analysis_db, load_function_index_for_db, compute_stats, filter_by_library
from helpers.cache import cache_result, get_cached
from helpers.errors import db_error_handler, safe_parse_args
from helpers.json_output import emit_json


def generate_triage(db_path: str, app_only: bool = False, *, no_cache: bool = False) -> dict:
    """Run full classification and compute triage metrics.

    Args:
        db_path: Path to the individual analysis DB.
        app_only: When True, pre-filter library functions before classification.
        no_cache: When True, bypass cache and recompute from scratch.

    Returns a dict with all triage data (usable for both text and JSON output).
    """
    params = {"app_only": app_only}
    if not no_cache:
        cached = get_cached(db_path, "triage_summary", params=params)
        if cached is not None:
            return cached

    # Load function_index for library-tag classification signals
    function_index = load_function_index_for_db(db_path)

    with db_error_handler(db_path, "generating triage summary"):
        with open_individual_analysis_db(db_path) as db:
            file_info = db.get_file_info()
            module_info = {
                "file_name": file_info.file_name if file_info else "(unknown)",
                "file_description": file_info.file_description if file_info else "",
                "company_name": file_info.company_name if file_info else "",
                "product_name": file_info.product_name if file_info else "",
                "file_version": file_info.file_version if file_info else "",
                "pdb_path": file_info.pdb_path if file_info else "",
            }

            # Classify all functions (with function_index for ground-truth signals)
            functions = db.get_all_functions()

            # Build app-only name set for pre-filtering
            app_names = None
            if app_only and function_index:
                app_names = set(filter_by_library(function_index, app_only=True).keys())

            results: list[ClassificationResult] = []
            for func in functions:
                if app_names is not None and func.function_name not in app_names:
                    continue
                results.append(classify_function(func, function_index=function_index))

        total = len(results)

        # Category distribution
        by_category: dict[str, list[ClassificationResult]] = defaultdict(list)
        for r in results:
            by_category[r.primary_category].append(r)

        category_dist = {}
        for cat in CATEGORIES:
            count = len(by_category.get(cat, []))
            if count > 0:
                category_dist[cat] = count

        # Library distribution (ground-truth from function_index)
        library_distribution = None
        if function_index:
            idx_stats = compute_stats(function_index)
            library_distribution = {
                "total_indexed": idx_stats["total_functions"],
                "app_functions": idx_stats["app_functions"],
                "library_functions": idx_stats["library_functions"],
                "library_breakdown": idx_stats["library_breakdown"],
            }

        # Noise vs signal
        noise_count = sum(len(by_category.get(c, [])) for c in LOW_INTEREST_CATEGORIES)
        signal_count = total - noise_count
        unknown_count = len(by_category.get("unknown", []))

        # Complexity metrics
        total_loops = sum(r.loop_count for r in results)
        functions_with_loops = sum(1 for r in results if r.loop_count > 0)
        functions_with_decompiled = sum(1 for r in results if r.has_decompiled)
        functions_with_dangerous = sum(1 for r in results if r.dangerous_api_count > 0)
        total_dangerous = sum(r.dangerous_api_count for r in results)

        # API category usage across entire module
        api_usage: dict[str, int] = defaultdict(int)
        for r in results:
            for cat, sigs in r.signals.items():
                for sig in sigs:
                    if sig.startswith("api:"):
                        api_usage[cat] += 1

        interesting = sorted(results, key=lambda r: (-r.interest_score, -r.loop_count))

        most_complex = sorted(results, key=lambda r: (-r.loop_count, -r.dangerous_api_count))

        data = {
            "module_info": module_info,
            "total_functions": total,
            "category_distribution": category_dist,
            "library_distribution": library_distribution,
            "noise_count": noise_count,
            "signal_count": signal_count,
            "unknown_count": unknown_count,
            "metrics": {
                "functions_with_decompiled": functions_with_decompiled,
                "functions_with_loops": functions_with_loops,
                "total_loops": total_loops,
                "functions_with_dangerous_apis": functions_with_dangerous,
                "total_dangerous_api_refs": total_dangerous,
            },
            "api_category_usage": dict(api_usage),
            "top_interesting": [r.to_dict() for r in interesting[:30]],
            "most_complex": [
                {"function_id": r.function_id, "function_name": r.function_name,
                 "loop_count": r.loop_count, "category": r.primary_category,
                 "interest": r.interest_score}
                for r in most_complex[:15] if most_complex and most_complex[0].loop_count > 0
            ],
        }

        cache_result(db_path, "triage_summary", data, params=params)
        return data


def print_text_triage(data: dict, top_n: int = 10) -> None:
    """Print human-readable triage summary."""
    mi = data["module_info"]
    total = data["total_functions"]

    print(f"{'#' * 80}")
    print(f"  MODULE TRIAGE SUMMARY")
    print(f"{'#' * 80}")
    print(f"  Module:      {mi['file_name']}")
    if mi.get("file_description"):
        print(f"  Description: {mi['file_description']}")
    if mi.get("company_name"):
        print(f"  Company:     {mi['company_name']}")
    if mi.get("file_version"):
        print(f"  Version:     {mi['file_version']}")
    if mi.get("pdb_path"):
        print(f"  PDB:         {mi['pdb_path']}")
    print()

    m = data["metrics"]
    print(f"  Total functions:         {total}")
    print(f"  With decompiled code:    {m['functions_with_decompiled']}")
    print(f"  Signal (interesting):    {data['signal_count']}")
    print(f"  Noise (infra/compiler):  {data['noise_count']}")
    print(f"  Unclassified:            {data['unknown_count']}")
    print(f"  With dangerous APIs:     {m['functions_with_dangerous_apis']} ({m['total_dangerous_api_refs']} refs)")
    print(f"  With loops:              {m['functions_with_loops']} ({m['total_loops']} total loops)")
    print()

    # Category distribution
    print(f"  CATEGORY DISTRIBUTION:")
    print(f"  {'Category':<22} {'Count':>6} {'%':>6}  {'Bar'}")
    print(f"  {'-' * 22} {'-' * 6} {'-' * 6}  {'-' * 40}")
    for cat in CATEGORIES:
        count = data["category_distribution"].get(cat, 0)
        if count == 0:
            continue
        pct = (count / total * 100) if total > 0 else 0
        bar_len = int(pct / 2.5)
        bar = "#" * bar_len
        marker = " *" if cat in LOW_INTEREST_CATEGORIES else ""
        print(f"  {cat:<22} {count:>6} {pct:>5.1f}%  {bar}{marker}")
    print(f"\n  * = low-interest infrastructure\n")

    # Library distribution (ground-truth from function_index)
    lib_dist = data.get("library_distribution")
    if lib_dist:
        print(f"  LIBRARY DISTRIBUTION (from function_index, ground-truth):")
        print(f"    Application code:  {lib_dist['app_functions']:>5}")
        print(f"    Library code:      {lib_dist['library_functions']:>5}")
        if lib_dist["library_breakdown"]:
            for tag, count in sorted(lib_dist["library_breakdown"].items()):
                print(f"      {tag:<20} {count:>5}")
        lib_pct = lib_dist["library_functions"] / lib_dist["total_indexed"] * 100 if lib_dist["total_indexed"] else 0
        print(f"    Noise ratio:       {lib_pct:.0f}% library code")
        print()

    # API category usage
    if data["api_category_usage"]:
        print(f"  API USAGE BY CATEGORY (functions using each API type):")
        for cat, count in sorted(data["api_category_usage"].items(), key=lambda x: -x[1]):
            print(f"    {cat:<22} {count:>5} function(s)")
        print()

    # Top interesting functions
    top = data["top_interesting"][:top_n]
    if top:
        print(f"  TOP {len(top)} MOST INTERESTING FUNCTIONS:")
        print(f"  {'ID':>6}  {'Int':>3}  {'Category':<22}  {'Loops':>5}  {'Name'}")
        print(f"  {'-' * 6}  {'-' * 3}  {'-' * 22}  {'-' * 5}  {'-' * 40}")
        for f in top:
            name = f["function_name"] or "(unnamed)"
            if len(name) > 40:
                name = name[:37] + "..."
            print(
                f"  {f['function_id']:>6}  "
                f"{f['interest_score']:>3}  "
                f"{f['primary_category']:<22}  "
                f"{f['loop_count']:>5}  "
                f"{name}"
            )
        print()

    # Most complex
    most_complex = data["most_complex"][:10]
    if most_complex:
        print(f"  MOST COMPLEX FUNCTIONS (by loop count):")
        print(f"  {'ID':>6}  {'Loops':>5}  {'Category':<22}  {'Name'}")
        print(f"  {'-' * 6}  {'-' * 5}  {'-' * 22}  {'-' * 40}")
        for f in most_complex:
            name = f["function_name"] or "(unnamed)"
            if len(name) > 40:
                name = name[:37] + "..."
            print(f"  {f['function_id']:>6}  {f['loop_count']:>5}  {f['category']:<22}  {name}")
        print()

    # Triage recommendation
    print(f"  TRIAGE RECOMMENDATION:")
    if data["metrics"]["functions_with_dangerous_apis"] > 0:
        print(f"    - {m['functions_with_dangerous_apis']} functions use dangerous APIs -- review these first")
    if data["category_distribution"].get("security", 0) > 0:
        print(f"    - {data['category_distribution']['security']} security-related functions to audit")
    if data["category_distribution"].get("crypto", 0) > 0:
        print(f"    - {data['category_distribution']['crypto']} crypto functions -- check implementation correctness")
    if data["noise_count"] > total * 0.3:
        pct = data["noise_count"] / total * 100
        print(f"    - {pct:.0f}% of functions are infrastructure noise -- use --app-only or --no-telemetry --no-compiler to filter")
    if data["unknown_count"] > total * 0.2:
        print(f"    - {data['unknown_count']} unclassified functions -- may need manual review")
    print(f"    - Focus on the top {min(top_n, len(top))} functions listed above (highest interest scores)")
    print(f"    - Use classify_function.py for detailed analysis of specific functions")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a high-level triage summary for a module.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("db_path", help="Path to the individual analysis DB")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--top", type=int, default=10, help="Number of top functions to show (default: 10)")
    parser.add_argument("--app-only", action="store_true", help="Exclude library/boilerplate functions (WIL/STL/WRL/CRT/ETW)")
    parser.add_argument("--no-cache", action="store_true", help="Bypass result cache and recompute from scratch")
    args = safe_parse_args(parser)

    db_path = resolve_db_path(args.db_path)
    data = generate_triage(db_path, app_only=args.app_only, no_cache=args.no_cache)

    if args.json:
        emit_json(data)
    else:
        print_text_triage(data, top_n=args.top)


if __name__ == "__main__":
    main()
