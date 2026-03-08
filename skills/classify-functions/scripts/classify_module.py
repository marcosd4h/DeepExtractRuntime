#!/usr/bin/env python3
"""Classify all functions in a module by purpose category.

Usage:
    python classify_module.py <db_path>
    python classify_module.py <db_path> --json
    python classify_module.py <db_path> --category security
    python classify_module.py <db_path> --min-interest 5
    python classify_module.py <db_path> --no-telemetry --no-compiler

Examples:
    python classify_module.py extracted_dbs/appinfo_dll_e98d25a9e8.db
    python classify_module.py extracted_dbs/appinfo_dll_e98d25a9e8.db --json
    python classify_module.py extracted_dbs/cmd_exe_6d109a3a00.db --category crypto --category security
    python classify_module.py extracted_dbs/appinfo_dll_e98d25a9e8.db --min-interest 4 --no-telemetry

Output:
    Categorized function index for the entire module. Default is human-readable
    text with category distribution and per-category function lists.
    Use --json for machine-readable output.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

# Import shared utilities (sets up sys.path)
from _common import (
    WORKSPACE_ROOT,
    CATEGORIES,
    LOW_INTEREST_CATEGORIES,
    AsmMetrics,
    ClassificationResult,
    classify_function,
    resolve_db_path,
)

from helpers import (
    filter_by_library,
    filter_decompiled,
    load_function_index_for_db,
    open_individual_analysis_db,
)
from helpers.errors import db_error_handler, safe_parse_args
from helpers.cache import cache_result, get_cached
from helpers.json_output import emit_json
from helpers.progress import progress_iter


def _result_to_cacheable(r: ClassificationResult) -> dict:
    """Serialize a ClassificationResult to a JSON-safe dict (lossless)."""
    d = r.to_dict()
    if r.asm_metrics:
        d["_asm_metrics"] = {
            "instruction_count": r.asm_metrics.instruction_count,
            "call_count": r.asm_metrics.call_count,
            "branch_count": r.asm_metrics.branch_count,
            "ret_count": r.asm_metrics.ret_count,
            "has_syscall": r.asm_metrics.has_syscall,
            "is_leaf": r.asm_metrics.is_leaf,
            "is_tiny": r.asm_metrics.is_tiny,
        }
    return d


def _result_from_cached(d: dict) -> ClassificationResult:
    """Reconstruct a ClassificationResult from a cached dict."""
    asm = None
    asm_data = d.get("_asm_metrics")
    if asm_data:
        asm = AsmMetrics(**asm_data)
    elif d.get("asm_instruction_count", 0) or d.get("asm_call_count", 0):
        asm = AsmMetrics(
            instruction_count=d.get("asm_instruction_count", 0),
            call_count=d.get("asm_call_count", 0),
        )
    return ClassificationResult(
        function_id=d["function_id"],
        function_name=d["function_name"],
        primary_category=d["primary_category"],
        secondary_categories=d.get("secondary_categories", []),
        scores=d.get("scores", {}),
        signals=d.get("signals", {}),
        interest_score=d.get("interest_score", 0),
        asm_metrics=asm,
        has_decompiled=d.get("has_decompiled", False),
        loop_count=d.get("loop_count", 0),
        api_count=d.get("api_count", 0),
        string_count=d.get("string_count", 0),
        dangerous_api_count=d.get("dangerous_api_count", 0),
    )


def classify_all_functions(
    db_path: str,
    function_index: dict | None = None,
    *,
    no_cache: bool = False,
) -> tuple[dict, list[ClassificationResult]]:
    """Classify every function in a module DB.

    Args:
        db_path: Path to the individual analysis DB.
        function_index: Optional pre-loaded function_index dict. If None,
            will be auto-loaded from the DB's module name.
        no_cache: When True, bypass cache and recompute from scratch.

    Returns:
        (module_info_dict, list_of_ClassificationResult)
    """
    if not no_cache:
        cached = get_cached(db_path, "classify_module")
        if cached is not None:
            return cached["module_info"], [_result_from_cached(r) for r in cached["results"]]

    # Auto-load function_index if not provided
    if function_index is None:
        function_index = load_function_index_for_db(db_path)

    with db_error_handler(db_path, "classifying module functions"):
        with open_individual_analysis_db(db_path) as db:
            file_info = db.get_file_info()
            module_info = {
                "file_name": file_info.file_name if file_info else "(unknown)",
                "file_description": file_info.file_description if file_info else "",
                "company_name": file_info.company_name if file_info else "",
                "db_path": db_path,
            }

            functions = db.get_all_functions()
            results = []
            for func in progress_iter(functions, label="classify_module", json_mode=no_cache):
                result = classify_function(func, function_index=function_index)
                results.append(result)

    cache_result(db_path, "classify_module", {
        "module_info": module_info,
        "results": [_result_to_cacheable(r) for r in results],
    })

    return module_info, results


def print_text_output(
    module_info: dict,
    results: list[ClassificationResult],
    filter_categories: list[str] | None = None,
    min_interest: int = 0,
    exclude_telemetry: bool = False,
    exclude_compiler: bool = False,
    app_only: bool = False,
    function_index: dict | None = None,
) -> None:
    """Print human-readable categorized function index."""
    # Apply filters
    filtered = results
    if app_only and function_index:
        app_index = filter_by_library(function_index, app_only=True)
        app_index = filter_decompiled(app_index, decompiled=True)
        app_names = set(app_index.keys())
        filtered = [r for r in filtered if r.function_name in app_names]
    if exclude_telemetry:
        filtered = [r for r in filtered if r.primary_category != "telemetry"]
    if exclude_compiler:
        filtered = [r for r in filtered if r.primary_category != "compiler_generated"]
    if min_interest > 0:
        filtered = [r for r in filtered if r.interest_score >= min_interest]
    if filter_categories:
        filtered = [r for r in filtered if r.primary_category in filter_categories]

    # Module header
    print(f"{'#' * 80}")
    print(f"  MODULE FUNCTION CLASSIFICATION")
    print(f"  Module: {module_info['file_name']}")
    if module_info.get("file_description"):
        print(f"  Description: {module_info['file_description']}")
    if module_info.get("company_name"):
        print(f"  Company: {module_info['company_name']}")
    print(f"  Total functions: {len(results)}")
    if len(filtered) != len(results):
        print(f"  Shown (after filters): {len(filtered)}")
    print(f"{'#' * 80}\n")

    # Category distribution (always show full, even when filtered)
    by_category: dict[str, list[ClassificationResult]] = defaultdict(list)
    for r in results:
        by_category[r.primary_category].append(r)

    print("CATEGORY DISTRIBUTION:")
    print(f"{'Category':<22} {'Count':>6} {'%':>6}  {'Bar'}")
    print(f"{'-' * 22} {'-' * 6} {'-' * 6}  {'-' * 40}")
    total = len(results)
    for cat in CATEGORIES:
        count = len(by_category.get(cat, []))
        if count == 0:
            continue
        pct = (count / total * 100) if total > 0 else 0
        bar_len = int(pct / 2.5)
        bar = "#" * bar_len
        marker = " *" if cat in LOW_INTEREST_CATEGORIES else ""
        print(f"{cat:<22} {count:>6} {pct:>5.1f}%  {bar}{marker}")
    print(f"\n  * = low-interest infrastructure category\n")

    # Per-category function lists
    if filter_categories:
        cats_to_show = filter_categories
    else:
        cats_to_show = [c for c in CATEGORIES if by_category.get(c)]

    for cat in cats_to_show:
        cat_results = by_category.get(cat, [])
        if not cat_results:
            continue

        # Apply per-function filters
        shown = cat_results
        if exclude_telemetry and cat == "telemetry":
            continue
        if exclude_compiler and cat == "compiler_generated":
            continue
        if min_interest > 0:
            shown = [r for r in shown if r.interest_score >= min_interest]
        if not shown:
            continue

        # Sort by interest score descending
        shown.sort(key=lambda r: (-r.interest_score, r.function_name))

        print(f"\n{'=' * 80}")
        print(f"  {cat.upper()} ({len(shown)} function{'s' if len(shown) != 1 else ''})")
        print(f"{'=' * 80}")
        print(f"{'ID':>6}  {'Interest':>8}  {'Loops':>5}  {'ASM':>5}  {'APIs':>5}  {'Function Name'}")
        print(f"{'-' * 6}  {'-' * 8}  {'-' * 5}  {'-' * 5}  {'-' * 5}  {'-' * 50}")
        for r in shown:
            name = r.function_name or "(unnamed)"
            if len(name) > 50:
                name = name[:47] + "..."
            asm_count = r.asm_metrics.instruction_count if r.asm_metrics else 0
            dec = "D" if r.has_decompiled else " "
            print(
                f"{r.function_id:>6}  "
                f"{r.interest_score:>6}  {dec} "
                f"{r.loop_count:>5}  "
                f"{asm_count:>5}  "
                f"{r.api_count:>5}  "
                f"{name}"
            )
            # Show secondary categories if present
            if r.secondary_categories:
                secs = ", ".join(r.secondary_categories)
                print(f"{'':>6}  {'':>8}  {'':>5}  {'':>5}  {'':>5}    also: {secs}")


def print_json_output(
    module_info: dict,
    results: list[ClassificationResult],
    filter_categories: list[str] | None = None,
    min_interest: int = 0,
    exclude_telemetry: bool = False,
    exclude_compiler: bool = False,
    app_only: bool = False,
    function_index: dict | None = None,
) -> None:
    """Print machine-readable JSON output."""
    filtered = results
    if app_only and function_index:
        app_index = filter_by_library(function_index, app_only=True)
        app_index = filter_decompiled(app_index, decompiled=True)
        app_names = set(app_index.keys())
        filtered = [r for r in filtered if r.function_name in app_names]
    if exclude_telemetry:
        filtered = [r for r in filtered if r.primary_category != "telemetry"]
    if exclude_compiler:
        filtered = [r for r in filtered if r.primary_category != "compiler_generated"]
    if min_interest > 0:
        filtered = [r for r in filtered if r.interest_score >= min_interest]
    if filter_categories:
        filtered = [r for r in filtered if r.primary_category in filter_categories]

    # Build per-category output
    by_category: dict[str, list[dict]] = defaultdict(list)
    for r in filtered:
        by_category[r.primary_category].append(r.to_dict())

    # Category stats (always from full results)
    stats: dict[str, int] = defaultdict(int)
    for r in results:
        stats[r.primary_category] += 1

    output = {
        "module": module_info,
        "total_functions": len(results),
        "shown_functions": len(filtered),
        "category_distribution": dict(stats),
        "categories": {cat: funcs for cat, funcs in sorted(by_category.items())},
    }
    emit_json(output)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Classify all functions in a module by purpose category.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("db_path", help="Path to the individual analysis DB")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--category", dest="categories", action="append", help="Filter to specific category (repeatable)")
    parser.add_argument("--min-interest", type=int, default=0, help="Only show functions with interest >= N")
    parser.add_argument("--no-telemetry", action="store_true", help="Exclude telemetry functions")
    parser.add_argument("--no-compiler", action="store_true", help="Exclude compiler-generated functions")
    parser.add_argument("--app-only", action="store_true", help="Exclude library/boilerplate functions (WIL/STL/WRL/CRT/ETW)")
    parser.add_argument("--no-cache", action="store_true", help="Bypass result cache and recompute from scratch")
    args = safe_parse_args(parser)

    db_path = resolve_db_path(args.db_path)
    # Load function_index once (used for both classification and filtering)
    function_index = load_function_index_for_db(db_path)
    module_info, results = classify_all_functions(db_path, function_index=function_index, no_cache=args.no_cache)

    if args.json:
        print_json_output(
            module_info, results,
            filter_categories=args.categories,
            min_interest=args.min_interest,
            exclude_telemetry=args.no_telemetry,
            exclude_compiler=args.no_compiler,
            app_only=args.app_only,
            function_index=function_index,
        )
    else:
        print_text_output(
            module_info, results,
            filter_categories=args.categories,
            min_interest=args.min_interest,
            exclude_telemetry=args.no_telemetry,
            exclude_compiler=args.no_compiler,
            app_only=args.app_only,
            function_index=function_index,
        )


if __name__ == "__main__":
    main()
