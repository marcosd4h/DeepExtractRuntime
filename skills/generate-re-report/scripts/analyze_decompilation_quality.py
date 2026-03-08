#!/usr/bin/env python3
"""Decompilation quality metrics: scan analysis_errors to assess Hex-Rays output quality.

Reads the ``analysis_errors`` JSON field from every function in the DB and
produces per-module statistics: success rates, error categories, problematic
functions, and confidence tiers.

Usage:
    python analyze_decompilation_quality.py <db_path>
    python analyze_decompilation_quality.py <db_path> --json
    python analyze_decompilation_quality.py <db_path> --no-cache

Output:
    Module-wide decompilation quality report with:
    - Overall success rates (decompiled, assembly-only, failed)
    - Error category breakdown
    - Top problematic functions by error count/severity
    - Confidence tiers (high/medium/low quality decompilation)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from _common import (
    WORKSPACE_ROOT,
    open_analysis_db,
    parse_json_safe,
    resolve_db_path,
)
from helpers.cache import get_cached, cache_result
from helpers.errors import db_error_handler, emit_error, safe_parse_args
from helpers.json_output import emit_json


# ---------------------------------------------------------------------------
# Error categorization patterns
# ---------------------------------------------------------------------------

_ERROR_CATEGORIES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"decompil(?:ation|er)\s+fail", re.I), "decompilation_failure"),
    (re.compile(r"timeout|timed?\s*out", re.I), "timeout"),
    (re.compile(r"stack\s+frame|stack\s+variable", re.I), "stack_analysis"),
    (re.compile(r"type\s+(?:error|mismatch|conflict)", re.I), "type_error"),
    (re.compile(r"truncat", re.I), "truncation"),
    (re.compile(r"xref.*(?:limit|cap|max)", re.I), "xref_limit"),
    (re.compile(r"assembl(?:y|er)", re.I), "assembly_error"),
    (re.compile(r"loop\s+(?:analysis|detect)", re.I), "loop_analysis"),
    (re.compile(r"string\s+(?:extract|literal)", re.I), "string_extraction"),
    (re.compile(r"warning", re.I), "warning"),
]


def categorize_error(error_text: str) -> str:
    """Classify an error message into a category."""
    for pattern, category in _ERROR_CATEGORIES:
        if pattern.search(error_text):
            return category
    return "other"


# ---------------------------------------------------------------------------
# Quality tier assignment
# ---------------------------------------------------------------------------

def _assign_quality_tier(
    has_decompiled: bool,
    has_assembly: bool,
    error_count: int,
    warning_count: int,
) -> str:
    """Assign a quality tier to a function's decompilation output."""
    if not has_decompiled:
        return "no_decompilation"
    if not has_assembly:
        return "decompiled_no_asm"
    if error_count == 0 and warning_count == 0:
        return "high"
    if error_count == 0:
        return "medium"
    if error_count <= 2:
        return "low"
    return "problematic"


# ---------------------------------------------------------------------------
# Module-wide analysis
# ---------------------------------------------------------------------------

def analyze_decompilation_quality(
    db_path: str, *, no_cache: bool = False
) -> dict[str, Any]:
    """Scan all functions and produce decompilation quality metrics."""
    if not no_cache:
        cached = get_cached(db_path, "decompilation_quality")
        if cached is not None:
            return cached

    with db_error_handler(db_path, "analyzing decompilation quality"):
        with open_analysis_db(db_path) as db:
            file_info = db.get_file_info()
            all_funcs = db.get_all_functions()

    module_name = file_info.file_name if file_info else Path(db_path).stem

    total = len(all_funcs)
    has_decompiled = 0
    has_assembly = 0
    has_both = 0
    has_neither = 0
    total_errors = 0
    total_warnings = 0

    error_category_counts: Counter = Counter()
    quality_tiers: Counter = Counter()
    problematic_functions: list[dict] = []
    functions_with_errors: list[dict] = []

    for func in all_funcs:
        decomp = bool(func.decompiled_code and func.decompiled_code.strip())
        asm = bool(func.assembly_code and func.assembly_code.strip())

        if decomp:
            has_decompiled += 1
        if asm:
            has_assembly += 1
        if decomp and asm:
            has_both += 1
        if not decomp and not asm:
            has_neither += 1

        # Parse analysis_errors
        errors_data = parse_json_safe(func.analysis_errors)
        func_errors: list[str] = []
        func_warnings: list[str] = []

        if isinstance(errors_data, list):
            for item in errors_data:
                if isinstance(item, str):
                    if "warning" in item.lower():
                        func_warnings.append(item)
                    else:
                        func_errors.append(item)
                elif isinstance(item, dict):
                    msg = item.get("message", item.get("error", str(item)))
                    severity = item.get("severity", "error")
                    if severity == "warning":
                        func_warnings.append(msg)
                    else:
                        func_errors.append(msg)
        elif isinstance(errors_data, dict):
            for key, val in errors_data.items():
                if isinstance(val, list):
                    for v in val:
                        msg = str(v)
                        if "warning" in key.lower():
                            func_warnings.append(msg)
                        else:
                            func_errors.append(msg)
                elif val:
                    msg = str(val)
                    if "warning" in key.lower():
                        func_warnings.append(msg)
                    else:
                        func_errors.append(msg)

        for err in func_errors:
            error_category_counts[categorize_error(err)] += 1
        total_errors += len(func_errors)
        total_warnings += len(func_warnings)

        tier = _assign_quality_tier(decomp, asm, len(func_errors), len(func_warnings))
        quality_tiers[tier] += 1

        fname = func.function_name or f"sub_{func.function_id}"
        if func_errors:
            entry = {
                "function_name": fname,
                "function_id": func.function_id,
                "error_count": len(func_errors),
                "warning_count": len(func_warnings),
                "errors": func_errors[:5],
                "categories": list(set(categorize_error(e) for e in func_errors)),
                "has_decompiled": decomp,
                "has_assembly": asm,
            }
            functions_with_errors.append(entry)
            if len(func_errors) >= 3 or not decomp:
                problematic_functions.append(entry)

    # Sort by error count
    functions_with_errors.sort(key=lambda x: x["error_count"], reverse=True)
    problematic_functions.sort(key=lambda x: x["error_count"], reverse=True)

    result = {
        "module_name": module_name,
        "total_functions": total,
        "coverage": {
            "has_decompiled": has_decompiled,
            "has_assembly": has_assembly,
            "has_both": has_both,
            "has_neither": has_neither,
            "decompilation_rate": round(has_decompiled / total * 100, 1) if total else 0,
            "assembly_rate": round(has_assembly / total * 100, 1) if total else 0,
        },
        "quality_tiers": {
            "high": quality_tiers.get("high", 0),
            "medium": quality_tiers.get("medium", 0),
            "low": quality_tiers.get("low", 0),
            "problematic": quality_tiers.get("problematic", 0),
            "no_decompilation": quality_tiers.get("no_decompilation", 0),
            "decompiled_no_asm": quality_tiers.get("decompiled_no_asm", 0),
        },
        "error_summary": {
            "total_errors": total_errors,
            "total_warnings": total_warnings,
            "functions_with_errors": len(functions_with_errors),
            "error_categories": dict(error_category_counts.most_common()),
        },
        "top_problematic_functions": problematic_functions[:20],
        "top_functions_with_errors": functions_with_errors[:30],
    }

    cache_result(db_path, "decompilation_quality", result)
    return result


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def print_quality_report(report: dict, as_json: bool = False) -> None:
    """Print decompilation quality report."""
    if as_json:
        emit_json(report, default=str)
        return

    cov = report["coverage"]
    tiers = report["quality_tiers"]
    errs = report["error_summary"]
    total = report["total_functions"]

    print(f"\n{'=' * 70}")
    print(f"  Decompilation Quality Report: {report['module_name']}")
    print(f"{'=' * 70}")

    print(f"\n  Coverage ({total} functions):")
    print(f"    Decompiled:     {cov['has_decompiled']:>5}  ({cov['decompilation_rate']:.1f}%)")
    print(f"    Assembly:       {cov['has_assembly']:>5}  ({cov['assembly_rate']:.1f}%)")
    print(f"    Both:           {cov['has_both']:>5}")
    print(f"    Neither:        {cov['has_neither']:>5}")

    print(f"\n  Quality Tiers:")
    for tier_name in ["high", "medium", "low", "problematic", "no_decompilation"]:
        count = tiers.get(tier_name, 0)
        pct = round(count / total * 100, 1) if total else 0
        print(f"    {tier_name:<20} {count:>5}  ({pct:.1f}%)")

    print(f"\n  Error Summary:")
    print(f"    Total errors:              {errs['total_errors']}")
    print(f"    Total warnings:            {errs['total_warnings']}")
    print(f"    Functions with errors:      {errs['functions_with_errors']}")

    if errs["error_categories"]:
        print(f"\n  Error Categories:")
        for cat, count in errs["error_categories"].items():
            print(f"    {cat:<25} {count:>5}")

    if report["top_problematic_functions"]:
        print(f"\n  Top Problematic Functions:")
        for f in report["top_problematic_functions"][:10]:
            print(f"    {f['error_count']:>3} errors  {f['function_name']} (ID {f['function_id']})")
            for cat in f["categories"][:3]:
                print(f"               [{cat}]")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze decompilation quality across a module.",
    )
    parser.add_argument("db_path", help="Path to the individual analysis DB")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--no-cache", action="store_true", help="Bypass cache")
    args = safe_parse_args(parser)

    db_path = resolve_db_path(args.db_path)

    report = analyze_decompilation_quality(db_path, no_cache=args.no_cache)
    print_quality_report(report, as_json=args.json)


if __name__ == "__main__":
    main()
