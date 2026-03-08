#!/usr/bin/env python3
"""Scan all functions in a module for decompiler accuracy issues.

Usage:
    python scan_module.py <db_path>
    python scan_module.py <db_path> --min-severity HIGH
    python scan_module.py <db_path> --top 20
    python scan_module.py <db_path> --json

Examples:
    python scan_module.py extracted_dbs/appinfo_dll_e98d25a9e8.db
    python scan_module.py extracted_dbs/cmd_exe_6d109a3a00.db --min-severity CRITICAL --top 10
    python scan_module.py extracted_dbs/appinfo_dll_e98d25a9e8.db --json

Output:
    Ranked list of functions sorted by decompiler issue severity. Shows which
    functions have the most (and most severe) accuracy issues, enabling triage
    of which functions to verify in detail.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

from _common import (
    WORKSPACE_ROOT,
    Severity,
    SEVERITY_LABELS,
    VerificationResult,
    parse_assembly,
    parse_decompiled,
    run_heuristic_checks,
    resolve_db_path,
    is_decompilation_failure,
)

from helpers import (
    build_id_map,
    emit_error,
    filter_by_library,
    filter_decompiled,
    load_function_index_for_db,
    open_individual_analysis_db,
)
from helpers.cache import get_cached, cache_result
from helpers.errors import ErrorCode, db_error_handler, safe_parse_args
from helpers.json_output import emit_json
from helpers.progress import progress_iter


# Map severity strings to enum values
_SEVERITY_FROM_STR = {v: k for k, v in SEVERITY_LABELS.items()}
_SEVERITY_ALIASES = {"MEDIUM": "MODERATE", "MED": "MODERATE"}


def scan_module(
    db_path: str,
    min_severity: Severity = Severity.LOW,
    top_n: int = 0,
    output_json: bool = False,
    app_only: bool = False,
    no_cache: bool = False,
) -> None:
    """Scan all functions in a module and report accuracy issues."""
    cache_params = {"sev": min_severity.value, "app": app_only}
    if not no_cache and output_json:
        cached = get_cached(db_path, "scan_module_verify", params=cache_params)
        if cached is not None:
            if top_n > 0:
                cached["functions"] = cached.get("functions", [])[:top_n]
            emit_json(cached)
            return
    function_index = load_function_index_for_db(db_path)
    selected_index = function_index
    library_names = set()
    meta_by_id: dict[int, dict] = {}

    if selected_index:
        if app_only:
            library_names = {k for k, v in selected_index.items() if v.get("library") is not None}
            selected_index = filter_by_library(selected_index, app_only=True)
        selected_index = filter_decompiled(selected_index, decompiled=True)
        selected_index = {k: v for k, v in selected_index.items() if bool(v.get("has_assembly", False))}
        meta_by_id = {fid: entry for fid, (_, entry) in build_id_map(selected_index).items()}

    with db_error_handler(db_path, "scanning module for decompiler issues"):
        with open_individual_analysis_db(db_path) as db:
            # Module info
            file_info = db.get_file_info()
            module_name = file_info.file_name if file_info else "(unknown)"
            module_desc = file_info.file_description if file_info else ""

            total_count = db.count_functions()
            if meta_by_id:
                functions = db.get_functions_by_ids(sorted(meta_by_id.keys()))
            else:
                functions = db.search_functions(has_decompiled_code=True)

        if not functions:
            emit_error("No functions with decompiled code found", ErrorCode.NO_DATA)
            return

        results: list[VerificationResult] = []
        skipped = 0
        library_skipped = 0
        total_scanned = 0

        for func in progress_iter(functions, label="scan_module", json_mode=output_json):
            if app_only and library_names and (func.function_name or "") in library_names:
                skipped += 1
                library_skipped += 1
                continue
            index_entry = meta_by_id.get(func.function_id)
            if index_entry is not None:
                has_asm = bool(index_entry.get("has_assembly", False))
                has_decomp = bool(index_entry.get("has_decompiled", False))
            else:
                has_asm = bool(func.assembly_code and func.assembly_code.strip())
                has_decomp = bool(
                    func.decompiled_code
                    and func.decompiled_code.strip()
                    and not is_decompilation_failure(func.decompiled_code)
                )

            if not has_asm or not has_decomp:
                skipped += 1
                continue

            total_scanned += 1

            # Parse and analyze
            _, asm_stats = parse_assembly(func.assembly_code)
            decomp_stats = parse_decompiled(func.decompiled_code)

            issues = run_heuristic_checks(
                asm_stats,
                decomp_stats,
                mangled_name=func.mangled_name,
                function_signature=func.function_signature,
                function_signature_extended=func.function_signature_extended,
            )

            # Filter by minimum severity
            filtered_issues = [i for i in issues if i.severity >= min_severity]

            if filtered_issues:
                result = VerificationResult(
                    function_id=func.function_id,
                    function_name=func.function_name or "(unnamed)",
                    has_decompiled=has_decomp,
                    has_assembly=has_asm,
                    asm_stats=asm_stats,
                    decomp_stats=decomp_stats,
                )
                for issue in filtered_issues:
                    result.add_issue(issue)
                results.append(result)

        # Sort by severity score (highest first)
        results.sort(key=lambda r: -r.severity_score)

        # Track total before truncation
        total_with_issues = len(results)

        # Apply top-N limit
        if top_n > 0:
            results = results[:top_n]

        if output_json:
            _output_json(results, module_name, module_desc, total_count,
                         len(functions), total_scanned, skipped, min_severity,
                         total_with_issues)
        else:
            _output_human(results, module_name, module_desc, total_count,
                          len(functions), total_scanned, skipped, min_severity, db_path,
                          total_with_issues, library_skipped=library_skipped)


def _output_json(
    results: list[VerificationResult],
    module_name: str,
    module_desc: str,
    total_functions: int,
    decompiled_functions: int,
    scanned: int,
    skipped: int,
    min_severity: Severity,
    total_with_issues: int = 0,
) -> None:
    # Aggregate stats
    category_counts: dict[str, int] = defaultdict(int)
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MODERATE": 0, "LOW": 0}

    for r in results:
        for issue in r.issues:
            category_counts[issue.category] += 1
            severity_counts[SEVERITY_LABELS[issue.severity]] += 1

    output = {
        "module_name": module_name,
        "module_description": module_desc,
        "scan_summary": {
            "total_functions": total_functions,
            "decompiled_functions": decompiled_functions,
            "scanned": scanned,
            "skipped_no_assembly": skipped,
            "functions_with_issues": total_with_issues,
            "functions_shown": len(results),
            "min_severity_filter": SEVERITY_LABELS[min_severity],
        },
        "issue_distribution": {
            "by_severity": severity_counts,
            "by_category": dict(category_counts),
        },
        "functions": [r.to_dict() for r in results],
    }
    emit_json(output)
    return output


def _output_human(
    results: list[VerificationResult],
    module_name: str,
    module_desc: str,
    total_functions: int,
    decompiled_functions: int,
    scanned: int,
    skipped: int,
    min_severity: Severity,
    db_path: str,
    total_with_issues: int = 0,
    library_skipped: int = 0,
) -> None:
    print(f"{'#' * 80}")
    print(f"  DECOMPILER ACCURACY SCAN: {module_name}")
    if module_desc:
        print(f"  {module_desc}")
    print(f"  DB: {db_path}")
    print(f"{'#' * 80}")
    print()

    # Summary
    print(f"Scan Summary:")
    print(f"  Total functions in module:   {total_functions}")
    print(f"  Functions with decompiled:   {decompiled_functions}")
    print(f"  Functions scanned (asm+dec): {scanned}")
    print(f"  Skipped (no assembly):       {skipped}")
    if library_skipped > 0:
        print(f"  Skipped (library functions): {library_skipped}")
    print(f"  Functions with issues:       {total_with_issues}")
    if len(results) < total_with_issues:
        print(f"  Showing top:                {len(results)}")
    if min_severity > Severity.LOW:
        print(f"  Minimum severity filter:     {SEVERITY_LABELS[min_severity]}")
    print()

    if not results:
        print("No decompiler accuracy issues detected by automated heuristics.")
        print("\nNOTE: Automated heuristics cannot detect all issue types. For thorough")
        print("verification, use verify_function.py on functions of interest.")
        return

    # Issue distribution
    category_counts: dict[str, int] = defaultdict(int)
    severity_counts = defaultdict(int)
    total_issues = 0

    for r in results:
        for issue in r.issues:
            category_counts[issue.category] += 1
            severity_counts[SEVERITY_LABELS[issue.severity]] += 1
            total_issues += 1

    print(f"Issue Distribution ({total_issues} total across {len(results)} functions):")
    print(f"  By severity: ", end="")
    sev_parts = []
    for sev_name in ["CRITICAL", "HIGH", "MODERATE", "LOW"]:
        count = severity_counts.get(sev_name, 0)
        if count > 0:
            sev_parts.append(f"{count} {sev_name}")
    print(", ".join(sev_parts))

    print(f"  By category:")
    for cat, count in sorted(category_counts.items(), key=lambda x: -x[1]):
        label = cat.replace("_", " ").title()
        print(f"    {label:<35} {count}")
    print()

    # Ranked function list
    print(f"{'=' * 80}")
    print(f"  FUNCTIONS WITH ISSUES (ranked by severity)")
    print(f"{'=' * 80}")
    print()

    print(f"{'Rank':>4}  {'Score':>5}  {'Sev':>8}  {'C':>2} {'H':>2} {'M':>2} {'L':>2}  {'ID':>6}  {'Function Name'}")
    print(f"{'-' * 4}  {'-' * 5}  {'-' * 8}  {'-' * 2} {'-' * 2} {'-' * 2} {'-' * 2}  {'-' * 6}  {'-' * 50}")

    for rank, r in enumerate(results, 1):
        sev = SEVERITY_LABELS[r.max_severity]
        name = r.function_name
        if len(name) > 50:
            name = name[:47] + "..."
        print(
            f"{rank:>4}  {r.severity_score:>5}  {sev:>8}  "
            f"{r.critical_count:>2} {r.high_count:>2} {r.moderate_count:>2} {r.low_count:>2}  "
            f"{r.function_id:>6}  {name}"
        )

    print()
    print(f"Legend: C=Critical, H=High, M=Moderate, L=Low")
    print(f"Score = C*100 + H*10 + M*3 + L*1")
    print()

    # Detail for top-5
    detail_count = min(5, len(results))
    print(f"{'=' * 80}")
    print(f"  TOP {detail_count} FUNCTION DETAILS")
    print(f"{'=' * 80}")

    for r in results[:detail_count]:
        print(f"\n--- {r.function_name} (ID={r.function_id}, score={r.severity_score}) ---")
        for idx, issue in enumerate(r.issues, 1):
            sev = SEVERITY_LABELS[issue.severity]
            print(f"  [{sev}] #{idx}: {issue.summary}")
            if issue.suggested_fix:
                print(f"    Fix: {issue.suggested_fix}")

    print(f"\n{'=' * 80}")
    print(f"  NEXT STEPS")
    print(f"{'=' * 80}")
    print()
    print(f"To verify a specific function in detail:")
    print(f"  python .agent/skills/verify-decompiled/scripts/verify_function.py {db_path} --id <ID>")
    print()
    print(f"Start with the highest-scored functions above -- they are most likely to have")
    print(f"real decompiler accuracy issues that affect code understanding.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan all functions in a module for decompiler accuracy issues.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("db_path", help="Path to the individual analysis DB")
    parser.add_argument(
        "--min-severity",
        type=str.upper,
        choices=["LOW", "MODERATE", "MEDIUM", "HIGH", "CRITICAL"],
        default="LOW",
        help="Minimum severity to include; MEDIUM is an alias for MODERATE (default: LOW)",
    )
    parser.add_argument("--top", type=int, default=0, help="Show only top N functions (0 = all)")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--app-only", action="store_true", help="Skip library-tagged functions (from function_index)")
    parser.add_argument("--no-cache", action="store_true", help="Bypass result cache and recompute from scratch")
    args = safe_parse_args(parser)

    db_path = resolve_db_path(args.db_path)
    sev_str = _SEVERITY_ALIASES.get(args.min_severity, args.min_severity)
    min_sev = _SEVERITY_FROM_STR.get(sev_str, Severity.LOW)

    scan_module(db_path, min_severity=min_sev, top_n=args.top, output_json=args.json, app_only=args.app_only, no_cache=args.no_cache)


if __name__ == "__main__":
    main()
