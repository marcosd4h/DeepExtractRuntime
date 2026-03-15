#!/usr/bin/env python3
"""Rank functions by multiple complexity metrics.

Usage:
    python .agent/skills/generate-re-report/scripts/analyze_complexity.py <db_path>
    python .agent/skills/generate-re-report/scripts/analyze_complexity.py <db_path> --json
    python .agent/skills/generate-re-report/scripts/analyze_complexity.py <db_path> --top 20
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import (
    build_app_name_set,
    get_complexity_bucket,
    get_size_bucket,
    open_analysis_db,
    parse_json_safe,
    resolve_db_path,
    fmt_count,
    fmt_pct,
)
from helpers.cache import get_cached, cache_result
from helpers.errors import db_error_handler, safe_parse_args
from helpers.json_output import emit_json


def analyze_complexity(db_path: str, app_only: bool = False, *, no_cache: bool = False) -> dict:
    """Rank all functions by multiple complexity dimensions.

    Returns dict with keys:
        by_loops: [{id, name, loop_count, max_nesting, max_cyclomatic, has_infinite}]
        by_xrefs: [{id, name, inbound, outbound, hub_score}]
        by_global_state: [{id, name, reads, writes, total, globals}]
        by_size: [{id, name, instruction_count, decompiled_lines}]
        with_errors: [{id, name, errors}]
        distributions: {size: {bucket: count}, complexity: {bucket: count}, type: {class: N, standalone: N}}
        function_count: int
    """
    params = {"app_only": app_only}
    if not no_cache:
        cached = get_cached(db_path, "analyze_complexity", params=params)
        if cached is not None:
            return cached

    with db_error_handler(db_path, "analyzing complexity"):
        with open_analysis_db(db_path) as db:
            all_funcs = db.get_all_functions()

    # Build app-only filter set when requested
    app_names = build_app_name_set(db_path) if app_only else None

    by_loops = []
    by_xrefs = []
    by_global_state = []
    by_size = []
    with_errors = []

    size_dist: dict[str, int] = defaultdict(int)
    complexity_dist: dict[str, int] = defaultdict(int)
    type_dist = {"class_method": 0, "standalone": 0}

    for func in all_funcs:
        fid = func.function_id
        fname = func.function_name or f"sub_{fid}"

        # Skip library functions when --app-only is active
        if app_names is not None and fname not in app_names:
            continue

        # --- Loop analysis ---
        loop_data = parse_json_safe(func.loop_analysis)
        loop_count = 0
        max_nesting = 0
        max_cyclomatic = 0
        has_infinite = False

        if isinstance(loop_data, dict):
            loop_count = loop_data.get("loop_count", 0) or 0
            loops = loop_data.get("loops", [])
            if isinstance(loops, list):
                for loop in loops:
                    if isinstance(loop, dict):
                        nest = loop.get("nesting_level", 0) or 0
                        cyc = loop.get("cyclomatic_complexity", 0) or 0
                        inf = loop.get("is_infinite", False)
                        max_nesting = max(max_nesting, nest)
                        max_cyclomatic = max(max_cyclomatic, cyc)
                        if inf:
                            has_infinite = True

        if loop_count > 0:
            by_loops.append({
                "function_id": fid, "function_name": fname,
                "loop_count": loop_count, "max_nesting": max_nesting,
                "max_cyclomatic": max_cyclomatic, "has_infinite": has_infinite,
            })

        complexity_dist[get_complexity_bucket(loop_count)] += 1

        # --- Xref counts ---
        inbound = parse_json_safe(func.simple_inbound_xrefs) or []
        outbound = parse_json_safe(func.simple_outbound_xrefs) or []
        in_count = len(inbound) if isinstance(inbound, list) else 0
        out_count = len(outbound) if isinstance(outbound, list) else 0
        hub_score = in_count + out_count

        if hub_score > 0:
            by_xrefs.append({
                "function_id": fid, "function_name": fname,
                "inbound": in_count, "outbound": out_count, "hub_score": hub_score,
            })

        # --- Global state access ---
        globals_data = parse_json_safe(func.global_var_accesses) or []
        if isinstance(globals_data, list) and globals_data:
            reads = sum(1 for g in globals_data if isinstance(g, dict) and g.get("access_type") == "Read")
            writes = sum(1 for g in globals_data if isinstance(g, dict) and g.get("access_type") == "Write")
            global_names = set()
            for g in globals_data:
                if isinstance(g, dict):
                    n = g.get("name", g.get("address", ""))
                    if n:
                        global_names.add(n)
            by_global_state.append({
                "function_id": fid, "function_name": fname,
                "reads": reads, "writes": writes, "total": reads + writes,
                "globals": sorted(global_names)[:10],
            })

        # --- Size ---
        asm_lines = sum(1 for line in (func.assembly_code or "").splitlines() if line.strip() and not line.strip().startswith(";"))
        decomp_lines = len(func.decompiled_code.splitlines()) if func.decompiled_code else 0
        by_size.append({
            "function_id": fid, "function_name": fname,
            "instruction_count": asm_lines, "decompiled_lines": decomp_lines,
        })
        size_dist[get_size_bucket(asm_lines)] += 1

        # --- Type distribution ---
        if "::" in fname:
            type_dist["class_method"] += 1
        else:
            type_dist["standalone"] += 1

        # --- Analysis errors ---
        errors = parse_json_safe(func.analysis_errors) or []
        if isinstance(errors, list) and errors:
            with_errors.append({
                "function_id": fid, "function_name": fname,
                "errors": [
                    e.get("error", e.get("reason", str(e)))
                    for e in errors if isinstance(e, dict)
                ][:5],
            })

    # Sort rankings
    by_loops.sort(key=lambda x: (-x["loop_count"], -x["max_cyclomatic"]))
    by_xrefs.sort(key=lambda x: -x["hub_score"])
    by_global_state.sort(key=lambda x: -x["total"])
    by_size.sort(key=lambda x: -x["instruction_count"])

    result = {
        "by_loops": by_loops,
        "by_xrefs": by_xrefs,
        "by_global_state": by_global_state,
        "by_size": by_size,
        "with_errors": with_errors,
        "distributions": {
            "size": dict(size_dist),
            "complexity": dict(complexity_dist),
            "type": type_dist,
        },
        "function_count": len(all_funcs),
    }

    cache_result(db_path, "analyze_complexity", result, params=params)
    return result


def format_complexity_report(result: dict, top_n: int = 10) -> str:
    """Format complexity analysis as markdown."""
    lines = []
    lines.append("## Complexity Hotspots\n")

    total = result.get("function_count", 0)
    lines.append(f"**{total:,} total functions analyzed**\n")

    # Function distribution
    dist = result.get("distributions", {})
    size_dist = dist.get("size", {})
    type_dist = dist.get("type", {})
    complexity_dist = dist.get("complexity", {})

    lines.append("### Function Distribution\n")
    lines.append("**By type:**")
    for t, c in type_dist.items():
        lines.append(f"- {t.replace('_', ' ').title()}: {c:,} ({fmt_pct(c, total)})")
    lines.append("")

    lines.append("**By size (assembly instructions):**")
    for bucket in ["tiny", "small", "medium", "large", "huge"]:
        c = size_dist.get(bucket, 0)
        if c > 0:
            lines.append(f"- {bucket.title()}: {c:,} ({fmt_pct(c, total)})")
    lines.append("")

    lines.append("**By loop complexity:**")
    for bucket in ["simple", "moderate", "complex"]:
        c = complexity_dist.get(bucket, 0)
        if c > 0:
            lines.append(f"- {bucket.title()}: {c:,} ({fmt_pct(c, total)})")
    lines.append("")

    # Top by loops
    by_loops = result.get("by_loops", [])
    if by_loops:
        lines.append(f"### Top {min(top_n, len(by_loops))} by Loop Complexity\n")
        lines.append("| Rank | Function | Loops | Max Nesting | Cyclomatic | Infinite? |")
        lines.append("|---|---|---|---|---|---|")
        for i, entry in enumerate(by_loops[:top_n], 1):
            inf = "Yes" if entry["has_infinite"] else "No"
            lines.append(
                f"| {i} | `{entry['name']}` | {entry['loop_count']} | "
                f"{entry['max_nesting']} | {entry['max_cyclomatic']} | {inf} |"
            )
        lines.append("")

    # Top by xrefs (hub functions)
    by_xrefs = result.get("by_xrefs", [])
    if by_xrefs:
        lines.append(f"### Top {min(top_n, len(by_xrefs))} by Cross-Reference Count (Hub Functions)\n")
        lines.append("| Function | Inbound | Outbound | Hub Score |")
        lines.append("|---|---|---|---|")
        for entry in by_xrefs[:top_n]:
            lines.append(
                f"| `{entry['name']}` | {entry['inbound']} | "
                f"{entry['outbound']} | {entry['hub_score']} |"
            )
        lines.append("")

    # Top by global state
    by_globals = result.get("by_global_state", [])
    if by_globals:
        lines.append(f"### Top {min(top_n, len(by_globals))} by Global State Access\n")
        lines.append("| Function | Reads | Writes | Total | Sample Globals |")
        lines.append("|---|---|---|---|---|")
        for entry in by_globals[:top_n]:
            globals_str = ", ".join(f"`{g}`" for g in entry["globals"][:3])
            if len(entry["globals"]) > 3:
                globals_str += "..."
            lines.append(
                f"| `{entry['name']}` | {entry['reads']} | {entry['writes']} | "
                f"{entry['total']} | {globals_str} |"
            )
        lines.append("")

    # Top by size
    by_size = result.get("by_size", [])
    if by_size:
        lines.append(f"### Top {min(top_n, len(by_size))} Largest Functions\n")
        lines.append("| Function | Assembly Lines | Decompiled Lines |")
        lines.append("|---|---|---|")
        for entry in by_size[:top_n]:
            lines.append(
                f"| `{entry['name']}` | {entry['instruction_count']} | {entry['decompiled_lines']} |"
            )
        lines.append("")

    # Functions with errors
    with_errors = result.get("with_errors", [])
    if with_errors:
        lines.append(f"### Functions with Analysis Errors ({len(with_errors)})\n")
        for entry in with_errors[:top_n]:
            errors_str = "; ".join(str(e)[:80] for e in entry["errors"][:2])
            lines.append(f"- `{entry['name']}`: {errors_str}")
        if len(with_errors) > top_n:
            lines.append(f"- _... and {len(with_errors) - top_n} more_")
        lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Rank functions by complexity metrics")
    parser.add_argument("db_path", help="Path to individual analysis DB")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--top", type=int, default=10, help="Show top N per ranking (default: 10)")
    parser.add_argument("--app-only", action="store_true", help="Exclude library/boilerplate functions")
    parser.add_argument("--no-cache", action="store_true", help="Bypass result cache")
    args = safe_parse_args(parser)

    result = analyze_complexity(args.db_path, app_only=args.app_only, no_cache=args.no_cache)

    if args.json:
        emit_json(result, default=str)
    else:
        print(format_complexity_report(result, top_n=args.top))


if __name__ == "__main__":
    main()
