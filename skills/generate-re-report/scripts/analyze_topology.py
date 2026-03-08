#!/usr/bin/env python3
"""Compute call graph topology metrics for a module.

Usage:
    python .agent/skills/generate-re-report/scripts/analyze_topology.py <db_path>
    python .agent/skills/generate-re-report/scripts/analyze_topology.py <db_path> --json
    python .agent/skills/generate-re-report/scripts/analyze_topology.py <db_path> --top 20
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict, deque
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import (
    load_index_for_db,
    open_analysis_db,
    parse_json_safe,
    resolve_db_path,
    fmt_count,
    fmt_pct,
)
from helpers.cache import cache_result, get_cached
from helpers.callgraph import CallGraph
from helpers.errors import db_error_handler, safe_parse_args
from helpers.json_output import emit_json


def analyze_topology(db_path: str, app_only: bool = False, *, no_cache: bool = False) -> dict:
    """Compute call graph topology metrics.

    Returns dict with keys:
        graph_stats: {nodes, edges, density}
        entry_reachability: [{name, id, reachable_count, reachable_pct}]
        dead_code: [{name, id}] - functions with 0 inbound, not exports
        leaf_functions: [{name, id}] - functions with 0 outbound calls
        root_functions: [{name, id, outbound}] - called but call nothing
        recursive_groups: [{functions, size}] - SCCs with size > 1
        bottleneck_functions: [{name, id, paths_through}] - appear on many paths
        call_depth_distribution: {depth: count}
        max_depth_from_entries: [{name, id, max_depth}]
    """
    params = {"app_only": app_only}
    if not no_cache:
        cached = get_cached(db_path, "analyze_topology", params=params)
        if cached is not None:
            return cached

    with db_error_handler(db_path, "analyzing topology"):
        with open_analysis_db(db_path) as db:
            all_funcs = db.get_all_functions()
            fi = db.get_file_info()

    # Build unified call graph
    graph = CallGraph.from_functions(all_funcs)

    # Get id-based edge views for topology metrics
    forward = graph.id_forward_edges()
    reverse = graph.id_reverse_edges()
    id_to_name = graph.id_to_name
    all_ids = set(id_to_name.keys())

    # Load function_index for library-tag filtering
    function_index = load_index_for_db(db_path)
    library_names: set[str] = set()
    if function_index:
        library_names = {k for k, v in function_index.items() if v.get("library") is not None}

    # --- Entry points and exports ---
    entry_ids = set()
    export_names = set()
    if fi:
        exports = parse_json_safe(fi.exports) or []
        for exp in exports:
            if isinstance(exp, dict):
                ename = exp.get("function_name", "")
                if ename:
                    export_names.add(ename.lower())

        entries = parse_json_safe(fi.entry_point) or []
        for ep in entries:
            if isinstance(ep, dict):
                epname = ep.get("function_name", ep.get("entry_name", ""))
                if epname:
                    export_names.add(epname.lower())

    # Map export names to IDs
    for fid, fname in id_to_name.items():
        if fname.lower() in export_names:
            entry_ids.add(fid)

    # --- Graph stats ---
    total_edges = sum(len(v) for v in forward.values())
    node_count = len(all_ids)
    density = total_edges / (node_count * (node_count - 1)) if node_count > 1 else 0.0

    # --- Entry point reachability (via shared CallGraph) ---
    entry_reachability = []
    for eid in sorted(entry_ids):
        ename = id_to_name.get(eid, f"id_{eid}")
        reachable = graph.reachable_from(ename)
        entry_reachability.append({
            "name": ename,
            "id": eid,
            "reachable_count": len(reachable),
            "reachable_pct": f"{100.0 * len(reachable) / node_count:.1f}%" if node_count > 0 else "0%",
        })
    entry_reachability.sort(key=lambda x: -x["reachable_count"])

    # --- Dead code candidates ---
    dead_code = []
    for fid in all_ids:
        inbound = reverse.get(fid, set())
        if not inbound and fid not in entry_ids:
            fname = id_to_name.get(fid, f"sub_{fid}")
            # Skip compiler-generated, unnamed, and library/boilerplate functions
            # (WIL template instantiations with zero inbound refs are NOT dead code)
            if not fname.startswith("__") and not fname.startswith("_guard") and fname not in library_names:
                dead_code.append({"name": fname, "id": fid})
    dead_code.sort(key=lambda x: x["name"])

    # --- Leaf functions ---
    leaf_functions = []
    for fid in all_ids:
        if not forward.get(fid):
            leaf_functions.append({"name": id_to_name.get(fid, f"sub_{fid}"), "id": fid})
    leaf_functions.sort(key=lambda x: x["name"])

    # --- Root functions (have outbound but no inbound, and are not exports) ---
    root_functions = []
    for fid in all_ids:
        out = forward.get(fid, set())
        inb = reverse.get(fid, set())
        if out and not inb and fid not in entry_ids:
            root_functions.append({
                "name": id_to_name.get(fid, f"sub_{fid}"),
                "id": fid,
                "outbound": len(out),
            })
    root_functions.sort(key=lambda x: -x["outbound"])

    # --- Recursive groups (SCCs > 1, via shared CallGraph) ---
    name_sccs = graph.strongly_connected_components()
    recursive_groups = []
    for scc in name_sccs:
        recursive_groups.append({
            "functions": scc,
            "size": len(scc),
        })
    recursive_groups.sort(key=lambda x: -x["size"])

    # --- Call depth from entries (via shared CallGraph) ---
    max_depth_from_entries = []
    for eid in sorted(entry_ids):
        ename = id_to_name.get(eid, f"id_{eid}")
        depth = graph.max_depth_from(ename)
        max_depth_from_entries.append({
            "name": ename,
            "id": eid,
            "max_depth": depth,
        })
    max_depth_from_entries.sort(key=lambda x: -x["max_depth"])

    # --- Call depth distribution ---
    depth_dist: dict[int, int] = defaultdict(int)
    for eid in entry_ids:
        visited = set()
        queue = deque([(eid, 0)])
        while queue:
            node, depth = queue.popleft()
            if node in visited:
                continue
            visited.add(node)
            depth_dist[depth] += 1
            for neighbor in forward.get(node, []):
                if neighbor not in visited and depth < 50:
                    queue.append((neighbor, depth + 1))

    # --- Bottleneck functions ---
    # Approximate: functions with high betweenness (many inbound * many outbound)
    bottlenecks = []
    for fid in all_ids:
        inb = len(reverse.get(fid, set()))
        out = len(forward.get(fid, set()))
        if inb >= 3 and out >= 3:
            bottlenecks.append({
                "name": id_to_name.get(fid, f"sub_{fid}"),
                "id": fid,
                "inbound": inb,
                "outbound": out,
                "paths_through": inb * out,
            })
    bottlenecks.sort(key=lambda x: -x["paths_through"])

    result = {
        "graph_stats": {"nodes": node_count, "edges": total_edges, "density": round(density, 6)},
        "entry_reachability": entry_reachability,
        "dead_code": dead_code,
        "leaf_functions": leaf_functions,
        "root_functions": root_functions,
        "recursive_groups": recursive_groups,
        "bottleneck_functions": bottlenecks,
        "call_depth_distribution": dict(sorted(depth_dist.items())),
        "max_depth_from_entries": max_depth_from_entries,
        "export_count": len(entry_ids),
    }

    cache_result(db_path, "analyze_topology", result, params=params)
    return result


def format_topology_report(result: dict, top_n: int = 10) -> str:
    """Format topology analysis as markdown."""
    lines = []
    lines.append("## Cross-Reference Topology\n")

    stats = result.get("graph_stats", {})
    lines.append(f"**Call graph**: {stats.get('nodes', 0):,} nodes, "
                 f"{stats.get('edges', 0):,} edges "
                 f"(density: {stats.get('density', 0):.6f})\n")

    # Entry reachability
    entry_reach = result.get("entry_reachability", [])
    if entry_reach:
        lines.append(f"### Entry Point Reachability ({len(entry_reach)} exports/entries)\n")
        lines.append("| Entry Point | Reachable Functions | Coverage |")
        lines.append("|---|---|---|")
        for e in entry_reach[:top_n]:
            lines.append(f"| `{e['name']}` | {e['reachable_count']} | {e['reachable_pct']} |")
        if len(entry_reach) > top_n:
            lines.append(f"| _... {len(entry_reach) - top_n} more_ | | |")
        lines.append("")

    # Dead code
    dead = result.get("dead_code", [])
    if dead:
        lines.append(f"### Dead Code Candidates ({len(dead)} functions)\n")
        lines.append("Functions with zero inbound references that are not exports/entries:\n")
        for d in dead[:top_n]:
            lines.append(f"- `{d['name']}`")
        if len(dead) > top_n:
            lines.append(f"- _... and {len(dead) - top_n} more_")
        lines.append("")

    # Leaf functions
    leaves = result.get("leaf_functions", [])
    if leaves:
        lines.append(f"### Leaf Functions ({len(leaves)})\n")
        lines.append("Functions with zero outbound calls:\n")
        for l in leaves[:top_n]:
            lines.append(f"- `{l['name']}`")
        if len(leaves) > top_n:
            lines.append(f"- _... and {len(leaves) - top_n} more_")
        lines.append("")

    # Recursive groups
    recursive = result.get("recursive_groups", [])
    if recursive:
        lines.append(f"### Recursive Groups ({len(recursive)} clusters)\n")
        for g in recursive[:5]:
            funcs = ", ".join(f"`{f}`" for f in g["functions"][:5])
            if g["size"] > 5:
                funcs += f" _+{g['size'] - 5} more_"
            lines.append(f"- **{g['size']} functions**: {funcs}")
        lines.append("")

    # Bottleneck functions
    bottlenecks = result.get("bottleneck_functions", [])
    if bottlenecks:
        lines.append(f"### Bottleneck Functions\n")
        lines.append("Functions with high path-through count between entry points and internal functions:\n")
        lines.append("| Function | Inbound | Outbound | Paths Through |")
        lines.append("|---|---|---|---|")
        for b in bottlenecks[:top_n]:
            lines.append(f"| `{b['name']}` | {b['inbound']} | {b['outbound']} | {b['paths_through']} |")
        lines.append("")

    # Call depth
    max_depths = result.get("max_depth_from_entries", [])
    if max_depths:
        lines.append("### Max Call Depth from Entry Points\n")
        lines.append("| Entry Point | Max Depth |")
        lines.append("|---|---|")
        for d in max_depths[:top_n]:
            lines.append(f"| `{d['name']}` | {d['max_depth']} |")
        lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Compute call graph topology metrics")
    parser.add_argument("db_path", help="Path to individual analysis DB")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--top", type=int, default=10, help="Show top N per section (default: 10)")
    parser.add_argument("--app-only", action="store_true", help="Exclude library/boilerplate functions")
    parser.add_argument("--no-cache", action="store_true", help="Bypass result cache and recompute from scratch")
    args = safe_parse_args(parser)

    result = analyze_topology(args.db_path, app_only=args.app_only, no_cache=args.no_cache)

    if args.json:
        emit_json(result, default=str)
    else:
        print(format_topology_report(result, top_n=args.top))


if __name__ == "__main__":
    main()
