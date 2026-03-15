"""Prepare cross-module callgraph context for AI memory corruption scanning.

Builds a JSON callgraph structure from a target function or set of entry
points using CrossModuleGraph.  IPC edges (RPC/COM/WinRT) are NOT injected
into the BFS -- they would pull in every lateral RPC handler and their
subtrees, bloating the graph.  IPC reachability is instead recorded as
metadata on entry-point nodes.

The output includes:
  - Forward call tree (nodes + edges from actual call instructions only)
  - Traversal plan: every node classified as MUST_READ / KNOWN_API /
    TELEMETRY / LIBRARY, grouped by depth level
  - Optionally (--with-code): pre-loaded decompiled code + assembly for
    all MUST_READ functions at depth 0 and 1

The scanning LLM receives depth 0+1 code upfront.  For deeper levels, the
coordinator batch-fetches code on demand based on the LLM's taint-guided
next_depth_requests (iterative depth-expansion pattern).
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

_SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT_DIR))

from _common import (
    WORKSPACE_ROOT,
    CrossModuleGraph,
    ErrorCode,
    db_error_handler,
    emit_error,
    emit_json,
    filter_application_functions,
    is_library_function,
    load_function_index_for_db,
    open_individual_analysis_db,
    parse_json_safe,
    resolve_db_path,
    resolve_tracking_db,
    safe_parse_args,
    status_message,
)
from helpers.batch_operations import batch_extract_function_data
from helpers.script_runner import run_skill_script


# ---------------------------------------------------------------------------
# Constants for node classification
# ---------------------------------------------------------------------------

SYSTEM_DLLS = frozenset({
    "ntdll.dll", "kernel32.dll", "kernelbase.dll", "rpcrt4.dll",
    "oleaut32.dll", "combase.dll", "ucrtbase.dll", "ws2_32.dll",
    "sspicli.dll", "advapi32.dll", "sechost.dll", "msvcrt.dll",
    "netutils.dll", "user32.dll", "gdi32.dll", "shell32.dll",
    "shlwapi.dll", "mswsock.dll", "crypt32.dll", "bcrypt.dll",
    "ncrypt.dll", "secur32.dll", "iphlpapi.dll", "dnsapi.dll",
    "netapi32.dll", "samlib.dll", "wldap32.dll",
})

_TELEMETRY_PREFIXES = (
    "WPP_SF_", "WPP_", "McTemplate", "EventWrite", "EtwTrace",
    "EtwEvent", "TraceLogging",
)

_THUNK_PATTERNS = re.compile(
    r"^(?:_?_?guard_dispatch_icall|_?_?tailMerge_|_?_?delayLoadHelper|"
    r"load_[A-Z]|_?memcpy_\d|_?memset_\d|_?memcmp_\d|_?memmove_\d|"
    r"_?_?security_check_cookie|_?_?GSHandlerCheck|_?_?C_specific_handler|"
    r"_?_?report_rangecheckfailure|_?_?chkstk|"
    r"_o__wcs|_o_wcs|_o__mbsc)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Entry point discovery
# ---------------------------------------------------------------------------

def _discover_entry_points(db_path: str) -> list[dict]:
    """Run discover_entrypoints.py and return the entry point list."""
    result = run_skill_script(
        "map-attack-surface",
        "discover_entrypoints.py",
        [db_path, "--json"],
        timeout=60,
        json_output=True,
    )
    if not result.get("success"):
        return []
    json_data = result.get("json_data", {})
    if isinstance(json_data, dict):
        return json_data.get("entrypoints", [])
    return []


# ---------------------------------------------------------------------------
# Node classification
# ---------------------------------------------------------------------------

def _classify_node(
    node: dict,
    target_module: str,
    lib_funcs: set[str],
) -> str:
    """Classify a callgraph node into MUST_READ / KNOWN_API / TELEMETRY / LIBRARY."""
    func_name = node["function"]
    module = node["module"]

    if func_name in lib_funcs:
        return "LIBRARY"

    for prefix in _TELEMETRY_PREFIXES:
        if func_name.startswith(prefix):
            return "TELEMETRY"

    if _THUNK_PATTERNS.match(func_name):
        return "KNOWN_API"

    if module.lower() in {s.lower() for s in SYSTEM_DLLS}:
        return "KNOWN_API"

    if module.lower() == target_module.lower():
        if node.get("function_id") is not None:
            return "MUST_READ"
        return "KNOWN_API"

    return "KNOWN_API"


def _compute_traversal_plan(
    nodes: dict[str, dict],
    target_module: str,
    lib_funcs: set[str],
    max_depth: int,
) -> dict[str, Any]:
    """Classify all nodes and group by depth for iterative expansion."""
    by_depth: dict[str, list[dict]] = defaultdict(list)
    counts = {"must_read": 0, "known_api": 0, "telemetry": 0, "library": 0, "total": 0}
    must_read_by_depth: dict[str, int] = defaultdict(int)

    for node_key, node in nodes.items():
        category = _classify_node(node, target_module, lib_funcs)
        depth = node.get("depth", 0)
        depth_str = str(depth)

        entry = {
            "node": node_key,
            "function": node["function"],
            "module": node["module"],
            "category": category,
        }
        if category == "MUST_READ":
            entry["function_id"] = node.get("function_id")

        by_depth[depth_str].append(entry)
        counts[category.lower()] = counts.get(category.lower(), 0) + 1
        counts["total"] += 1
        if category == "MUST_READ":
            must_read_by_depth[depth_str] += 1

    for depth_str in sorted(by_depth, key=int):
        by_depth[depth_str].sort(key=lambda e: (
            0 if e["category"] == "MUST_READ" else
            1 if e["category"] == "KNOWN_API" else
            2 if e["category"] == "TELEMETRY" else 3,
            e["function"],
        ))

    return {
        "by_depth": dict(by_depth),
        "counts": counts,
        "must_read_by_depth": dict(must_read_by_depth),
    }


# ---------------------------------------------------------------------------
# Callgraph building (NO IPC edge injection)
# ---------------------------------------------------------------------------

def _build_callgraph(
    db_path: str,
    root_function: str,
    root_module: str,
    max_depth: int,
    function_index: dict | None,
) -> dict[str, Any]:
    """Build a cross-module callgraph rooted at the given function.

    IPC edges are NOT injected.  The BFS follows only internal call edges
    and external import edges -- the actual forward call tree.
    """
    tracking_db = resolve_tracking_db()
    if tracking_db is None:
        status_message("No tracking DB found; building single-module callgraph")

    status_message(f"Building cross-module callgraph from {root_function} (depth {max_depth})...")

    graph = CrossModuleGraph.from_tracking_db(tracking_db=tracking_db)

    reachable = graph.reachable_from(root_module, root_function, max_depth=max_depth)
    adjacency = graph.build_unified_adjacency()

    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, str]] = []

    lib_funcs: set[str] = set()
    if function_index:
        for fname, entry in function_index.items():
            if is_library_function(entry):
                lib_funcs.add(fname)

    for mod_name, func_depths in reachable.items():
        for func_name, depth in func_depths.items():
            node_key = f"{mod_name}::{func_name}"
            is_lib = func_name in lib_funcs
            nodes[node_key] = {
                "module": mod_name,
                "function": func_name,
                "depth": depth,
                "is_library": is_lib,
            }

    for (src_mod, src_func), targets in adjacency.items():
        src_key = f"{src_mod}::{src_func}"
        if src_key not in nodes:
            continue
        for tgt_mod, tgt_func in targets:
            tgt_key = f"{tgt_mod}::{tgt_func}"
            if tgt_key not in nodes:
                continue
            edges.append({
                "from": src_key,
                "to": tgt_key,
                "edge_type": "call",
            })

    graph.close()

    return {"nodes": nodes, "edges": edges, "lib_funcs": lib_funcs}


# ---------------------------------------------------------------------------
# Pre-load decompiled code for depth 0+1 MUST_READ functions
# ---------------------------------------------------------------------------

def _preload_code(
    db_path: str,
    traversal_plan: dict,
    target_module: str,
) -> dict[str, dict]:
    """Batch-extract code for MUST_READ functions at depth 0 and 1."""
    func_names: list[str] = []
    for depth_str in ("0", "1"):
        for entry in traversal_plan.get("by_depth", {}).get(depth_str, []):
            if entry["category"] == "MUST_READ":
                func_names.append(entry["function"])

    if not func_names:
        return {}

    status_message(f"Pre-loading code for {len(func_names)} depth 0+1 MUST_READ functions...")

    with open_individual_analysis_db(db_path) as db:
        name_to_ids: dict[str, int] = {}
        for name in func_names:
            matches = db.get_function_by_name(name)
            if matches:
                name_to_ids[name] = matches[0].function_id

        ids = list(name_to_ids.values())
        if not ids:
            return {}

        raw = batch_extract_function_data(db, ids)

    result: dict[str, dict] = {}
    for name, fid in name_to_ids.items():
        data = raw.get(fid)
        if data:
            node_key = f"{target_module}::{name}"
            result[node_key] = data

    return result


# ---------------------------------------------------------------------------
# Resolve function_id for MUST_READ nodes in the target module
# ---------------------------------------------------------------------------

def _resolve_function_ids(
    db_path: str,
    nodes: dict[str, dict],
    target_module: str,
) -> None:
    """Look up function_id for target-module nodes and store on node dicts."""
    target_names = [
        n["function"] for n in nodes.values()
        if n["module"].lower() == target_module.lower()
    ]
    if not target_names:
        return

    with open_individual_analysis_db(db_path) as db:
        for name in target_names:
            matches = db.get_function_by_name(name)
            if matches:
                node_key = f"{target_module}::{name}"
                if node_key in nodes:
                    nodes[node_key]["function_id"] = matches[0].function_id


# ---------------------------------------------------------------------------
# IPC reachability annotation
# ---------------------------------------------------------------------------

def _annotate_ipc_reachability(
    nodes: dict[str, dict],
    entry_point_metadata: list[dict],
) -> None:
    """Tag entry-point nodes with IPC reachability metadata."""
    ep_map = {ep["function_name"]: ep for ep in entry_point_metadata}
    for node_key, node in nodes.items():
        if not node.get("is_entry_point"):
            continue
        ep = ep_map.get(node["function"])
        if ep:
            entry_type = ep.get("entry_type", "")
            if "RPC" in entry_type:
                node["ipc_reachability"] = "rpc_handler"
            elif "COM" in entry_type:
                node["ipc_reachability"] = "com_method"
            elif "WINRT" in entry_type:
                node["ipc_reachability"] = "winrt_method"
            elif entry_type:
                node["ipc_reachability"] = entry_type.lower()


# ---------------------------------------------------------------------------
# Main logic
# ---------------------------------------------------------------------------

def prepare_context(
    db_path: str,
    function_name: str | None = None,
    entry_points_mode: bool = False,
    max_depth: int = 5,
    with_code: bool = False,
) -> dict[str, Any]:
    """Prepare the full callgraph context for AI scanning."""
    with db_error_handler(db_path, "loading module info"):
        with open_individual_analysis_db(db_path) as db:
            fi = db.get_file_info()
            module_name = fi.file_name if fi else "unknown"

    function_index = load_function_index_for_db(db_path)

    entry_point_metadata: list[dict] = []
    if function_name:
        root_functions = [function_name]
        eps = _discover_entry_points(db_path)
        for ep in eps:
            if ep.get("function_name") == function_name:
                entry_point_metadata = [{
                    "function_name": ep.get("function_name", ""),
                    "entry_type": ep.get("entry_type", ""),
                    "attack_score": ep.get("attack_score", 0),
                    "rpc_opnum": ep.get("rpc_opnum"),
                    "rpc_interface_id": ep.get("rpc_interface_id", ""),
                    "com_clsid": ep.get("com_clsid", ""),
                    "dangerous_ops_reachable": ep.get("dangerous_ops_reachable", 0),
                    "tainted_args": ep.get("tainted_args", []),
                }]
                break
    elif entry_points_mode:
        status_message("Auto-discovering entry points...")
        eps = _discover_entry_points(db_path)
        eps_sorted = sorted(eps, key=lambda e: e.get("attack_score", 0), reverse=True)
        root_functions = [ep["function_name"] for ep in eps_sorted[:10] if ep.get("function_name")]
        entry_point_metadata = [
            {
                "function_name": ep.get("function_name", ""),
                "entry_type": ep.get("entry_type", ""),
                "attack_score": ep.get("attack_score", 0),
                "rpc_opnum": ep.get("rpc_opnum"),
                "rpc_interface_id": ep.get("rpc_interface_id", ""),
                "com_clsid": ep.get("com_clsid", ""),
                "dangerous_ops_reachable": ep.get("dangerous_ops_reachable", 0),
                "tainted_args": ep.get("tainted_args", []),
            }
            for ep in eps_sorted[:10]
        ]
    else:
        emit_error("Either --function or --entry-points is required", ErrorCode.INVALID_ARGS)
        return {}

    all_nodes: dict[str, dict] = {}
    all_edges: list[dict] = []

    for root_func in root_functions:
        status_message(f"Building callgraph for {root_func}...")
        cg = _build_callgraph(db_path, root_func, module_name, max_depth, function_index)

        for node_key, node_data in cg["nodes"].items():
            if node_key not in all_nodes:
                all_nodes[node_key] = node_data
                if node_data.get("is_entry_point") is None:
                    node_data["is_entry_point"] = (node_data["function"] == root_func)

        all_edges.extend(cg["edges"])

    for node_key, node_data in all_nodes.items():
        if node_data.get("function") in root_functions:
            node_data["is_entry_point"] = True

    _annotate_ipc_reachability(all_nodes, entry_point_metadata)

    _resolve_function_ids(db_path, all_nodes, module_name)

    seen_edges: set[tuple[str, str]] = set()
    deduped_edges: list[dict] = []
    for e in all_edges:
        key = (e["from"], e["to"])
        if key not in seen_edges:
            seen_edges.add(key)
            deduped_edges.append(e)

    lib_funcs: set[str] = set()
    if function_index:
        for fname, entry in function_index.items():
            if is_library_function(entry):
                lib_funcs.add(fname)

    traversal_plan = _compute_traversal_plan(
        all_nodes, module_name, lib_funcs, max_depth,
    )

    modules_involved = sorted(set(n["module"] for n in all_nodes.values()))

    preloaded_code: dict[str, dict] | None = None
    preloaded_count = 0
    if with_code:
        preloaded_code = _preload_code(db_path, traversal_plan, module_name)
        preloaded_count = len(preloaded_code)

    result: dict[str, Any] = {
        "status": "ok",
        "module": module_name,
        "db_path": str(db_path),
        "max_depth": max_depth,
        "root_functions": root_functions,
        "entry_points": entry_point_metadata,
        "callgraph": {
            "nodes": all_nodes,
            "edges": deduped_edges,
        },
        "traversal_plan": traversal_plan,
        "stats": {
            "total_nodes": len(all_nodes),
            "must_read": traversal_plan["counts"]["must_read"],
            "known_api": traversal_plan["counts"]["known_api"],
            "telemetry": traversal_plan["counts"]["telemetry"],
            "library": traversal_plan["counts"]["library"],
            "total_edges": len(deduped_edges),
            "modules_involved": modules_involved,
        },
        "_summary": {
            "module": module_name,
            "root_functions": root_functions,
            "depth": max_depth,
            "total_nodes": len(all_nodes),
            "must_read_count": traversal_plan["counts"]["must_read"],
            "must_read_by_depth": traversal_plan["must_read_by_depth"],
            "preloaded_count": preloaded_count,
            "modules": modules_involved,
        },
    }

    if preloaded_code is not None:
        result["preloaded_code"] = preloaded_code

    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prepare cross-module callgraph context for AI memory corruption scanning"
    )
    parser.add_argument("db_path", help="Path to the individual analysis database")
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("--function", dest="function_name", metavar="NAME",
                              help="Build callgraph from a specific function")
    target_group.add_argument("--entry-points", action="store_true",
                              help="Auto-discover entry points and build callgraphs")
    parser.add_argument("--depth", type=int, default=5,
                        help="Maximum callgraph depth (default: 5)")
    parser.add_argument("--with-code", action="store_true",
                        help="Pre-load decompiled code for depth 0+1 MUST_READ functions")
    parser.add_argument("--json", action="store_true", help="JSON output mode")
    args = safe_parse_args(parser)

    db_path = resolve_db_path(args.db_path)
    result = prepare_context(
        db_path,
        function_name=args.function_name,
        entry_points_mode=args.entry_points,
        max_depth=args.depth,
        with_code=args.with_code,
    )

    if args.json:
        emit_json(result)
    else:
        stats = result.get("stats", {})
        tp = result.get("traversal_plan", {})
        print(f"=== Callgraph Context: {result.get('module', '')} ===")
        print(f"  Root functions: {', '.join(result.get('root_functions', []))}")
        print(f"  Depth:          {result.get('max_depth', 0)}")
        print(f"  Total nodes:    {stats.get('total_nodes', 0)}")
        print(f"  MUST_READ:      {stats.get('must_read', 0)}")
        print(f"  KNOWN_API:      {stats.get('known_api', 0)}")
        print(f"  TELEMETRY:      {stats.get('telemetry', 0)}")
        print(f"  LIBRARY:        {stats.get('library', 0)}")
        print(f"  Total edges:    {stats.get('total_edges', 0)}")
        print(f"  Modules:        {', '.join(stats.get('modules_involved', []))}")
        print()
        must_by_depth = tp.get("must_read_by_depth", {})
        if must_by_depth:
            print("  MUST_READ by depth:")
            for d in sorted(must_by_depth, key=int):
                print(f"    depth {d}: {must_by_depth[d]}")
            print()
        preloaded = result.get("preloaded_code")
        if preloaded:
            print(f"  Pre-loaded code for {len(preloaded)} functions (depth 0+1)")
            for key in sorted(preloaded):
                code = preloaded[key].get("decompiled_code", "")
                lines = len(code.splitlines()) if code else 0
                print(f"    {key}: {lines} lines")
            print()
        for ep in result.get("entry_points", []):
            print(f"  [{ep.get('entry_type', '?')}] {ep['function_name']}  "
                  f"(score={ep.get('attack_score', 0):.2f})")


if __name__ == "__main__":
    main()
