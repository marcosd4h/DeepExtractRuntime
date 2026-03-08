#!/usr/bin/env python3
"""Trace an RPC handler's data flow from dispatch to dangerous sinks.

Usage:
    python trace_rpc_chain.py <db_path> --function <func_name>
    python trace_rpc_chain.py <db_path> --function RAiLaunchAdminProcess --json
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

_SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT_DIR))

from _common import (
    db_error_handler,
    emit_json,
    open_individual_analysis_db,
    parse_json_safe,
    require_rpc_index,
)
from helpers.errors import safe_parse_args
from helpers.callgraph import CallGraph
from helpers.api_taxonomy import classify_api_security, get_dangerous_api_set


def trace_handler(db_path: str, function_name: str, max_depth: int = 8) -> dict[str, Any]:
    """Trace an RPC handler's call chain and dangerous sinks."""
    idx = require_rpc_index()
    result: dict[str, Any] = {
        "function_name": function_name,
        "rpc_context": {},
        "call_chain": [],
        "dangerous_sinks": [],
        "depth_to_first_sink": None,
    }

    with db_error_handler(db_path, f"tracing RPC chain for {function_name}"):
        with open_individual_analysis_db(db_path) as db:
            fi = db.get_file_info()
            module_name = fi.file_name if fi else ""

            if module_name and idx.loaded:
                iface = idx.get_interface_for_procedure(module_name, function_name)
                if iface:
                    result["rpc_context"] = {
                        "interface_id": iface.interface_id,
                        "interface_version": iface.interface_version,
                        "opnum": idx.procedure_to_opnum(module_name, function_name),
                        "protocols": sorted(iface.protocols),
                        "risk_tier": iface.risk_tier,
                        "service_name": iface.service_name,
                        "complex_types": iface.complex_types[:5],
                    }

            all_funcs = db.get_all_functions()
            graph = CallGraph.from_functions(all_funcs)
            reachable = graph.reachable_from(function_name, max_depth=max_depth)

            func_map = {f.function_name: f for f in all_funcs if f.function_name}
            dangerous_apis = get_dangerous_api_set()

            chain_entries = []
            sinks = []
            min_sink_depth = None

            for fname, depth in sorted(reachable.items(), key=lambda x: x[1]):
                func = func_map.get(fname)
                sig = ""
                if func:
                    sig = func.function_signature_extended or func.function_signature or ""

                chain_entries.append({
                    "function_name": fname,
                    "depth": depth,
                    "signature": sig[:120] if sig else "",
                })

                if func:
                    outbound = parse_json_safe(func.simple_outbound_xrefs) or []
                    for xref in outbound:
                        if not isinstance(xref, dict):
                            continue
                        callee = xref.get("function_name", "")
                        if not callee:
                            continue
                        sec_cat = classify_api_security(callee)
                        is_dangerous = callee in dangerous_apis
                        if sec_cat or is_dangerous:
                            sinks.append({
                                "api": callee,
                                "called_by": fname,
                                "depth": depth,
                                "security_category": sec_cat or "dangerous_api",
                            })
                            if min_sink_depth is None or depth < min_sink_depth:
                                min_sink_depth = depth

            result["call_chain"] = chain_entries[:100]
            result["dangerous_sinks"] = sinks
            result["depth_to_first_sink"] = min_sink_depth
            result["reachable_count"] = len(reachable)

    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Trace RPC handler call chain.")
    parser.add_argument("db_path", help="Path to module analysis DB")
    parser.add_argument("--function", required=True, help="RPC handler function name")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--depth", type=int, default=8, help="Max trace depth")
    args = safe_parse_args(parser)

    result = trace_handler(args.db_path, args.function, max_depth=args.depth)

    if args.json:
        emit_json(result)
        return

    ctx = result.get("rpc_context", {})
    print(f"{'=' * 80}")
    print(f"RPC CHAIN TRACE: {result['function_name']}")
    print(f"{'=' * 80}")

    if ctx:
        print(f"  Interface:  {ctx.get('interface_id', '?')} v{ctx.get('interface_version', '?')}")
        print(f"  Opnum:      {ctx.get('opnum', '?')}")
        print(f"  Protocols:  {', '.join(ctx.get('protocols', []))}")
        print(f"  Risk tier:  {ctx.get('risk_tier', '?')}")
        if ctx.get("service_name"):
            print(f"  Service:    {ctx['service_name']}")
    print(f"  Reachable:  {result.get('reachable_count', 0)} functions")
    print(f"  Sinks:      {len(result.get('dangerous_sinks', []))} dangerous operations")
    if result.get("depth_to_first_sink") is not None:
        print(f"  First sink: depth {result['depth_to_first_sink']}")
    print()

    sinks = result.get("dangerous_sinks", [])
    if sinks:
        print(f"  Dangerous sinks:")
        for s in sinks[:20]:
            print(f"    depth {s['depth']}: {s['called_by']} -> {s['api']} [{s['security_category']}]")
    print()


if __name__ == "__main__":
    main()
