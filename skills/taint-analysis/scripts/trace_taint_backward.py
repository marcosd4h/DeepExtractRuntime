#!/usr/bin/env python3
"""Backward taint origin analysis: discover where tainted parameters come from.

Uses ``CallGraph.callers_of()`` to discover callers, then invokes
``backward_trace.py --target <our_function>`` on each caller to determine
what expression they pass for the tainted parameters.  Each argument
origin is classified (parameter, call_result, constant, global, etc.) and
the caller chain is built into a tree.

Usage:
    python trace_taint_backward.py <db_path> <function_name> --params 1
    python trace_taint_backward.py <db_path> --id <fid> --params 1,3 --depth 2
    python trace_taint_backward.py <db_path> <function_name> --json
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from _common import (
    WORKSPACE_ROOT,
    CallGraph,
    emit_error,
    emit_json,
    get_function,
    get_workspace_args,
    param_name_for,
    resolve_db_path,
    resolve_tainted_params,
    run_skill_script,
    validate_function_id,
    SOURCE_SEVERITY,
)
from helpers.errors import db_error_handler, emit_error, ErrorCode, safe_parse_args  # noqa: E402

# ---------------------------------------------------------------------------
# Core backward taint analysis
# ---------------------------------------------------------------------------


def _classify_origin_risk(classification: dict) -> str:
    """Map a backward_trace classification dict to a risk label."""
    otype = classification.get("type", "expression")
    if otype == "parameter":
        return "HIGH"
    if otype == "param_dereference":
        return "HIGH"
    if otype == "call_result":
        return "MEDIUM"
    if otype in ("global", "local_variable"):
        return "MEDIUM"
    if otype in ("constant", "string_literal"):
        return "NONE"
    return "LOW"


def _extract_caller_origins(bt_result: dict, our_params: list[int]) -> list[dict]:
    """Parse backward_trace JSON output to extract what each caller passes."""
    origins: list[dict] = []
    if bt_result.get("status") != "ok":
        return origins

    for site in bt_result.get("call_sites", []):
        for arg in site.get("arguments", []):
            arg_num = arg.get("number", 0)
            if arg_num not in our_params:
                continue
            classification = arg.get("classification", {})
            origin = {
                "for_param": arg_num,
                "expression": arg.get("expression", "?"),
                "origin_type": classification.get("type", "expression"),
                "risk": _classify_origin_risk(classification),
                "classification": classification,
                "line_number": site.get("line_number"),
                "line": site.get("line", ""),
            }
            if arg.get("deeper_trace"):
                origin["deeper_trace"] = arg["deeper_trace"]
            if arg.get("param_origins"):
                origin["param_origins"] = arg["param_origins"]
            origins.append(origin)

    return origins


def trace_backward(
    db_path: str,
    function_name: str | None = None,
    function_id: int | None = None,
    params: list[int] | None = None,
    depth: int = 1,
) -> dict:
    """Run backward taint origin analysis."""
    func = get_function(db_path, function_name=function_name, function_id=function_id)
    if not func:
        target = function_name or f"ID={function_id}"
        emit_error(f"Function '{target}' not found in {Path(db_path).name}", ErrorCode.NOT_FOUND)

    sig = func.get("function_signature", "") or ""
    code = func.get("decompiled_code", "") or ""
    target_name = func["function_name"]

    if params is None:
        params = resolve_tainted_params(None, sig, code)

    # Discover callers via call graph
    with db_error_handler(db_path, "building call graph"):
        cg = CallGraph.from_db(db_path)

    caller_ids = cg.callers_of(target_name, max_depth=1)
    # caller_ids is a set of function names (or IDs depending on impl)

    inbound_xrefs = func.get("inbound_xrefs", [])
    caller_entries: list[dict] = []

    for xref in inbound_xrefs:
        if not isinstance(xref, dict):
            continue
        caller_name = xref.get("function_name", "")
        caller_id = xref.get("function_id")
        caller_module = xref.get("module_name", "")

        if caller_id is None:
            caller_entries.append({
                "caller_name": caller_name,
                "caller_id": None,
                "status": "external",
                "module": caller_module,
                "origins": [],
            })
            continue

        bt_args = [db_path, "--id", str(caller_id), "--target", target_name]
        if depth > 1:
            bt_args += ["--callers", "--depth", str(depth - 1)]

        bt_result = run_skill_script(
            "data-flow-tracer",
            "backward_trace.py",
            bt_args,
            json_output=True,
            timeout=60,
        )

        bt_data = bt_result.get("json_data")
        origins: list[dict] = []
        if bt_data and bt_result.get("success"):
            origins = _extract_caller_origins(bt_data, params)

        entry = {
            "caller_name": caller_name,
            "caller_id": caller_id,
            "status": "resolved" if origins else "no_origins",
            "origins": origins,
        }
        caller_entries.append(entry)

    high_risk = sum(
        1 for c in caller_entries
        for o in c.get("origins", [])
        if o.get("risk") == "HIGH"
    )

    return {
        "status": "ok",
        "function": {
            "function_id": func["function_id"],
            "function_name": func["function_name"],
            "function_signature": func["function_signature"],
            "module_name": func["module_name"],
            "db": Path(db_path).name,
        },
        "tainted_params": params,
        "depth": depth,
        "callers": caller_entries,
        "summary": {
            "total_callers": len(caller_entries),
            "resolved": sum(1 for c in caller_entries if c["status"] == "resolved"),
            "external": sum(1 for c in caller_entries if c["status"] == "external"),
            "high_risk_origins": high_risk,
        },
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Backward taint origin analysis: discover where tainted parameters come from.",
    )
    parser.add_argument("db_path", help="Path to the module analysis DB")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--function", "--name", dest="function_name", metavar="NAME",
                       help="Function name")
    group.add_argument("--id", "--function-id", type=int, dest="function_id")
    parser.add_argument("function_name_pos", nargs="?", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--params", default=None, help="Comma-separated param numbers (1-based); omit for all")
    parser.add_argument("--depth", type=int, default=1, help="Max caller recursion depth (default: 1)")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--no-cache", action="store_true")
    args = safe_parse_args(parser)
    if args.function_name_pos and not args.function_name:
        args.function_name = args.function_name_pos

    if not args.function_name and args.function_id is None:
        parser.error("Provide a function name or --id")
    if args.function_id is not None:
        args.function_id = validate_function_id(args.function_id)

    db_path = resolve_db_path(args.db_path)
    params = None
    if args.params:
        params = [int(p.strip()) for p in args.params.split(",") if p.strip().isdigit()]

    result = trace_backward(
        db_path=db_path,
        function_name=args.function_name,
        function_id=args.function_id,
        params=params,
        depth=args.depth,
    )

    if args.json:
        emit_json(result)
    else:
        _print_result(result)


def _print_result(result: dict) -> None:
    status = result.get("status", "")
    if status == "not_found":
        print(f"[NOT FOUND] {result.get('target', '?')} in {result.get('db', '?')}")
        return

    func = result.get("function", {})
    params = result.get("tainted_params", [])
    pnames = ", ".join(param_name_for(p) for p in params)
    print(f"\n{'=' * 78}")
    print(f"Backward Taint Origin: {func.get('function_name', '?')}")
    print(f"{'=' * 78}")
    print(f"Module: {func.get('module_name', '?')}")
    print(f"Signature: {func.get('function_signature', '?')}")
    print(f"Tracing origins of: {pnames}")

    callers = result.get("callers", [])
    if not callers:
        print("\nNo callers found.")
        return

    print(f"\n--- {len(callers)} Caller(s) ---\n")
    for c in callers:
        cname = c.get("caller_name", "?")
        cstatus = c.get("status", "?")
        if cstatus == "external":
            print(f"  {cname} [{c.get('module', '?')}] -- external, cannot inspect")
            continue

        origins = c.get("origins", [])
        if not origins:
            print(f"  {cname} [ID={c.get('caller_id')}] -- no origin data")
            continue

        for o in origins:
            risk = o.get("risk", "?")
            print(f"  {cname} passes {o['expression']} for param {o['for_param']} "
                  f"-- origin: {o['origin_type']} (risk: {risk})")
            if o.get("line"):
                print(f"    L{o.get('line_number', '?')}: {o['line'][:120]}")
    print()

    summary = result.get("summary", {})
    print(f"Summary: {summary.get('total_callers', 0)} callers | "
          f"{summary.get('resolved', 0)} resolved | "
          f"{summary.get('external', 0)} external | "
          f"{summary.get('high_risk_origins', 0)} high-risk origins")


if __name__ == "__main__":
    main()
