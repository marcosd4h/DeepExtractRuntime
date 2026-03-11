#!/usr/bin/env python3
"""Taint analysis orchestrator -- entry point for single-function taint analysis.

Resolves the target function, infers parameters if not specified, then
dispatches to ``trace_taint_forward.py`` and/or ``trace_taint_backward.py``
based on ``--direction``.  Results are merged into a unified report via
``generate_taint_report.py``.

Usage:
    python taint_function.py <db_path> <function_name>
    python taint_function.py <db_path> <function_name> --params 1,3
    python taint_function.py <db_path> --id <fid> --params 1 --depth 3 --direction both
    python taint_function.py <db_path> <function_name> --json

Defaults:
    --direction forward
    --depth 2
    --params (all parameters inferred from signature)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from _common import (
    WORKSPACE_ROOT,
    emit_error,
    emit_json,
    get_function,
    param_name_for,
    resolve_db_path,
    resolve_tainted_params,
    validate_function_id,
)
from helpers.errors import emit_error, ErrorCode, safe_parse_args
from trace_taint_forward import trace_forward
from trace_taint_backward import trace_backward
from generate_taint_report import build_report, render_markdown


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def taint_function(
    db_path: str,
    function_name: str | None = None,
    function_id: int | None = None,
    params_arg: str | None = None,
    depth: int = 2,
    direction: str = "forward",
    json_output: bool = False,
    cross_module: bool = False,
    cross_depth: int = 1,
) -> dict:
    """Run taint analysis on a single function."""
    func = get_function(db_path, function_name=function_name, function_id=function_id)
    if not func:
        target = function_name or f"ID={function_id}"
        emit_error(f"Function '{target}' not found", ErrorCode.NOT_FOUND)

    fid = func["function_id"]
    sig = func.get("function_signature", "") or ""
    code = func.get("decompiled_code", "") or ""
    params = resolve_tainted_params(params_arg, sig, code)

    forward_data = None
    backward_data = None

    if direction in ("forward", "both"):
        forward_data = trace_forward(
            db_path=db_path,
            function_id=fid,
            params=params,
            depth=depth,
            cross_module=cross_module,
            cross_depth=cross_depth,
        )

    if direction in ("backward", "both"):
        backward_data = trace_backward(
            db_path=db_path,
            function_id=fid,
            params=params,
            depth=depth,
        )

    return build_report(forward_data, backward_data, direction=direction)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Taint analysis: trace attacker-controlled inputs to dangerous sinks.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("db_path", help="Path to the module analysis DB")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--function", "--name", dest="function_name", metavar="NAME",
                       help="Function name")
    group.add_argument("--id", "--function-id", type=int, dest="function_id")
    parser.add_argument("function_name_pos", nargs="?", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--params", default=None, help="Comma-separated param numbers (1-based); omit for all")
    parser.add_argument("--depth", type=int, default=2, help="Max recursion depth (default: 2)")
    parser.add_argument(
        "--direction",
        choices=["forward", "backward", "both"],
        default="forward",
        help="Trace direction (default: forward)",
    )
    parser.add_argument("--cross-module", action="store_true",
                        help="Resolve external callees to other analyzed modules and recurse")
    parser.add_argument("--cross-depth", type=int, default=1,
                        help="Max cross-module hops (default: 1)")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--no-cache", action="store_true")
    args = safe_parse_args(parser)
    if args.function_name_pos and not args.function_name:
        args.function_name = args.function_name_pos

    if not args.function_name and args.function_id is None:
        emit_error("Provide a function name or --id", ErrorCode.INVALID_ARGS)
    if args.function_id is not None:
        args.function_id = validate_function_id(args.function_id)

    db_path = resolve_db_path(args.db_path)

    report = taint_function(
        db_path=db_path,
        function_name=args.function_name,
        function_id=args.function_id,
        params_arg=args.params,
        depth=args.depth,
        direction=args.direction,
        json_output=args.json,
        cross_module=args.cross_module,
        cross_depth=args.cross_depth,
    )

    if args.json:
        emit_json(report)
    else:
        print(render_markdown(report))


if __name__ == "__main__":
    main()
