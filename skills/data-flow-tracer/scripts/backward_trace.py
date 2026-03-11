#!/usr/bin/env python3
"""Backward data-flow trace: find where an API call's arguments originate.

Given a function and a target API call within it, traces backward to find
where each argument comes from: function parameter, another call's return
value, global variable, constant, or complex expression.

Usage:
    python backward_trace.py <db_path> <function_name> --target <API_name>
    python backward_trace.py <db_path> <function_name> --target <API_name> --arg N
    python backward_trace.py <db_path> <function_name> --target <API_name> --callers
    python backward_trace.py <db_path> --id <function_id> --target <API_name>
    python backward_trace.py <db_path> <function_name> --target <API_name> --json

Examples:
    # Where do all arguments to CreateFileW in AiLaunchProcess come from?
    python backward_trace.py extracted_dbs/appinfo_dll_e98d25a9e8.db AiLaunchProcess --target CreateFileW

    # Trace just the 1st argument, then show what each caller passes
    python backward_trace.py extracted_dbs/appinfo_dll_e98d25a9e8.db AiLaunchProcess --target CreateProcessAsUserW --arg 1 --callers

    # Deep trace: follow callers recursively
    python backward_trace.py extracted_dbs/cmd_exe_6d109a3a00.db eComSrv --target CreateProcessW --arg 2 --callers --depth 2

    # JSON output
    python backward_trace.py extracted_dbs/appinfo_dll_e98d25a9e8.db AiLaunchProcess --target CreateFileW --json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from _common import (
    WORKSPACE_ROOT,
    classify_expression,
    emit_error,
    extract_function_calls,
    param_name_for,
    parse_json_safe,
    resolve_db_path,
    resolve_tracking_db,
    trace_variable_origin,
)

from helpers import (
    load_function_index_for_db,
    open_analyzed_files_db,
    open_individual_analysis_db,
    resolve_function,
    validate_function_id,
)
from helpers.cache import get_cached, cache_result
from helpers.errors import ErrorCode, db_error_handler, emit_error, safe_parse_args
from helpers.json_output import emit_json


def _get_function(db_path: str, function_name: str = None, function_id: int = None):
    """Retrieve a function record from the DB."""
    function_index = load_function_index_for_db(db_path)
    with db_error_handler(db_path, "loading function data"):
        with open_individual_analysis_db(db_path) as db:
            func, _err = resolve_function(
                db, name=function_name, function_id=function_id,
                function_index=function_index,
            )

            if not func:
                return None

            file_info = db.get_file_info()
            module_name = file_info.file_name if file_info else Path(db_path).stem

    return {
        "function_id": func.function_id,
        "function_name": func.function_name,
        "function_signature": func.function_signature,
        "function_signature_extended": func.function_signature_extended,
        "decompiled_code": func.decompiled_code or "",
        "assembly_code": func.assembly_code or "",
        "module_name": module_name,
        "db_path": db_path,
        "outbound_xrefs": parse_json_safe(func.simple_outbound_xrefs) or [],
        "inbound_xrefs": parse_json_safe(func.simple_inbound_xrefs) or [],
    }


def _resolve_caller_db(caller_module: str) -> str | None:
    """Resolve a caller's module name to its analysis DB path."""
    tracking_path = resolve_tracking_db()
    if tracking_path is None:
        return None
    tracking = Path(tracking_path)
    with db_error_handler(str(tracking), "resolving caller module"):
        with open_analyzed_files_db(str(tracking)) as db:
            records = db.get_by_file_name(caller_module)
            for r in records:
                if r.status == "COMPLETE" and r.analysis_db_path:
                    abs_path = tracking.parent / r.analysis_db_path
                    if abs_path.exists():
                        return str(abs_path)
    return None


def _format_origin(origin: dict, indent: str = "") -> str:
    """Format a classified origin for display."""
    otype = origin["type"]
    line_info = f" (L{origin['line_number']})" if "line_number" in origin else ""

    if otype == "parameter":
        return f"{indent}PARAMETER a{origin['param_number']}{line_info}"
    elif otype == "call_result":
        return f"{indent}RETURN VALUE of {origin['function']}(){line_info}"
    elif otype == "global":
        return f"{indent}GLOBAL VARIABLE {origin['name']}{line_info}"
    elif otype == "constant":
        return f"{indent}CONSTANT {origin['value']}{line_info}"
    elif otype == "string_literal":
        val = origin["value"][:60] + "..." if len(origin.get("value", "")) > 60 else origin.get("value", "")
        return f"{indent}STRING LITERAL {val}{line_info}"
    elif otype == "local_variable":
        return f"{indent}LOCAL VARIABLE {origin['name']}{line_info}"
    elif otype == "param_dereference":
        return f"{indent}DEREFERENCE of param a{origin['param_number']}: {origin['expression']}{line_info}"
    else:
        expr = origin.get("expression", origin.get("raw_expression", "?"))
        return f"{indent}EXPRESSION: {expr}{line_info}"


# ---------------------------------------------------------------------------
# Core trace logic (returns structured data)
# ---------------------------------------------------------------------------


def backward_trace(
    db_path: str,
    function_name: str = None,
    function_id: int = None,
    target_api: str = "",
    target_arg: int = None,
    show_callers: bool = False,
    max_depth: int = 1,
    current_depth: int = 0,
    visited: set = None,
) -> dict:
    """Trace backward: find where a target API call's arguments come from.

    Returns a structured result dict.
    """
    if visited is None:
        visited = set()

    result = {
        "depth": current_depth,
        "target_api": target_api,
        "target_arg": target_arg,
    }

    func = _get_function(db_path, function_name=function_name, function_id=function_id)
    if not func:
        target = function_name or f"ID={function_id}"
        result["status"] = "not_found"
        result["target"] = target
        result["db"] = Path(db_path).name
        return result

    visit_key = (db_path, func["function_name"])
    if visit_key in visited:
        result["status"] = "cycle"
        result["function_name"] = func["function_name"]
        return result
    visited.add(visit_key)

    result["function"] = {
        "function_id": func["function_id"],
        "function_name": func["function_name"],
        "function_signature": func["function_signature"],
        "module_name": func["module_name"],
        "db": Path(db_path).name,
    }

    code = func["decompiled_code"]
    if not code:
        result["status"] = "no_code"
        return result

    # -- Find all calls to the target API via xrefs + decompiled code --
    from helpers.decompiled_parser import discover_calls_with_xrefs
    all_calls = discover_calls_with_xrefs(code, func.get("outbound_xrefs", []))
    target_calls = [c for c in all_calls if c["function_name"].lower() == target_api.lower()
                    or target_api.lower() in c["function_name"].lower()]

    if not target_calls:
        target_calls = [c for c in all_calls
                        if target_api.lower().replace("__imp_", "") in c["function_name"].lower().replace("__imp_", "")]

    if not target_calls:
        seen = set()
        available = []
        for c in sorted(all_calls, key=lambda x: x["function_name"]):
            if c["function_name"] not in seen:
                seen.add(c["function_name"])
                available.append(c["function_name"])
        result["status"] = "target_not_found"
        result["available_calls"] = available
        result["total_call_count"] = len(all_calls)
        return result

    result["status"] = "ok"
    result["call_sites"] = []

    # -- Analyze each call site --
    for ci, call in enumerate(target_calls):
        site = {
            "index": ci + 1,
            "line_number": call["line_number"],
            "line": call["line"],
            "result_var": call["result_var"],
            "arguments": [],
            "param_origins": [],
            "callers": None,
        }

        args = call["arguments"]
        if not args:
            result["call_sites"].append(site)
            continue

        # Determine which args to analyze
        if target_arg is not None:
            if target_arg < 1 or target_arg > len(args):
                site["arg_error"] = f"Arg {target_arg} requested but call has {len(args)} args"
                result["call_sites"].append(site)
                continue
            analyze_args = [(target_arg - 1, args[target_arg - 1])]
        else:
            analyze_args = list(enumerate(args))

        param_origins = []

        for arg_idx, arg_expr in analyze_args:
            arg_num = arg_idx + 1
            classified = classify_expression(arg_expr)

            arg_data = {
                "number": arg_num,
                "expression": arg_expr,
                "classification": classified,
                "deeper_trace": [],
                "param_origins": [],
            }

            # Classify the immediate expression
            if classified["type"] == "local_variable":
                origins = trace_variable_origin(code, classified["name"])
                if origins:
                    arg_data["deeper_trace"] = origins
                    for orig in origins:
                        if orig["type"] == "parameter":
                            param_origins.append(orig["param_number"])
                            arg_data["param_origins"].append(orig["param_number"])
                        elif "deeper_origin" in orig:
                            for deep in orig["deeper_origin"]:
                                if deep["type"] == "parameter":
                                    param_origins.append(deep["param_number"])
                                    arg_data["param_origins"].append(deep["param_number"])

            elif classified["type"] == "parameter":
                param_origins.append(classified["param_number"])
                arg_data["param_origins"].append(classified["param_number"])

            elif classified["type"] == "param_dereference":
                param_origins.append(classified["param_number"])
                arg_data["param_origins"].append(classified["param_number"])

            site["arguments"].append(arg_data)

        site["param_origins"] = sorted(set(param_origins))

        # -- Collect caller context if requested and origin is a parameter --
        if show_callers and param_origins:
            site["callers"] = _collect_caller_context(
                func, param_origins, db_path,
                max_depth=max_depth, current_depth=current_depth,
                visited=visited,
            )

        result["call_sites"].append(site)

    return result


def _collect_caller_context(
    func: dict,
    param_numbers: list[int],
    db_path: str,
    max_depth: int = 1,
    current_depth: int = 0,
    visited: set = None,
) -> dict:
    """Collect what each caller passes for the specified parameters.

    Returns {has_inbound, traced_params, callers}.
    """
    unique_params = sorted(set(param_numbers))
    inbound = func["inbound_xrefs"]

    if not inbound:
        return {"has_inbound": False, "traced_params": unique_params, "callers": []}

    callers = []
    for xref in inbound:
        if not isinstance(xref, dict):
            continue
        caller_name = xref.get("function_name", "?")
        caller_id = xref.get("function_id")

        if caller_id is None:
            module = xref.get("module_name", "?")
            callers.append({
                "caller_name": caller_name,
                "caller_id": None,
                "status": "external",
                "module_name": module,
            })
            continue

        # Get caller's decompiled code
        caller_func = _get_function(db_path, function_id=caller_id)
        if not caller_func or not caller_func["decompiled_code"]:
            callers.append({
                "caller_name": caller_name,
                "caller_id": caller_id,
                "status": "no_code",
            })
            continue

        caller_code = caller_func["decompiled_code"]

        # Find calls from this caller to our function
        caller_calls = extract_function_calls(caller_code)
        our_calls = [c for c in caller_calls
                     if c["function_name"] == func["function_name"]
                     or func["function_name"] in c["function_name"]]

        if not our_calls:
            callers.append({
                "caller_name": caller_name,
                "caller_id": caller_id,
                "status": "call_not_found",
            })
            continue

        caller_entry = {
            "caller_name": caller_name,
            "caller_id": caller_id,
            "status": "resolved",
            "call_sites": [],
        }

        for oc in our_calls:
            call_data = {
                "line_number": oc["line_number"],
                "line": oc["line"],
                "param_passes": [],
            }

            for pn in unique_params:
                if pn <= len(oc["arguments"]):
                    arg_expr = oc["arguments"][pn - 1]
                    classified = classify_expression(arg_expr)
                    pass_data = {
                        "param_number": pn,
                        "expression": arg_expr,
                        "classification": classified,
                    }

                    # If the caller passes one of its own parameters, recurse
                    if classified["type"] == "parameter" and current_depth < max_depth:
                        caller_param = classified["param_number"]
                        pass_data["caller_param"] = caller_param
                        pass_data["recursive_callers"] = _collect_caller_context(
                            caller_func, [caller_param], db_path,
                            max_depth=max_depth, current_depth=current_depth + 1,
                            visited=visited,
                        )

                    call_data["param_passes"].append(pass_data)

            caller_entry["call_sites"].append(call_data)

        callers.append(caller_entry)

    return {"has_inbound": True, "traced_params": unique_params, "callers": callers}


# ---------------------------------------------------------------------------
# Text rendering (human-readable output)
# ---------------------------------------------------------------------------


def _print_backward_trace(result: dict) -> None:
    """Print backward trace result as human-readable text."""
    depth = result.get("depth", 0)
    indent = "  " * depth
    prefix = f"[Depth {depth}]" if depth > 0 else "[Start]"
    status = result.get("status", "")
    target_api = result["target_api"]

    if status == "not_found":
        print(f"{indent}[NOT FOUND] {result['target']} in {result['db']}")
        return

    if status == "cycle":
        print(f"{indent}[CYCLE] Already traced {result['function_name']}")
        return

    func = result["function"]

    print(f"\n{indent}{'=' * (80 - len(indent))}")
    print(f"{indent}{prefix} Backward trace: {func['function_name']}  target={target_api}")
    print(f"{indent}{'=' * (80 - len(indent))}")
    print(f"{indent}Module: {func['module_name']}")
    print(f"{indent}Signature: {func['function_signature'] or '(unknown)'}")
    print(f"{indent}DB: {func['db']}")

    if status == "no_code":
        print(f"\n{indent}(no decompiled code available)")
        return

    if status == "target_not_found":
        total = result.get("total_call_count", len(result.get("available_calls", [])))
        print(f"\n{indent}[NOT FOUND] No call to '{target_api}' found in decompiled code.")
        print(f"{indent}Available calls ({total}):")
        for name in result.get("available_calls", []):
            print(f"{indent}  {name}()")
        return

    for site in result.get("call_sites", []):
        print(f"\n{indent}--- Call site {site['index']}: L{site['line_number']} ---")
        print(f"{indent}  {site['line']}")
        if site.get("result_var"):
            print(f"{indent}  Result stored in: {site['result_var']}")

        if site.get("arg_error"):
            print(f"{indent}  [ERROR] {site['arg_error']}")
            continue

        if not site.get("arguments"):
            print(f"{indent}  (no arguments)")
            continue

        for arg_data in site["arguments"]:
            classified = arg_data["classification"]
            print(f"\n{indent}  Argument {arg_data['number']}: {arg_data['expression']}")
            print(f"{indent}    -> {_format_origin(classified)}")

            # If it's a local variable, show the deeper trace
            if classified["type"] == "local_variable" and arg_data.get("deeper_trace"):
                print(f"{indent}    Tracing {classified['name']} backward:")
                for orig in arg_data["deeper_trace"]:
                    print(f"{indent}      -> {_format_origin(orig)}")
                    if "deeper_origin" in orig:
                        for deep in orig["deeper_origin"]:
                            print(f"{indent}        -> {_format_origin(deep)}")

        # -- Show callers if collected --
        if site.get("callers") is not None:
            _print_caller_context(site["callers"], indent)


def _print_caller_context(caller_data: dict, indent: str) -> None:
    """Print caller context as human-readable text."""
    unique_params = caller_data["traced_params"]
    print(f"\n{indent}  Origin traced to parameter(s): {', '.join(f'a{p}' for p in unique_params)}")
    print(f"{indent}  Checking callers to see what they pass...")

    if not caller_data["has_inbound"]:
        print(f"{indent}  (no inbound callers recorded)")
        return

    callers_shown = 0
    for caller in caller_data["callers"]:
        status = caller["status"]
        name = caller["caller_name"]
        cid = caller.get("caller_id")

        if status == "external":
            module = caller.get("module_name", "?")
            print(f"{indent}  Caller: {name} ({module}) [external, cannot inspect]")
            continue

        if status == "no_code":
            print(f"{indent}  Caller: {name} [ID={cid}] (no decompiled code)")
            continue

        if status == "call_not_found":
            print(f"{indent}  Caller: {name} [ID={cid}] (call not found in decompiled code)")
            continue

        callers_shown += 1
        for call_data in caller.get("call_sites", []):
            print(f"\n{indent}  Caller: {name}  [ID={cid}]")
            print(f"{indent}    L{call_data['line_number']}: {call_data['line']}")
            for pp in call_data.get("param_passes", []):
                pn = pp["param_number"]
                print(f"{indent}    Passes as param {pn}: {pp['expression']}")
                print(f"{indent}      -> {_format_origin(pp['classification'])}")

                if pp["classification"]["type"] == "parameter" and pp.get("recursive_callers"):
                    caller_param = pp["classification"]["param_number"]
                    print(f"{indent}      (Caller receives this as its own param a{caller_param} -- tracing further...)")
                    _print_caller_context(pp["recursive_callers"], indent + "    ")

    if callers_shown == 0:
        print(f"{indent}  (no resolvable callers found)")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Backward data-flow trace: find where an API call's arguments originate.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("db_path", help="Path to the module's analysis DB")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--function", "--name", dest="function_name", metavar="NAME",
                       help="Function name containing the target call")
    group.add_argument("--id", "--function-id", type=int, dest="function_id", help="Function ID")
    parser.add_argument("function_name_pos", nargs="?", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--target", required=True, help="Target API/function name to trace arguments for")
    parser.add_argument("--arg", type=int, default=None, help="Specific argument number to trace (1-based)")
    parser.add_argument("--callers", action="store_true", help="Show what each caller passes when origin is a parameter")
    parser.add_argument("--depth", type=int, default=1, help="Max caller recursion depth (default: 1)")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--app-only", action="store_true", help="Skip library-tagged functions (from function_index)")
    parser.add_argument("--no-cache", action="store_true", help="Bypass cache and force fresh analysis")
    args = safe_parse_args(parser)
    if args.function_name_pos and not args.function_name:
        args.function_name = args.function_name_pos

    if not args.function_name and args.function_id is None:
        emit_error("Provide a function name or --id", ErrorCode.INVALID_ARGS)
    if args.function_id is not None:
        args.function_id = validate_function_id(args.function_id)

    db_path = resolve_db_path(args.db_path)

    cache_params = {}
    if args.function_name:
        cache_params["function_name"] = args.function_name
    if args.function_id is not None:
        cache_params["function_id"] = args.function_id
    cache_params["target"] = args.target
    if args.arg is not None:
        cache_params["arg"] = args.arg
    if args.callers:
        cache_params["callers"] = True
    cache_params["depth"] = args.depth

    if not args.no_cache:
        cached = get_cached(db_path, "backward_trace", params=cache_params)
        if cached is not None:
            if args.json:
                emit_json(cached)
            else:
                _print_backward_trace(cached)
            return

    result = backward_trace(
        db_path=db_path,
        function_name=args.function_name,
        function_id=args.function_id,
        target_api=args.target,
        target_arg=args.arg,
        show_callers=args.callers,
        max_depth=args.depth,
    )

    top_status = result.get("status", "")

    if args.json and top_status == "not_found":
        emit_error(f"Function '{result.get('target', '?')}' not found in {result.get('db', '?')}", ErrorCode.NOT_FOUND)
    if args.json and top_status == "no_code":
        fname = result.get("function", {}).get("function_name", "?")
        emit_error(f"No decompiled code for '{fname}'", ErrorCode.NO_DATA)
    if args.json and top_status == "target_not_found":
        avail = result.get("total_call_count", 0)
        emit_error(f"Target API '{args.target}' not called by this function ({avail} calls available)", ErrorCode.NO_DATA)

    cache_result(db_path, "backward_trace", result, params=cache_params)

    if args.json:
        emit_json(result)
    else:
        _print_backward_trace(result)


if __name__ == "__main__":
    main()
