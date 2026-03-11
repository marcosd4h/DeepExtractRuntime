#!/usr/bin/env python3
"""Forward data-flow trace: track where a function parameter flows to.

Given a function and a parameter number, traces where that parameter goes:
- Which function calls receive it (and at which argument position)
- Whether it's written to global variables
- Whether it's returned from the function
- Assembly-level register propagation (optional)

Usage:
    python forward_trace.py <db_path> <function_name> --param N
    python forward_trace.py <db_path> --id <function_id> --param N
    python forward_trace.py <db_path> <function_name> --param N --depth 2
    python forward_trace.py <db_path> <function_name> --param N --assembly
    python forward_trace.py <db_path> <function_name> --param N --json

Examples:
    # Where does parameter 1 of AiLaunchProcess go?
    python forward_trace.py extracted_dbs/appinfo_dll_e98d25a9e8.db AiLaunchProcess --param 1

    # Recursive trace: follow into callees up to depth 2
    python forward_trace.py extracted_dbs/cmd_exe_6d109a3a00.db BatLoop --param 1 --depth 2

    # Include assembly register tracking
    python forward_trace.py extracted_dbs/cmd_exe_6d109a3a00.db eComSrv --param 2 --assembly

    # JSON output
    python forward_trace.py extracted_dbs/appinfo_dll_e98d25a9e8.db AiLaunchProcess --param 1 --json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from _common import (
    WORKSPACE_ROOT,
    PARAM_REGISTERS,
    emit_error,
    extract_function_calls,
    find_param_in_calls,
    find_param_register_aliases,
    find_global_writes_in_assembly,
    param_name_for,
    parse_json_safe,
    resolve_db_path,
    resolve_tracking_db,
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
        "mangled_name": func.mangled_name,
        "decompiled_code": func.decompiled_code or "",
        "assembly_code": func.assembly_code or "",
        "module_name": module_name,
        "db_path": db_path,
        "outbound_xrefs": parse_json_safe(func.simple_outbound_xrefs) or [],
        "inbound_xrefs": parse_json_safe(func.simple_inbound_xrefs) or [],
        "global_var_accesses": parse_json_safe(func.global_var_accesses) or [],
        "string_literals": parse_json_safe(func.string_literals) or [],
    }


def _resolve_callee_db(callee_module: str) -> str | None:
    """Resolve a callee's module name to its analysis DB path."""
    tracking_path = resolve_tracking_db()
    if tracking_path is None:
        return None
    tracking = Path(tracking_path)
    with db_error_handler(str(tracking), "resolving callee module"):
        with open_analyzed_files_db(str(tracking)) as db:
            records = db.get_by_file_name(callee_module)
            for r in records:
                if r.status == "COMPLETE" and r.analysis_db_path:
                    abs_path = tracking.parent / r.analysis_db_path
                    if abs_path.exists():
                        return str(abs_path)
    return None


# ---------------------------------------------------------------------------
# Core trace logic (returns structured data)
# ---------------------------------------------------------------------------


def forward_trace(
    db_path: str,
    function_name: str = None,
    function_id: int = None,
    param_number: int = 1,
    max_depth: int = 1,
    show_assembly: bool = False,
    current_depth: int = 0,
    visited: set = None,
) -> dict:
    """Trace a parameter forward through a function and its callees.

    Returns a structured result dict.
    """
    if visited is None:
        visited = set()

    pname = param_name_for(param_number)

    result = {
        "depth": current_depth,
        "param_number": param_number,
        "param_name": pname,
    }

    func = _get_function(db_path, function_name=function_name, function_id=function_id)
    if not func:
        target = function_name or f"ID={function_id}"
        result["status"] = "not_found"
        result["target"] = target
        result["db"] = Path(db_path).name
        return result

    visit_key = (db_path, func["function_name"], param_number)
    if visit_key in visited:
        result["status"] = "cycle"
        result["function_name"] = func["function_name"]
        return result
    visited.add(visit_key)

    result["function"] = {
        "function_id": func["function_id"],
        "function_name": func["function_name"],
        "function_signature": func["function_signature"],
        "function_signature_extended": func.get("function_signature_extended"),
        "module_name": func["module_name"],
        "db": Path(db_path).name,
    }

    code = func["decompiled_code"]
    if not code:
        result["status"] = "no_code"
        return result

    result["status"] = "ok"

    # -- Find all references to the parameter --
    param_refs = []
    pat = re.compile(rf"\b{pname}\b")
    for i, line in enumerate(code.splitlines(), 1):
        if pat.search(line.strip()):
            param_refs.append({"line_number": i, "line": line.strip()})

    result["param_references"] = param_refs
    result["param_reference_count"] = len(param_refs)

    # -- Find calls that use the parameter --
    call_usages_raw = find_param_in_calls(code, pname)

    # Cross-reference with outbound xrefs for classification
    outbound_map = {}
    for xref in func["outbound_xrefs"]:
        if isinstance(xref, dict):
            name = xref.get("function_name", "")
            outbound_map[name] = xref

    call_usages = []
    for cu in call_usages_raw:
        fname = cu["function_name"]
        xref = outbound_map.get(fname, {})
        call_usages.append({
            "function_name": fname,
            "arg_position": cu["arg_position"],
            "arg_expression": cu["arg_expression"],
            "is_direct": cu["is_direct"],
            "line_number": cu["line_number"],
            "line": cu["line"],
            "module_name": xref.get("module_name", ""),
            "function_id": xref.get("function_id"),
        })

    result["call_usages"] = call_usages

    # -- Check global variable writes --
    global_writes = [g for g in func["global_var_accesses"] if isinstance(g, dict) and g.get("access_type") == "Write"]
    param_global_writes = []
    if global_writes:
        param_ref_lines = {pr["line_number"] for pr in param_refs}
        for gw in global_writes:
            gname = gw.get("name", "")
            for pr in param_refs:
                if gname and gname in pr["line"]:
                    param_global_writes.append(gw)
                    break

    result["global_writes"] = {
        "all_count": len(global_writes),
        "param_linked": param_global_writes,
        "param_linked_count": len(param_global_writes),
    }

    # -- Check if parameter is returned --
    return_lines = [pr["line"] for pr in param_refs if pr["line"].strip().startswith("return")]
    result["returned_lines"] = return_lines

    # -- Assembly register tracking --
    result["assembly_tracking"] = None
    if show_assembly and func["assembly_code"] and param_number <= 4:
        asm = func["assembly_code"]
        aliases = find_param_register_aliases(asm, param_number)
        primary = list(PARAM_REGISTERS[param_number])[0] if param_number in PARAM_REGISTERS else "?"

        stores = find_global_writes_in_assembly(asm, aliases)
        result["assembly_tracking"] = {
            "primary_register": primary,
            "tracked_registers": sorted(aliases),
            "memory_stores": stores[:10],
            "total_memory_stores": len(stores),
        }

    # -- Recursive follow into callees --
    result["callee_traces"] = []
    if current_depth < max_depth and call_usages:
        for cu in call_usages:
            callee_name = cu["function_name"]
            callee_arg_pos = cu["arg_position"] + 1  # 1-based param number
            callee_id = cu.get("function_id")
            callee_module = cu.get("module_name", "")

            callee_db = None
            if callee_id is not None:
                callee_db = db_path
            elif callee_module and callee_module not in ("data", "vtable"):
                callee_db = _resolve_callee_db(callee_module)

            if callee_db:
                sub_result = forward_trace(
                    db_path=callee_db,
                    function_name=callee_name if callee_id is None else None,
                    function_id=callee_id,
                    param_number=callee_arg_pos,
                    max_depth=max_depth,
                    show_assembly=show_assembly,
                    current_depth=current_depth + 1,
                    visited=visited,
                )
                result["callee_traces"].append(sub_result)

    return result


# ---------------------------------------------------------------------------
# Text rendering (human-readable output)
# ---------------------------------------------------------------------------


def _print_forward_trace(result: dict) -> None:
    """Print forward trace result as human-readable text."""
    depth = result.get("depth", 0)
    indent = "  " * depth
    prefix = f"[Depth {depth}]" if depth > 0 else "[Start]"
    status = result.get("status", "")
    param_number = result["param_number"]
    pname = result["param_name"]

    if status == "not_found":
        print(f"{indent}[NOT FOUND] {result['target']} in {result['db']}")
        return

    if status == "cycle":
        print(f"{indent}[CYCLE] Already traced {result['function_name']} param {param_number}")
        return

    func = result["function"]

    # -- Header --
    print(f"\n{indent}{'=' * (80 - len(indent))}")
    print(f"{indent}{prefix} Forward trace: {func['function_name']}  param {param_number} ({pname})")
    print(f"{indent}{'=' * (80 - len(indent))}")
    print(f"{indent}Module: {func['module_name']}")
    print(f"{indent}Signature: {func['function_signature'] or '(unknown)'}")
    if func.get("function_signature_extended") and func["function_signature_extended"] != func["function_signature"]:
        print(f"{indent}Extended:  {func['function_signature_extended']}")
    print(f"{indent}DB: {func['db']}")

    if status == "no_code":
        print(f"\n{indent}(no decompiled code available)")
        return

    # -- Param references --
    param_refs = result.get("param_references", [])
    print(f"\n{indent}References to '{pname}' ({len(param_refs)} lines):")
    for pr in param_refs[:20]:
        print(f"{indent}  L{pr['line_number']:>4}: {pr['line']}")
    if len(param_refs) > 20:
        print(f"{indent}  ... ({len(param_refs) - 20} more lines)")

    # -- Call usages --
    call_usages = result.get("call_usages", [])
    if call_usages:
        print(f"\n{indent}Passed as argument to ({len(call_usages)} call sites):")
        for cu in call_usages:
            fname = cu["function_name"]
            pos = cu["arg_position"] + 1
            direct = " (direct)" if cu["is_direct"] else " (in expression)"
            module = cu.get("module_name", "")
            fid = cu.get("function_id")
            loc = f"  [{module}]" if module else ""
            internal = f"  [internal, ID={fid}]" if fid else ""
            print(f"{indent}  -> {fname}() arg {pos}: {cu['arg_expression']}{direct}{loc}{internal}")
    else:
        print(f"\n{indent}Not passed to any function calls.")

    # -- Global writes --
    gw_data = result.get("global_writes", {})
    all_count = gw_data.get("all_count", 0)
    param_linked = gw_data.get("param_linked", [])
    if all_count > 0:
        if param_linked:
            print(f"\n{indent}Potentially written to globals ({len(param_linked)}):")
            for gw in param_linked:
                print(f"{indent}  -> {gw.get('name', '?')} at {gw.get('address', '?')}")
        else:
            print(f"\n{indent}Global writes in function ({all_count}) but none clearly linked to {pname}.")
    else:
        print(f"\n{indent}No global variable writes in this function.")

    # -- Return --
    return_lines = result.get("returned_lines", [])
    if return_lines:
        print(f"\n{indent}Parameter is RETURNED:")
        for rl in return_lines:
            print(f"{indent}  {rl}")

    # -- Assembly tracking --
    asm_data = result.get("assembly_tracking")
    if asm_data:
        primary = asm_data["primary_register"]
        print(f"\n{indent}Assembly register tracking (param {param_number} = {primary}):")
        print(f"{indent}  Tracked registers: {', '.join(asm_data['tracked_registers'])}")
        stores = asm_data.get("memory_stores", [])
        if stores:
            print(f"{indent}  Memory stores ({asm_data.get('total_memory_stores', len(stores))}):")
            for s in stores:
                print(f"{indent}    L{s['line_number']:>4}: {s['instruction']}")

    # -- Callee traces --
    callee_traces = result.get("callee_traces", [])
    if callee_traces:
        max_depth = depth  # approximation; use depth info from sub-results
        for sub in callee_traces:
            sub_depth = sub.get("depth", depth + 1)
            if sub_depth == depth + 1:
                # Print the "following callees" header once before the first callee at this depth
                break
        else:
            sub_depth = depth + 1

        print(f"\n{indent}--- Following callees (depth {sub_depth}/{sub_depth}) ---")
        for sub in callee_traces:
            _print_forward_trace(sub)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Forward data-flow trace: track where a function parameter flows to.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("db_path", help="Path to the module's analysis DB")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--function", "--name", dest="function_name", metavar="NAME",
                       help="Function name")
    group.add_argument("--id", "--function-id", type=int, dest="function_id", help="Function ID")
    parser.add_argument("function_name_pos", nargs="?", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--param", type=int, required=True, help="Parameter number (1-based)")
    parser.add_argument("--depth", type=int, default=1, help="Max recursion depth (default: 1)")
    parser.add_argument("--assembly", action="store_true", help="Include assembly register tracking")
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
    if args.param < 1:
        emit_error("Parameter number must be >= 1", ErrorCode.INVALID_ARGS)

    db_path = resolve_db_path(args.db_path)

    cache_params = {}
    if args.function_name:
        cache_params["function_name"] = args.function_name
    if args.function_id is not None:
        cache_params["function_id"] = args.function_id
    cache_params["param"] = args.param
    cache_params["depth"] = args.depth
    if args.assembly:
        cache_params["assembly"] = True

    if not args.no_cache:
        cached = get_cached(db_path, "forward_trace", params=cache_params)
        if cached is not None:
            if args.json:
                emit_json(cached)
            else:
                _print_forward_trace(cached)
            return

    result = forward_trace(
        db_path=db_path,
        function_name=args.function_name,
        function_id=args.function_id,
        param_number=args.param,
        max_depth=args.depth,
        show_assembly=args.assembly,
    )

    top_status = result.get("status", "")

    if args.json and top_status == "not_found":
        emit_error(f"Function '{result.get('target', '?')}' not found in {result.get('db', '?')}", ErrorCode.NOT_FOUND)
    if args.json and top_status == "no_code":
        fname = result.get("function", {}).get("function_name", "?")
        emit_error(f"No decompiled code for '{fname}'", ErrorCode.NO_DATA)

    cache_result(db_path, "forward_trace", result, params=cache_params)

    if args.json:
        emit_json(result)
    else:
        _print_forward_trace(result)


if __name__ == "__main__":
    main()
