#!/usr/bin/env python3
"""Collect function sets for batch lifting.

Supports four collection modes:
1. Class methods:  all methods of a C++ class
2. Call chain:     BFS from a function through internal calls
3. Export-down:    from a named export down N levels of internal calls
4. List classes:   enumerate all C++ classes with method counts

Output includes function IDs, names, signatures, dependency order,
and cross-reference summary within the set.

Usage:
    python collect_functions.py <db_path> --class <ClassName>
    python collect_functions.py <db_path> --chain <FunctionName> [--depth N]
    python collect_functions.py <db_path> --chain _ --id <function_id> [--depth N]
    python collect_functions.py <db_path> --export <ExportName> [--depth N]
    python collect_functions.py <db_path> --export _ --id <function_id> [--depth N]
    python collect_functions.py <db_path> --list-classes [--skip-library]

    # JSON output for piping to prepare_batch_lift.py
    python collect_functions.py <db_path> --class <ClassName> --json

Examples:
    # All methods of CSecurityDescriptor
    python collect_functions.py extracted_dbs/appinfo_dll_e98d25a9e8.db --class CSecurityDescriptor

    # Call chain from BatLoop down 3 levels
    python collect_functions.py extracted_dbs/cmd_exe_6d109a3a00.db --chain BatLoop --depth 3

    # From export AiLaunchProcess down 2 levels
    python collect_functions.py extracted_dbs/appinfo_dll_e98d25a9e8.db --export AiLaunchProcess --depth 2

    # List all C++ classes and their method counts
    python collect_functions.py extracted_dbs/appinfo_dll_e98d25a9e8.db --list-classes
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, deque
from pathlib import Path
from typing import Optional

from _common import (
    WORKSPACE_ROOT,
    emit_error,
    parse_class_from_mangled,
    parse_json_safe,
    resolve_db_path,
    topological_sort_functions,
)
from helpers.errors import ErrorCode, emit_error, safe_parse_args

from helpers import (
    build_id_map,
    filter_decompiled,
    get_function_id,
    load_function_index_for_db,
    open_individual_analysis_db,
    resolve_function,
    resolve_module_dir,
    search_index,
)
from helpers.cache import get_cached, cache_result
from helpers.errors import db_error_handler
from helpers.json_output import emit_json


# ---------------------------------------------------------------------------
# Collection modes
# ---------------------------------------------------------------------------


def collect_class_methods(db_path: str, class_name: str, no_cache: bool = False) -> dict:
    """Collect all methods of a C++ class from a module DB."""
    cache_params = {"class": class_name}
    if not no_cache:
        cached = get_cached(db_path, "collect_class_methods", params=cache_params)
        if cached is not None:
            return cached
    with db_error_handler(db_path, "collecting class methods"):
        with open_individual_analysis_db(db_path) as db:
            all_funcs = db.get_all_functions()
            file_info = db.get_file_info()
            module_name = file_info.file_name if file_info else Path(db_path).stem

    # Load function_index for library filtering
    function_index = load_function_index_for_db(db_path)
    library_names = set()
    decompiled_names = set()
    if function_index:
        library_names = {k for k, v in function_index.items() if v.get("library") is not None}
        decompiled_names = set(filter_decompiled(function_index, decompiled=True).keys())

    # Find methods by mangled name
    method_ids: set[int] = set()
    methods = []

    for func in all_funcs:
        if library_names and (func.function_name or "") in library_names:
            continue
        if decompiled_names and (func.function_name or "") not in decompiled_names:
            continue
        if func.mangled_name:
            parsed = parse_class_from_mangled(func.mangled_name)
            if parsed and parsed["class_name"] == class_name:
                methods.append(func)
                method_ids.add(func.function_id)

    # Also include functions whose signatures reference the class type
    for func in all_funcs:
        if func.function_id in method_ids:
            continue
        if decompiled_names and (func.function_name or "") not in decompiled_names:
            continue
        sig = func.function_signature or ""
        sig_ext = func.function_signature_extended or ""
        if class_name + " " in sig or class_name + " " in sig_ext or \
           class_name + "*" in sig or class_name + "*" in sig_ext or \
           class_name + " *" in sig or class_name + " *" in sig_ext:
            methods.append(func)
            method_ids.add(func.function_id)

    dep_order = topological_sort_functions(methods, method_ids)

    result = {
        "mode": "class",
        "class_name": class_name,
        "module_name": module_name,
        "db_path": db_path,
        "function_count": len(methods),
        "functions": [_func_summary(f, function_index=function_index) for f in methods],
        "dependency_order": dep_order,
    }
    cache_result(db_path, "collect_class_methods", result, params=cache_params)
    return result


def collect_call_chain(
    db_path: str,
    start_name: Optional[str] = None,
    start_id: Optional[int] = None,
    max_depth: int = 3,
    skip_library: bool = False,
) -> dict:
    """BFS from a starting function through internal calls (same module)."""
    function_index = load_function_index_for_db(db_path)
    decompiled_id_set: set[int] = set()
    if function_index:
        decompiled_id_set = set(build_id_map(filter_decompiled(function_index, decompiled=True)).keys())

    with db_error_handler(db_path, "collecting call chain"):
        with open_individual_analysis_db(db_path) as db:
            start_func = _find_function(db, function_index=function_index, name=start_name, fid=start_id)
            if not start_func:
                target = start_name or f"ID={start_id}"
                emit_error(f"Function not found: {target}", ErrorCode.NOT_FOUND)
            if decompiled_id_set and start_func.function_id not in decompiled_id_set:
                emit_error(f"Start function has no decompiled code: {start_func.function_name}", ErrorCode.NOT_FOUND)

            file_info = db.get_file_info()
            module_name = file_info.file_name if file_info else Path(db_path).stem

            # Load function_index for library filtering
            library_names = set()
            if skip_library and function_index:
                library_names = {k for k, v in function_index.items() if v.get("library") is not None}

            # BFS through internal calls
            collected: dict[int, object] = {start_func.function_id: start_func}
            depths: dict[int, int] = {start_func.function_id: 0}
            queue: deque[tuple[int, int]] = deque([(start_func.function_id, 0)])

            while queue:
                fid, depth = queue.popleft()
                if depth >= max_depth:
                    continue

                func = collected.get(fid) or db.get_function_by_id(fid)
                if not func:
                    continue
                collected[fid] = func

                outbound = parse_json_safe(func.simple_outbound_xrefs) or []
                candidate_ids: list[int] = []
                for xref in outbound:
                    if not isinstance(xref, dict):
                        continue
                    callee_id = xref.get("function_id")
                    module = xref.get("module_name", "")
                    ftype = xref.get("function_type", 0)
                    # Skip data refs and vtable refs
                    if module in ("data", "vtable") or ftype in (4, 8):
                        continue
                    # Skip library functions if requested
                    if skip_library and library_names:
                        callee_name = xref.get("function_name", "")
                        if callee_name in library_names:
                            continue
                    if callee_id is not None and callee_id not in collected:
                        if decompiled_id_set and callee_id not in decompiled_id_set:
                            continue
                        candidate_ids.append(callee_id)
                if candidate_ids:
                    fetched = {f.function_id: f for f in db.get_functions_by_ids(candidate_ids)}
                    for cid in candidate_ids:
                        callee = fetched.get(cid)
                        if callee and cid not in collected:
                            collected[cid] = callee
                            depths[cid] = depth + 1
                            queue.append((cid, depth + 1))

    functions = list(collected.values())
    id_set = set(collected.keys())
    dep_order = topological_sort_functions(functions, id_set)

    # Count external (unresolvable) calls from the set
    external_calls: dict[str, set[str]] = {}
    for func in functions:
        outbound = parse_json_safe(func.simple_outbound_xrefs) or []
        for xref in outbound:
            if not isinstance(xref, dict):
                continue
            if xref.get("function_id") is None:
                module = xref.get("module_name", "unknown")
                fname = xref.get("function_name", "?")
                if module not in ("data", "vtable"):
                    external_calls.setdefault(module, set()).add(fname)

    return {
        "mode": "chain",
        "start_function": start_func.function_name,
        "start_id": start_func.function_id,
        "max_depth": max_depth,
        "module_name": module_name,
        "db_path": db_path,
        "function_count": len(functions),
        "functions": [
            _func_summary(
                f,
                depth=depths.get(f.function_id, 0),
                function_index=function_index,
            )
            for f in functions
        ],
        "dependency_order": dep_order,
        "external_calls_summary": {
            mod: sorted(fnames) for mod, fnames in sorted(external_calls.items())
        },
    }


def collect_export_down(
    db_path: str,
    export_name: str,
    max_depth: int = 3,
    skip_library: bool = False,
    function_id: int | None = None,
) -> dict:
    """Collect from a named export down N levels of internal calls."""
    with db_error_handler(db_path, "collecting export-down functions"):
        with open_individual_analysis_db(db_path) as db:
            function_index = load_function_index_for_db(db_path)

        func = None
        if function_id is not None:
            func = db.get_function_by_id(function_id)
            if not func:
                emit_error(f"Function ID {function_id} not found", ErrorCode.NOT_FOUND)
        else:
            if function_index:
                entry = function_index.get(export_name)
                if entry is None:
                    export_name_lower = export_name.lower()
                    for fname, candidate in function_index.items():
                        if fname.lower() == export_name_lower:
                            entry = candidate
                            break
                    if entry is None:
                        matches = search_index(function_index, export_name)
                        if matches:
                            entry = next(iter(matches.values()))
                fid = get_function_id(entry) if entry else None
                if fid is not None:
                    func = db.get_function_by_id(fid)

            if func is None:
                results = db.get_function_by_name(export_name)
                if not results:
                    results = db.search_functions(name_contains=export_name)
                func = results[0] if results else None

            if not func:
                emit_error(f"Export/function not found: {export_name}", ErrorCode.NOT_FOUND)

        # Verify it's actually an export
        file_info = db.get_file_info()
        exports_json = parse_json_safe(file_info.exports) if file_info else None
        export_names = set()
        if exports_json and isinstance(exports_json, list):
            for exp in exports_json:
                if isinstance(exp, dict):
                    export_names.add(exp.get("function_name", "").lower())

        is_export = func.function_name and func.function_name.lower() in export_names

    # Delegate to chain collection
    result = collect_call_chain(db_path, start_id=func.function_id, max_depth=max_depth, skip_library=skip_library)
    result["mode"] = "export_down"
    result["export_name"] = export_name
    result["is_confirmed_export"] = is_export
    return result


def list_classes(db_path: str, skip_library: bool = False) -> dict:
    """Enumerate all C++ classes in a module with per-class method counts."""
    with db_error_handler(db_path, "listing classes"):
        with open_individual_analysis_db(db_path) as db:
            all_funcs = db.get_all_functions()
            file_info = db.get_file_info()
            module_name = file_info.file_name if file_info else Path(db_path).stem

    function_index = load_function_index_for_db(db_path)
    library_names: set[str] = set()
    if skip_library and function_index:
        library_names = {k for k, v in function_index.items() if v.get("library") is not None}

    class_counter: Counter[str] = Counter()
    for func in all_funcs:
        if library_names and (func.function_name or "") in library_names:
            continue
        if func.mangled_name:
            parsed = parse_class_from_mangled(func.mangled_name)
            if parsed:
                class_counter[parsed["class_name"]] += 1

    mod_dir = resolve_module_dir(module_name)

    classes = []
    for name, count in class_counter.most_common():
        entry: dict = {"name": name, "method_count": count}
        if mod_dir is not None:
            lifted_path = mod_dir / f"lifted_{name}.cpp"
            if lifted_path.is_file():
                entry["already_lifted"] = True
                entry["lifted_file"] = str(lifted_path)
            else:
                entry["already_lifted"] = False
        classes.append(entry)

    return {
        "status": "ok",
        "module_name": module_name,
        "db_path": db_path,
        "classes": classes,
        "total_classes": len(classes),
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find_function(db, function_index=None, name=None, fid=None):
    """Find a function by name or ID."""
    func, _err = resolve_function(
        db, name=name, function_id=fid, function_index=function_index,
    )
    return func


def _func_summary(func, depth=None, function_index=None) -> dict:
    """Create a summary dict for a function."""
    has_code = None
    if function_index and func.function_name:
        entry = function_index.get(func.function_name)
        if entry and "has_decompiled" in entry:
            has_code = bool(entry.get("has_decompiled"))
    if has_code is None:
        has_code = bool(
            func.decompiled_code
            and func.decompiled_code.strip()
            and "Decompiler not available" not in func.decompiled_code
            and "Decompilation failed" not in func.decompiled_code
        )
    role = None
    if func.mangled_name:
        parsed = parse_class_from_mangled(func.mangled_name)
        if parsed:
            role = parsed["role"]

    d = {
        "function_id": func.function_id,
        "function_name": func.function_name,
        "function_signature": func.function_signature,
        "mangled_name": func.mangled_name,
        "has_decompiled": has_code,
        "role": role,
    }
    if depth is not None:
        d["depth"] = depth
    return d


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


def print_text_output(result: dict) -> None:
    """Print human-readable output."""
    if "error" in result:
        emit_error(result['error'], ErrorCode.NOT_FOUND)

    mode = result["mode"]
    module = result["module_name"]
    count = result["function_count"]

    print(f"{'=' * 80}")
    if mode == "class":
        print(f"  Class: {result['class_name']}  ({module})")
    elif mode == "chain":
        print(f"  Call chain from: {result['start_function']}  ({module})")
        print(f"  Max depth: {result['max_depth']}")
    elif mode == "export_down":
        print(f"  Export-down from: {result.get('export_name', '?')}  ({module})")
        confirmed = result.get("is_confirmed_export", False)
        print(f"  Confirmed export: {'yes' if confirmed else 'no (function found but not in exports list)'}")
        print(f"  Max depth: {result['max_depth']}")
    print(f"  Functions collected: {count}")
    print(f"  DB: {result['db_path']}")
    print(f"{'=' * 80}")

    # Dependency order
    dep_order = result.get("dependency_order", [])
    id_to_func = {f["function_id"]: f for f in result["functions"]}

    print(f"\nLift order (callees first -> callers last):")
    print(f"{'-' * 70}")
    for i, fid in enumerate(dep_order, 1):
        f = id_to_func.get(fid, {})
        name = f.get("function_name", f"ID={fid}")
        sig = f.get("function_signature", "")
        has_code = "ok" if f.get("has_decompiled") else "NO CODE"
        role = f.get("role", "")
        role_str = f"  [{role}]" if role else ""
        depth_str = f"  (depth={f['depth']})" if "depth" in f else ""
        if len(sig) > 50:
            sig = sig[:47] + "..."
        print(f"  {i:>3}. [{has_code:>7}] {name}{role_str}{depth_str}")
        if sig:
            print(f"       {sig}")

    # Functions without decompiled code
    no_code = [f for f in result["functions"] if not f.get("has_decompiled")]
    if no_code:
        print(f"\nWarning: {len(no_code)} function(s) lack decompiled code:")
        for f in no_code:
            print(f"  - {f['function_name']} (ID={f['function_id']})")

    # External calls summary (chain/export modes)
    ext = result.get("external_calls_summary", {})
    if ext:
        total = sum(len(fnames) for fnames in ext.values())
        print(f"\nExternal calls from this set ({total} unique across {len(ext)} module(s)):")
        for mod, fnames in sorted(ext.items()):
            print(f"  {mod}: {', '.join(fnames[:5])}" +
                  (f" ... (+{len(fnames) - 5} more)" if len(fnames) > 5 else ""))

    print(f"\nUse --json for machine-readable output to pipe to prepare_batch_lift.py")


def print_list_classes_output(result: dict) -> None:
    """Print human-readable class listing."""
    module = result["module_name"]
    total = result["total_classes"]
    classes = result["classes"]

    print(f"{'=' * 70}")
    print(f"  C++ classes in {module}  ({total} classes)")
    print(f"  DB: {result['db_path']}")
    print(f"{'=' * 70}")

    if not classes:
        print("\n  No C++ classes found.")
        return

    max_name_len = max(len(c["name"]) for c in classes)
    col_width = min(max(max_name_len, 10), 50)

    print(f"\n  {'Class':<{col_width}}  Methods  Status")
    print(f"  {'-' * col_width}  -------  ----------")
    for c in classes:
        lifted = c.get("already_lifted", False)
        tag = "[LIFTED]" if lifted else ""
        print(f"  {c['name']:<{col_width}}  {c['method_count']:>7}  {tag}")

    lifted_count = sum(1 for c in classes if c.get("already_lifted"))
    if lifted_count:
        print(f"\n  {lifted_count}/{total} class(es) already lifted.")

    print(f"\nUse --class <ClassName> to collect methods for batch lifting.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Collect function sets for batch lifting.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("db_path", help="Path to the module's analysis DB")

    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--class", dest="class_name", help="Collect all methods of a C++ class")
    mode_group.add_argument("--chain", dest="chain_func", help="Collect call chain from a function")
    mode_group.add_argument("--export", dest="export_name", help="Collect from an export down N levels")
    mode_group.add_argument("--list-classes", action="store_true", help="List all C++ classes with method counts")

    parser.add_argument("--id", "--function-id", dest="function_id", type=int,
                        help="Function ID (overrides name for --chain / --export modes)")
    parser.add_argument("--depth", type=int, default=3, help="Max call depth for chain/export modes (default: 3)")
    parser.add_argument("--json", action="store_true", help="Output as JSON (for piping)")
    parser.add_argument("--skip-library", action="store_true", help="Skip library-tagged functions (from function_index)")
    args = safe_parse_args(parser)

    db_path = resolve_db_path(args.db_path)

    try:
        if args.list_classes:
            result = list_classes(db_path, skip_library=args.skip_library)
            if args.json:
                emit_json(result)
            else:
                print_list_classes_output(result)
            return

        if args.class_name:
            result = collect_class_methods(db_path, args.class_name)
        elif args.chain_func or args.function_id:
            result = collect_call_chain(
                db_path,
                start_name=args.chain_func if not args.function_id else None,
                start_id=args.function_id,
                max_depth=args.depth,
                skip_library=args.skip_library,
            )
        elif args.export_name:
            result = collect_export_down(db_path, args.export_name, max_depth=args.depth,
                                        skip_library=args.skip_library, function_id=args.function_id)
        else:
            emit_error("Specify --class, --chain, --export, or --list-classes", ErrorCode.INVALID_ARGS)
    except FileNotFoundError as e:
        emit_error(str(e), ErrorCode.NOT_FOUND)
    except Exception as e:
        emit_error(f"{type(e).__name__}: {e}", ErrorCode.UNKNOWN)

    if args.json:
        emit_json(result)
    else:
        print_text_output(result)


if __name__ == "__main__":
    main()
