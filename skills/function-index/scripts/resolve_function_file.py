#!/usr/bin/env python3
"""Resolve function name(s) to their absolute .cpp file paths.

Designed for programmatic use by other skills and scripts. Given a function
name and optionally a module, prints the absolute path to the .cpp file
containing that function.

Usage:
    python resolve_function_file.py <function_name>
    python resolve_function_file.py <function_name> --module appinfo_dll
    python resolve_function_file.py --names "FuncA,FuncB,FuncC" --module appinfo_dll
    python resolve_function_file.py --file appinfo_dll_standalone_group_5.cpp --module appinfo_dll

Examples:
    # Resolve a single function to its file path
    python resolve_function_file.py AiCheckSecureApplicationDirectory

    # Resolve within a specific module
    python resolve_function_file.py AiCheckSecureApplicationDirectory --module appinfo_dll

    # Resolve multiple functions at once (comma-separated)
    python resolve_function_file.py --names "AiCheckLUA,AiLaunchProcess,BatLoop"

    # Resolve all functions in a specific .cpp file
    python resolve_function_file.py --file appinfo_dll_standalone_group_5.cpp --module appinfo_dll

    # JSON output for scripting
    python resolve_function_file.py AiCheckSecureApplicationDirectory --json

Output (default):
    module_name|file_path|library_tag

Output (JSON):
    [{"function_name": ..., "module": ..., "file": ..., "file_path": ..., "library": ...}]
"""

from __future__ import annotations

import argparse
import json
import sys

from _common import (
    get_files,
    get_function_id,
    get_primary_file,
    has_assembly,
    has_decompiled,
    list_extracted_modules,
    load_function_index,
    resolve_module_dir,
)
from helpers.errors import ErrorCode, emit_error, safe_parse_args
from helpers.json_output import emit_json_list


def resolve_single(
    function_name: str,
    module_name: str | None = None,
) -> list[dict]:
    """Resolve a single function name to its file path(s)."""
    results: list[dict] = []
    modules = [module_name] if module_name else list_extracted_modules()

    for mod in modules:
        index = load_function_index(mod)
        if index is None:
            continue
        if function_name in index:
            entry = index[function_name]
            mod_dir = resolve_module_dir(mod)
            entry_files = get_files(entry)
            primary = entry_files[0] if entry_files else None
            if primary is None:
                file_path = None
            else:
                file_path = str(mod_dir / primary) if mod_dir else primary
            results.append({
                "function_name": function_name,
                "module": mod,
                "files": entry_files,
                "file": primary,
                "file_path": file_path,
                "library": entry.get("library"),
                "function_id": get_function_id(entry),
                "has_decompiled": has_decompiled(entry),
                "has_assembly": has_assembly(entry),
            })
    return results


def resolve_batch(
    names: list[str],
    module_name: str | None = None,
) -> list[dict]:
    """Resolve multiple function names at once."""
    results: list[dict] = []
    modules = [module_name] if module_name else list_extracted_modules()

    for mod in modules:
        index = load_function_index(mod)
        if index is None:
            continue
        mod_dir = resolve_module_dir(mod)
        for name in names:
            if name in index:
                entry = index[name]
                entry_files = get_files(entry)
                primary = entry_files[0] if entry_files else None
                if primary is None:
                    file_path = None
                else:
                    file_path = str(mod_dir / primary) if mod_dir else primary
                results.append({
                    "function_name": name,
                    "module": mod,
                    "files": entry_files,
                    "file": primary,
                    "file_path": file_path,
                    "library": entry.get("library"),
                    "function_id": get_function_id(entry),
                    "has_decompiled": has_decompiled(entry),
                    "has_assembly": has_assembly(entry),
                })
    return results


def resolve_by_file(
    cpp_file: str,
    module_name: str,
) -> list[dict]:
    """List all functions in a specific .cpp file."""
    index = load_function_index(module_name)
    if index is None:
        return []

    mod_dir = resolve_module_dir(module_name)
    file_path = str(mod_dir / cpp_file) if mod_dir else cpp_file

    results: list[dict] = []
    for func_name, entry in index.items():
        if cpp_file in get_files(entry):
            results.append({
                "function_name": func_name,
                "module": module_name,
                "files": get_files(entry),
                "file": cpp_file,
                "file_path": file_path,
                "library": entry.get("library"),
                "function_id": get_function_id(entry),
                "has_decompiled": has_decompiled(entry),
                "has_assembly": has_assembly(entry),
            })
    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Resolve function names to .cpp file paths.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--function", "--name", dest="function_name", metavar="NAME",
                        help="Function name to resolve")
    parser.add_argument("function_name_pos", nargs="?", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--names", help="Comma-separated list of function names to resolve")
    parser.add_argument("--file", dest="cpp_file", help="List functions in a specific .cpp file")
    parser.add_argument("--module", help="Restrict to a specific module")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = safe_parse_args(parser)
    if args.function_name_pos and not args.function_name:
        args.function_name = args.function_name_pos

    if not args.function_name and not args.names and not args.cpp_file:
        emit_error("Provide function_name, --names, or --file", ErrorCode.INVALID_ARGS)

    if args.cpp_file:
        if not args.module:
            emit_error("--file requires --module", ErrorCode.INVALID_ARGS)
        results = resolve_by_file(args.cpp_file, args.module)
    elif args.names:
        name_list = [n.strip() for n in args.names.split(",") if n.strip()]
        results = resolve_batch(name_list, module_name=args.module)
    else:
        results = resolve_single(args.function_name, module_name=args.module)

    if args.json:
        emit_json_list("results", results)
    else:
        if not results:
            emit_error("No matches found", ErrorCode.NOT_FOUND)
        for r in results:
            lib = r["library"] or "app"
            file_display = r["file_path"] or "(no decompiled output)"
            print(f"{r['module']}|{file_display}|{lib}")


if __name__ == "__main__":
    main()
