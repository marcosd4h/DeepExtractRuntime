#!/usr/bin/env python3
"""List and filter functions in a module's function_index.json.

Usage:
    python index_functions.py <module>
    python index_functions.py <module> --app-only
    python index_functions.py <module> --library WIL
    python index_functions.py <module> --by-file
    python index_functions.py <module> --stats
    python index_functions.py --all --stats

Examples:
    # List all functions in appinfo_dll
    python index_functions.py appinfo_dll

    # Only application code (no WIL/STL/WRL/CRT/ETW)
    python index_functions.py appinfo_dll --app-only

    # Only WIL boilerplate functions
    python index_functions.py appinfo.dll --library WIL

    # Group by .cpp file
    python index_functions.py appinfo_dll --by-file

    # Show statistics only
    python index_functions.py appinfo_dll --stats

    # Stats for all modules
    python index_functions.py --all --stats

    # Functions in a specific .cpp file
    python index_functions.py appinfo_dll --file appinfo_dll_standalone_group_5.cpp

    # JSON output
    python index_functions.py appinfo_dll --app-only --json

Output:
    Sorted list of function names with library tags and file assignments.
"""

from __future__ import annotations

import argparse
import json
import sys

from _common import (
    compute_stats,
    filter_decompiled,
    filter_by_library,
    get_files,
    get_primary_file,
    group_by_file,
    group_by_library,
    has_assembly,
    has_decompiled,
    list_extracted_modules,
    load_function_index,
)
from helpers.errors import ErrorCode, emit_error, safe_parse_args
from helpers.json_output import emit_json


def print_stats(module_name: str, stats: dict) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {module_name}")
    print(f"{'=' * 60}")
    print(f"  Total functions:   {stats['total_functions']}")
    print(f"  Application code:  {stats['app_functions']}")
    print(f"  Library code:      {stats['library_functions']}")
    if stats["library_breakdown"]:
        for tag, count in sorted(stats["library_breakdown"].items()):
            print(f"    {tag:<20} {count}")
    print(f"  Decompiled funcs:  {stats.get('decompiled_count', 0)}")
    print(f"  No decompiled:     {stats.get('no_decompiled_count', 0)}")
    print(f"  Assembly funcs:    {stats.get('assembly_count', 0)}")
    print(f"  Total .cpp files:  {stats['file_count']}")


def print_function_list(
    index: dict,
    module_name: str,
    by_file: bool = False,
    file_filter: str | None = None,
) -> None:
    if file_filter:
        matching = {
            k: v for k, v in index.items() if file_filter in get_files(v)
        }
        if not matching:
            print(f"No functions found in file '{file_filter}'.")
            return
        print(f"\n--- {module_name} / {file_filter} ({len(matching)} functions) ---\n")
        for name in sorted(matching.keys()):
            lib = matching[name].get("library")
            tag = f"  [{lib}]" if lib else ""
            print(f"  {name}{tag}")
        return

    if by_file:
        groups = group_by_file(index)
        for fname in sorted(groups.keys(), key=lambda k: (k is None, str(k).lower() if k else "")):
            funcs = sorted(groups[fname])
            file_display = fname if fname is not None else "(no file)"
            print(f"\n--- {file_display} ({len(funcs)} functions) ---")
            for fn in funcs:
                lib = index[fn].get("library")
                tag = f"  [{lib}]" if lib else ""
                decomp = "decompiled" if has_decompiled(index[fn]) else "no-decompiled"
                assembly = "asm" if has_assembly(index[fn]) else "no-asm"
                print(f"  {fn}{tag}  [{decomp}; {assembly}]")
        print(f"\n{len(index)} function(s) in {len(groups)} file(s).")
        return

    # Default: sorted list
    for name in sorted(index.keys()):
        entry = index[name]
        lib = entry.get("library")
        tag = f"  [{lib}]" if lib else ""
        file_display = get_primary_file(entry) or "(no file)"
        decomp = "decompiled" if has_decompiled(entry) else "no-decompiled"
        assembly = "asm" if has_assembly(entry) else "no-asm"
        print(f"  {name}{tag}  [{decomp}; {assembly}]  ->  {file_display}")
    print(f"\n{len(index)} function(s).")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="List and filter functions from function_index.json.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("module", nargs="?", help="Module name or folder (e.g., appinfo_dll, appinfo.dll)")
    parser.add_argument("--all", action="store_true", help="Process all extracted modules")
    parser.add_argument("--app-only", action="store_true", help="Only application code (library=null)")
    parser.add_argument("--lib-only", action="store_true", help="Only library/boilerplate code")
    parser.add_argument("--library", help="Filter by library tag (WIL, STL, WRL, CRT, ETW/TraceLogging)")
    parser.add_argument(
        "--decompiled-only",
        action="store_true",
        help="Only functions with has_decompiled=true",
    )
    parser.add_argument(
        "--include-no-decompiled",
        action="store_true",
        help="Include functions where has_decompiled=false (default unless --decompiled-only).",
    )
    parser.add_argument("--by-file", action="store_true", help="Group output by .cpp file")
    parser.add_argument("--file", dest="file_filter", help="Show only functions in a specific .cpp file")
    parser.add_argument("--stats", action="store_true", help="Show statistics only")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = safe_parse_args(parser)

    if not args.module and not args.all:
        emit_error("Provide a module name or use --all", ErrorCode.INVALID_ARGS)

    if args.all:
        modules = list_extracted_modules()
        if not modules:
            print("No extracted modules found.")
            return

        if args.stats:
            all_stats = {}
            for mod in modules:
                index = load_function_index(mod)
                if index:
                    stats = compute_stats(index)
                    if args.json:
                        all_stats[mod] = stats
                    else:
                        print_stats(mod, stats)

            if args.json:
                emit_json(all_stats)
            else:
                # Summary totals
                total = sum(
                    compute_stats(load_function_index(m))["total_functions"]
                    for m in modules
                    if load_function_index(m)
                )
                print(f"\n{'=' * 60}")
                print(f"  TOTAL: {total} functions across {len(modules)} modules")
                print(f"{'=' * 60}")
            return

        # List all functions across all modules
        if args.json:
            all_filtered: dict[str, list] = {}
            for mod in modules:
                index = load_function_index(mod)
                if index is None:
                    continue
                filtered = filter_by_library(
                    index, library=args.library,
                    app_only=args.app_only, lib_only=args.lib_only,
                )
                include_no_decompiled = args.include_no_decompiled or not args.decompiled_only
                if not include_no_decompiled:
                    filtered = filter_decompiled(filtered, decompiled=True)
                if filtered:
                    all_filtered[mod] = filtered
            emit_json({
                "module_count": len(all_filtered),
                "total_functions": sum(len(v) for v in all_filtered.values()),
                "modules": all_filtered,
            })
            return

        for mod in modules:
            index = load_function_index(mod)
            if index is None:
                continue
            filtered = filter_by_library(
                index,
                library=args.library,
                app_only=args.app_only,
                lib_only=args.lib_only,
            )
            include_no_decompiled = args.include_no_decompiled or not args.decompiled_only
            if not include_no_decompiled:
                filtered = filter_decompiled(filtered, decompiled=True)
            if filtered:
                print(f"\n{'#' * 60}")
                print(f"  {mod} ({len(filtered)} functions)")
                print(f"{'#' * 60}")
                print_function_list(
                    filtered, mod,
                    by_file=args.by_file,
                    file_filter=args.file_filter,
                )
        return

    # Single module
    index = load_function_index(args.module)
    if index is None:
        available = list_extracted_modules()
        msg = f"Module '{args.module}' not found or has no function_index.json."
        if available:
            msg += f" Available modules: {', '.join(available)}"
        emit_error(msg, ErrorCode.NOT_FOUND)

    filtered = filter_by_library(
        index,
        library=args.library,
        app_only=args.app_only,
        lib_only=args.lib_only,
    )
    include_no_decompiled = args.include_no_decompiled or not args.decompiled_only
    if not include_no_decompiled:
        filtered = filter_decompiled(filtered, decompiled=True)

    if args.stats:
        stats = compute_stats(filtered)
        if args.json:
            emit_json(stats)
        else:
            print_stats(args.module, stats)
        return

    if args.json:
        emit_json(filtered)
        return

    print_function_list(
        filtered, args.module,
        by_file=args.by_file,
        file_filter=args.file_filter,
    )


if __name__ == "__main__":
    main()
