#!/usr/bin/env python3
"""Look up functions by name across one or all extracted modules.

Usage:
    python lookup_function.py <function_name>
    python lookup_function.py <function_name> --module appinfo_dll
    python lookup_function.py --search <pattern>
    python lookup_function.py --search <pattern> --module appinfo.dll

Examples:
    # Exact lookup across all modules
    python lookup_function.py AiCheckSecureApplicationDirectory

    # Exact lookup in a specific module
    python lookup_function.py AiCheckSecureApplicationDirectory --module appinfo_dll

    # Search by substring (case-insensitive)
    python lookup_function.py --search "CheckSecure"

    # Search with regex
    python lookup_function.py --search "Ai.*Launch" --regex

    # JSON output for programmatic use
    python lookup_function.py --search "BatLoop" --json

Output:
    For each match: module name, .cpp file, library tag, and full path.
"""

from __future__ import annotations

import argparse
import json
import re
import sys

from _common import (
    EXTRACTED_CODE_DIR,
    filter_by_library,
    get_function_id,
    has_assembly,
    has_decompiled,
    list_extracted_modules,
    load_function_index,
    resolve_module_dir,
)
from helpers.errors import ErrorCode, emit_error, safe_parse_args
from helpers.json_output import emit_json_list


def lookup_exact(
    function_name: str,
    module_name: str | None = None,
) -> list[dict]:
    """Find exact function name matches."""
    results: list[dict] = []
    modules = [module_name] if module_name else list_extracted_modules()

    for mod in modules:
        index = load_function_index(mod)
        if index is None:
            continue
        if function_name in index:
            entry = index[function_name]
            mod_dir = resolve_module_dir(mod)
            file_name = entry.get("file")
            if file_name is None:
                file_path = None
            else:
                file_path = str(mod_dir / file_name) if mod_dir else file_name
            results.append({
                "function_name": function_name,
                "module": mod,
                "file": file_name,
                "file_path": file_path,
                "library": entry.get("library"),
                "function_id": get_function_id(entry),
                "has_decompiled": has_decompiled(entry),
                "has_assembly": has_assembly(entry),
            })
    return results


def search_functions(
    pattern: str,
    module_name: str | None = None,
    use_regex: bool = False,
    app_only: bool = False,
    lib_only: bool = False,
    library: str | None = None,
    limit: int | None = None,
) -> list[dict]:
    """Search for functions matching a pattern."""
    results: list[dict] = []
    modules = [module_name] if module_name else list_extracted_modules()

    if use_regex:
        try:
            pat = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            emit_error(f"Invalid regex pattern: {e}", ErrorCode.INVALID_ARGS)
    else:
        pat_lower = pattern.lower()

    for mod in modules:
        index = load_function_index(mod)
        if index is None:
            continue

        filtered = filter_by_library(index, library=library, app_only=app_only, lib_only=lib_only)

        for func_name, entry in filtered.items():
            if use_regex:
                if not pat.search(func_name):
                    continue
            else:
                if pat_lower not in func_name.lower():
                    continue

            mod_dir = resolve_module_dir(mod)
            file_name = entry.get("file")
            if file_name is None:
                file_path = None
            else:
                file_path = str(mod_dir / file_name) if mod_dir else file_name
            results.append({
                "function_name": func_name,
                "module": mod,
                "file": file_name,
                "file_path": file_path,
                "library": entry.get("library"),
                "function_id": get_function_id(entry),
                "has_decompiled": has_decompiled(entry),
                "has_assembly": has_assembly(entry),
            })

            if limit and len(results) >= limit:
                return results

    return results


def print_results(results: list[dict], as_json: bool = False) -> None:
    if as_json:
        emit_json_list("results", results)
        return

    if not results:
        print("No functions found.")
        return

    # Group by module for readability
    by_module: dict[str, list[dict]] = {}
    for r in results:
        by_module.setdefault(r["module"], []).append(r)

    for mod, funcs in sorted(by_module.items()):
        print(f"\n--- {mod} ({len(funcs)} match{'es' if len(funcs) != 1 else ''}) ---\n")
        for f in sorted(funcs, key=lambda x: x["function_name"]):
            lib_tag = f"  [{f['library']}]" if f["library"] else ""
            function_id = f["function_id"] if f["function_id"] is not None else "?"
            decomp = "decompiled" if f["has_decompiled"] else "no-decompiled"
            assembly = "asm" if f["has_assembly"] else "no-asm"
            file_display = f["file"] or "(no decompiled output)"
            print(f"  {f['function_name']}{lib_tag}  [id={function_id}; {decomp}; {assembly}]")
            print(f"    -> {file_display}")

    total = len(results)
    mod_count = len(by_module)
    print(f"\n{total} function(s) found across {mod_count} module(s).")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Look up functions in function_index.json files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--function", "--name", dest="function_name", metavar="NAME",
                        help="Exact function name to look up")
    parser.add_argument("function_name_pos", nargs="?", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--search", dest="pattern", help="Search pattern (substring, case-insensitive)")
    parser.add_argument("--regex", action="store_true", help="Treat --search pattern as regex")
    parser.add_argument("--module", help="Restrict to a specific module (name or folder)")
    parser.add_argument("--app-only", action="store_true", help="Only application code (library=null)")
    parser.add_argument("--lib-only", action="store_true", help="Only library/boilerplate code")
    parser.add_argument("--library", help="Filter by library tag (WIL, STL, WRL, CRT, ETW/TraceLogging)")
    parser.add_argument("--limit", type=int, help="Maximum results to return")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = safe_parse_args(parser)
    if args.function_name_pos and not args.function_name:
        args.function_name = args.function_name_pos

    if not args.function_name and not args.pattern:
        parser.error("Provide a function_name or use --search <pattern>")

    if args.function_name:
        results = lookup_exact(args.function_name, module_name=args.module)
        if not results and not args.json:
            # Fall back to substring search
            print(f"No exact match for '{args.function_name}'. Trying substring search...\n")
            results = search_functions(
                args.function_name,
                module_name=args.module,
                app_only=args.app_only,
                lib_only=args.lib_only,
                library=args.library,
                limit=args.limit or 20,
            )
    else:
        results = search_functions(
            args.pattern,
            module_name=args.module,
            use_regex=args.regex,
            app_only=args.app_only,
            lib_only=args.lib_only,
            library=args.library,
            limit=args.limit,
        )

    print_results(results, as_json=args.json)


if __name__ == "__main__":
    main()
