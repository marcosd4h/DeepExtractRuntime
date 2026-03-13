#!/usr/bin/env python3
"""Global state mapping: build a producer/consumer map for global variables.

Scans all functions in a module to identify which functions read and write
each global variable, producing a comprehensive producer/consumer map.

Usage:
    python global_state_map.py <db_path>
    python global_state_map.py <db_path> --global <name_or_address>
    python global_state_map.py <db_path> --summary
    python global_state_map.py <db_path> --json
    python global_state_map.py <db_path> --writers-only
    python global_state_map.py <db_path> --shared-only

Examples:
    # Full producer/consumer map for a module
    python global_state_map.py extracted_dbs/appinfo_dll_e98d25a9e8.db

    # Focus on a specific global variable
    python global_state_map.py extracted_dbs/cmd_exe_6d109a3a00.db --global dword_18005C380

    # Summary: global counts and top shared variables
    python global_state_map.py extracted_dbs/appinfo_dll_e98d25a9e8.db --summary

    # Only globals that are both read and written (shared state)
    python global_state_map.py extracted_dbs/cmd_exe_6d109a3a00.db --shared-only

    # JSON output for further processing
    python global_state_map.py extracted_dbs/appinfo_dll_e98d25a9e8.db --json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

from _common import (
    WORKSPACE_ROOT,
    parse_json_safe,
    resolve_db_path,
)

from helpers import load_function_index_for_db, open_individual_analysis_db
from helpers.cache import get_cached, cache_result
from helpers.errors import db_error_handler, safe_parse_args
from helpers.json_output import emit_json
from helpers.progress import status_message


def build_global_map(db_path: str, app_only: bool = False, no_cache: bool = False) -> dict[str, dict]:
    """Scan all functions and build a global variable access map.

    Returns dict keyed by global variable name:
    {
        "global_name": {
            "address": "hex_addr",
            "readers": [{"function_name": ..., "function_id": ...}, ...],
            "writers": [{"function_name": ..., "function_id": ...}, ...],
        }
    }
    """
    cache_params = {"app_only": app_only} if app_only else None
    if not no_cache:
        cached = get_cached(db_path, "global_state_map", params=cache_params)
        if cached is not None:
            return cached

    global_map: dict[str, dict] = {}
    function_index = load_function_index_for_db(db_path)
    library_names = set()
    if function_index and app_only:
        library_names = {k for k, v in function_index.items() if v.get("library") is not None}

    with db_error_handler(db_path, "scanning global variable accesses"):
        with open_individual_analysis_db(db_path) as db:
            functions = db.get_all_functions()

    for func in functions:
        if app_only and library_names and (func.function_name or "") in library_names:
            continue
        accesses = parse_json_safe(func.global_var_accesses)
        if not accesses or not isinstance(accesses, list):
            continue

        func_info = {
            "function_name": func.function_name or f"sub_{func.function_id}",
            "function_id": func.function_id,
        }

        for access in accesses:
            if not isinstance(access, dict):
                continue

            name = access.get("name", "")
            address = access.get("address", "")
            access_type = access.get("access_type", "")

            if not name:
                name = address or "unknown"

            key = name

            if key not in global_map:
                global_map[key] = {
                    "address": address,
                    "name": name,
                    "readers": [],
                    "writers": [],
                }

            if access_type == "Read":
                # Avoid duplicates
                if not any(r["function_id"] == func.function_id for r in global_map[key]["readers"]):
                    global_map[key]["readers"].append(func_info)
            elif access_type == "Write":
                if not any(w["function_id"] == func.function_id for w in global_map[key]["writers"]):
                    global_map[key]["writers"].append(func_info)

    cache_result(db_path, "global_state_map", global_map, params=cache_params)
    return global_map


def print_global_detail(name: str, info: dict, indent: str = "") -> None:
    """Print detailed info for a single global variable."""
    addr = info.get("address", "?")
    readers = info.get("readers", [])
    writers = info.get("writers", [])

    print(f"\n{indent}{name}  (addr: {addr})")
    print(f"{indent}  Writers ({len(writers)}):")
    if writers:
        for w in sorted(writers, key=lambda x: x["function_name"]):
            print(f"{indent}    <- {w['function_name']}  [ID={w['function_id']}]")
    else:
        print(f"{indent}    (none)")

    print(f"{indent}  Readers ({len(readers)}):")
    if readers:
        for r in sorted(readers, key=lambda x: x["function_name"]):
            print(f"{indent}    -> {r['function_name']}  [ID={r['function_id']}]")
    else:
        print(f"{indent}    (none)")


def print_full_map(global_map: dict[str, dict]) -> None:
    """Print the full producer/consumer map."""
    if not global_map:
        print("No global variable accesses found in this module.")
        return

    # Sort by number of total accessors (most shared first)
    sorted_globals = sorted(
        global_map.items(),
        key=lambda x: len(x[1]["readers"]) + len(x[1]["writers"]),
        reverse=True,
    )

    total_globals = len(sorted_globals)
    shared = sum(1 for _, v in sorted_globals if v["readers"] and v["writers"])
    write_only = sum(1 for _, v in sorted_globals if v["writers"] and not v["readers"])
    read_only = sum(1 for _, v in sorted_globals if v["readers"] and not v["writers"])

    print(f"Global Variable Producer/Consumer Map")
    print(f"{'=' * 60}")
    print(f"Total globals: {total_globals}")
    print(f"  Shared (read + written): {shared}")
    print(f"  Write-only: {write_only}")
    print(f"  Read-only: {read_only}")
    print(f"{'=' * 60}")

    for name, info in sorted_globals:
        print_global_detail(name, info)


def print_summary(global_map: dict[str, dict]) -> None:
    """Print a compact summary of the global state map."""
    if not global_map:
        print("No global variable accesses found.")
        return

    total = len(global_map)
    shared = [(n, v) for n, v in global_map.items() if v["readers"] and v["writers"]]
    write_only = [(n, v) for n, v in global_map.items() if v["writers"] and not v["readers"]]
    read_only = [(n, v) for n, v in global_map.items() if v["readers"] and not v["writers"]]

    print(f"Global State Summary")
    print(f"{'=' * 60}")
    print(f"Total globals: {total}")
    print(f"  Shared (R+W): {len(shared)}  |  Write-only: {len(write_only)}  |  Read-only: {len(read_only)}")

    if shared:
        # Sort shared by accessor count
        shared.sort(key=lambda x: len(x[1]["readers"]) + len(x[1]["writers"]), reverse=True)
        print(f"\nTop shared globals (most accessors):")
        for name, info in shared[:15]:
            w = len(info["writers"])
            r = len(info["readers"])
            print(f"  {name:<40} {w}W / {r}R  (addr: {info.get('address', '?')})")

    if write_only:
        print(f"\nWrite-only globals ({len(write_only)}):")
        for name, info in sorted(write_only, key=lambda x: x[0])[:10]:
            writers = ", ".join(w["function_name"] for w in info["writers"][:3])
            extra = f" +{len(info['writers']) - 3} more" if len(info["writers"]) > 3 else ""
            print(f"  {name:<40} writers: {writers}{extra}")


def filter_by_name(global_map: dict[str, dict], name_filter: str) -> dict[str, dict]:
    """Return globals whose name or address matches *name_filter* (substring, case-insensitive)."""
    needle = name_filter.lower()
    return {
        k: v for k, v in global_map.items()
        if needle in k.lower() or needle in v.get("address", "").lower()
    }


def print_filtered(global_map: dict[str, dict], name_filter: str) -> None:
    """Print globals matching a name/address filter."""
    matches = filter_by_name(global_map, name_filter)
    if not matches:
        print(f"No global matching '{name_filter}' found.")
        print(f"Available globals ({len(global_map)}):")
        for name in sorted(global_map.keys())[:20]:
            print(f"  {name}")
        if len(global_map) > 20:
            print(f"  ... ({len(global_map) - 20} more)")
        return

    for name, info in sorted(matches.items()):
        print_global_detail(name, info)


def print_shared_only(global_map: dict[str, dict]) -> None:
    """Print only globals that are both read and written."""
    shared = {k: v for k, v in global_map.items() if v["readers"] and v["writers"]}
    if not shared:
        print("No shared (read+written) globals found.")
        return

    print(f"Shared Global Variables ({len(shared)} globals with both readers and writers)")
    print(f"{'=' * 60}")
    sorted_shared = sorted(
        shared.items(),
        key=lambda x: len(x[1]["readers"]) + len(x[1]["writers"]),
        reverse=True,
    )
    for name, info in sorted_shared:
        print_global_detail(name, info)


def print_writers_only(global_map: dict[str, dict]) -> None:
    """Print only globals that are written, grouped by writer count."""
    written = {k: v for k, v in global_map.items() if v["writers"]}
    if not written:
        print("No global writes found.")
        return

    print(f"Global Variable Writers ({len(written)} written globals)")
    print(f"{'=' * 60}")
    sorted_written = sorted(
        written.items(),
        key=lambda x: len(x[1]["writers"]),
        reverse=True,
    )
    for name, info in sorted_written:
        addr = info.get("address", "?")
        writers = info["writers"]
        readers = info["readers"]
        print(f"\n  {name}  (addr: {addr})  -- {len(writers)}W / {len(readers)}R")
        for w in sorted(writers, key=lambda x: x["function_name"]):
            print(f"    <- {w['function_name']}  [ID={w['function_id']}]")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build a global variable producer/consumer map for a module.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("db_path", help="Path to the module's analysis DB")
    parser.add_argument("--global", dest="global_filter", help="Filter to a specific global variable name or address")
    parser.add_argument("--summary", action="store_true", help="Print compact summary")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--shared-only", action="store_true", help="Only show globals that are both read and written")
    parser.add_argument("--writers-only", action="store_true", help="Only show globals that are written")
    parser.add_argument("--app-only", action="store_true", help="Skip library-tagged functions (from function_index)")
    parser.add_argument("--no-cache", action="store_true", help="Bypass cache and force fresh analysis")
    args = safe_parse_args(parser)

    db_path = resolve_db_path(args.db_path)

    status_message(f"Scanning all functions in {Path(db_path).name}...")
    global_map = build_global_map(db_path, app_only=args.app_only, no_cache=args.no_cache)
    status_message(f"Found {len(global_map)} global variables.")

    if args.global_filter:
        global_map = filter_by_name(global_map, args.global_filter)
    if args.shared_only:
        global_map = {k: v for k, v in global_map.items() if v["writers"] and v["readers"]}
    if args.writers_only:
        global_map = {k: v for k, v in global_map.items() if v["writers"]}

    if args.json:
        emit_json(global_map)
    elif args.global_filter:
        if not global_map:
            print(f"No global matching '{args.global_filter}' found.")
            return
        for name, info in sorted(global_map.items()):
            print_global_detail(name, info)
    elif args.summary:
        print_summary(global_map)
    elif args.shared_only:
        print_shared_only(global_map)
    elif args.writers_only:
        print_writers_only(global_map)
    else:
        print_full_map(global_map)


if __name__ == "__main__":
    main()
