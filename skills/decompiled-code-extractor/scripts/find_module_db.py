#!/usr/bin/env python3
"""Find the analysis DB path for a module by name, extension, or list all modules.

Usage:
    python find_module_db.py <module_name>
    python find_module_db.py --ext .dll
    python find_module_db.py --list

Examples:
    python find_module_db.py appinfo.dll
    python find_module_db.py cmd.exe
    python find_module_db.py --ext .dll
    python find_module_db.py --list

Output:
    Prints matching module records with their DB paths and status.
"""

from __future__ import annotations

import argparse
import json
import sys

from _common import WORKSPACE_ROOT, open_analyzed_files_db
from helpers import _resolve_tracking_db as _resolve_tracking_db_impl
from helpers.errors import emit_error, db_error_handler, safe_parse_args
from helpers.json_output import emit_json_list


def _resolve_tracking_db() -> str:
    """Find the analyzed_files.db tracking database."""
    return _resolve_tracking_db_impl(WORKSPACE_ROOT)


def print_records(records: list, label: str = "") -> None:
    if not records:
        print(f"No modules found{' for ' + label if label else ''}.")
        return

    if label:
        print(f"Modules matching '{label}':\n")

    print(f"{'Status':<10}  {'File Name':<30}  {'Extension':<8}  {'DB Path'}")
    print(f"{'-' * 10}  {'-' * 30}  {'-' * 8}  {'-' * 60}")
    for r in records:
        name = r.file_name or "(unknown)"
        ext = r.file_extension or ""
        db_path = r.analysis_db_path or "(not available)"
        # Resolve to absolute path for convenience
        if r.analysis_db_path:
            abs_path = WORKSPACE_ROOT / r.analysis_db_path
            if abs_path.exists():
                db_path = str(abs_path)
        print(f"{r.status:<10}  {name:<30}  {ext:<8}  {db_path}")

    print(f"\n{len(records)} module(s) found.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Find the analysis DB path for a module.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("module_name", nargs="?", help="Module filename to search for (e.g., appinfo.dll)")
    group.add_argument("--ext", dest="extension", help="Search by file extension (e.g., .dll, .exe)")
    group.add_argument("--list", action="store_true", help="List all analyzed modules")
    parser.add_argument("--db", dest="tracking_db", help="Path to analyzed_files.db (auto-detected if omitted)")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = safe_parse_args(parser)

    db_path = args.tracking_db or _resolve_tracking_db()
    if not db_path:
        emit_error(
            "Cannot locate analyzed_files.db tracking database. "
            "Provide --db <path> or ensure extracted_dbs/ exists.",
            "NOT_FOUND",
        )
        return

    with db_error_handler(db_path, "querying module tracking database"):
        with open_analyzed_files_db(db_path) as db:
            if args.list:
                records = db.get_all()
            elif args.extension:
                records = db.get_by_extension(args.extension)
            elif args.module_name:
                records = db.get_by_file_name(args.module_name)
                if not records:
                    records = db.search(name_contains=args.module_name)
            else:
                records = []

    if args.json:
        out = []
        for r in records:
            db_resolved = r.analysis_db_path or ""
            if r.analysis_db_path:
                abs_path = WORKSPACE_ROOT / r.analysis_db_path
                if abs_path.exists():
                    db_resolved = str(abs_path)
            out.append({
                "file_name": r.file_name,
                "file_extension": r.file_extension,
                "status": r.status,
                "analysis_db_path": db_resolved,
            })
        emit_json_list("modules", out)
    else:
        label = ""
        if args.extension:
            label = args.extension
        elif args.module_name:
            label = args.module_name
        print_records(records, label=label)


if __name__ == "__main__":
    main()
