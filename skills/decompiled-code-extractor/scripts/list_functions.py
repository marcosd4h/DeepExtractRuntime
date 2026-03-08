#!/usr/bin/env python3
"""List or search functions in an individual analysis database.

Usage:
    python list_functions.py <db_path>
    python list_functions.py <db_path> --search <pattern>
    python list_functions.py <db_path> --with-signatures
    python list_functions.py <db_path> --has-decompiled

Examples:
    python list_functions.py extracted_dbs/appinfo_dll_e98d25a9e8.db
    python list_functions.py extracted_dbs/cmd_exe_6d109a3a00.db --search "Bat"
    python list_functions.py extracted_dbs/cmd_exe_6d109a3a00.db --with-signatures --has-decompiled

Output:
    Prints function names and optionally signatures. With --search, filters by
    name pattern. Summary includes total count and module info.
"""

from __future__ import annotations

import argparse
import json
import sys

from _common import (
    filter_decompiled,
    get_function_id,
    load_function_index_for_db,
    open_individual_analysis_db,
    resolve_db_path,
    search_index,
)
from helpers.errors import ErrorCode, db_error_handler, emit_error, safe_parse_args
from helpers.json_output import emit_json


def main() -> None:
    parser = argparse.ArgumentParser(
        description="List or search functions in an analysis database.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("db_path", help="Path to the individual analysis DB")
    parser.add_argument("--search", dest="pattern", help="Filter functions by name pattern (case-insensitive)")
    parser.add_argument("--with-signatures", action="store_true", help="Include function signatures in output")
    parser.add_argument("--has-decompiled", action="store_true", help="Only show functions with decompiled code")
    parser.add_argument("--limit", type=int, default=0, help="Limit number of results (0 = no limit)")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = safe_parse_args(parser)

    db_path = resolve_db_path(args.db_path)

    function_index = load_function_index_for_db(db_path)

    with db_error_handler(db_path, "listing functions"):
        with open_individual_analysis_db(db_path) as db:
            file_info = db.get_file_info()
            total = db.count_functions()

            if not args.json:
                if file_info:
                    print(f"Module: {file_info.file_name or '(unknown)'}")
                    if file_info.file_description:
                        print(f"Description: {file_info.file_description}")
                    if file_info.company_name:
                        print(f"Company: {file_info.company_name}")
                print(f"Total functions in DB: {total}\n")

            index_rows = None
            if function_index and (args.pattern or args.has_decompiled):
                idx = function_index
                if args.has_decompiled:
                    idx = filter_decompiled(idx, decompiled=True)
                if args.pattern:
                    idx = search_index(idx, args.pattern)
                index_rows = [
                    {
                        "function_id": get_function_id(entry),
                        "function_name": name,
                        "has_assembly": bool(entry.get("has_assembly", False)),
                        "has_decompiled": bool(entry.get("has_decompiled", False)),
                    }
                    for name, entry in idx.items()
                ]
                index_rows.sort(key=lambda r: (r["function_name"] or "").lower())
                if args.limit > 0:
                    index_rows = index_rows[: args.limit]

            if index_rows is not None:
                functions = []
            elif args.pattern:
                functions = db.search_functions(
                    name_contains=args.pattern,
                    has_decompiled_code=args.has_decompiled or None,
                )
            elif args.has_decompiled:
                functions = db.search_functions(has_decompiled_code=True)
            else:
                functions = db.get_all_functions(limit=args.limit if args.limit > 0 else None)

            # JSON output -- emit structured data only, no human-readable text
            if args.json:
                rows = []
                if index_rows is not None:
                    for row in index_rows:
                        rows.append(row)
                else:
                    for func in functions:
                        rows.append({
                            "function_id": func.function_id,
                            "function_name": func.function_name,
                            "has_assembly": bool(func.assembly_code),
                            "has_decompiled": bool(func.decompiled_code),
                        })
                if args.pattern and not rows:
                    emit_error(
                        f"No functions matching '{args.pattern}'",
                        ErrorCode.NO_DATA,
                    )
                emit_json({
                    "module": file_info.file_name if file_info else None,
                    "total_functions": total,
                    "shown": len(rows),
                    "pattern": args.pattern,
                    "functions": rows,
                })
                return

            # Human-readable output
            if index_rows is not None and not index_rows:
                label = f" matching '{args.pattern}'" if args.pattern else ""
                print(f"No functions found{label}.")
                return
            if index_rows is None and not functions:
                label = f" matching '{args.pattern}'" if args.pattern else ""
                print(f"No functions found{label}.")
                return

            if args.with_signatures:
                print(f"{'ID':>6}  {'Function Name':<50}  {'Signature'}")
                print(f"{'-' * 6}  {'-' * 50}  {'-' * 70}")
                if index_rows is not None:
                    sig_ids = [r["function_id"] for r in index_rows if isinstance(r.get("function_id"), int)]
                    sig_map = {f.function_id: f for f in db.get_functions_by_ids(sig_ids)} if sig_ids else {}
                    for row in index_rows:
                        fid = row["function_id"]
                        func = sig_map.get(fid) if isinstance(fid, int) else None
                        name = row["function_name"] or "(unnamed)"
                        sig = func.function_signature if func else ""
                        if len(name) > 50:
                            name = name[:47] + "..."
                        if len(sig) > 70:
                            sig = sig[:67] + "..."
                        print(f"{(fid if fid is not None else '?'):>6}  {name:<50}  {sig}")
                else:
                    for func in functions:
                        name = func.function_name or "(unnamed)"
                        sig = func.function_signature or ""
                        if len(name) > 50:
                            name = name[:47] + "..."
                        if len(sig) > 70:
                            sig = sig[:67] + "..."
                        print(f"{func.function_id:>6}  {name:<50}  {sig}")
            else:
                print(f"{'ID':>6}  {'Function Name'}")
                print(f"{'-' * 6}  {'-' * 60}")
                if index_rows is not None:
                    for row in index_rows:
                        name = row["function_name"] or "(unnamed)"
                        has_asm = "asm" if row["has_assembly"] else "   "
                        has_dec = "dec" if row["has_decompiled"] else "   "
                        fid = row["function_id"]
                        print(f"{(fid if fid is not None else '?'):>6}  {name:<60}  [{has_asm}|{has_dec}]")
                else:
                    for func in functions:
                        name = func.function_name or "(unnamed)"
                        has_asm = "asm" if func.assembly_code else "   "
                        has_dec = "dec" if func.decompiled_code else "   "
                        print(f"{func.function_id:>6}  {name:<60}  [{has_asm}|{has_dec}]")

            shown = len(index_rows) if index_rows is not None else len(functions)
            label = f" matching '{args.pattern}'" if args.pattern else ""
            extra = f" (filtered from {total} total)" if args.pattern or args.has_decompiled else ""
            print(f"\n{shown} function(s) listed{label}{extra}.")


if __name__ == "__main__":
    main()
