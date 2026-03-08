#!/usr/bin/env python3
"""Prepare a batch lift plan: extract data for a function set, scan shared
struct patterns, and output an ordered lift plan.

Takes function IDs directly or reads the JSON output of collect_functions.py.

Usage:
    # From collect_functions.py JSON output
    python collect_functions.py <db_path> --class CSecurityDescriptor --json > funcs.json
    python prepare_batch_lift.py --from-json funcs.json

    # Direct IDs
    python prepare_batch_lift.py <db_path> --ids 42,43,44,45

    # Summary only (no code output)
    python prepare_batch_lift.py --from-json funcs.json --summary

    # Structs only (for iterative accumulation)
    python prepare_batch_lift.py --from-json funcs.json --structs-only

Output:
    Full lift plan with:
    - Lift order (callees first)
    - Accumulated struct definitions across all functions
    - Per-function: signatures, decompiled code, assembly, xrefs, strings
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Optional

from _common import (
    WORKSPACE_ROOT,
    emit_error,
    format_struct_definition,
    merge_struct_fields,
    parse_class_from_mangled,
    parse_json_safe,
    resolve_db_path,
    scan_struct_accesses,
    topological_sort_functions,
)
from helpers.errors import ErrorCode, db_error_handler, log_warning, safe_parse_args
from helpers import open_individual_analysis_db
from helpers.json_output import emit_json


# ---------------------------------------------------------------------------
# Data extraction
# ---------------------------------------------------------------------------


def extract_function_data(db_path: str, function_ids: list[int]) -> dict:
    """Extract all data for a list of function IDs from a single DB.

    Returns {function_id: {full data dict}} in extraction order.
    """
    results = {}
    with db_error_handler(db_path, "preparing batch lift"):
        with open_individual_analysis_db(db_path) as db:
            file_info = db.get_file_info()
            module_name = file_info.file_name if file_info else Path(db_path).stem

            func_map = {f.function_id: f for f in db.get_functions_by_ids(function_ids)}
            for fid in function_ids:
                func = func_map.get(fid)
                if not func:
                    results[fid] = {"error": f"Function ID {fid} not found", "code": "NOT_FOUND"}
                    continue

                outbound = parse_json_safe(func.simple_outbound_xrefs) or []
                inbound = parse_json_safe(func.simple_inbound_xrefs) or []
                strings = parse_json_safe(func.string_literals) or []
                vtables = parse_json_safe(func.vtable_contexts) or []
                globals_acc = parse_json_safe(func.global_var_accesses) or []
                stack = parse_json_safe(func.stack_frame)
                loops = parse_json_safe(func.loop_analysis)

                results[fid] = {
                    "function_id": fid,
                    "function_name": func.function_name,
                    "function_signature": func.function_signature,
                    "function_signature_extended": func.function_signature_extended,
                    "mangled_name": func.mangled_name,
                    "decompiled_code": func.decompiled_code,
                    "assembly_code": func.assembly_code,
                    "string_literals": strings,
                    "outbound_xrefs": outbound,
                    "inbound_xrefs": inbound,
                    "vtable_contexts": vtables,
                    "global_var_accesses": globals_acc,
                    "stack_frame": stack,
                    "loop_analysis": loops,
                    "module_name": module_name,
                }

    return results


def scan_shared_structs(
    func_data: dict[int, dict],
    function_ids_ordered: list[int],
) -> dict[str, Any]:
    """Scan struct access patterns across all functions and merge results.

    Groups accesses by the first parameter (a1, typically `this` for class methods),
    then merges fields across all functions.

    Returns {base_param: {fields: [...], source_functions: [...], struct_def: str}}.
    """
    # Collect accesses grouped by base parameter across all functions
    all_accesses: dict[str, list[dict]] = defaultdict(list)
    source_map: dict[str, list[str]] = defaultdict(list)

    for fid in function_ids_ordered:
        data = func_data.get(fid)
        if not data or "error" in data:
            continue
        code = data.get("decompiled_code", "")
        if not code:
            continue

        accesses = scan_struct_accesses(code)
        for acc in accesses:
            base = acc["base"]
            all_accesses[base].append(acc)
            fname = data.get("function_name", f"ID={fid}")
            if fname not in source_map[base]:
                source_map[base].append(fname)

    # Phase 1: Build per-base entries with inferred struct names
    per_base: dict[str, dict] = {}
    for base, accesses in sorted(all_accesses.items()):
        if len(accesses) < 2:
            continue  # Skip trivial single-access bases

        fields = merge_struct_fields({base: accesses})
        if not fields:
            continue

        struct_name = _infer_struct_name(base, func_data, function_ids_ordered)
        per_base[base] = {
            "struct_name": struct_name,
            "fields": fields,
            "source_functions": source_map[base],
        }

    # Phase 2: Consolidate entries with the same inferred struct name
    # (e.g., a1, a2, v3 all mapping to "cmdnode" get merged into one entry)
    consolidated: dict[str, dict] = {}
    for base, entry in per_base.items():
        sname = entry["struct_name"]
        if sname in consolidated:
            # Merge fields: take the union of all fields, larger size wins per offset
            existing_fields = {f["offset"]: f for f in consolidated[sname]["fields"]}
            for field in entry["fields"]:
                off = field["offset"]
                if off not in existing_fields or field["size"] > existing_fields[off]["size"]:
                    existing_fields[off] = field
            consolidated[sname]["fields"] = sorted(existing_fields.values(), key=lambda f: f["offset"])
            # Merge source functions
            for fn in entry["source_functions"]:
                if fn not in consolidated[sname]["source_functions"]:
                    consolidated[sname]["source_functions"].append(fn)
            consolidated[sname]["base_params"].append(base)
        else:
            consolidated[sname] = {
                "struct_name": sname,
                "fields": entry["fields"],
                "source_functions": list(entry["source_functions"]),
                "base_params": [base],
            }

    # Phase 3: Generate struct definitions
    structs = {}
    for sname, entry in consolidated.items():
        struct_def = format_struct_definition(
            sname, entry["fields"], func_count=len(entry["source_functions"]),
        )
        key = sname  # Use struct name as key (not base param)
        structs[key] = {
            "struct_name": sname,
            "field_count": len(entry["fields"]),
            "fields": entry["fields"],
            "source_functions": entry["source_functions"],
            "base_params": entry["base_params"],
            "struct_definition": struct_def,
        }

    return structs


def _infer_struct_name(
    base_param: str,
    func_data: dict[int, dict],
    function_ids: list[int],
) -> str:
    """Try to infer a struct name from context.

    Checks: mangled names for class info, function signatures for type hints.
    Falls back to 'Struct_<base>' placeholder.
    """
    # Check if the base is a1/this -- likely the class type for class methods
    if base_param in ("a1", "this"):
        for fid in function_ids:
            data = func_data.get(fid, {})
            mangled = data.get("mangled_name", "")
            if mangled:
                parsed = parse_class_from_mangled(mangled)
                if parsed:
                    return parsed["class_name"]

    # Check function signatures for type hints
    for fid in function_ids:
        data = func_data.get(fid, {})
        sig = data.get("function_signature_extended") or data.get("function_signature", "")
        # Look for struct/class type in signature
        if "struct " in sig:
            import re
            m = re.search(r'struct\s+(\w+)', sig)
            if m:
                return m.group(1)

    return f"Struct_{base_param}"


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


def print_full_plan(
    func_data: dict[int, dict],
    dep_order: list[int],
    structs: dict[str, Any],
    metadata: dict,
) -> None:
    """Print the complete batch lift plan."""
    mode = metadata.get("mode", "batch")
    module = metadata.get("module_name", "unknown")

    print(f"{'#' * 80}")
    print(f"  BATCH LIFT PLAN")
    print(f"{'#' * 80}")
    print(f"  Module: {module}")
    print(f"  DB: {metadata.get('db_path', '?')}")
    if mode == "class":
        print(f"  Mode: Lift all methods of {metadata.get('class_name', '?')}")
    elif mode == "chain":
        print(f"  Mode: Call chain from {metadata.get('start_function', '?')} (depth {metadata.get('max_depth', '?')})")
    elif mode == "export_down":
        print(f"  Mode: Export-down from {metadata.get('export_name', '?')} (depth {metadata.get('max_depth', '?')})")
    print(f"  Functions: {len(dep_order)}")
    print(f"  Structs detected: {len(structs)}")
    print(f"{'#' * 80}")

    # Struct definitions
    if structs:
        print(f"\n{'=' * 80}")
        print(f"  SHARED STRUCT DEFINITIONS")
        print(f"  (accumulated across all {len(dep_order)} functions)")
        print(f"{'=' * 80}")
        for base, sdata in structs.items():
            print(f"\n// Base parameter: {base}")
            print(f"// Source functions: {', '.join(sdata['source_functions'][:5])}" +
                  (f" ... (+{len(sdata['source_functions']) - 5} more)" if len(sdata['source_functions']) > 5 else ""))
            print(sdata["struct_definition"])

    # Lift order summary
    print(f"\n{'=' * 80}")
    print(f"  LIFT ORDER (callees first -> callers last)")
    print(f"{'=' * 80}")
    for i, fid in enumerate(dep_order, 1):
        data = func_data.get(fid, {})
        name = data.get("function_name", f"ID={fid}")
        sig = data.get("function_signature", "")
        has_code = bool(data.get("decompiled_code"))
        has_asm = bool(data.get("assembly_code"))
        status = "ready" if (has_code and has_asm) else ("code-only" if has_code else "NO DATA")
        if len(sig) > 60:
            sig = sig[:57] + "..."
        print(f"  {i:>3}. [{status:>9}] {name}  (ID={fid})")
        if sig:
            print(f"       {sig}")

    # Per-function data
    for i, fid in enumerate(dep_order, 1):
        data = func_data.get(fid, {})
        if "error" in data:
            print(f"\n{'=' * 80}")
            print(f"  FUNCTION {i}/{len(dep_order)}: ERROR -- {data['error']}")
            continue

        name = data.get("function_name", f"ID={fid}")
        print(f"\n\n{'=' * 80}")
        print(f"  FUNCTION {i}/{len(dep_order)}: {name}")
        print(f"{'=' * 80}")

        _print_section("SIGNATURE", data.get("function_signature"))
        ext = data.get("function_signature_extended")
        if ext and ext != data.get("function_signature"):
            _print_section("SIGNATURE (extended)", ext)
        _print_section("MANGLED NAME", data.get("mangled_name"))
        _print_section("DECOMPILED CODE", data.get("decompiled_code"))
        _print_section("ASSEMBLY CODE", data.get("assembly_code"))

        # Compact xref summaries
        outbound = data.get("outbound_xrefs", [])
        if outbound:
            internal = [x for x in outbound if isinstance(x, dict) and x.get("function_id") is not None]
            external = [x for x in outbound if isinstance(x, dict) and x.get("function_id") is None
                        and x.get("module_name") not in ("data", "vtable")
                        and x.get("function_type") not in (4, 8)]
            in_set = [x for x in internal if x["function_id"] in set(dep_order)]

            lines = []
            if in_set:
                lines.append(f"  Within lift set ({len(in_set)}):")
                for x in sorted(in_set, key=lambda e: e.get("function_name", "")):
                    lines.append(f"    -> {x.get('function_name', '?')}  [ID={x['function_id']}]")
            other_internal = [x for x in internal if x["function_id"] not in set(dep_order)]
            if other_internal:
                lines.append(f"  Other internal ({len(other_internal)}):")
                for x in sorted(other_internal, key=lambda e: e.get("function_name", ""))[:10]:
                    lines.append(f"    -> {x.get('function_name', '?')}  [ID={x['function_id']}]")
                if len(other_internal) > 10:
                    lines.append(f"    ... +{len(other_internal) - 10} more")
            if external:
                lines.append(f"  External ({len(external)}):")
                for x in sorted(external, key=lambda e: e.get("function_name", ""))[:10]:
                    lines.append(f"    -> {x.get('function_name', '?')}  [{x.get('module_name', '?')}]")
                if len(external) > 10:
                    lines.append(f"    ... +{len(external) - 10} more")
            _print_section("OUTBOUND CALLS", "\n".join(lines))

        strings = data.get("string_literals", [])
        if strings:
            _print_section("STRING LITERALS", json.dumps(strings[:20], indent=2, ensure_ascii=False) +
                          (f"\n... (+{len(strings) - 20} more)" if len(strings) > 20 else ""))

        vtables = data.get("vtable_contexts", [])
        if vtables:
            _print_section("VTABLE CONTEXTS", json.dumps(vtables, indent=2, ensure_ascii=False))


def print_summary(
    func_data: dict[int, dict],
    dep_order: list[int],
    structs: dict[str, Any],
    metadata: dict,
) -> None:
    """Print compact summary (no code)."""
    module = metadata.get("module_name", "unknown")

    print(f"Batch lift summary: {len(dep_order)} functions from {module}\n")

    if structs:
        print(f"Shared struct definitions ({len(structs)}):")
        for base, sdata in structs.items():
            print(f"  {sdata['struct_name']}: {sdata['field_count']} fields, "
                  f"from {len(sdata['source_functions'])} function(s)")
        print()

    print(f"Lift order (callees first):")
    for i, fid in enumerate(dep_order, 1):
        data = func_data.get(fid, {})
        name = data.get("function_name", f"ID={fid}")
        has_code = bool(data.get("decompiled_code"))
        asm_lines = len(data.get("assembly_code", "").splitlines()) if data.get("assembly_code") else 0
        code_lines = len(data.get("decompiled_code", "").splitlines()) if data.get("decompiled_code") else 0
        print(f"  {i:>3}. {name}  (ID={fid}, {code_lines}L code, {asm_lines}L asm)")


def print_structs_only(structs: dict[str, Any]) -> None:
    """Print only the accumulated struct definitions."""
    if not structs:
        print("No struct patterns detected across the function set.")
        return

    print(f"// Accumulated struct definitions from batch scan\n")
    print(f"#pragma once")
    print(f"#include <stdint.h>\n")
    for base, sdata in structs.items():
        print(f"// Base parameter: {base}")
        print(f"// Source: {', '.join(sdata['source_functions'][:5])}")
        print(sdata["struct_definition"])
        print()


def _print_section(title: str, content: Optional[str]) -> None:
    """Print a labeled section."""
    print(f"\n--- {title} ---")
    if content is None or (isinstance(content, str) and not content.strip()):
        print("(none)")
    else:
        print(content)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prepare a batch lift plan with shared context.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--from-json", dest="json_file",
                       help="JSON file from collect_functions.py --json")
    source.add_argument("--ids", dest="direct_ids",
                       help="Comma-separated function IDs (requires db_path)")

    parser.add_argument("db_path", nargs="?", help="DB path (required with --ids)")
    parser.add_argument("--summary", action="store_true", help="Compact summary only (no code)")
    parser.add_argument("--structs-only", action="store_true", help="Output only struct definitions")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = safe_parse_args(parser)

    try:
        # Load function set
        if args.json_file:
            json_path = Path(args.json_file)
            if not json_path.is_absolute():
                json_path = WORKSPACE_ROOT / args.json_file
            with open(json_path) as f:
                manifest = json.load(f)

            db_path = resolve_db_path(manifest["db_path"])
            dep_order = manifest.get("dependency_order", [])
            function_ids = dep_order if dep_order else [f["function_id"] for f in manifest["functions"]]
            metadata = manifest

        elif args.direct_ids:
            if not args.db_path:
                parser.error("--ids requires a db_path argument")
            db_path = resolve_db_path(args.db_path)
            function_ids = [int(x.strip()) for x in args.direct_ids.split(",")]
            dep_order = function_ids  # Use as-is when no ordering info available
            metadata = {"mode": "direct", "db_path": db_path, "module_name": Path(db_path).stem}

        else:
            parser.error("Provide --from-json or --ids")
            return

        # Extract all function data
        func_data = extract_function_data(db_path, function_ids)

        if not dep_order or args.direct_ids:
            with db_error_handler(db_path, "preparing batch lift"):
                with open_individual_analysis_db(db_path) as db:
                    funcs = db.get_functions_by_ids(function_ids)
                dep_order = topological_sort_functions(funcs, set(function_ids))

        # Scan shared struct patterns
        structs = scan_shared_structs(func_data, dep_order)

        # Output
        if args.json:
            result = {
                "metadata": metadata,
                "dependency_order": dep_order,
                "function_count": len(dep_order),
                "struct_count": len(structs),
                "structs": structs,
                "functions": func_data,
            }
            emit_json(result)
        elif args.structs_only:
            print_structs_only(structs)
        elif args.summary:
            print_summary(func_data, dep_order, structs, metadata)
        else:
            print_full_plan(func_data, dep_order, structs, metadata)

    except FileNotFoundError as e:
        emit_error(str(e), ErrorCode.NOT_FOUND)
    except Exception as e:
        log_warning(f"Unexpected error during batch lift: {e}", "UNKNOWN")
        emit_error(f"{type(e).__name__}: {e}", ErrorCode.UNKNOWN)


if __name__ == "__main__":
    main()
