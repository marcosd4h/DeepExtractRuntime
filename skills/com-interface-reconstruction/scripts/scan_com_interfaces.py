#!/usr/bin/env python3
"""Scan a module for all COM interfaces, QI implementations, and vtable layouts.

Usage:
    python scan_com_interfaces.py <db_path>
    python scan_com_interfaces.py <db_path> --json
    python scan_com_interfaces.py <db_path> --vtable-only

Examples:
    python scan_com_interfaces.py extracted_dbs/appinfo_dll_e98d25a9e8.db
    python scan_com_interfaces.py extracted_dbs/appinfo_dll_e98d25a9e8.db --json
    python scan_com_interfaces.py extracted_dbs/appinfo_dll_e98d25a9e8.db --vtable-only

Output:
    COM interface inventory: QI/AddRef/Release implementations, vtable-derived
    method tables, WRL class count, COM API usage summary.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

from _common import (
    WORKSPACE_ROOT,
    COM_API_NAMES,
    IUNKNOWN_METHOD_NAMES,
    QIImplementation,
    COMInterface,
    classify_iunknown_method,
    classify_vtable_as_com,
    parse_com_class_from_mangled,
    parse_json_safe,
    parse_vtable_methods,
    resolve_db_path,
)

from helpers import open_individual_analysis_db
from helpers.cache import get_cached, cache_result
from helpers.errors import db_error_handler, safe_parse_args
from helpers.json_output import emit_json


def scan_module(db_path: str, vtable_only: bool = False, *, no_cache: bool = False) -> dict:
    """Scan a module for all COM-related structures.

    Returns a comprehensive dict with QI implementations, vtable interfaces,
    COM API usage, and summary statistics.
    """
    params = {"vtable_only": vtable_only}
    if not no_cache:
        cached = get_cached(db_path, "scan_com_interfaces", params=params)
        if cached is not None:
            return cached

    with db_error_handler(db_path, "scanning COM interfaces"):
        with open_individual_analysis_db(db_path) as db:
            file_info = db.get_file_info()
            module_name = file_info.file_name if file_info else "(unknown)"

            all_functions = db.get_all_functions()

    qi_impls: list[QIImplementation] = []
    addref_impls: list[QIImplementation] = []
    release_impls: list[QIImplementation] = []
    vtable_interfaces: list[dict] = []
    wrl_function_count = 0
    com_api_callers: dict[str, list[dict]] = defaultdict(list)
    vtable_context_count = 0

    # Collect unique vtable skeletons (deduplicate by content)
    seen_vtable_skeletons: set[str] = set()

    for func in all_functions:
        fname = func.function_name or ""
        mangled = func.mangled_name or ""
        fid = func.function_id

        # --- Detect WRL functions ---
        if "Microsoft::WRL" in fname or "Microsoft::WRL" in mangled:
            wrl_function_count += 1

        if not vtable_only:
            # --- Detect QI/AddRef/Release implementations ---
            method_type = classify_iunknown_method(fname)
            if method_type and mangled:
                parsed = parse_com_class_from_mangled(mangled)
                class_name = parsed["class_name"] if parsed else ""
                impl = QIImplementation(
                    function_id=fid,
                    function_name=fname,
                    mangled_name=mangled,
                    class_name=class_name,
                    method_type=method_type,
                    has_adjustor=parsed["has_adjustor"] if parsed else False,
                    adjustor_offset=parsed["adjustor_offset"] if parsed else 0,
                )
                if method_type == "QueryInterface":
                    qi_impls.append(impl)
                elif method_type == "AddRef":
                    addref_impls.append(impl)
                elif method_type == "Release":
                    release_impls.append(impl)

            # --- Detect COM API usage ---
            simple_xrefs = parse_json_safe(func.simple_outbound_xrefs)
            if simple_xrefs and isinstance(simple_xrefs, list):
                for xref in simple_xrefs:
                    if isinstance(xref, dict):
                        callee = xref.get("function_name", "")
                        if callee in COM_API_NAMES:
                            com_api_callers[callee].append({
                                "function_id": fid,
                                "function_name": fname,
                            })

        # --- Extract vtable contexts ---
        vtable_ctx = parse_json_safe(func.vtable_contexts)
        if vtable_ctx and isinstance(vtable_ctx, list):
            vtable_context_count += 1
            for entry in vtable_ctx:
                if not isinstance(entry, dict):
                    continue
                classes = entry.get("reconstructed_classes", [])
                source_ea = entry.get("source_ea", "")
                for skeleton in classes:
                    if not isinstance(skeleton, str):
                        continue
                    # Deduplicate
                    if skeleton in seen_vtable_skeletons:
                        continue
                    seen_vtable_skeletons.add(skeleton)

                    methods = parse_vtable_methods(skeleton)
                    if not methods:
                        continue

                    # Extract class name from skeleton
                    import re
                    class_match = re.search(r'class\s+(?:[\w]+\s+)?([\w:]+(?:<[^>]+>)?)', skeleton)
                    vtable_class = class_match.group(1) if class_match else "(unknown)"

                    com_info = classify_vtable_as_com(methods, class_name=vtable_class)

                    vtable_interfaces.append({
                        "source_function_id": fid,
                        "source_ea": source_ea,
                        "class_name": vtable_class,
                        "methods": methods,
                        "slot_count": len(methods),
                        "is_com": com_info["is_com"],
                        "base_interface": com_info["base_interface"],
                        "custom_method_start_slot": com_info["custom_method_start_slot"],
                        "confidence": com_info["confidence"],
                    })

    # Build summary
    summary = {
        "total_functions_scanned": len(all_functions),
        "qi_implementations": len(qi_impls),
        "addref_implementations": len(addref_impls),
        "release_implementations": len(release_impls),
        "wrl_function_count": wrl_function_count,
        "vtable_context_functions": vtable_context_count,
        "unique_vtable_skeletons": len(vtable_interfaces),
        "com_vtables": sum(1 for v in vtable_interfaces if v["is_com"]),
        "non_com_vtables": sum(1 for v in vtable_interfaces if not v["is_com"]),
        "com_api_callers": {api: len(callers) for api, callers in com_api_callers.items()},
    }

    # Identify unique COM classes from QI implementations
    com_classes: set[str] = set()
    for impl in qi_impls + addref_impls + release_impls:
        if impl.class_name:
            com_classes.add(impl.class_name)
    summary["unique_com_classes"] = len(com_classes)

    result = {
        "module": module_name,
        "com_summary": summary,
        "qi_implementations": [impl.to_dict() for impl in qi_impls],
        "addref_implementations": [impl.to_dict() for impl in addref_impls],
        "release_implementations": [impl.to_dict() for impl in release_impls],
        "vtable_interfaces": vtable_interfaces,
        "com_api_usage": {api: callers for api, callers in com_api_callers.items()},
        "com_classes": sorted(com_classes),
    }

    cache_result(db_path, "scan_com_interfaces", result, params=params)
    return result


def print_text_scan(data: dict) -> None:
    """Print human-readable COM scan results."""
    s = data["com_summary"]
    print(f"{'=' * 80}")
    print(f"  COM INTERFACE SCAN: {data['module']}")
    print(f"{'=' * 80}")
    print()
    print(f"  Functions scanned:        {s['total_functions_scanned']}")
    print(f"  WRL functions:            {s['wrl_function_count']}")
    print(f"  QI implementations:       {s['qi_implementations']}")
    print(f"  AddRef implementations:   {s['addref_implementations']}")
    print(f"  Release implementations:  {s['release_implementations']}")
    print(f"  Unique COM classes:       {s['unique_com_classes']}")
    print(f"  VTable context functions: {s['vtable_context_functions']}")
    print(f"  Unique vtable skeletons:  {s['unique_vtable_skeletons']}")
    print(f"    COM vtables:            {s['com_vtables']}")
    print(f"    Non-COM vtables:        {s['non_com_vtables']}")
    print()

    # COM Classes
    if data["com_classes"]:
        print(f"  COM CLASSES (from QI/AddRef/Release):")
        for cls in data["com_classes"]:
            qi_count = sum(1 for q in data["qi_implementations"] if q["class_name"] == cls)
            ar_count = sum(1 for q in data["addref_implementations"] if q["class_name"] == cls)
            rel_count = sum(1 for q in data["release_implementations"] if q["class_name"] == cls)
            print(f"    {cls:<50}  QI={qi_count} AddRef={ar_count} Release={rel_count}")
        print()

    # QI implementations
    if data["qi_implementations"]:
        print(f"  QUERYINTERFACE IMPLEMENTATIONS:")
        print(f"  {'ID':>6}  {'Class':<40}  {'Adjustor':>8}  {'Name'}")
        print(f"  {'-'*6}  {'-'*40}  {'-'*8}  {'-'*50}")
        for qi in data["qi_implementations"]:
            cls = qi["class_name"]
            if len(cls) > 40:
                cls = cls[:37] + "..."
            adj = f"+{qi['adjustor_offset']}" if qi["has_adjustor"] else ""
            name = qi["function_name"]
            if len(name) > 50:
                name = name[:47] + "..."
            print(f"  {qi['function_id']:>6}  {cls:<40}  {adj:>8}  {name}")
        print()

    # COM vtable interfaces -- grouped by confidence
    com_vtables = [v for v in data["vtable_interfaces"] if v["is_com"]]
    if com_vtables:
        for confidence in ("high", "medium", "low"):
            group = [v for v in com_vtables if v.get("confidence") == confidence]
            if not group:
                continue
            print(f"  COM VTABLE INTERFACES -- {confidence.upper()} confidence ({len(group)}):")
            for vtbl in group:
                cls_name = vtbl["class_name"]
                if len(cls_name) > 70:
                    cls_name = cls_name[:67] + "..."
                print(f"\n    Class: {cls_name}")
                print(f"    Base:  {vtbl['base_interface']}")
                print(f"    Slots: {vtbl['slot_count']}")
                print(f"    Source: function {vtbl['source_function_id']} @ {vtbl['source_ea']}")
                start = vtbl["custom_method_start_slot"]
                custom_methods = [m for m in vtbl["methods"] if m["slot"] >= start]
                if custom_methods:
                    label = f"Custom methods (slot {start}+):" if start > 0 else "Methods:"
                    print(f"    {label}")
                    for m in custom_methods[:15]:
                        method_name = m["method_name"]
                        if len(method_name) > 60:
                            method_name = method_name[:57] + "..."
                        print(f"      [{m['slot']}] {m['offset_hex']}: {method_name}")
                    if len(custom_methods) > 15:
                        print(f"      ... and {len(custom_methods) - 15} more")
            print()

    # COM API usage
    if data["com_api_usage"]:
        print(f"  COM API USAGE:")
        for api, callers in sorted(data["com_api_usage"].items(), key=lambda x: -len(x[1])):
            print(f"    {api}: {len(callers)} caller(s)")
            for caller in callers[:5]:
                name = caller["function_name"]
                if len(name) > 60:
                    name = name[:57] + "..."
                print(f"      [{caller['function_id']}] {name}")
            if len(callers) > 5:
                print(f"      ... and {len(callers) - 5} more")
        print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan a module for COM interfaces and vtable layouts.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("db_path", help="Path to the individual analysis DB")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--vtable-only", action="store_true",
                        help="Only scan vtable contexts (skip QI/API detection)")
    parser.add_argument("--no-cache", action="store_true", help="Bypass result cache")
    args = safe_parse_args(parser)

    db_path = resolve_db_path(args.db_path)
    with db_error_handler(db_path, "COM interface scanning"):
        data = scan_module(db_path, vtable_only=args.vtable_only, no_cache=args.no_cache)

    if args.json:
        emit_json(data)
    else:
        print_text_scan(data)


if __name__ == "__main__":
    main()
