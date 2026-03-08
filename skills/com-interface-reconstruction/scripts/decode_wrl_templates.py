#!/usr/bin/env python3
"""Decode Microsoft::WRL::* template instantiations from mangled/demangled names.

Usage:
    python decode_wrl_templates.py <db_path>
    python decode_wrl_templates.py <db_path> --json
    python decode_wrl_templates.py <db_path> --type RuntimeClass
    python decode_wrl_templates.py <db_path> --type ComPtr

Examples:
    python decode_wrl_templates.py extracted_dbs/appinfo_dll_e98d25a9e8.db
    python decode_wrl_templates.py extracted_dbs/appinfo_dll_e98d25a9e8.db --json
    python decode_wrl_templates.py extracted_dbs/appinfo_dll_e98d25a9e8.db --type RuntimeClass

Output:
    Decoded WRL class hierarchies: interface lists per RuntimeClass, flags,
    ComPtr usage, weak reference support, FtmBase presence.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path

from _common import (
    WORKSPACE_ROOT,
    RUNTIME_CLASS_FLAGS,
    WRLClassInfo,
    _label_from_interfaces,
    decode_comptr_usage,
    decode_wrl_runtime_class,
    parse_com_class_from_mangled,
    parse_json_safe,
    resolve_db_path,
)

from helpers import open_individual_analysis_db
from helpers.errors import db_error_handler, safe_parse_args
from helpers.json_output import emit_json


def decode_wrl_module(db_path: str, type_filter: str = "") -> dict:
    """Decode all WRL template instantiations in a module.

    Args:
        db_path: Path to the individual analysis DB.
        type_filter: Optional filter -- "RuntimeClass", "ComPtr", etc.

    Returns dict with WRL classes, ComPtr usage, and summary.
    """
    with db_error_handler(db_path, "decoding WRL templates"):
        with open_individual_analysis_db(db_path) as db:
            file_info = db.get_file_info()
            module_name = file_info.file_name if file_info else "(unknown)"

            # Find all WRL-related functions
            wrl_functions = db.search_functions(name_contains="Microsoft::WRL")
            all_functions = db.get_all_functions()

    # --- Decode RuntimeClassImpl / RuntimeClass templates ---
    wrl_classes: dict[str, WRLClassInfo] = {}  # keyed by a normalized class key
    comptr_usage: dict[str, list[dict]] = defaultdict(list)  # interface -> function list
    hstring_refs: list[dict] = []
    implements_helpers: list[dict] = []

    for func in wrl_functions:
        fname = func.function_name or ""
        fid = func.function_id

        # Skip if type filter is active and doesn't match
        if type_filter:
            if type_filter.lower() == "runtimeclass" and "RuntimeClass" not in fname:
                continue
            if type_filter.lower() == "comptr" and "ComPtr" not in fname:
                continue
            if type_filter.lower() == "hstring" and "HString" not in fname:
                continue

        func_info = {"function_id": fid, "function_name": fname}

        # --- RuntimeClassImpl / RuntimeClass ---
        if "RuntimeClassImpl<" in fname or "RuntimeClass<" in fname:
            info = decode_wrl_runtime_class(fname, func.mangled_name or "")
            if info:
                _finalize_class_name(info)
                key = _make_class_key(info)
                if key in wrl_classes:
                    # Merge source functions
                    wrl_classes[key].source_functions.append(func_info)
                    # Update class name if we found a better one
                    if info.class_name != "Unknown" and wrl_classes[key].class_name == "Unknown":
                        wrl_classes[key].class_name = info.class_name
                else:
                    info.source_functions = [func_info]
                    wrl_classes[key] = info

        # --- ComPtr usage ---
        if "ComPtr<" in fname:
            iface = decode_comptr_usage(fname)
            if iface:
                comptr_usage[iface].append(func_info)

        # --- HStringReference ---
        if "HStringReference" in fname or "HString" in fname:
            hstring_refs.append(func_info)

        # --- ImplementsHelper (interface enumeration) ---
        if "ImplementsHelper<" in fname:
            implements_helpers.append({
                **func_info,
                "interfaces": _extract_implements_interfaces(fname),
            })

    # Also scan for ComPtr in non-WRL functions (ComPtr<IFoo>::InternalRelease etc.)
    if not type_filter or type_filter.lower() == "comptr":
        for func in all_functions:
            fname = func.function_name or ""
            if "ComPtr<" in fname and "Microsoft::WRL" not in fname:
                iface = decode_comptr_usage(fname)
                if iface:
                    comptr_usage[iface].append({
                        "function_id": func.function_id,
                        "function_name": fname,
                    })

    # Build summary
    summary = {
        "total_wrl_functions": len(wrl_functions),
        "wrl_runtime_classes": len(wrl_classes),
        "comptr_interfaces": len(comptr_usage),
        "hstring_references": len(hstring_refs),
        "implements_helpers": len(implements_helpers),
    }

    return {
        "module": module_name,
        "wrl_summary": summary,
        "wrl_classes": [info.to_dict() for info in sorted(wrl_classes.values(), key=lambda x: x.class_name)],
        "comptr_usage": {
            iface: funcs for iface, funcs in sorted(comptr_usage.items())
        },
        "hstring_references": hstring_refs,
        "implements_helpers": implements_helpers,
    }


def _make_class_key(info: WRLClassInfo) -> str:
    """Create a dedup key for a WRL class based on its interface list and flags."""
    ifaces = tuple(sorted(info.interfaces))
    return f"{info.runtime_class_flags}|{ifaces}"


def _finalize_class_name(info: WRLClassInfo) -> None:
    """Set a meaningful class name if extraction returned 'Unknown'."""
    if info.class_name == "Unknown" and info.interfaces:
        info.class_name = _label_from_interfaces(info.interfaces)


def _extract_implements_interfaces(fname: str) -> list[str]:
    """Extract interface names from an ImplementsHelper function name."""
    # Pattern: ImplementsHelper<RuntimeClassFlags<N>, M, IFoo, IBar, ...>
    match = re.search(r'ImplementsHelper<[^>]*?,\s*\d+,\s*(.+?)>', fname)
    if not match:
        return []

    rest = match.group(1)
    # Split by comma respecting template brackets
    depth = 0
    current = []
    results = []
    for ch in rest:
        if ch == '<':
            depth += 1
            current.append(ch)
        elif ch == '>':
            depth -= 1
            current.append(ch)
        elif ch == ',' and depth == 0:
            results.append(''.join(current).strip())
            current = []
        else:
            current.append(ch)
    remaining = ''.join(current).strip()
    if remaining:
        results.append(remaining)

    # Filter out WRL internal types
    filtered = []
    for iface in results:
        iface = iface.strip()
        if not iface:
            continue
        if "FtmBase" in iface:
            continue
        if iface.startswith("Microsoft::WRL::") and "Implements" in iface:
            continue
        filtered.append(iface)

    return filtered


def print_text_decode(data: dict) -> None:
    """Print human-readable WRL template decode results."""
    s = data["wrl_summary"]
    print(f"{'=' * 80}")
    print(f"  WRL TEMPLATE DECODE: {data['module']}")
    print(f"{'=' * 80}")
    print()
    print(f"  Total WRL functions:      {s['total_wrl_functions']}")
    print(f"  WRL RuntimeClasses:       {s['wrl_runtime_classes']}")
    print(f"  ComPtr<> interfaces used: {s['comptr_interfaces']}")
    print(f"  HString references:       {s['hstring_references']}")
    print(f"  ImplementsHelper chains:  {s['implements_helpers']}")
    print()

    # WRL RuntimeClasses
    if data["wrl_classes"]:
        print(f"  WRL RUNTIME CLASSES:")
        print(f"  {'-' * 76}")
        for cls in data["wrl_classes"]:
            print(f"\n    Class: {cls['class_name']}")
            print(f"    Flags: RuntimeClassFlags<{cls['runtime_class_flags']}> = {cls['flags_meaning']}")
            print(f"    Weak ref:     {'Yes' if cls['weak_reference_support'] else 'No'}")
            print(f"    IInspectable: {'Yes' if cls['iinspectable_support'] else 'No'}")
            print(f"    FtmBase:      {'Yes' if cls['has_ftm_base'] else 'No'}")
            if cls["interfaces"]:
                print(f"    Interfaces:")
                for iface in cls["interfaces"]:
                    if len(iface) > 68:
                        iface = iface[:65] + "..."
                    print(f"      - {iface}")
            print(f"    Source functions: {len(cls['source_functions'])}")
            for sf in cls["source_functions"][:3]:
                name = sf["function_name"]
                if len(name) > 60:
                    name = name[:57] + "..."
                print(f"      [{sf['function_id']}] {name}")
            if len(cls["source_functions"]) > 3:
                print(f"      ... and {len(cls['source_functions']) - 3} more")
        print()

    # ComPtr usage
    if data["comptr_usage"]:
        print(f"  COMPTR INTERFACE USAGE:")
        print(f"  {'Interface':<50}  {'References':>10}")
        print(f"  {'-' * 50}  {'-' * 10}")
        for iface, funcs in sorted(data["comptr_usage"].items(), key=lambda x: -len(x[1])):
            display_iface = iface if len(iface) <= 50 else iface[:47] + "..."
            print(f"  {display_iface:<50}  {len(funcs):>10}")
        print()

    # ImplementsHelper chains
    if data["implements_helpers"]:
        print(f"  IMPLEMENTS HELPER CHAINS:")
        for ih in data["implements_helpers"]:
            name = ih["function_name"]
            if len(name) > 70:
                name = name[:67] + "..."
            print(f"    [{ih['function_id']}] {name}")
            if ih["interfaces"]:
                for iface in ih["interfaces"]:
                    if len(iface) > 60:
                        iface = iface[:57] + "..."
                    print(f"      -> {iface}")
        print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Decode WRL template instantiations from a module.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("db_path", help="Path to the individual analysis DB")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--type", dest="type_filter", default="",
                        help="Filter WRL type: RuntimeClass, ComPtr, HString")
    args = safe_parse_args(parser)

    db_path = resolve_db_path(args.db_path)
    with db_error_handler(db_path, "WRL template decoding"):
        data = decode_wrl_module(db_path, type_filter=args.type_filter)

    if args.json:
        emit_json(data)
    else:
        print_text_decode(data)


if __name__ == "__main__":
    main()
