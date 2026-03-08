#!/usr/bin/env python3
"""Map which COM/WRL interfaces each class implements.

Merges evidence from multiple sources: WRL template parameters, QI dispatch
code, vtable analysis, and mangled name patterns.

Usage:
    python map_class_interfaces.py <db_path>
    python map_class_interfaces.py <db_path> --json
    python map_class_interfaces.py <db_path> --class CAppInfoService

Examples:
    python map_class_interfaces.py extracted_dbs/appinfo_dll_e98d25a9e8.db
    python map_class_interfaces.py extracted_dbs/appinfo_dll_e98d25a9e8.db --json
    python map_class_interfaces.py extracted_dbs/appinfo_dll_e98d25a9e8.db --class RuntimeClassImpl

Output:
    Per-class interface lists with evidence sources, WRL flags, weak ref support,
    FtmBase presence, and aggregated method inventory.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from _common import (
    WORKSPACE_ROOT,
    COMClassInfo,
    classify_iunknown_method,
    classify_vtable_as_com,
    decode_wrl_runtime_class,
    find_guids_in_text,
    parse_com_class_from_mangled,
    parse_json_safe,
    parse_vtable_methods,
    resolve_db_path,
    resolve_guid_name,
)

from helpers import open_individual_analysis_db
from helpers.errors import db_error_handler, safe_parse_args
from helpers.json_output import emit_json


def map_interfaces(db_path: str, class_filter: str = "") -> dict:
    """Build a comprehensive class-to-interface mapping for a module.

    Merges evidence from:
    1. WRL template parameters (RuntimeClassImpl encodes interface list)
    2. QI/AddRef/Release implementations (class membership)
    3. VTable contexts (method slot analysis)
    4. Mangled name patterns (class::method relationships)
    5. Decompiled code (GUID comparisons in QI implementations)

    Returns dict with class_interface_map, summary, and evidence details.
    """
    with db_error_handler(db_path, "mapping class interfaces"):
        with open_individual_analysis_db(db_path) as db:
            file_info = db.get_file_info()
            module_name = file_info.file_name if file_info else "(unknown)"
            all_functions = db.get_all_functions()

    classes: dict[str, COMClassInfo] = {}

    def _get_class(name: str) -> COMClassInfo:
        if name not in classes:
            classes[name] = COMClassInfo(class_name=name)
        return classes[name]

    # --- Pass 1: WRL template analysis (highest confidence) ---
    for func in all_functions:
        fname = func.function_name or ""
        fid = func.function_id

        if "RuntimeClassImpl<" in fname or "RuntimeClass<" in fname:
            info = decode_wrl_runtime_class(fname, func.mangled_name or "")
            if not info:
                continue

            cls_name = info.class_name
            if class_filter and class_filter.lower() not in cls_name.lower():
                continue

            cls = _get_class(cls_name)
            cls.runtime_class_flags = info.runtime_class_flags
            cls.supports_weak_ref = info.weak_reference_support
            cls.has_ftm = info.has_ftm_base

            for iface in info.interfaces:
                if iface not in cls.interfaces:
                    cls.interfaces.append(iface)
                cls.evidence.setdefault(iface, [])
                if "wrl_template" not in cls.evidence[iface]:
                    cls.evidence[iface].append("wrl_template")

            # FtmBase implies IMarshal
            if info.has_ftm_base:
                if "IMarshal" not in cls.interfaces:
                    cls.interfaces.append("IMarshal")
                cls.evidence.setdefault("IMarshal", [])
                if "ftm_base" not in cls.evidence["IMarshal"]:
                    cls.evidence["IMarshal"].append("ftm_base")

    # --- Pass 2: QI/AddRef/Release and mangled name analysis ---
    for func in all_functions:
        fname = func.function_name or ""
        mangled = func.mangled_name or ""
        fid = func.function_id

        if not mangled:
            continue

        parsed = parse_com_class_from_mangled(mangled)
        if not parsed:
            continue

        cls_name = parsed["class_name"]
        if class_filter and class_filter.lower() not in cls_name.lower():
            continue

        # Classify IUnknown methods
        method_type = classify_iunknown_method(fname)
        if method_type:
            cls = _get_class(cls_name)
            if method_type == "QueryInterface":
                if fid not in cls.qi_function_ids:
                    cls.qi_function_ids.append(fid)
                # Ensure IUnknown is in interface list
                if "IUnknown" not in cls.interfaces:
                    cls.interfaces.append("IUnknown")
                cls.evidence.setdefault("IUnknown", [])
                if "inherent" not in cls.evidence["IUnknown"]:
                    cls.evidence["IUnknown"].append("inherent")

                # --- Scan QI decompiled code for GUID comparisons ---
                _scan_qi_for_interfaces(func, cls)

            elif method_type == "AddRef":
                if fid not in cls.addref_function_ids:
                    cls.addref_function_ids.append(fid)
            elif method_type == "Release":
                if fid not in cls.release_function_ids:
                    cls.release_function_ids.append(fid)
        else:
            # Regular method -- track for class membership
            if parsed["role"] in ("method", "constructor", "destructor", "vdel_destructor"):
                cls = _get_class(cls_name)
                if fid not in cls.other_method_ids:
                    cls.other_method_ids.append(fid)

    # --- Pass 3: VTable context analysis ---
    seen_skeletons: set[str] = set()
    for func in all_functions:
        vtable_ctx = parse_json_safe(func.vtable_contexts)
        if not vtable_ctx or not isinstance(vtable_ctx, list):
            continue

        for entry in vtable_ctx:
            if not isinstance(entry, dict):
                continue
            for skeleton in entry.get("reconstructed_classes", []):
                if not isinstance(skeleton, str) or skeleton in seen_skeletons:
                    continue
                seen_skeletons.add(skeleton)

                methods = parse_vtable_methods(skeleton)
                if not methods:
                    continue

                # Extract class name from skeleton first
                class_match = re.search(r'class\s+(?:[\w]+\s+)?([\w:]+(?:<[^>]+>)?)', skeleton)
                vtable_class = class_match.group(1) if class_match else None
                if not vtable_class:
                    continue

                com_info = classify_vtable_as_com(methods, class_name=vtable_class)
                if not com_info["is_com"]:
                    continue

                if class_filter and class_filter.lower() not in vtable_class.lower():
                    continue

                cls = _get_class(vtable_class)
                # Record vtable methods
                start = com_info["custom_method_start_slot"]
                custom = [m for m in methods if m["slot"] >= start]
                for m in custom:
                    if m not in cls.vtable_methods:
                        cls.vtable_methods.append(m)

    # --- Cleanup: Remove empty/noise classes ---
    # Only keep classes that have at least one of: QI impl, WRL info, or vtable methods
    filtered_classes = {}
    for name, cls in classes.items():
        has_com_evidence = (
            cls.qi_function_ids
            or cls.runtime_class_flags is not None
            or cls.vtable_methods
            or len(cls.interfaces) > 1  # More than just IUnknown
        )
        if has_com_evidence:
            filtered_classes[name] = cls

    # Summary
    summary = {
        "total_com_classes": len(filtered_classes),
        "total_interfaces_discovered": len(set(
            iface for cls in filtered_classes.values() for iface in cls.interfaces
        )),
        "classes_with_qi": sum(1 for c in filtered_classes.values() if c.qi_function_ids),
        "classes_with_wrl_info": sum(
            1 for c in filtered_classes.values() if c.runtime_class_flags is not None
        ),
        "classes_with_vtable_methods": sum(
            1 for c in filtered_classes.values() if c.vtable_methods
        ),
        "classes_with_ftm": sum(1 for c in filtered_classes.values() if c.has_ftm),
        "classes_with_weak_ref": sum(1 for c in filtered_classes.values() if c.supports_weak_ref),
    }

    return {
        "module": module_name,
        "summary": summary,
        "class_interface_map": {
            name: cls.to_dict()
            for name, cls in sorted(filtered_classes.items())
        },
    }


def _scan_qi_for_interfaces(func, cls: COMClassInfo) -> None:
    """Scan a QueryInterface implementation's decompiled code for GUID comparisons.

    Detects interface IIDs from inline GUID constants and IsEqualGUID calls.
    """
    code = func.decompiled_code or ""
    if not code:
        return

    # Look for GUID patterns in the decompiled code
    guids = find_guids_in_text(code)
    for guid in guids:
        iid_name = resolve_guid_name(guid)
        if iid_name:
            # Convert IID_IFoo to IFoo
            iface_name = iid_name.replace("IID_", "")
            if iface_name not in cls.interfaces:
                cls.interfaces.append(iface_name)
            cls.evidence.setdefault(iface_name, [])
            if "qi_guid_comparison" not in cls.evidence[iface_name]:
                cls.evidence[iface_name].append("qi_guid_comparison")

    # Look for IsEqualGUID or memcmp patterns with known IID references
    # Pattern: IsEqualGUID(riid, &IID_IFoo) or comparison against known constants
    iid_refs = re.findall(r'IID_(\w+)', code)
    for iid_ref in iid_refs:
        if iid_ref not in cls.interfaces:
            cls.interfaces.append(iid_ref)
        cls.evidence.setdefault(iid_ref, [])
        if "qi_iid_reference" not in cls.evidence[iid_ref]:
            cls.evidence[iid_ref].append("qi_iid_reference")

    # Also check string literals for IID references
    strings = parse_json_safe(func.string_literals)
    if strings and isinstance(strings, list):
        for s in strings:
            if isinstance(s, str) and ("IID" in s or "CLSID" in s):
                guids_in_str = find_guids_in_text(s)
                for guid in guids_in_str:
                    iid_name = resolve_guid_name(guid)
                    if iid_name:
                        iface_name = iid_name.replace("IID_", "")
                        if iface_name not in cls.interfaces:
                            cls.interfaces.append(iface_name)
                        cls.evidence.setdefault(iface_name, [])
                        if "string_literal" not in cls.evidence[iface_name]:
                            cls.evidence[iface_name].append("string_literal")


def print_text_map(data: dict) -> None:
    """Print human-readable class-to-interface mapping."""
    s = data["summary"]
    print(f"{'=' * 80}")
    print(f"  CLASS-TO-INTERFACE MAP: {data['module']}")
    print(f"{'=' * 80}")
    print()
    print(f"  COM classes found:           {s['total_com_classes']}")
    print(f"  Total interfaces discovered: {s['total_interfaces_discovered']}")
    print(f"  Classes with QI impl:        {s['classes_with_qi']}")
    print(f"  Classes with WRL info:       {s['classes_with_wrl_info']}")
    print(f"  Classes with vtable methods: {s['classes_with_vtable_methods']}")
    print(f"  Classes with FtmBase:        {s['classes_with_ftm']}")
    print(f"  Classes with weak ref:       {s['classes_with_weak_ref']}")
    print()

    for name, cls_data in data["class_interface_map"].items():
        print(f"  {'=' * 76}")
        print(f"  CLASS: {name}")
        print(f"  {'=' * 76}")

        # Flags
        if cls_data.get("runtime_class_flags") is not None:
            from _common import RUNTIME_CLASS_FLAGS
            flags = cls_data["runtime_class_flags"]
            meaning = RUNTIME_CLASS_FLAGS.get(flags, f"Unknown({flags})")
            print(f"    RuntimeClassFlags: {flags} ({meaning})")
        if cls_data.get("has_ftm"):
            print(f"    FtmBase: Yes (free-threaded marshalling)")
        if cls_data.get("supports_weak_ref"):
            print(f"    Weak reference support: Yes")

        # QI/AddRef/Release function IDs
        if cls_data.get("qi_function_ids"):
            print(f"    QI function IDs:      {cls_data['qi_function_ids']}")
        if cls_data.get("addref_function_ids"):
            print(f"    AddRef function IDs:  {cls_data['addref_function_ids']}")
        if cls_data.get("release_function_ids"):
            print(f"    Release function IDs: {cls_data['release_function_ids']}")
        other_count = len(cls_data.get("other_method_ids", []))
        if other_count > 0:
            print(f"    Other methods:        {other_count} function(s)")

        # Interfaces
        if cls_data.get("interfaces"):
            print(f"\n    INTERFACES ({len(cls_data['interfaces'])}):")
            for iface in cls_data["interfaces"]:
                evidence = cls_data.get("evidence", {}).get(iface, [])
                ev_str = ", ".join(evidence) if evidence else "inferred"
                display_iface = iface if len(iface) <= 55 else iface[:52] + "..."
                print(f"      {display_iface:<55}  [{ev_str}]")

        # VTable methods
        if cls_data.get("vtable_methods"):
            print(f"\n    VTABLE METHODS ({len(cls_data['vtable_methods'])}):")
            for m in cls_data["vtable_methods"]:
                print(f"      [{m['slot']}] {m['offset_hex']}: {m['method_name']}")

        print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Map which interfaces each COM class implements.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("db_path", help="Path to the individual analysis DB")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--class", dest="class_filter", default="",
                        help="Filter to classes matching this name pattern")
    args = safe_parse_args(parser)

    db_path = resolve_db_path(args.db_path)
    with db_error_handler(db_path, "class-interface mapping"):
        data = map_interfaces(db_path, class_filter=args.class_filter)

    if args.json:
        emit_json(data)
    else:
        print_text_map(data)


if __name__ == "__main__":
    main()
