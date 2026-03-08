#!/usr/bin/env python3
"""List COM methods for a module or CLSID with optional pseudo-IDL.

Usage:
    python enumerate_com_methods.py wuapi.dll --json
    python enumerate_com_methods.py bfe18e9c-6d87-4450-b37c-e02f0b373803 --show-pseudo-idl
    python enumerate_com_methods.py wuapi.dll --interface IUpdate3 --json
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT_DIR))

from _common import emit_json, is_clsid, require_com_index
from helpers.errors import safe_parse_args


def main() -> None:
    parser = argparse.ArgumentParser(description="List COM methods.")
    parser.add_argument("module_or_clsid", help="Module name or CLSID GUID")
    parser.add_argument("--interface", help="Filter to a specific interface name (substring match)")
    parser.add_argument("--show-pseudo-idl", action="store_true", help="Show pseudo-IDL definitions")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = safe_parse_args(parser)

    idx = require_com_index()
    target = args.module_or_clsid

    if is_clsid(target):
        srv = idx.get_server_by_clsid(target)
        servers = [srv] if srv else []
        scope = "clsid"
    else:
        servers = idx.get_servers_for_module(target)
        scope = "module"

    all_interfaces = []
    for s in servers:
        for iface in s.interfaces:
            if args.interface and args.interface.lower() not in iface.name.lower():
                continue
            all_interfaces.append((s, iface))

    if args.json:
        iface_dicts = []
        for s, iface in all_interfaces:
            d = iface.to_dict()
            d["server_name"] = s.name
            d["clsid"] = s.clsid
            if not args.show_pseudo_idl:
                d.pop("pseudo_idl", None)
            iface_dicts.append(d)
        emit_json({
            "target": target,
            "scope": scope,
            "total_interfaces": len(all_interfaces),
            "total_methods": sum(iface.method_count for _, iface in all_interfaces),
            "interfaces": iface_dicts,
        })
        return

    if not all_interfaces:
        print(f"No COM interfaces found for: {target}")
        return

    total_methods = sum(iface.method_count for _, iface in all_interfaces)
    print(f"{'=' * 80}")
    print(f"COM METHODS: {target} ({scope})")
    print(f"{'=' * 80}")
    print(f"  Interfaces: {len(all_interfaces)}")
    print(f"  Methods:    {total_methods}")
    print()

    for s, iface in all_interfaces:
        print(f"  Interface: {iface.name}")
        if iface.guid:
            print(f"    GUID: {iface.guid}")
        print(f"    Server: {s.name}  (CLSID: {s.clsid})")
        print(f"    Methods ({iface.method_count}):")
        for m in iface.methods:
            print(f"      [{m.access}] {m.short_name}  ({m.binary_name})")

        if args.show_pseudo_idl and iface.pseudo_idl:
            print(f"    Pseudo-IDL:")
            for line in iface.pseudo_idl:
                print(f"      {line}")
        print()


if __name__ == "__main__":
    main()
