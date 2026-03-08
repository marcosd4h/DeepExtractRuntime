#!/usr/bin/env python3
"""List all RPC interfaces for a module with full metadata.

Usage:
    python resolve_rpc_interface.py <module_name>
    python resolve_rpc_interface.py appinfo.dll --json
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT_DIR))

from _common import emit_json, require_rpc_index
from helpers.errors import safe_parse_args


def main() -> None:
    parser = argparse.ArgumentParser(description="List RPC interfaces for a module.")
    parser.add_argument("module", help="Module name (e.g. appinfo.dll)")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--with-stubs", action="store_true",
                        help="Include procedure signatures from parsed C# stubs")
    args = safe_parse_args(parser)

    idx = require_rpc_index()
    ifaces = idx.get_interfaces_for_module(args.module)
    procedures = idx.get_procedures_for_module(args.module)

    if args.json:
        iface_dicts = []
        for iface in ifaces:
            d = iface.to_dict()
            if args.with_stubs:
                sigs = idx.get_procedure_signatures(iface.interface_id)
                d["stub_signatures"] = [s.to_dict() for s in sigs] if sigs else []
            iface_dicts.append(d)
        emit_json({
            "module": args.module,
            "interface_count": len(ifaces),
            "total_procedures": len(procedures),
            "interfaces": iface_dicts,
            "all_procedures": procedures,
        })
        return

    if not ifaces:
        print(f"No RPC interfaces found for module: {args.module}")
        return

    print(f"{'=' * 80}")
    print(f"RPC INTERFACES: {args.module}")
    print(f"{'=' * 80}")
    print(f"  Interfaces: {len(ifaces)}")
    print(f"  Total procedures: {len(procedures)}")
    print()

    for i, iface in enumerate(ifaces, 1):
        print(f"  [{i}] Interface {iface.interface_id} v{iface.interface_version}")
        print(f"      Risk tier:   {iface.risk_tier.upper()}")
        print(f"      Protocols:   {', '.join(sorted(iface.protocols)) or 'none'}")
        print(f"      Endpoints:   {len(iface.endpoints)}")
        for ep in iface.endpoints[:3]:
            print(f"                   {ep[:80]}")
        if iface.service_name:
            running = "RUNNING" if iface.is_service_running else "stopped"
            print(f"      Service:     {iface.service_name} ({iface.service_display_name}) [{running}]")
        print(f"      Procedures:  {iface.procedure_count}")
        for proc in iface.procedure_names[:10]:
            print(f"                   - {proc}")
        if len(iface.procedure_names) > 10:
            print(f"                   ... and {len(iface.procedure_names) - 10} more")
        if iface.has_complex_types:
            print(f"      NDR types:   {', '.join(iface.complex_types[:3])}")

        if args.with_stubs:
            sigs = idx.get_procedure_signatures(iface.interface_id)
            if sigs:
                print(f"      Stub signatures ({len(sigs)}):")
                for sig in sigs:
                    params = ", ".join(
                        f"{p.direction} {p.ndr_type} {p.name}"
                        for p in sig.parameters
                    )
                    print(f"        [{sig.opnum:>3}] {sig.return_type} {sig.name}({params})")
        print()


if __name__ == "__main__":
    main()
