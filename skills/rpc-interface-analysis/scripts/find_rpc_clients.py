#!/usr/bin/env python3
"""Find all modules that implement or consume a given RPC interface UUID.

Usage:
    python find_rpc_clients.py <interface_uuid>
    python find_rpc_clients.py 0497b57d-2e66-424f-a0c6-157cd5d41700 --json
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
    parser = argparse.ArgumentParser(description="Find modules for an RPC interface UUID.")
    parser.add_argument("uuid", help="RPC interface UUID")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = safe_parse_args(parser)

    idx = require_rpc_index()
    ifaces = idx._by_uuid.get(args.uuid.lower(), [])

    servers = [i for i in ifaces if not i.is_client]
    clients = [i for i in ifaces if i.is_client]

    stub = idx.get_stub_for_interface(args.uuid) if idx.stubs_loaded else None
    stub_fallback = not clients and stub is not None

    if args.json:
        result = {
            "interface_uuid": args.uuid,
            "server_count": len(servers),
            "client_count": len(clients),
            "servers": [i.to_dict() for i in servers],
            "clients": [i.to_dict() for i in clients],
        }
        if stub_fallback:
            result["stub_client"] = {
                "source_executable": stub.source_executable,
                "procedure_count": stub.procedure_count,
                "note": "No runtime client binaries found; data derived from C# client stub.",
            }
        emit_json(result)
        return

    print(f"{'=' * 80}")
    print(f"RPC INTERFACE: {args.uuid}")
    print(f"{'=' * 80}")

    if not ifaces and not stub_fallback:
        print(f"  No modules found for this interface UUID.")
        return

    if servers:
        print(f"\n  SERVER implementations ({len(servers)}):")
        for s in servers:
            svc = f" [{s.service_name}]" if s.service_name else ""
            proto = ", ".join(sorted(s.protocols)) or "none"
            print(f"    - {s.binary_name}{svc}  protocols: {proto}  procs: {s.procedure_count}")
            for p in s.procedure_names[:5]:
                print(f"        {p}")
            if len(s.procedure_names) > 5:
                print(f"        ... +{len(s.procedure_names) - 5} more")

    if clients:
        print(f"\n  CLIENT consumers ({len(clients)}):")
        for c in clients:
            print(f"    - {c.binary_name}")
    elif stub_fallback:
        print(f"\n  CLIENT consumers (from stub data):")
        print(f"    - Source executable: {stub.source_executable}")
        print(f"      Procedures in stub: {stub.procedure_count}")
        print(f"      (No runtime client binaries found; data derived from C# client stub)")

    print()


if __name__ == "__main__":
    main()
