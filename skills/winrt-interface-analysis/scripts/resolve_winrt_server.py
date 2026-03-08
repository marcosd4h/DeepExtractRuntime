#!/usr/bin/env python3
"""List all WinRT server classes hosted in a module with full metadata.

Usage:
    python resolve_winrt_server.py <module_name>
    python resolve_winrt_server.py TaskFlowDataEngine.dll --json
    python resolve_winrt_server.py TaskFlowDataEngine.dll --context medium_il_privileged --json
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT_DIR))

from _common import emit_json, parse_context, require_winrt_index
from helpers.errors import safe_parse_args


def main() -> None:
    parser = argparse.ArgumentParser(description="List WinRT servers for a module.")
    parser.add_argument("module", help="Module name (e.g. TaskFlowDataEngine.dll)")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--context", help="Filter by access context")
    args = safe_parse_args(parser)

    idx = require_winrt_index()
    servers = idx.get_servers_for_module(args.module)
    ctx = parse_context(args.context)

    if args.json:
        srv_dicts = []
        for srv in servers:
            d = srv.to_dict()
            if ctx is not None:
                d["risk_tier"] = srv.risk_tier(ctx)
            srv_dicts.append(d)
        emit_json({
            "module": args.module,
            "server_count": len(servers),
            "total_methods": sum(s.method_count for s in servers),
            "servers": srv_dicts,
        })
        return

    if not servers:
        print(f"No WinRT servers found for module: {args.module}")
        return

    print(f"{'=' * 80}")
    print(f"WINRT SERVERS: {args.module}")
    print(f"{'=' * 80}")
    print(f"  Server classes: {len(servers)}")
    print(f"  Total methods:  {sum(s.method_count for s in servers)}")
    print()

    for i, srv in enumerate(servers, 1):
        tier = srv.risk_tier(ctx) if ctx else srv.best_risk_tier
        print(f"  [{i}] {srv.name}")
        print(f"      Risk tier:       {tier.upper()}")
        print(f"      Activation:      {srv.activation_type}")
        print(f"      Trust level:     {srv.trust_level}")
        if srv.server_identity:
            print(f"      Server identity: {srv.server_identity}")
        if srv.service_name:
            print(f"      Service:         {srv.service_name}")
        print(f"      Interfaces:      {srv.interface_count}")
        print(f"      Methods:         {srv.method_count}")
        contexts = ", ".join(str(c) for c in sorted(srv.access_contexts, key=str))
        print(f"      Access contexts: {contexts}")
        for iface in srv.interfaces:
            print(f"        Interface: {iface.name}")
            if iface.guid:
                print(f"          GUID: {iface.guid}")
            for m in iface.methods[:5]:
                print(f"          - {m.short_name}")
            if len(iface.methods) > 5:
                print(f"          ... and {len(iface.methods) - 5} more")
        print()


if __name__ == "__main__":
    main()
