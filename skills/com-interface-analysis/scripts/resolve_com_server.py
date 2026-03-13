#!/usr/bin/env python3
"""List all COM servers hosted in a module or look up by CLSID.

Usage:
    python resolve_com_server.py wuapi.dll --json
    python resolve_com_server.py bfe18e9c-6d87-4450-b37c-e02f0b373803 --json
    python resolve_com_server.py wbengine.exe --context medium_il_privileged --json
    python resolve_com_server.py --workspace --json
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT_DIR))

from _common import emit_json, is_clsid, parse_context, require_com_index
from helpers.errors import safe_parse_args, emit_error


def _handle_workspace(as_json: bool) -> None:
    """Show workspace modules that implement COM servers."""
    from helpers.ipc_workspace import discover_workspace_ipc_servers
    result = discover_workspace_ipc_servers(ipc_types=["com"])
    if as_json:
        emit_json(result)
    else:
        com = result.get("com", {})
        count = result.get("summary", {}).get("com_modules", 0)
        print(f"\n=== Workspace COM Servers ({count} module(s)) ===\n")
        if not com:
            print("  No workspace modules implement COM servers.\n")
            return
        for module, info in sorted(com.items()):
            print(f"  {module}: {info['server_count']} server(s)")
            for srv in info["servers"]:
                ctxs = ", ".join(srv["access_contexts"])
                print(f"    {srv['clsid']} {srv['name'] or '(unnamed)'}  [{ctxs}]")
        print()


def main() -> None:
    parser = argparse.ArgumentParser(description="List COM servers for a module or CLSID.")
    parser.add_argument("module_or_clsid", nargs="?", help="Module name or CLSID GUID")
    parser.add_argument("--workspace", action="store_true",
                        help="Show workspace modules that implement COM servers")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--context", help="Filter by access context")
    args = safe_parse_args(parser)

    if args.workspace:
        _handle_workspace(args.json)
        return

    if not args.module_or_clsid:
        emit_error("Provide a module name, CLSID, or use --workspace", "INVALID_ARGS")

    idx = require_com_index()
    ctx = parse_context(args.context)
    target = args.module_or_clsid

    if is_clsid(target):
        srv = idx.get_server_by_clsid(target)
        servers = [srv] if srv else []
        scope = "clsid"
    else:
        servers = idx.get_servers_for_module(target)
        scope = "module"

    if args.json:
        srv_dicts = []
        for srv in servers:
            d = srv.to_dict()
            if ctx is not None:
                d["risk_tier"] = srv.risk_tier(ctx)
            srv_dicts.append(d)
        emit_json({
            "target": target,
            "scope": scope,
            "server_count": len(servers),
            "total_methods": sum(s.method_count for s in servers),
            "servers": srv_dicts,
        })
        return

    if not servers:
        print(f"No COM servers found for: {target}")
        return

    print(f"{'=' * 80}")
    print(f"COM SERVERS: {target} ({scope})")
    print(f"{'=' * 80}")
    print(f"  Server count:  {len(servers)}")
    print(f"  Total methods: {sum(s.method_count for s in servers)}")
    print()

    for i, srv in enumerate(servers, 1):
        tier = srv.risk_tier(ctx) if ctx else srv.best_risk_tier
        print(f"  [{i}] {srv.name}  (CLSID: {srv.clsid})")
        print(f"      Risk tier:         {tier.upper()}")
        print(f"      Server type:       {srv.server_type}")
        print(f"      Binary:            {srv.hosting_binary}")
        if srv.service_name:
            print(f"      Service:           {srv.service_name}")
        if srv.service_user:
            print(f"      Service user:      {srv.service_user}")
        if srv.run_as:
            print(f"      RunAs:             {srv.run_as}")
        print(f"      Can elevate:       {srv.can_elevate}")
        print(f"      Auto elevation:    {srv.auto_elevation}")
        print(f"      Remote activation: {srv.supports_remote_activation}")
        print(f"      Trusted marshal:   {srv.trusted_marshaller}")
        print(f"      Interfaces:        {srv.interface_count}")
        print(f"      Methods:           {srv.method_count}")
        contexts = ", ".join(str(c) for c in sorted(srv.access_contexts, key=str))
        print(f"      Access contexts:   {contexts}")
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
