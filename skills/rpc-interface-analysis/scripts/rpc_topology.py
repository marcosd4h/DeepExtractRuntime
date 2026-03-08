#!/usr/bin/env python3
"""Build client-server RPC topology from runtime and stub data.

Combines pipe name and ALPC endpoint data from the RPC index, stub metadata
(source executables), and service grouping to produce a system-wide or
per-module topology view of RPC communication channels.

Usage:
    python rpc_topology.py --json
    python rpc_topology.py appinfo.dll
    python rpc_topology.py --top 20 --json
"""

from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

_SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT_DIR))

from _common import emit_json, require_rpc_index
from helpers.errors import safe_parse_args


def _build_topology(idx, module_filter: str | None = None) -> list[dict[str, Any]]:
    """Build topology entries keyed by interface UUID.

    Each entry describes a server, its transport channels, the service it
    belongs to, and any client binaries that consume the interface (from
    runtime data or stub source_executable fallback).
    """
    topo: dict[str, dict[str, Any]] = {}

    servers = idx.get_servers()
    if module_filter:
        servers = [s for s in servers if s.binary_name.lower() == module_filter.lower()]

    for iface in servers:
        uid = iface.interface_id.lower()
        if uid in topo:
            topo[uid]["server_binaries"].add(iface.binary_name)
            topo[uid]["protocols"].update(iface.protocols)
            topo[uid]["pipe_names"].update(iface.pipe_names)
            topo[uid]["alpc_endpoints"].update(iface.alpc_endpoints)
            for port in iface.tcp_ports:
                topo[uid]["tcp_ports"].add(port)
            if iface.service_name:
                topo[uid]["services"].add(iface.service_name)
            continue

        topo[uid] = {
            "interface_id": iface.interface_id,
            "interface_version": iface.interface_version,
            "risk_tier": iface.risk_tier,
            "procedure_count": iface.procedure_count,
            "server_binaries": {iface.binary_name},
            "protocols": set(iface.protocols),
            "pipe_names": set(iface.pipe_names),
            "alpc_endpoints": set(iface.alpc_endpoints),
            "tcp_ports": set(iface.tcp_ports),
            "services": {iface.service_name} if iface.service_name else set(),
            "client_binaries": set(),
            "stub_source": "",
        }

    clients = idx.get_clients()
    if module_filter:
        clients = [c for c in clients if c.binary_name.lower() == module_filter.lower()]
    for client in clients:
        uid = client.interface_id.lower()
        if uid in topo:
            topo[uid]["client_binaries"].add(client.binary_name)

    if idx.stubs_loaded:
        for uid, entry in topo.items():
            stub = idx.get_stub_for_interface(uid)
            if stub and stub.source_executable:
                entry["stub_source"] = stub.source_executable
                if not entry["client_binaries"]:
                    entry["client_binaries"].add(stub.source_executable)

    return _serialize_topology(topo)


def _serialize_topology(topo: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert internal sets to sorted lists for output."""
    results = []
    for entry in topo.values():
        results.append({
            "interface_id": entry["interface_id"],
            "interface_version": entry["interface_version"],
            "risk_tier": entry["risk_tier"],
            "procedure_count": entry["procedure_count"],
            "server_binaries": sorted(entry["server_binaries"]),
            "client_binaries": sorted(entry["client_binaries"]),
            "services": sorted(entry["services"]),
            "protocols": sorted(entry["protocols"]),
            "pipe_names": sorted(entry["pipe_names"]),
            "alpc_endpoints": sorted(entry["alpc_endpoints"]),
            "tcp_ports": sorted(entry["tcp_ports"]),
            "stub_source": entry["stub_source"],
        })
    tier_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    results.sort(key=lambda e: (tier_order.get(e["risk_tier"], 99), -e["procedure_count"]))
    return results


def _group_by_service(entries: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Group topology entries by service name for summary display."""
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for entry in entries:
        svcs = entry.get("services") or ["(no service)"]
        for svc in svcs:
            groups[svc].append(entry)
    return dict(groups)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build RPC client-server topology from runtime + stub data.",
    )
    parser.add_argument("module", nargs="?", help="Module name to scope (omit for system-wide)")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--top", type=int, default=0, help="Show top N entries by risk")
    args = safe_parse_args(parser)

    idx = require_rpc_index()
    entries = _build_topology(idx, module_filter=args.module)

    if args.top > 0:
        entries = entries[:args.top]

    if args.json:
        service_groups = _group_by_service(entries)
        emit_json({
            "scope": args.module or "system_wide",
            "total_channels": len(entries),
            "with_clients": sum(1 for e in entries if e["client_binaries"]),
            "with_pipes": sum(1 for e in entries if e["pipe_names"]),
            "with_alpc": sum(1 for e in entries if e["alpc_endpoints"]),
            "with_tcp": sum(1 for e in entries if e["tcp_ports"]),
            "entries": entries,
            "by_service": {
                svc: [e["interface_id"] for e in group]
                for svc, group in service_groups.items()
            },
        })
        return

    scope = args.module or "SYSTEM-WIDE"
    print(f"{'=' * 100}")
    print(f"RPC TOPOLOGY: {scope} ({len(entries)} channels)")
    print(f"{'=' * 100}")

    channels_with_clients = sum(1 for e in entries if e["client_binaries"])
    print(f"  Channels with known clients: {channels_with_clients}/{len(entries)}")
    print(f"  Named-pipe channels: {sum(1 for e in entries if e['pipe_names'])}")
    print(f"  ALPC channels: {sum(1 for e in entries if e['alpc_endpoints'])}")
    print(f"  TCP channels: {sum(1 for e in entries if e['tcp_ports'])}")
    print()

    print(
        f"{'#':>3}  {'Risk':>8}  {'Procs':>5}  "
        f"{'Server':<25}  {'Client':<25}  "
        f"{'Transport':<20}  Interface UUID"
    )
    print(
        f"{'-' * 3}  {'-' * 8}  {'-' * 5}  "
        f"{'-' * 25}  {'-' * 25}  "
        f"{'-' * 20}  {'-' * 36}"
    )

    for rank, entry in enumerate(entries, 1):
        server = ", ".join(entry["server_binaries"][:2]) or "-"
        client = ", ".join(entry["client_binaries"][:2]) or "-"
        transports = []
        if entry["pipe_names"]:
            transports.append(f"pipe:{entry['pipe_names'][0]}")
        if entry["alpc_endpoints"]:
            transports.append(f"alpc:{entry['alpc_endpoints'][0]}")
        if entry["tcp_ports"]:
            transports.append(f"tcp:{entry['tcp_ports'][0]}")
        transport_str = ", ".join(transports) if transports else "-"

        print(
            f"#{rank:<2}  {entry['risk_tier'].upper():>8}  "
            f"{entry['procedure_count']:>5}  "
            f"{server:<25}  {client:<25}  "
            f"{transport_str:<20}  "
            f"{entry['interface_id']}"
        )

    service_groups = _group_by_service(entries)
    if service_groups:
        print(f"\n{'=' * 100}")
        print(f"SERVICE GROUPS")
        print(f"{'=' * 100}")
        for svc, group in sorted(service_groups.items()):
            iface_ids = ", ".join(e["interface_id"][:13] + "..." for e in group[:3])
            suffix = f" +{len(group) - 3} more" if len(group) > 3 else ""
            print(f"  {svc:<30} ({len(group)} interfaces)  {iface_ids}{suffix}")

    print()


if __name__ == "__main__":
    main()
