#!/usr/bin/env python3
"""Risk-ranked RPC attack surface, per module or system-wide.

Usage:
    python map_rpc_surface.py appinfo.dll --json
    python map_rpc_surface.py --system-wide --top 20
    python map_rpc_surface.py --system-wide --tier critical
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT_DIR))

from _common import RpcInterface, emit_json, emit_json_list, require_rpc_index
from helpers.errors import safe_parse_args

_TIER_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _sort_key(iface: RpcInterface) -> tuple:
    return (
        _TIER_ORDER.get(iface.risk_tier, 99),
        -iface.procedure_count,
        not iface.is_service_running,
        iface.binary_name.lower(),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Risk-ranked RPC attack surface.")
    parser.add_argument("module", nargs="?", help="Module name (omit for --system-wide)")
    parser.add_argument("--system-wide", action="store_true", help="Rank all modules")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--top", type=int, default=0, help="Show top N interfaces")
    parser.add_argument("--tier", type=str.lower, choices=["critical", "high", "medium", "low"],
                        help="Filter to a specific risk tier")
    parser.add_argument("--servers-only", action="store_true", help="Exclude client interfaces")
    parser.add_argument("--with-blast-radius", action="store_true",
                        help="Include blast-radius (co-hosted sibling) data per interface")
    args = safe_parse_args(parser)

    idx = require_rpc_index()

    if args.module and not args.system_wide:
        ifaces = idx.get_interfaces_for_module(args.module)
    else:
        ifaces = list(idx.get_servers() if args.servers_only else idx._interfaces)

    if args.tier:
        ifaces = [i for i in ifaces if i.risk_tier == args.tier]
    if args.servers_only:
        ifaces = [i for i in ifaces if not i.is_client]

    ifaces.sort(key=_sort_key)

    if args.top > 0:
        ifaces = ifaces[:args.top]

    if args.json:
        label = args.module or "system_wide"
        iface_dicts = []
        for iface in ifaces:
            d = iface.to_dict()
            if args.with_blast_radius:
                d["blast_radius"] = idx.compute_blast_radius(iface.interface_id)
            iface_dicts.append(d)
        emit_json({
            "scope": label,
            "total_interfaces": len(ifaces),
            "by_tier": {
                t: sum(1 for i in ifaces if i.risk_tier == t)
                for t in ("critical", "high", "medium", "low")
            },
            "interfaces": iface_dicts,
        })
        return

    scope = args.module or "SYSTEM-WIDE"
    print(f"{'=' * 90}")
    print(f"RPC ATTACK SURFACE: {scope} ({len(ifaces)} interfaces)")
    print(f"{'=' * 90}")

    tier_counts = {}
    for i in ifaces:
        tier_counts[i.risk_tier] = tier_counts.get(i.risk_tier, 0) + 1
    for tier in ("critical", "high", "medium", "low"):
        cnt = tier_counts.get(tier, 0)
        if cnt:
            print(f"  {tier.upper():>8}: {cnt}")
    print()

    print(f"{'Rank':>4}  {'Risk':>8}  {'Procs':>5}  {'Service':<25}  {'Binary':<30}  Interface UUID")
    print(f"{'-' * 4}  {'-' * 8}  {'-' * 5}  {'-' * 25}  {'-' * 30}  {'-' * 36}")

    for rank, iface in enumerate(ifaces, 1):
        svc = iface.service_name or "-"
        print(
            f"#{rank:<3}  {iface.risk_tier.upper():>8}  "
            f"{iface.procedure_count:>5}  "
            f"{svc:<25}  "
            f"{iface.binary_name:<30}  "
            f"{iface.interface_id}"
        )
        if args.with_blast_radius:
            br = idx.compute_blast_radius(iface.interface_id)
            if br.get("found"):
                print(
                    f"      Blast radius: {br['sibling_count']} siblings, "
                    f"{br['total_procedures']} total procs, "
                    f"protocols: {', '.join(br['combined_protocols']) or 'none'}"
                )


if __name__ == "__main__":
    main()
