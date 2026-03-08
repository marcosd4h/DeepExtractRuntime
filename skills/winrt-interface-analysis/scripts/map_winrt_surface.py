#!/usr/bin/env python3
"""Risk-ranked WinRT attack surface, per module or system-wide.

Usage:
    python map_winrt_surface.py appinfo.dll --json
    python map_winrt_surface.py --system-wide --top 20
    python map_winrt_surface.py --system-wide --tier critical --json
    python map_winrt_surface.py --privileged-only --context medium_il_privileged --json
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT_DIR))

from _common import WinrtServer, emit_json, parse_context, require_winrt_index
from helpers.errors import safe_parse_args

_TIER_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _sort_key(server: WinrtServer) -> tuple:
    return (
        _TIER_ORDER.get(server.best_risk_tier, 99),
        -server.method_count,
        not server.runs_as_system,
        server.name.lower(),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Risk-ranked WinRT attack surface.")
    parser.add_argument("module", nargs="?", help="Module name (omit for --system-wide)")
    parser.add_argument("--system-wide", action="store_true", help="Rank all servers")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--top", type=int, default=0, help="Show top N servers")
    parser.add_argument("--tier", type=str.lower, choices=["critical", "high", "medium", "low"],
                        help="Filter to a specific risk tier")
    parser.add_argument("--context", help="Filter by access context")
    parser.add_argument("--privileged-only", action="store_true",
                        help="Only show servers on privileged processes")
    args = safe_parse_args(parser)

    idx = require_winrt_index()
    ctx = parse_context(args.context)

    if args.module and not args.system_wide:
        servers = idx.get_servers_for_module(args.module)
    elif args.privileged_only:
        caller_il = ctx.caller_il if ctx else "medium"
        servers = idx.get_privileged_surface(caller_il)
    else:
        servers = list(idx._servers)

    if args.tier:
        servers = [s for s in servers if s.best_risk_tier == args.tier]

    servers.sort(key=_sort_key)

    if args.top > 0:
        servers = servers[:args.top]

    if args.json:
        label = args.module or "system_wide"
        srv_dicts = []
        for srv in servers:
            d = srv.to_dict()
            if ctx is not None:
                d["risk_tier"] = srv.risk_tier(ctx)
            srv_dicts.append(d)
        emit_json({
            "scope": label,
            "total_servers": len(servers),
            "by_tier": {
                t: sum(1 for s in servers if s.best_risk_tier == t)
                for t in ("critical", "high", "medium", "low")
            },
            "servers": srv_dicts,
        })
        return

    scope = args.module or "SYSTEM-WIDE"
    print(f"{'=' * 90}")
    print(f"WINRT ATTACK SURFACE: {scope} ({len(servers)} servers)")
    print(f"{'=' * 90}")

    tier_counts: dict[str, int] = {}
    for s in servers:
        t = s.best_risk_tier
        tier_counts[t] = tier_counts.get(t, 0) + 1
    for tier in ("critical", "high", "medium", "low"):
        cnt = tier_counts.get(tier, 0)
        if cnt:
            print(f"  {tier.upper():>8}: {cnt}")
    print()

    print(f"{'Rank':>4}  {'Risk':>8}  {'Methods':>7}  {'Activation':<14}  {'Identity':<25}  Class Name")
    print(f"{'-' * 4}  {'-' * 8}  {'-' * 7}  {'-' * 14}  {'-' * 25}  {'-' * 40}")

    for rank, srv in enumerate(servers, 1):
        identity = srv.server_identity or "-"
        print(
            f"#{rank:<3}  {srv.best_risk_tier.upper():>8}  "
            f"{srv.method_count:>7}  "
            f"{srv.activation_type:<14}  "
            f"{identity:<25}  "
            f"{srv.name}"
        )


if __name__ == "__main__":
    main()
