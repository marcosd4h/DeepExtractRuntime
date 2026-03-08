#!/usr/bin/env python3
"""Find COM privilege escalation targets.

Focuses on medium-IL reachable servers running as SYSTEM/privileged,
cross-referencing with method semantics for highest-value targets.

Usage:
    python find_com_privesc.py --json
    python find_com_privesc.py --context medium_il_privileged --top 20 --json
    python find_com_privesc.py --include-uac --json
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT_DIR))

from _common import ComServer, emit_json, parse_context, require_com_index
from helpers.errors import safe_parse_args

_HIGH_VALUE_PATTERNS = re.compile(
    r"(?i)(launch|execute|create|write|delete|set|put|install|"
    r"update|register|config|policy|shutdown|reboot|crypt|"
    r"impersonat|token|credential|elevat)"
)


def _score_server(srv: ComServer) -> float:
    """Heuristic score for EoP attractiveness (0.0--1.0)."""
    score = 0.0
    if srv.runs_as_system:
        score += 0.30
    if srv.is_out_of_process:
        score += 0.15
    if srv.can_elevate or srv.auto_elevation:
        score += 0.15
    if srv.has_permissive_launch:
        score += 0.10
    if srv.has_permissive_access:
        score += 0.10
    if srv.supports_remote_activation:
        score += 0.05
    if srv.trusted_marshaller:
        score += 0.05

    high_value_count = sum(
        1 for m in srv.methods_flat if _HIGH_VALUE_PATTERNS.search(m.short_name)
    )
    method_score = min(high_value_count / max(srv.method_count, 1), 1.0) * 0.10
    score += method_score
    return min(score, 1.0)


def main() -> None:
    parser = argparse.ArgumentParser(description="Find COM privilege escalation targets.")
    parser.add_argument("--context", default="medium_il_privileged",
                        help="Access context (default: medium_il_privileged)")
    parser.add_argument("--top", type=int, default=0, help="Show top N targets")
    parser.add_argument("--include-uac", action="store_true",
                        help="Include CanElevate/AutoElevation servers (UAC bypass candidates)")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = safe_parse_args(parser)

    idx = require_com_index()
    ctx = parse_context(args.context)
    caller_il = ctx.caller_il if ctx else "medium"

    candidates = idx.get_privileged_surface(caller_il)

    scored: list[tuple[float, ComServer]] = []
    for srv in candidates:
        if srv.is_out_of_process or (args.include_uac and (srv.can_elevate or srv.auto_elevation)):
            s = _score_server(srv)
            scored.append((s, srv))

    scored.sort(key=lambda x: -x[0])

    if args.top > 0:
        scored = scored[:args.top]

    if args.json:
        targets = []
        for score, srv in scored:
            d = srv.to_dict()
            d["privesc_score"] = round(score, 3)
            d["high_value_methods"] = [
                m.to_dict() for m in srv.methods_flat
                if _HIGH_VALUE_PATTERNS.search(m.short_name)
            ]
            targets.append(d)
        emit_json({
            "caller_il": caller_il,
            "total_candidates": len(candidates),
            "scored_targets": len(scored),
            "targets": targets,
        })
        return

    print(f"{'=' * 90}")
    print(f"COM PRIVILEGE ESCALATION TARGETS (caller: {caller_il}-IL)")
    print(f"{'=' * 90}")
    print(f"  Candidates:      {len(candidates)}")
    print(f"  Scored targets:  {len(scored)}")
    print()

    print(f"{'Rank':>4}  {'Score':>5}  {'Methods':>7}  {'Service':<20}  Name")
    print(f"{'-' * 4}  {'-' * 5}  {'-' * 7}  {'-' * 20}  {'-' * 40}")

    for rank, (score, srv) in enumerate(scored, 1):
        svc = srv.service_name or "-"
        print(f"#{rank:<3}  {score:.2f}   {srv.method_count:>7}  {svc:<20}  {srv.name}")

        high_value = [m for m in srv.methods_flat if _HIGH_VALUE_PATTERNS.search(m.short_name)]
        if high_value:
            for m in high_value[:3]:
                print(f"        -> {m.short_name} [{m.interface_name}]")
            if len(high_value) > 3:
                print(f"        ... and {len(high_value) - 3} more high-value methods")
        print()


if __name__ == "__main__":
    main()
