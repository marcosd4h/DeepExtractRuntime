#!/usr/bin/env python3
"""Find WinRT privilege escalation targets.

Focuses on medium-IL reachable servers running as SYSTEM/privileged,
cross-referencing with method semantics for highest-value targets.

Usage:
    python find_winrt_privesc.py --json
    python find_winrt_privesc.py --context medium_il_privileged --top 20 --json
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT_DIR))

from _common import WinrtServer, emit_json, parse_context, require_winrt_index
from helpers.errors import safe_parse_args

_HIGH_VALUE_PATTERNS = re.compile(
    r"(?i)(launch|execute|create|write|delete|set|put|install|"
    r"update|register|config|policy|shutdown|reboot|crypt|"
    r"impersonat|token|credential|elevat)"
)


def _score_server(srv: WinrtServer) -> float:
    """Heuristic score for EoP attractiveness (0.0--1.0)."""
    score = 0.0
    if srv.runs_as_system:
        score += 0.30
    if srv.is_out_of_process:
        score += 0.15
    if srv.has_permissive_sddl:
        score += 0.10
    if srv.is_remote_activatable:
        score += 0.05
    if srv.is_base_trust:
        score += 0.05

    method_surface = min(srv.method_count / 20.0, 1.0) * 0.10
    score += method_surface

    high_value_count = sum(
        1 for m in srv.methods_flat if _HIGH_VALUE_PATTERNS.search(m.short_name)
    )
    high_value_ratio = min(high_value_count / max(srv.method_count, 1), 1.0) * 0.20
    score += high_value_ratio

    context_breadth = min(len(srv.access_contexts) / 4.0, 1.0) * 0.05
    score += context_breadth

    return min(score, 1.0)


def main() -> None:
    parser = argparse.ArgumentParser(description="Find WinRT privilege escalation targets.")
    parser.add_argument("--context", default="medium_il_privileged",
                        help="Access context (default: medium_il_privileged)")
    parser.add_argument("--top", type=int, default=0, help="Show top N targets")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = safe_parse_args(parser)

    idx = require_winrt_index()
    ctx = parse_context(args.context)
    caller_il = ctx.caller_il if ctx else "medium"

    candidates = idx.get_privileged_surface(caller_il)

    scored: list[tuple[float, WinrtServer]] = []
    for srv in candidates:
        if srv.is_out_of_process:
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
    print(f"WINRT PRIVILEGE ESCALATION TARGETS (caller: {caller_il}-IL)")
    print(f"{'=' * 90}")
    print(f"  Candidates: {len(candidates)}")
    print(f"  Scored OOP targets: {len(scored)}")
    print()

    print(f"{'Rank':>4}  {'Score':>5}  {'Risk':>8}  {'Methods':>7}  {'Identity':<25}  Class")
    print(f"{'-' * 4}  {'-' * 5}  {'-' * 8}  {'-' * 7}  {'-' * 25}  {'-' * 40}")

    for rank, (score, srv) in enumerate(scored, 1):
        identity = srv.server_identity or "-"
        tier = srv.risk_tier(ctx) if ctx else srv.best_risk_tier
        print(
            f"#{rank:<3}  {score:.2f}   {tier.upper():>8}  "
            f"{srv.method_count:>7}  "
            f"{identity:<25}  "
            f"{srv.name}"
        )

        high_value = [m for m in srv.methods_flat if _HIGH_VALUE_PATTERNS.search(m.short_name)]
        if high_value:
            for m in high_value[:3]:
                print(f"        >> {m.short_name}")
            if len(high_value) > 3:
                print(f"        ... and {len(high_value) - 3} more high-value methods")


if __name__ == "__main__":
    main()
