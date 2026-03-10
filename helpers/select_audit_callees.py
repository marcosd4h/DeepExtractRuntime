#!/usr/bin/env python3
"""Select callees for deep extraction during /audit (Steps 3h + 3i).

Implements the deterministic selection algorithms from audit.md:
  - Step 3h: Deep security callee selection (tier-based from dossier)
  - Step 3i: Taint-path intermediate callee selection

Usage:
    python select_audit_callees.py <db_path> \
        --dossier <dossier.json> \
        --attack-surface <attack_surface.json> \
        [--taint-forward <taint_forward.json>] \
        [--exclude <name1> <name2> ...] \
        [--json]

Output (--json):
    {
      "status": "ok",
      "should_run_3h": true,
      "trigger_reason": "dangerous_ops_reachable >= 10",
      "deep_callees": [...],
      "taint_callees": [...],
      "all_extractions": [...]
    }

Each entry in deep_callees / taint_callees / all_extractions:
    {
      "callee_name": "AiLaunchProcess",
      "function_id": 42,
      "step_name": "extract_deep_1",
      "tier": 1,
      "api_count": 11,
      "source": "3h",
      "rationale": "Tier 1 command_execution callee, 11 dangerous APIs"
    }
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_HELPERS_DIR = str(Path(__file__).resolve().parent)
_AGENT_DIR = str(Path(__file__).resolve().parents[1])
for _p in (_HELPERS_DIR, _AGENT_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from helpers.errors import ErrorCode, emit_error, safe_parse_args, db_error_handler
from helpers.json_output import emit_json
from helpers.progress import status_message
from helpers import open_individual_analysis_db


def _load_json_file(path: str) -> dict:
    """Load a JSON file, handling workspace results.json envelope."""
    with open(path) as f:
        data = json.load(f)
    if isinstance(data, dict) and "stdout" in data and "output_type" in data:
        return data["stdout"]
    return data


def _extract_callee_name(entry: str) -> str:
    """Extract callee name from 'CalleeName->API' format."""
    if "->" in entry:
        return entry.split("->")[0]
    return entry


def _check_decompiled_exists(db_path: str, callee_names: list[str]) -> dict[str, int | None]:
    """Check which callees have decompiled code and return name -> function_id mapping."""
    result: dict[str, int | None] = {}
    with db_error_handler(db_path, "checking callee decompiled code"):
        with open_individual_analysis_db(db_path) as db:
            for name in callee_names:
                rows = db.conn.execute(
                    "SELECT function_id, decompiled_code FROM functions WHERE function_name = ?",
                    (name,),
                ).fetchall()
                if rows:
                    for row in rows:
                        code = row[1] or ""
                        if code.strip() and not code.strip().lower().startswith("decompil"):
                            result[name] = row[0]
                            break
                    else:
                        result[name] = None
                else:
                    result[name] = None
    return result


def select_deep_callees(
    dossier: dict,
    attack_surface: dict | None,
    exclude_names: set[str],
    db_path: str,
) -> tuple[bool, str, list[dict]]:
    """Step 3h: Select deep security callees from dossier.

    Returns (should_run, trigger_reason, selected_callees).
    """
    dangerous_ops = dossier.get("dangerous_operations", {})
    reachability = dossier.get("reachability", {})
    ipc_context = reachability.get("ipc_context", {})

    is_rpc_handler = ipc_context.get("is_rpc_handler", False)
    dangerous_ops_reachable = 0
    if attack_surface:
        dangerous_ops_reachable = attack_surface.get("dangerous_ops_reachable", 0) or 0

    should_run = dangerous_ops_reachable >= 10 or is_rpc_handler
    if not should_run:
        return False, "", []

    trigger = (
        f"dangerous_ops_reachable={dangerous_ops_reachable} >= 10"
        if dangerous_ops_reachable >= 10
        else "is_rpc_handler=true"
    )

    security_callees = dangerous_ops.get("security_relevant_callees", {})
    callee_dangerous_apis = dangerous_ops.get("callee_dangerous_apis", {})

    cmd_exec_entries = security_callees.get("command_execution", [])
    privilege_entries = security_callees.get("privilege", [])

    tier1_names: set[str] = set()
    for entry in cmd_exec_entries:
        name = _extract_callee_name(entry)
        if name and name not in exclude_names:
            tier1_names.add(name)

    tier2_names: set[str] = set()
    for entry in privilege_entries:
        name = _extract_callee_name(entry)
        if name and name not in exclude_names and name not in tier1_names:
            tier2_names.add(name)

    all_candidates = list(tier1_names) + list(tier2_names)
    if not all_candidates:
        return should_run, trigger, []

    decompiled_map = _check_decompiled_exists(db_path, all_candidates)

    candidates = []
    for name in all_candidates:
        fid = decompiled_map.get(name)
        if fid is None:
            continue
        tier = 1 if name in tier1_names else 2
        api_count = len(callee_dangerous_apis.get(name, []))
        candidates.append({
            "callee_name": name,
            "function_id": fid,
            "tier": tier,
            "api_count": api_count,
            "source": "3h",
        })

    candidates.sort(key=lambda c: (c["tier"], -c["api_count"]))
    selected = candidates[:4]

    for i, c in enumerate(selected, 1):
        c["step_name"] = f"extract_deep_{i}"
        tier_label = "command_execution" if c["tier"] == 1 else "privilege"
        c["rationale"] = f"Tier {c['tier']} {tier_label} callee, {c['api_count']} dangerous APIs"

    return should_run, trigger, selected


def select_taint_callees(
    taint_forward: dict | None,
    exclude_names: set[str],
    db_path: str,
) -> list[dict]:
    """Step 3i: Select taint-path intermediate callees.

    Returns selected_callees list.
    """
    if not taint_forward:
        return []

    findings = taint_forward.get("forward_findings", [])
    if not findings:
        return []

    callee_scores: dict[str, float] = {}
    for finding in findings:
        path_hops = finding.get("path_hops", 0)
        guards = finding.get("guards", [])
        if path_hops <= 1 or guards:
            continue

        path = finding.get("path", [])
        score = finding.get("score", 0.0)

        for element in path[1:-1]:
            if "." in element:
                func_name = element.split(".")[0]
            else:
                func_name = element
            if func_name and func_name not in exclude_names:
                if func_name not in callee_scores or score > callee_scores[func_name]:
                    callee_scores[func_name] = score

    if not callee_scores:
        return []

    candidate_names = list(callee_scores.keys())
    decompiled_map = _check_decompiled_exists(db_path, candidate_names)

    candidates = []
    for name in candidate_names:
        fid = decompiled_map.get(name)
        if fid is None:
            continue
        candidates.append({
            "callee_name": name,
            "function_id": fid,
            "tier": 0,
            "api_count": 0,
            "source": "3i",
            "taint_score": callee_scores[name],
        })

    candidates.sort(key=lambda c: -c["taint_score"])
    selected = candidates[:3]

    for i, c in enumerate(selected, 1):
        c["step_name"] = f"extract_taint_{i}"
        c["rationale"] = f"Unguarded multi-hop taint path intermediate, score={c['taint_score']:.3f}"

    return selected


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Select callees for deep extraction during /audit (Steps 3h + 3i).",
    )
    parser.add_argument("db_path", help="Path to the analysis DB")
    parser.add_argument("--dossier", required=True, help="Path to dossier results JSON")
    parser.add_argument("--attack-surface", dest="attack_surface", help="Path to attack surface results JSON")
    parser.add_argument("--taint-forward", dest="taint_forward", help="Path to taint forward results JSON")
    parser.add_argument(
        "--exclude", nargs="*", default=[],
        help="Callee names to exclude (already extracted by 3f)",
    )
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = safe_parse_args(parser)

    dossier = _load_json_file(args.dossier)

    attack_surface = None
    if args.attack_surface:
        try:
            attack_surface = _load_json_file(args.attack_surface)
        except (FileNotFoundError, json.JSONDecodeError):
            status_message("Attack surface results not available, skipping")

    taint_forward = None
    if args.taint_forward:
        try:
            taint_forward = _load_json_file(args.taint_forward)
        except (FileNotFoundError, json.JSONDecodeError):
            status_message("Taint forward results not available, skipping")

    exclude_names = set(args.exclude)

    should_run_3h, trigger_reason, deep_callees = select_deep_callees(
        dossier, attack_surface, exclude_names, args.db_path,
    )

    exclude_for_taint = exclude_names | {c["callee_name"] for c in deep_callees}
    taint_callees = select_taint_callees(taint_forward, exclude_for_taint, args.db_path)

    all_extractions = deep_callees + taint_callees

    if args.json:
        emit_json({
            "should_run_3h": should_run_3h,
            "trigger_reason": trigger_reason,
            "deep_callees": deep_callees,
            "deep_callee_count": len(deep_callees),
            "taint_callees": taint_callees,
            "taint_callee_count": len(taint_callees),
            "all_extractions": all_extractions,
            "total_extractions": len(all_extractions),
        })
    else:
        if should_run_3h:
            print(f"Step 3h triggered: {trigger_reason}")
            if deep_callees:
                print(f"\nStep 3h selection ({len(deep_callees)} callees):")
                for c in deep_callees:
                    print(f"  {c['step_name']}: {c['callee_name']:<30} [Tier {c['tier']}, {c['api_count']} APIs]")
            else:
                print("  (no qualifying callees found)")
        else:
            print("Step 3h: not triggered (conditions not met)")

        if taint_callees:
            print(f"\nStep 3i selection ({len(taint_callees)} callees):")
            for c in taint_callees:
                print(f"  {c['step_name']}: {c['callee_name']:<30} [score={c.get('taint_score', 0):.3f}]")
        else:
            print("\nStep 3i: no qualifying taint-path callees")

        if all_extractions:
            print(f"\nTotal extractions needed: {len(all_extractions)}")


if __name__ == "__main__":
    main()
