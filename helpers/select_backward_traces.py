#!/usr/bin/env python3
"""Select backward trace targets for /audit Step 3c.

Implements the Case A / Case B / Skip decision from audit.md:
  - Case A: Target function has direct dangerous calls → trace from target
  - Case B: Thin wrapper → trace from primary callee
  - Skip: Neither applies

Usage:
    python select_backward_traces.py \
        --dossier <dossier.json> \
        [--extract-callee <extract_callee.json>] \
        [--json]

Output (--json):
    {
      "status": "ok",
      "case": "A" | "B" | "skip",
      "traces": [
        {
          "function_id": 42,
          "function_name": "RAiLaunchAdminProcess",
          "target_api": "CreateProcessAsUserW",
          "category": "command_execution",
          "step_name": "backward_trace_command_execution"
        }
      ]
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

from helpers.errors import safe_parse_args
from helpers.json_output import emit_json
from helpers.api_taxonomy import classify_api_security


def _load_json_file(path: str) -> dict:
    """Load a JSON file, handling workspace results.json envelope."""
    with open(path) as f:
        data = json.load(f)
    if isinstance(data, dict) and "stdout" in data and "output_type" in data:
        return data["stdout"]
    return data


def _pick_one_per_category(apis: list[str], limit: int = 3) -> list[tuple[str, str]]:
    """Pick one API per security category, up to limit. Returns [(api, category)]."""
    seen_cats: set[str] = set()
    result: list[tuple[str, str]] = []
    for api in apis:
        cat = classify_api_security(api)
        if not cat or cat in seen_cats:
            continue
        seen_cats.add(cat)
        result.append((api, cat))
        if len(result) >= limit:
            break
    return result


def select_traces(dossier: dict, extract_callee: dict | None) -> dict:
    """Determine which backward traces to run.

    Returns dict with 'case', 'traces', and metadata.
    """
    dangerous_ops = dossier.get("dangerous_operations", {})
    identity = dossier.get("identity", {})
    dangerous_direct = dangerous_ops.get("dangerous_apis_direct", [])
    function_id = identity.get("function_id")
    function_name = identity.get("function_name", "")

    # Case A: target function has direct dangerous calls
    if dangerous_direct:
        targets = _pick_one_per_category(dangerous_direct, limit=3)
        traces = []
        for api, cat in targets:
            traces.append({
                "function_id": function_id,
                "function_name": function_name,
                "target_api": api,
                "category": cat,
                "step_name": f"backward_trace_{cat}",
            })
        return {"case": "A", "traces": traces}

    # Case B: thin wrapper with callee extracted
    if extract_callee is not None:
        callee_name = extract_callee.get("function_name", "")
        callee_id = extract_callee.get("function_id")

        callee_outbound = extract_callee.get("outbound_xrefs", [])
        callee_outbound_names: set[str] = set()
        for xref in callee_outbound:
            if isinstance(xref, dict):
                fname = xref.get("function_name", "")
                if fname:
                    callee_outbound_names.add(fname)

        callee_dangerous_map = dangerous_ops.get("callee_dangerous_apis", {})
        callee_dangerous = callee_dangerous_map.get(callee_name, [])

        direct_dangerous = [
            api for api in callee_dangerous if api in callee_outbound_names
        ]

        if direct_dangerous:
            targets = _pick_one_per_category(direct_dangerous, limit=3)
            traces = []
            for api, cat in targets:
                traces.append({
                    "function_id": callee_id,
                    "function_name": callee_name,
                    "target_api": api,
                    "category": cat,
                    "step_name": f"backward_trace_{cat}",
                })
            return {"case": "B", "traces": traces}

    return {"case": "skip", "traces": []}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Select backward trace targets for /audit Step 3c.",
    )
    parser.add_argument("--dossier", required=True, help="Path to dossier results JSON")
    parser.add_argument(
        "--extract-callee", dest="extract_callee",
        help="Path to extract_callee results JSON (if Step 3f ran)",
    )
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = safe_parse_args(parser)

    dossier = _load_json_file(args.dossier)

    extract_callee = None
    if args.extract_callee:
        try:
            extract_callee = _load_json_file(args.extract_callee)
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    result = select_traces(dossier, extract_callee)

    if args.json:
        emit_json({
            "case": result["case"],
            "trace_count": len(result["traces"]),
            "traces": result["traces"],
        })
    else:
        case = result["case"]
        traces = result["traces"]
        if case == "skip":
            print("Step 3c: SKIP (no direct dangerous APIs and no thin-wrapper callee)")
        else:
            label = "target function" if case == "A" else "primary callee"
            print(f"Step 3c: Case {case} ({label} has direct dangerous calls)")
            print(f"\nTraces to run ({len(traces)}):")
            for t in traces:
                print(f"  {t['step_name']}: {t['function_name']} --target {t['target_api']} [{t['category']}]")


if __name__ == "__main__":
    main()
