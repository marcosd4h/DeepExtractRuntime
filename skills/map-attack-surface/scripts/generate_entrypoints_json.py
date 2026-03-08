#!/usr/bin/env python3
"""Generate a CRS-compatible entrypoints.json from attack surface analysis.

Combines discovery + ranking to produce a structured JSON file suitable for
Cyber Reasoning Systems, fuzzing harness generators, or triage tooling.

Usage:
    python generate_entrypoints_json.py <db_path>
    python generate_entrypoints_json.py <db_path> -o entrypoints.json
    python generate_entrypoints_json.py <db_path> --top 20 --min-score 0.2

Examples:
    python generate_entrypoints_json.py extracted_dbs/appinfo_dll_e98d25a9e8.db
    python generate_entrypoints_json.py extracted_dbs/appinfo_dll_e98d25a9e8.db -o output/appinfo_entrypoints.json
    python generate_entrypoints_json.py extracted_dbs/cmd_exe_6d109a3a00.db --top 30

Output:
    JSON file with module metadata, ranked entry points, attack surface summary,
    and per-entry-point tainted argument recommendations.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT_DIR))

from _common import EntryPoint, EntryPointType, parse_json_safe
from rank_entrypoints import rank_entrypoints
from helpers import open_individual_analysis_db
from helpers.errors import db_error_handler, safe_parse_args
from helpers.json_output import emit_json


# ===========================================================================
# CRS Entrypoints Format
# ===========================================================================

def generate_entrypoints_json(
    db_path: str,
    max_depth: int = 10,
    top_n: int = 0,
    min_score: float = 0.0,
) -> dict:
    """Generate complete CRS-compatible entrypoints document.

    Schema:
    {
      "version": "1.0",
      "generated_at": "ISO-8601",
      "module": { module metadata },
      "attack_surface_summary": { statistics },
      "entry_points": [ ranked entry point records ],
      "type_distribution": { type -> count },
      "danger_hotspots": [ top dangerous functions reachable ]
    }
    """
    # Rank all entry points
    entries = rank_entrypoints(db_path, max_depth=max_depth)

    # Filter
    if min_score > 0:
        entries = [ep for ep in entries if ep.attack_score >= min_score]
    if top_n > 0:
        entries = entries[:top_n]

    # Get module metadata
    with db_error_handler(db_path, "loading module metadata for entrypoints"):
        with open_individual_analysis_db(db_path) as db:
            fi = db.get_file_info()
            total_funcs = db.count_functions()

    module_info = {}
    if fi:
        module_info = {
            "file_name": fi.file_name,
            "file_path": fi.file_path,
            "md5_hash": fi.md5_hash,
            "sha256_hash": fi.sha256_hash,
            "file_size_bytes": fi.file_size_bytes,
            "file_description": fi.file_description,
            "company_name": fi.company_name,
            "product_name": fi.product_name,
            "file_version": fi.file_version,
            "total_functions": total_funcs,
            "analysis_db": str(db_path),
        }

        # Security features
        sec = parse_json_safe(fi.security_features)
        if sec and isinstance(sec, dict):
            module_info["security_features"] = sec

    # Type distribution
    type_dist = Counter(ep.type_label for ep in entries)

    # Danger hotspots: collect all dangerous APIs reachable across all entry points
    danger_hotspot_counts: Counter = Counter()
    for ep in entries:
        for api in ep.dangerous_ops_list:
            danger_hotspot_counts[api] += 1

    # Build output document
    doc = {
        "version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "map-attack-surface/generate_entrypoints_json.py",
        "module": module_info,
        "attack_surface_summary": {
            "total_entry_points": len(entries),
            "total_module_functions": total_funcs,
            "entry_point_coverage": round(len(entries) / max(total_funcs, 1) * 100, 1),
            "avg_attack_score": round(
                sum(ep.attack_score for ep in entries) / max(len(entries), 1), 3
            ),
            "max_attack_score": round(max((ep.attack_score for ep in entries), default=0), 3),
            "entry_points_with_danger_reachable": sum(
                1 for ep in entries if ep.dangerous_ops_reachable > 0
            ),
            "total_unique_danger_apis": len(danger_hotspot_counts),
            "max_reachable_depth": max_depth,
        },
        "type_distribution": dict(type_dist.most_common()),
        "entry_points": [_entry_to_crs(ep) for ep in entries],
        "danger_hotspots": [
            {"api": api, "reachable_from_n_entrypoints": count}
            for api, count in danger_hotspot_counts.most_common(30)
        ],
    }

    return doc


def _entry_to_crs(ep: EntryPoint) -> dict:
    """Convert an EntryPoint to CRS-compatible JSON record."""
    rec = {
        "rank": ep.attack_rank,
        "function_name": ep.function_name,
        "function_id": ep.function_id,
        "attack_score": round(ep.attack_score, 4),
        "entry_type": ep.entry_type.name,
        "category": ep.category,
        "detection_source": ep.detection_source,
        "signature": ep.signature,
        "address": ep.address,
        "ordinal": ep.ordinal,
        "analysis": {
            "param_risk_score": round(ep.param_risk_score, 3),
            "param_risk_reasons": ep.param_risk_reasons,
            "reachable_functions": ep.reachable_count,
            "dangerous_ops_reachable": ep.dangerous_ops_reachable,
            "depth_to_first_danger": ep.depth_to_first_danger,
            "dangerous_apis": ep.dangerous_ops_list[:20],
        },
        "tainted_arguments": ep.tainted_args,
        "notes": ep.notes,
    }
    return rec


# ===========================================================================
# Main
# ===========================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate CRS-compatible entrypoints.json from attack surface analysis.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("db_path", help="Path to individual analysis DB")
    parser.add_argument("-o", "--output", help="Output file path (default: stdout)")
    parser.add_argument("--top", type=int, default=0, help="Include only top N entries")
    parser.add_argument("--depth", type=int, default=10, help="Max callgraph BFS depth (default: 10)")
    parser.add_argument("--min-score", type=float, default=0.0, help="Minimum attack score threshold")
    parser.add_argument("--pretty", action="store_true", default=True, help="Pretty-print JSON (default)")
    parser.add_argument("--compact", action="store_true", help="Compact JSON output")
    args = safe_parse_args(parser)

    with db_error_handler(args.db_path, "entrypoints JSON generation"):
        doc = generate_entrypoints_json(
            db_path=args.db_path,
            max_depth=args.depth,
            top_n=args.top,
            min_score=args.min_score,
        )

    indent = None if args.compact else 2
    output_doc = {"status": "ok"}
    output_doc.update(doc)
    json_str = json.dumps(output_doc, indent=indent, ensure_ascii=False)

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json_str, encoding="utf-8")
        print(f"Written to {output_path} ({len(doc['entry_points'])} entry points)", file=sys.stderr)
    else:
        emit_json(doc)


if __name__ == "__main__":
    main()
