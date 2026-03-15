"""Build a taint-focused module threat model for AI-driven taint scanning.

Gathers module identity, trust boundary classification, service type, attacker
model, entry points with sink density and taint parameter hints, and trust
transition opportunities.  Outputs a structured JSON document that anchors the
scanning agent's attention on data flow from attacker inputs to dangerous sinks.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

_SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT_DIR))

from _common import (
    SINK_SEVERITY,
    WORKSPACE_ROOT,
    classify_module_trust,
    classify_sink,
    db_error_handler,
    emit_error,
    emit_json,
    ErrorCode,
    open_individual_analysis_db,
    parse_json_safe,
    resolve_db_path,
    safe_parse_args,
    status_message,
)
from helpers.script_runner import run_skill_script


# ---------------------------------------------------------------------------
# Service type and attacker model inference
# ---------------------------------------------------------------------------

_ENTRY_TYPE_TO_SERVICE: dict[str, str] = {
    "RPC_HANDLER": "rpc_service",
    "RPC_STUB": "rpc_service",
    "COM_METHOD": "com_server",
    "COM_VTABLE_METHOD": "com_server",
    "WINRT_METHOD": "winrt_server",
    "EXPORT_DLL": "library",
    "EXPORT_EXE": "executable",
    "SERVICE_MAIN": "windows_service",
    "SERVICE_HANDLER": "windows_service",
    "TLS_CALLBACK": "executable",
}

_SERVICE_TO_ATTACKER: dict[str, str] = {
    "rpc_service": "remote unauthenticated (network RPC)",
    "com_server": "local authenticated (COM activation)",
    "winrt_server": "local app container (WinRT activation)",
    "windows_service": "remote or local (service entry)",
    "library": "depends on caller (DLL export)",
    "executable": "local user (process entry)",
}

# RPC/COM entry points: all non-this parameters are attacker-controlled
_TAINTED_ENTRY_TYPES = frozenset({
    "RPC_HANDLER", "RPC_STUB", "COM_METHOD", "COM_VTABLE_METHOD",
    "WINRT_METHOD", "EXPORT_DLL", "EXPORT_EXE",
})

_PARAM_RE = re.compile(r"\ba(\d+)\b")


def _infer_service_type(entry_points: list[dict]) -> str:
    """Infer the dominant service type from entry point types."""
    type_counts: dict[str, int] = {}
    for ep in entry_points:
        etype = ep.get("entry_type", "")
        stype = _ENTRY_TYPE_TO_SERVICE.get(etype, "unknown")
        type_counts[stype] = type_counts.get(stype, 0) + 1

    if not type_counts:
        return "unknown"
    return max(type_counts, key=lambda k: type_counts[k])


def _infer_attacker_model(service_type: str) -> str:
    return _SERVICE_TO_ATTACKER.get(service_type, "unknown")


# ---------------------------------------------------------------------------
# Entry point discovery
# ---------------------------------------------------------------------------

def _discover_entry_points(db_path: str) -> list[dict]:
    """Run discover_entrypoints.py and return the entry point list."""
    result = run_skill_script(
        "map-attack-surface",
        "discover_entrypoints.py",
        [db_path, "--json"],
        timeout=60,
        json_output=True,
    )
    if not result.get("success"):
        return []
    json_data = result.get("json_data", {})
    if isinstance(json_data, dict):
        return json_data.get("entrypoints", [])
    return []


# ---------------------------------------------------------------------------
# Module metadata loading
# ---------------------------------------------------------------------------

def _load_module_metadata(db_path: str) -> dict[str, Any]:
    """Load module metadata from the analysis DB's file_info."""
    with db_error_handler(db_path, "loading module metadata"):
        with open_individual_analysis_db(db_path) as db:
            fi = db.get_file_info()
            if not fi:
                return {}
            return {
                "file_name": fi.file_name or "",
                "file_path": fi.file_path or "",
                "file_description": fi.file_description or "",
                "company": fi.company_name or "",
                "file_size": fi.file_size_bytes or 0,
            }
    return {}


def _load_module_profile(db_path: str) -> dict[str, Any]:
    """Load module_profile.json if available next to file_info.json."""
    db_p = Path(db_path)
    module_name = db_p.stem.rsplit("_", 1)[0] if "_" in db_p.stem else db_p.stem
    profile_candidates = [
        WORKSPACE_ROOT / "extracted_code" / module_name / "module_profile.json",
    ]
    for candidate in profile_candidates:
        if candidate.is_file():
            try:
                return json.loads(candidate.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass
    return {}


# ---------------------------------------------------------------------------
# Sink density computation
# ---------------------------------------------------------------------------

def _compute_sink_density(db_path: str, function_name: str) -> dict[str, Any]:
    """Count dangerous sinks reachable from a function via outbound xrefs."""
    try:
        with open_individual_analysis_db(db_path) as db:
            matches = db.get_function_by_name(function_name)
            if not matches:
                return {"total_sinks": 0, "by_category": {}}
            func = matches[0]
            xrefs_raw = parse_json_safe(func.simple_outbound_xrefs) or []

            by_category: dict[str, int] = {}
            for xref in xrefs_raw:
                callee = xref if isinstance(xref, str) else xref.get("function_name", "")
                if not callee:
                    continue
                cat = classify_sink(callee)
                if cat:
                    by_category[cat] = by_category.get(cat, 0) + 1

            total = sum(by_category.values())
            severity = max(
                (SINK_SEVERITY.get(c, 0.0) for c in by_category),
                default=0.0,
            )
            return {
                "total_sinks": total,
                "max_sink_severity": round(severity, 2),
                "by_category": by_category,
            }
    except Exception:
        return {"total_sinks": 0, "by_category": {}}


def _infer_tainted_params(
    entry_type: str,
    function_name: str,
    db_path: str,
) -> list[dict]:
    """Infer which parameters are likely attacker-controlled based on entry type."""
    if entry_type not in _TAINTED_ENTRY_TYPES:
        return []

    try:
        with open_individual_analysis_db(db_path) as db:
            matches = db.get_function_by_name(function_name)
            if not matches:
                return [{"param": 1, "reason": "first parameter (default)"}]
            func = matches[0]
            sig = func.function_signature or ""
            code = func.decompiled_code or ""

            max_idx = 0
            for m in _PARAM_RE.finditer(sig + " " + code[:500]):
                max_idx = max(max_idx, int(m.group(1)))

            if max_idx < 1:
                max_idx = 1

            params: list[dict] = []
            for i in range(1, max_idx + 1):
                if "COM" in entry_type and i == 1:
                    params.append({"param": i, "reason": "this pointer (not tainted)"})
                else:
                    params.append({"param": i, "reason": f"attacker-controlled ({entry_type})"})
            return params
    except Exception:
        return [{"param": 1, "reason": "first parameter (default)"}]


# ---------------------------------------------------------------------------
# Trust transition opportunities
# ---------------------------------------------------------------------------

def _find_trust_transitions(
    db_path: str,
    entry_points: list[dict],
) -> list[dict]:
    """Identify trust boundary crossings available from this module."""
    transitions: list[dict] = []
    module_trust = classify_module_trust(db_path)

    rpc_types = {"RPC_HANDLER", "RPC_STUB"}
    com_types = {"COM_METHOD", "COM_VTABLE_METHOD"}
    winrt_types = {"WINRT_METHOD"}

    has_rpc = any(ep.get("entry_type", "") in rpc_types for ep in entry_points)
    has_com = any(ep.get("entry_type", "") in com_types for ep in entry_points)
    has_winrt = any(ep.get("entry_type", "") in winrt_types for ep in entry_points)

    if has_rpc:
        transitions.append({
            "boundary_type": "rpc",
            "from_trust": "user_process",
            "to_trust": module_trust,
            "description": "RPC client -> server handler (cross-process)",
        })
    if has_com:
        transitions.append({
            "boundary_type": "com",
            "from_trust": "user_process",
            "to_trust": module_trust,
            "description": "COM client -> server method (cross-process activation)",
        })
    if has_winrt:
        transitions.append({
            "boundary_type": "winrt",
            "from_trust": "user_process",
            "to_trust": module_trust,
            "description": "WinRT client -> server method (broker activation)",
        })

    return transitions


# ---------------------------------------------------------------------------
# Threat model builder
# ---------------------------------------------------------------------------

def build_threat_model(db_path: str) -> dict[str, Any]:
    """Build a taint-focused threat model for the module."""
    status_message("Discovering entry points...")
    entry_points = _discover_entry_points(db_path)
    top_entries = sorted(
        entry_points,
        key=lambda e: e.get("attack_score", 0),
        reverse=True,
    )[:15]

    status_message("Loading module metadata...")
    metadata = _load_module_metadata(db_path)
    profile = _load_module_profile(db_path)

    service_type = _infer_service_type(entry_points)
    attacker_model = _infer_attacker_model(service_type)

    status_message("Classifying module trust boundary...")
    module_trust = classify_module_trust(db_path)

    status_message("Computing sink density per entry point...")
    enriched_entries: list[dict] = []
    rpc_info: list[dict] = []
    com_info: list[dict] = []

    for ep in top_entries:
        func_name = ep.get("function_name", "")
        etype = ep.get("entry_type", "")

        sink_density = _compute_sink_density(db_path, func_name)
        tainted_params = _infer_tainted_params(etype, func_name, db_path)

        entry = {
            "function": func_name,
            "type": etype,
            "attack_score": ep.get("attack_score", 0),
            "dangerous_ops_reachable": ep.get("dangerous_ops_reachable", 0),
            "sink_density": sink_density,
            "tainted_params": tainted_params,
        }
        enriched_entries.append(entry)

        if "RPC" in etype:
            rpc_info.append({
                "function": func_name,
                "opnum": ep.get("rpc_opnum"),
                "interface": ep.get("rpc_interface_id", ""),
            })
        elif "COM" in etype:
            com_info.append({
                "function": func_name,
                "clsid": ep.get("com_clsid", ""),
                "interface": ep.get("com_interface_name", ""),
            })

    status_message("Identifying trust transition opportunities...")
    trust_transitions = _find_trust_transitions(db_path, entry_points)

    threat_model: dict[str, Any] = {
        "status": "ok",
        "module": metadata.get("file_name", ""),
        "description": metadata.get("file_description", ""),
        "service_type": service_type,
        "attacker_model": attacker_model,
        "trust_boundary": module_trust,
        "entry_point_count": len(entry_points),
        "top_entry_points": enriched_entries,
        "trust_transitions": trust_transitions if trust_transitions else None,
        "rpc_context": rpc_info if rpc_info else None,
        "com_context": com_info if com_info else None,
        "scale": profile.get("scale", {}),
        "api_profile": profile.get("api_profile", {}),
        "_summary": {
            "module": metadata.get("file_name", ""),
            "service_type": service_type,
            "attacker_model": attacker_model,
            "trust_boundary": module_trust,
            "entry_points": len(entry_points),
            "top_entries": [ep.get("function_name", "") for ep in top_entries[:5]],
            "total_sinks_top5": sum(
                e["sink_density"]["total_sinks"] for e in enriched_entries[:5]
            ),
        },
    }
    return threat_model


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build a taint-focused module threat model for AI taint scanning"
    )
    parser.add_argument("db_path", help="Path to the individual analysis database")
    parser.add_argument("--json", action="store_true", help="JSON output mode")
    args = safe_parse_args(parser)

    db_path = resolve_db_path(args.db_path)
    result = build_threat_model(db_path)

    if args.json:
        emit_json(result)
    else:
        tm = result
        print(f"=== Taint Threat Model: {tm['module']} ===")
        print(f"  Description:      {tm['description']}")
        print(f"  Service type:     {tm['service_type']}")
        print(f"  Attacker model:   {tm['attacker_model']}")
        print(f"  Trust boundary:   {tm['trust_boundary']}")
        print(f"  Entry points:     {tm['entry_point_count']}")
        print()
        if tm.get("trust_transitions"):
            print("  Trust Transitions:")
            for tt in tm["trust_transitions"]:
                print(f"    [{tt['boundary_type']}] {tt['from_trust']} -> "
                      f"{tt['to_trust']}: {tt['description']}")
            print()
        for ep in tm.get("top_entry_points", [])[:10]:
            sink = ep.get("sink_density", {})
            print(f"  [{ep['type']}] {ep['function']}  "
                  f"(score={ep['attack_score']:.2f}, "
                  f"sinks={sink.get('total_sinks', 0)}, "
                  f"max_severity={sink.get('max_sink_severity', 0):.2f})")
            tainted = [p for p in ep.get("tainted_params", [])
                       if "not tainted" not in p.get("reason", "")]
            if tainted:
                param_nums = ", ".join(f"a{p['param']}" for p in tainted)
                print(f"    tainted params: {param_nums}")


if __name__ == "__main__":
    main()
