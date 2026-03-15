"""Build a compact module threat model for AI-driven logic vulnerability scanning.

Gathers module identity, service type, privilege level, attacker model, entry
points, and crown-jewel operations.  Additionally collects logic-specific
structural enrichments: dispatch table profile, shared global state map, and
function classification summary.

Outputs a structured JSON document that anchors the scanning agent's attention
without bloating context.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

_SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT_DIR))

from _common import (
    WORKSPACE_ROOT,
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
# Logic-specific structural enrichments
# ---------------------------------------------------------------------------

def _build_shared_state_profile(db_path: str) -> dict[str, Any]:
    """Map shared global variables accessed by multiple functions."""
    result = run_skill_script(
        "data-flow-tracer",
        "global_state_map.py",
        [db_path, "--shared-only", "--json"],
        timeout=60,
        json_output=True,
    )
    if not result.get("success"):
        status_message("data-flow-tracer unavailable: shared globals data will be empty")
        return {"shared_globals_count": 0, "top_shared_globals": []}
    json_data = result.get("json_data", {})
    if not isinstance(json_data, dict):
        return {"shared_globals_count": 0, "top_shared_globals": []}

    globals_list = json_data.get("globals", [])
    top_globals = sorted(
        globals_list,
        key=lambda g: len(g.get("readers", [])) + len(g.get("writers", [])),
        reverse=True,
    )[:15]

    return {
        "shared_globals_count": len(globals_list),
        "top_shared_globals": [
            {
                "name": g.get("name", g.get("address", "unknown")),
                "readers": len(g.get("readers", [])),
                "writers": len(g.get("writers", [])),
            }
            for g in top_globals
        ],
    }


def _build_classification_summary(db_path: str) -> dict[str, Any]:
    """Get aggregate function classification counts for the module."""
    result = run_skill_script(
        "classify-functions",
        "triage_summary.py",
        [db_path, "--app-only", "--json"],
        timeout=60,
        json_output=True,
    )
    if not result.get("success"):
        return {"total_app_functions": 0}
    json_data = result.get("json_data", {})
    if not isinstance(json_data, dict):
        return {"total_app_functions": 0}

    counts = json_data.get("category_counts", json_data.get("counts", {}))
    total = json_data.get("total_functions", json_data.get("total_app_functions", 0))

    return {
        "security_functions": counts.get("security", 0),
        "dispatch_routing_functions": counts.get("dispatch_routing", counts.get("dispatch", 0)),
        "error_handling_functions": counts.get("error_handling", 0),
        "total_app_functions": total,
    }


# ---------------------------------------------------------------------------
# Threat model builder
# ---------------------------------------------------------------------------

def build_threat_model(db_path: str) -> dict[str, Any]:
    """Build a compact threat model for the module."""
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

    status_message("Building shared state profile...")
    shared_state_profile = _build_shared_state_profile(db_path)

    status_message("Building classification summary...")
    classification_summary = _build_classification_summary(db_path)

    rpc_info: list[dict] = []
    com_info: list[dict] = []
    for ep in top_entries:
        etype = ep.get("entry_type", "")
        if "RPC" in etype:
            rpc_info.append({
                "function": ep.get("function_name", ""),
                "opnum": ep.get("rpc_opnum"),
                "interface": ep.get("rpc_interface_id", ""),
            })
        elif "COM" in etype:
            com_info.append({
                "function": ep.get("function_name", ""),
                "clsid": ep.get("com_clsid", ""),
                "interface": ep.get("com_interface_name", ""),
            })

    threat_model = {
        "status": "ok",
        "module": metadata.get("file_name", ""),
        "description": metadata.get("file_description", ""),
        "service_type": service_type,
        "attacker_model": attacker_model,
        "entry_point_count": len(entry_points),
        "top_entry_points": [
            {
                "function": ep.get("function_name", ""),
                "type": ep.get("entry_type", ""),
                "attack_score": ep.get("attack_score", 0),
                "dangerous_ops_reachable": ep.get("dangerous_ops_reachable", 0),
            }
            for ep in top_entries
        ],
        "rpc_context": rpc_info if rpc_info else None,
        "com_context": com_info if com_info else None,
        "scale": profile.get("scale", {}),
        "api_profile": profile.get("api_profile", {}),
        "shared_state_profile": shared_state_profile,
        "classification_summary": classification_summary,
        "_summary": {
            "module": metadata.get("file_name", ""),
            "service_type": service_type,
            "attacker_model": attacker_model,
            "entry_points": len(entry_points),
            "top_entries": [ep.get("function_name", "") for ep in top_entries[:5]],
            "shared_globals": shared_state_profile.get("shared_globals_count", 0),
        },
    }
    return threat_model


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build a compact module threat model for AI logic vulnerability scanning"
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
        print(f"=== Threat Model: {tm['module']} ===")
        print(f"  Description:    {tm['description']}")
        print(f"  Service type:   {tm['service_type']}")
        print(f"  Attacker model: {tm['attacker_model']}")
        print(f"  Entry points:   {tm['entry_point_count']}")
        print()
        for ep in tm.get("top_entry_points", [])[:10]:
            print(f"  [{ep['type']}] {ep['function']}  "
                  f"(score={ep['attack_score']:.2f}, "
                  f"dangerous_ops={ep['dangerous_ops_reachable']})")
        ssp = tm.get("shared_state_profile", {})
        if ssp.get("shared_globals_count"):
            print(f"\n  Shared globals: {ssp['shared_globals_count']}")
            for g in ssp.get("top_shared_globals", [])[:5]:
                print(f"    {g['name']}: {g['readers']}R / {g['writers']}W")
        cs = tm.get("classification_summary", {})
        if cs.get("total_app_functions"):
            print(f"\n  Classification: {cs['total_app_functions']} app functions"
                  f" ({cs.get('security_functions', 0)} security,"
                  f" {cs.get('dispatch_routing_functions', 0)} dispatch)")


if __name__ == "__main__":
    main()
