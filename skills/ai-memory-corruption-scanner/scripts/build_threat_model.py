"""Build a compact module threat model for AI-driven memory corruption scanning.

Gathers module identity, service type, privilege level, attacker model, entry
points, and crown-jewel operations.  Outputs a structured JSON document that
anchors the scanning agent's attention without bloating context.
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
        "_summary": {
            "module": metadata.get("file_name", ""),
            "service_type": service_type,
            "attacker_model": attacker_model,
            "entry_points": len(entry_points),
            "top_entries": [ep.get("function_name", "") for ep in top_entries[:5]],
        },
    }
    return threat_model


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build a compact module threat model for AI memory corruption scanning"
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


if __name__ == "__main__":
    main()
