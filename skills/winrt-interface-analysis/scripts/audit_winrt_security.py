#!/usr/bin/env python3
"""WinRT security audit using server registration metadata.

Checks for: permissive SDDL, SYSTEM-identity servers reachable from
medium-IL, BaseTrust classes with large method surfaces, remote activation.

Usage:
    python audit_winrt_security.py <db_path> --json
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT_DIR))

from _common import (
    ErrorCode,
    emit_error,
    emit_json,
    open_individual_analysis_db,
    parse_json_safe,
    require_winrt_index,
    resolve_db_path,
)
from helpers.errors import db_error_handler, safe_parse_args  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="WinRT security audit.")
    parser.add_argument("db_path", help="Path to analysis database")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = safe_parse_args(parser)

    idx = require_winrt_index()

    try:
        db_resolved = resolve_db_path(args.db_path)
    except Exception:
        db_resolved = args.db_path

    findings: list[dict] = []

    with db_error_handler(db_resolved):
        db = open_individual_analysis_db(db_resolved)
        file_info = db.get_file_info()
        module_name = file_info.file_name if file_info else Path(db_resolved).stem

    servers = idx.get_servers_for_module(module_name)
    if not servers:
        if args.json:
            emit_json({
                "module": module_name,
                "finding_count": 0,
                "findings": [],
                "note": "No WinRT servers found for this module",
            })
        else:
            print(f"No WinRT servers found for module: {module_name}")
        return

    for srv in servers:
        if srv.has_permissive_sddl and srv.is_out_of_process:
            findings.append({
                "severity": "HIGH",
                "class": srv.name,
                "finding": "Permissive SDDL on OOP server",
                "detail": f"Server permissions grant wide access. "
                          f"Identity: {srv.server_identity or 'unknown'}",
                "sddl": srv.server_permissions or srv.default_access_permission,
            })

        if srv.runs_as_system and srv.is_out_of_process:
            for ctx in srv.access_contexts:
                if ctx.caller_il == "medium":
                    findings.append({
                        "severity": "CRITICAL",
                        "class": srv.name,
                        "finding": "SYSTEM server reachable from medium-IL",
                        "detail": f"OOP server runs as SYSTEM and is accessible "
                                  f"from medium integrity level ({ctx}). "
                                  f"Methods: {srv.method_count}",
                        "context": str(ctx),
                    })
                    break

        if srv.is_base_trust and srv.method_count > 10:
            findings.append({
                "severity": "MEDIUM",
                "class": srv.name,
                "finding": "BaseTrust class with large method surface",
                "detail": f"Trust level BaseTrust with {srv.method_count} methods. "
                          f"Activation: {srv.activation_type}",
            })

        if srv.is_remote_activatable:
            findings.append({
                "severity": "HIGH",
                "class": srv.name,
                "finding": "Remote activation supported",
                "detail": "Server supports remote activation, expanding attack surface.",
            })

    findings.sort(key=lambda f: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(f["severity"], 99))

    if args.json:
        emit_json({
            "module": module_name,
            "server_count": len(servers),
            "finding_count": len(findings),
            "findings": findings,
        })
        return

    print(f"{'=' * 80}")
    print(f"WINRT SECURITY AUDIT: {module_name}")
    print(f"{'=' * 80}")
    print(f"  Servers: {len(servers)}")
    print(f"  Findings: {len(findings)}")
    print()

    for i, finding in enumerate(findings, 1):
        print(f"  [{finding['severity']}] #{i}: {finding['finding']}")
        print(f"    Class: {finding['class']}")
        print(f"    {finding['detail']}")
        print()


if __name__ == "__main__":
    main()
