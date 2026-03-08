#!/usr/bin/env python3
"""COM security audit combining server metadata with decompiled code.

Checks for: permissive SDDL, SYSTEM-identity services with wide access,
elevation/auto-elevation flags, trusted marshallers, remote activation,
low service protection, missing access checks.

Usage:
    python audit_com_security.py wuapi.dll --json
    python audit_com_security.py bfe18e9c-6d87-4450-b37c-e02f0b373803 --json
    python audit_com_security.py wuapi.dll --context medium_il_privileged --json
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT_DIR))

from _common import emit_json, is_clsid, parse_context, require_com_index
from helpers.errors import safe_parse_args


def main() -> None:
    parser = argparse.ArgumentParser(description="COM security audit.")
    parser.add_argument("module_or_clsid", help="Module name or CLSID GUID")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--context", help="Filter by access context")
    args = safe_parse_args(parser)

    idx = require_com_index()
    ctx = parse_context(args.context)
    target = args.module_or_clsid

    if is_clsid(target):
        srv = idx.get_server_by_clsid(target)
        servers = [srv] if srv else []
    else:
        servers = idx.get_servers_for_module(target)

    if not servers:
        if args.json:
            emit_json({
                "target": target,
                "finding_count": 0,
                "findings": [],
                "note": "No COM servers found for this target",
            })
        else:
            print(f"No COM servers found for: {target}")
        return

    findings: list[dict] = []

    for srv in servers:
        # SYSTEM service reachable from medium-IL
        if srv.runs_as_system and srv.is_out_of_process:
            for c in srv.access_contexts:
                if c.caller_il == "medium":
                    findings.append({
                        "severity": "CRITICAL",
                        "server": srv.name,
                        "clsid": srv.clsid,
                        "finding": "SYSTEM service reachable from medium-IL",
                        "detail": f"OOP server runs as {srv.service_user or srv.run_as or 'SYSTEM'} "
                                  f"and is accessible from medium integrity level ({c}). "
                                  f"Methods: {srv.method_count}",
                        "context": str(c),
                    })
                    break

        # Elevation / auto-elevation
        if srv.can_elevate:
            findings.append({
                "severity": "HIGH",
                "server": srv.name,
                "clsid": srv.clsid,
                "finding": "COM server supports elevation (CanElevate)",
                "detail": f"Server can be activated with elevation moniker. "
                          f"Auto-elevation: {srv.auto_elevation}. "
                          f"Server type: {srv.server_type}",
            })
        elif srv.auto_elevation:
            findings.append({
                "severity": "HIGH",
                "server": srv.name,
                "clsid": srv.clsid,
                "finding": "COM server has auto-elevation enabled",
                "detail": f"AutoElevation flag is set. Server type: {srv.server_type}",
            })

        # Permissive launch SDDL
        if srv.has_permissive_launch and srv.is_out_of_process:
            findings.append({
                "severity": "HIGH",
                "server": srv.name,
                "clsid": srv.clsid,
                "finding": "Permissive launch permission on OOP server",
                "detail": f"Launch SDDL grants wide access. "
                          f"Service: {srv.service_name or 'none'}",
                "sddl": srv.launch_permission or srv.app_id_launch_permission,
            })

        # Permissive access SDDL
        if srv.has_permissive_access and srv.is_out_of_process:
            findings.append({
                "severity": "HIGH",
                "server": srv.name,
                "clsid": srv.clsid,
                "finding": "Permissive access permission on OOP server",
                "detail": f"Access SDDL grants wide access. "
                          f"Service: {srv.service_name or 'none'}",
                "sddl": srv.access_permission or srv.app_id_access_permission,
            })

        # Remote activation
        if srv.supports_remote_activation:
            findings.append({
                "severity": "HIGH",
                "server": srv.name,
                "clsid": srv.clsid,
                "finding": "Remote activation supported (DCOM)",
                "detail": "Server supports remote activation, expanding DCOM attack surface.",
            })

        # Trusted marshaller
        if srv.trusted_marshaller:
            findings.append({
                "severity": "MEDIUM",
                "server": srv.name,
                "clsid": srv.clsid,
                "finding": "Trusted marshaller flag set",
                "detail": "Server is a trusted marshaller, may bypass marshalling security.",
            })

        # Low service protection
        if srv.is_service and srv.service_protection_level == 0 and srv.runs_as_system:
            findings.append({
                "severity": "MEDIUM",
                "server": srv.name,
                "clsid": srv.clsid,
                "finding": "SYSTEM service with no protection level",
                "detail": f"Service '{srv.service_name}' runs as SYSTEM with "
                          f"ServiceProtectionLevel=0 (unprotected).",
            })

        # Low-IL access
        if srv.has_low_il_access or srv.has_low_il_launch:
            findings.append({
                "severity": "MEDIUM",
                "server": srv.name,
                "clsid": srv.clsid,
                "finding": "Accessible from low integrity level",
                "detail": f"HasLowILAccess={srv.has_low_il_access}, "
                          f"HasLowILLaunch={srv.has_low_il_launch}. "
                          f"Sandbox escape potential.",
            })

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: sev_order.get(f["severity"], 99))

    if args.json:
        emit_json({
            "target": target,
            "server_count": len(servers),
            "finding_count": len(findings),
            "findings": findings,
        })
        return

    print(f"{'=' * 80}")
    print(f"COM SECURITY AUDIT: {target}")
    print(f"{'=' * 80}")
    print(f"  Servers:  {len(servers)}")
    print(f"  Findings: {len(findings)}")
    print()

    for i, finding in enumerate(findings, 1):
        print(f"  [{finding['severity']}] #{i}: {finding['finding']}")
        print(f"    Server: {finding['server']}  (CLSID: {finding['clsid']})")
        print(f"    {finding['detail']}")
        print()


if __name__ == "__main__":
    main()
