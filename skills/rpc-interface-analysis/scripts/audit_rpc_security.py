#!/usr/bin/env python3
"""RPC-specific security audit combining index data with decompiled code.

Checks each RPC handler for:
- Missing impersonation (RpcImpersonateClient)
- Missing revert (RpcRevertToSelf)
- Privileged operations without identity checks
- Complex NDR type handling (serialization surface)
- Remote-reachable interfaces with potential weak security

Usage:
    python audit_rpc_security.py <db_path>
    python audit_rpc_security.py <db_path> --json
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT_DIR))

from _common import (
    RpcInterface,
    db_error_handler,
    emit_json,
    open_individual_analysis_db,
    parse_json_safe,
    require_rpc_index,
)
from helpers.errors import safe_parse_args

_IMPERSONATION_APIS = {"RpcImpersonateClient", "CoImpersonateClient", "ImpersonateNamedPipeClient"}
_REVERT_APIS = {"RpcRevertToSelf", "CoRevertToSelf", "RevertToSelf"}
_AUTH_REGISTER_APIS = {"RpcServerRegisterAuthInfo", "RpcServerRegisterAuthInfoA", "RpcServerRegisterAuthInfoW"}
_PRIV_OPS = {
    "CreateProcessW", "CreateProcessA", "CreateProcessAsUserW", "CreateProcessAsUserA",
    "OpenProcessToken", "AdjustTokenPrivileges", "SetTokenInformation",
    "RegSetValueExW", "RegCreateKeyExW", "RegDeleteKeyW",
    "CreateFileW", "DeleteFileW", "MoveFileExW",
    "SetSecurityInfo", "SetNamedSecurityInfoW",
    "NtCreateFile", "NtOpenProcess", "NtOpenKey",
}


@dataclass
class RpcFinding:
    function_name: str
    interface_id: str
    risk_tier: str
    finding_type: str
    severity: float
    description: str
    details: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "function_name": self.function_name,
            "interface_id": self.interface_id,
            "risk_tier": self.risk_tier,
            "finding_type": self.finding_type,
            "severity": self.severity,
            "description": self.description,
            "details": self.details,
        }


def audit_module(db_path: str) -> list[RpcFinding]:
    """Run RPC security audit on a module."""
    idx = require_rpc_index()
    findings: list[RpcFinding] = []

    with db_error_handler(db_path, "RPC security audit"):
        with open_individual_analysis_db(db_path) as db:
            fi = db.get_file_info()
            module_name = fi.file_name if fi else ""
            if not module_name:
                return findings

            ifaces = idx.get_interfaces_for_module(module_name)
            if not ifaces:
                return findings

            procedures = idx.get_procedures_for_module(module_name)
            all_funcs = {f.function_name: f for f in db.get_all_functions() if f.function_name}

            has_auth_register = False
            for func in all_funcs.values():
                outbound = parse_json_safe(func.simple_outbound_xrefs) or []
                for xref in outbound:
                    if isinstance(xref, dict):
                        api = re.sub(r"^(?:__imp_|_imp_)", "", xref.get("function_name", ""))
                        if api in _AUTH_REGISTER_APIS:
                            has_auth_register = True
                            break
                if has_auth_register:
                    break

            for proc_name in procedures:
                func = all_funcs.get(proc_name)
                if not func:
                    continue

                iface = idx.get_interface_for_procedure(module_name, proc_name)
                iface_id = iface.interface_id if iface else ""
                risk_tier = iface.risk_tier if iface else "low"

                outbound = parse_json_safe(func.simple_outbound_xrefs) or []
                called_apis: set[str] = set()
                for xref in outbound:
                    if isinstance(xref, dict):
                        api = re.sub(r"^(?:__imp_|_imp_)", "", xref.get("function_name", ""))
                        called_apis.add(api)

                has_impersonate = bool(called_apis & _IMPERSONATION_APIS)
                has_revert = bool(called_apis & _REVERT_APIS)
                priv_ops = called_apis & _PRIV_OPS

                if has_impersonate and not has_revert:
                    findings.append(RpcFinding(
                        function_name=proc_name,
                        interface_id=iface_id,
                        risk_tier=risk_tier,
                        finding_type="rpc_missing_revert",
                        severity=0.75,
                        description=f"RpcImpersonateClient without matching RpcRevertToSelf",
                        details=[f"Called: {', '.join(called_apis & _IMPERSONATION_APIS)}"],
                    ))

                if priv_ops and not has_impersonate:
                    sev = 0.85 if risk_tier in ("critical", "high") else 0.65
                    findings.append(RpcFinding(
                        function_name=proc_name,
                        interface_id=iface_id,
                        risk_tier=risk_tier,
                        finding_type="rpc_handler_no_impersonation",
                        severity=sev,
                        description="Privileged operations without client impersonation check",
                        details=[f"Privileged APIs: {', '.join(sorted(priv_ops)[:5])}"],
                    ))

                if iface and iface.has_complex_types:
                    decompiled = func.decompiled_code or ""
                    if re.search(r"(?:memcpy|memmove|RtlCopyMemory|CopyMemory)", decompiled):
                        findings.append(RpcFinding(
                            function_name=proc_name,
                            interface_id=iface_id,
                            risk_tier=risk_tier,
                            finding_type="rpc_complex_type_memcpy",
                            severity=0.70,
                            description="Handler with complex NDR types performs memory copy",
                            details=[f"NDR types: {', '.join(iface.complex_types[:3])}"],
                        ))

            for iface in ifaces:
                if iface.is_remote_reachable and not has_auth_register:
                    findings.append(RpcFinding(
                        function_name="(interface-level)",
                        interface_id=iface.interface_id,
                        risk_tier="critical",
                        finding_type="rpc_remote_no_auth",
                        severity=0.90,
                        description="Remote-reachable interface without RpcServerRegisterAuthInfo",
                        details=[f"Protocols: {', '.join(sorted(iface.protocols))}"],
                    ))

    findings.sort(key=lambda f: f.severity, reverse=True)
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="RPC security audit.")
    parser.add_argument("db_path", help="Path to module analysis DB")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = safe_parse_args(parser)

    findings = audit_module(args.db_path)

    if args.json:
        emit_json({
            "db_path": args.db_path,
            "finding_count": len(findings),
            "findings": [f.to_dict() for f in findings],
        })
        return

    print(f"{'=' * 80}")
    print(f"RPC SECURITY AUDIT: {len(findings)} findings")
    print(f"{'=' * 80}\n")

    for i, f in enumerate(findings, 1):
        print(f"  [{i}] {f.finding_type} (severity: {f.severity:.2f}, tier: {f.risk_tier})")
        print(f"      Function:  {f.function_name}")
        print(f"      Interface: {f.interface_id}")
        print(f"      {f.description}")
        for detail in f.details:
            print(f"      > {detail}")
        print()


if __name__ == "__main__":
    main()
