#!/usr/bin/env python3
"""RPC-specific security audit combining index data with decompiled code.

Checks each RPC handler for:
- Missing impersonation (RpcImpersonateClient)
- Missing revert (RpcRevertToSelf)
- Privileged operations without identity checks (transitive to depth N)
- Complex NDR type handling (serialization surface)
- Remote-reachable interfaces with potential weak security
- UAC/elevation handlers missing caller identity verification

Usage:
    python audit_rpc_security.py <db_path>
    python audit_rpc_security.py <db_path> --depth 5
    python audit_rpc_security.py <db_path> --json
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import deque
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

_DEFAULT_DEPTH = 3

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

_IDENTITY_CHECK_APIS = {
    "GetTokenInformation", "CheckTokenMembership", "NtQueryInformationToken",
    "ZwQueryInformationToken", "CheckTokenCapability",
    "GetSidSubAuthority", "EqualSid", "CheckTokenForSiloMembership",
    "RtlCheckTokenMembershipEx",
}

_ELEVATION_PROCEDURE_PATTERNS = re.compile(
    r"(?i)(?:LaunchAdmin|GetElevatedToken|GetTokenFor|OverrideDesktop"
    r"|DisableElevation|EnableElevation|ForceElevationPrompt"
    r"|LaunchProcessWithIdentity)",
)


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


def _strip_imp(name: str) -> str:
    return re.sub(r"^(?:__imp_|_imp_)", "", name)


def _get_direct_callees(func_record, all_funcs: dict) -> set[str]:
    """Extract cleaned API names from a function's outbound xrefs."""
    apis: set[str] = set()
    outbound = parse_json_safe(func_record.simple_outbound_xrefs) or []
    for xref in outbound:
        if isinstance(xref, dict):
            apis.add(_strip_imp(xref.get("function_name", "")))
    return apis


def _collect_transitive_calls(
    root_name: str,
    all_funcs: dict,
    depth: int = _DEFAULT_DEPTH,
) -> tuple[set[str], set[str]]:
    """BFS over internal call graph, returning (all_apis, internal_visited).

    Traverses callees up to *depth* hops.  Only follows edges into functions
    that exist in *all_funcs* (i.e. module-internal).  Returns the union of
    all external API names encountered along the way plus the set of internal
    function names visited.
    """
    all_apis: set[str] = set()
    visited: set[str] = set()
    queue: deque[tuple[str, int]] = deque()
    queue.append((root_name, 0))

    while queue:
        fname, d = queue.popleft()
        if fname in visited:
            continue
        visited.add(fname)

        func = all_funcs.get(fname)
        if func is None:
            continue

        callees = _get_direct_callees(func, all_funcs)
        all_apis |= callees

        if d < depth:
            for callee in callees:
                if callee in all_funcs and callee not in visited:
                    queue.append((callee, d + 1))

    return all_apis, visited


def _effective_risk_tier(iface: RpcInterface, proc_name: str) -> str:
    """Return the interface's risk tier, promoted for elevation procedures."""
    base = iface.risk_tier
    if _ELEVATION_PROCEDURE_PATTERNS.search(proc_name):
        if base in ("medium", "low"):
            return "high"
    return base


def audit_module(db_path: str, *, depth: int = _DEFAULT_DEPTH) -> tuple[list[RpcFinding], int]:
    """Run RPC security audit on a module.

    Returns (findings, analysis_depth) so callers can report the traversal depth.
    """
    idx = require_rpc_index()
    findings: list[RpcFinding] = []

    with db_error_handler(db_path, "RPC security audit"):
        with open_individual_analysis_db(db_path) as db:
            fi = db.get_file_info()
            module_name = fi.file_name if fi else ""
            if not module_name:
                return findings, depth

            ifaces = idx.get_interfaces_for_module(module_name)
            if not ifaces:
                return findings, depth

            procedures = idx.get_procedures_for_module(module_name)
            all_funcs = {f.function_name: f for f in db.get_all_functions() if f.function_name}

            has_auth_register = False
            for func in all_funcs.values():
                for api in _get_direct_callees(func, all_funcs):
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
                risk_tier = _effective_risk_tier(iface, proc_name) if iface else "low"

                transitive_apis, visited = _collect_transitive_calls(
                    proc_name, all_funcs, depth=depth,
                )

                has_impersonate = bool(transitive_apis & _IMPERSONATION_APIS)
                has_revert = bool(transitive_apis & _REVERT_APIS)
                priv_ops = transitive_apis & _PRIV_OPS

                if has_impersonate and not has_revert:
                    findings.append(RpcFinding(
                        function_name=proc_name,
                        interface_id=iface_id,
                        risk_tier=risk_tier,
                        finding_type="rpc_missing_revert",
                        severity=0.75,
                        description="RpcImpersonateClient without matching RpcRevertToSelf",
                        details=[f"Called: {', '.join(transitive_apis & _IMPERSONATION_APIS)}"],
                    ))

                if priv_ops and not has_impersonate:
                    sev = 0.85 if risk_tier in ("critical", "high") else 0.65
                    findings.append(RpcFinding(
                        function_name=proc_name,
                        interface_id=iface_id,
                        risk_tier=risk_tier,
                        finding_type="rpc_handler_no_impersonation",
                        severity=sev,
                        description=(
                            f"Privileged operations reachable (depth {depth}) "
                            f"without client impersonation check"
                        ),
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

                is_elevation_proc = _ELEVATION_PROCEDURE_PATTERNS.search(proc_name)
                if is_elevation_proc:
                    has_identity_check = bool(transitive_apis & _IDENTITY_CHECK_APIS)
                    if not has_identity_check:
                        sev = 0.90 if risk_tier in ("critical", "high") else 0.80
                        findings.append(RpcFinding(
                            function_name=proc_name,
                            interface_id=iface_id,
                            risk_tier=risk_tier,
                            finding_type="rpc_elevation_no_identity_check",
                            severity=sev,
                            description=(
                                f"Elevation/token handler reachable from Medium IL "
                                f"with no caller identity verification (depth {depth})"
                            ),
                            details=[
                                f"Searched {len(visited)} functions for: "
                                f"{', '.join(sorted(_IDENTITY_CHECK_APIS)[:4])}...",
                            ],
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
    return findings, depth


def main() -> None:
    parser = argparse.ArgumentParser(description="RPC security audit.")
    parser.add_argument("db_path", help="Path to module analysis DB")
    parser.add_argument("--depth", type=int, default=_DEFAULT_DEPTH,
                        help=f"Transitive call-graph traversal depth (default {_DEFAULT_DEPTH})")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = safe_parse_args(parser)

    findings, analysis_depth = audit_module(args.db_path, depth=args.depth)

    if args.json:
        result: dict[str, Any] = {
            "db_path": args.db_path,
            "analysis_depth": analysis_depth,
            "finding_count": len(findings),
            "findings": [f.to_dict() for f in findings],
        }
        if not findings:
            result["caveat"] = (
                f"0 findings from transitive analysis (depth {analysis_depth}). "
                f"Run /logic-scan or /taint for deeper guard-aware analysis "
                f"of handler call chains."
            )
        emit_json(result)
        return

    print(f"{'=' * 80}")
    print(f"RPC SECURITY AUDIT: {len(findings)} findings  "
          f"(call-graph depth: {analysis_depth})")
    print(f"{'=' * 80}\n")

    if not findings:
        print(f"  No findings at depth {analysis_depth}.")
        print(f"  NOTE: Run /logic-scan or /taint for deeper guard-aware")
        print(f"        analysis of handler call chains.\n")

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
