"""Unified finding schema for normalizing results across all vulnerability scanners.

Provides a common ``Finding`` dataclass and adapter functions that convert
ai-memory-corruption-scanner and ai-logic-scanner JSON outputs into a
uniform shape.  This enables cross-scanner merging,
deduplication, and ranking via :mod:`helpers.finding_merge`.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import asdict, dataclass, field
from typing import Any, Optional


@dataclass
class Finding:
    """Scanner-agnostic vulnerability finding."""

    function_name: str
    function_id: int | None = None
    module: str = ""
    source_type: str = ""
    source_category: str = ""
    sink: str = ""
    sink_category: str = ""
    severity: str = "MEDIUM"
    score: float = 0.0
    exploitability_score: float | None = None
    exploitability_rating: str | None = None
    verification_status: str | None = None
    guards: list[dict] = field(default_factory=list)
    path: list[str] = field(default_factory=list)
    evidence_lines: list[str] = field(default_factory=list)
    summary: str = ""
    verification_subgraph: dict = field(default_factory=dict)
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None and v != [] and v != {}}

    @property
    def dedup_key(self) -> str:
        """Key for deduplication: same function + same sink = one finding."""
        fid = self.function_id if self.function_id is not None else self.function_name
        return f"{fid}::{self.sink}::{self.source_category}"

    @property
    def path_signature(self) -> str:
        """Hash of the sorted path elements, for path-aware dedup."""
        canon = "|".join(sorted(self.path)) if self.path else ""
        return hashlib.sha256(canon.encode()).hexdigest()[:16]


def graduated_reachability_score(entry_type: str | None, hops: int) -> float:
    """Compute a graduated reachability score based on entry type and hop distance.

    Closer to the entry point = higher score.  Different entry types
    start with different base values reflecting their typical attack
    accessibility.

    Returns a float in ``[0.0, 1.0]``.
    """
    base_map = {
        "rpc_handler": 1.0,
        "com_method": 0.9,
        "export": 0.75,
        "entry_point": 0.8,
    }
    base = base_map.get(entry_type or "", 0.4)
    hop_factor = 1.0 / math.sqrt(max(hops, 1) + 1)
    if entry_type in (None, "internal"):
        base = min(base, 0.6)
    return min(base * hop_factor, 1.0)


def from_taint_finding(finding: dict, func_info: dict | None = None) -> Finding:
    """Convert a taint finding dict to a unified Finding."""
    fi = func_info or {}
    return Finding(
        function_name=fi.get("function_name", finding.get("param_name", "?")),
        function_id=fi.get("function_id"),
        module=fi.get("module_name", ""),
        source_type="taint",
        source_category=finding.get("sink_category", ""),
        sink=finding.get("sink", "?"),
        sink_category=finding.get("sink_category", "uncategorized_dangerous"),
        severity=finding.get("severity", "MEDIUM"),
        score=finding.get("score", 0.3),
        guards=finding.get("guards", []),
        path=finding.get("path", []),
        summary=f"Tainted {finding.get('param_name', '?')} reaches {finding.get('sink', '?')}",
        verification_subgraph=finding.get("verification_subgraph", {}),
    )


def from_memory_finding(finding: dict) -> Finding:
    """Convert a memory corruption finding dict to a unified Finding.

    Handles both the AI scanner output format (``vulnerability_type``,
    ``affected_functions``, ``evidence.code_lines``) and the legacy regex
    scanner format (``category``, ``function_name``, ``evidence_lines``).
    """
    if "vulnerability_type" in finding:
        return _from_ai_memory_finding(finding)

    cat = finding.get("category", "")
    return Finding(
        function_name=finding.get("function_name", "?"),
        function_id=finding.get("function_id"),
        source_type="memory_corruption",
        source_category=cat,
        sink=finding.get("dangerous_api", cat),
        sink_category=finding.get("dangerous_api_category", "memory_unsafe"),
        severity=finding.get("severity", "MEDIUM"),
        score=finding.get("score", 0.3),
        evidence_lines=finding.get("evidence_lines", []),
        summary=finding.get("summary", ""),
        extra=finding.get("extra", {}),
    )


def _from_ai_memory_finding(finding: dict) -> Finding:
    """Convert an AI memory corruption scanner finding to a unified Finding.

    AI scanner output schema::

        {
            "vulnerability_type": "integer_overflow_before_allocation",
            "cwe_id": "CWE-190",
            "affected_functions": ["Func1", "Func2"],
            "entry_point": "EntryPoint",
            "call_chain": ["EntryPoint", "Func1", "Func2"],
            "description": "...",
            "evidence": {"code_lines": [...], "assembly_confirmation": "..."},
            "data_flow": "...",
            "exploitation_assessment": "...",
            "severity_assessment": "CRITICAL",
            "mitigations_present": [...],
            "guards_on_path": [...]
        }
    """
    affected = finding.get("affected_functions", [])
    primary_func = affected[0] if affected else finding.get("entry_point", "?")
    evidence = finding.get("evidence", {})
    code_lines = evidence.get("code_lines", [])
    asm_confirmation = evidence.get("assembly_confirmation", "")

    severity_raw = finding.get("severity_assessment", "MEDIUM")
    severity = severity_raw.split()[0].upper() if severity_raw else "MEDIUM"
    if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        severity = "MEDIUM"

    return Finding(
        function_name=primary_func,
        source_type="memory_corruption",
        source_category=finding.get("vulnerability_type", ""),
        sink=finding.get("vulnerability_type", ""),
        sink_category="memory_unsafe",
        severity=severity,
        score={"CRITICAL": 0.95, "HIGH": 0.8, "MEDIUM": 0.5, "LOW": 0.2}.get(severity, 0.5),
        guards=[{"description": g} for g in finding.get("guards_on_path", [])],
        path=finding.get("call_chain", []),
        evidence_lines=code_lines + ([asm_confirmation] if asm_confirmation else []),
        summary=finding.get("description", ""),
        verification_subgraph=finding.get("verification_subgraph", {}),
        extra={
            "cwe_id": finding.get("cwe_id", ""),
            "entry_point": finding.get("entry_point", ""),
            "data_flow": finding.get("data_flow", ""),
            "exploitation_assessment": finding.get("exploitation_assessment", ""),
            "mitigations_present": finding.get("mitigations_present", []),
            "affected_functions": affected,
        },
    )


def from_logic_finding(finding: dict) -> Finding:
    """Convert a logic finding dict to a unified Finding.

    Handles both the AI logic scanner output format (``vulnerability_type``,
    ``affected_functions``, ``evidence.code_lines``) and the legacy hint
    generator format (``category``, ``function_name``, ``evidence_lines``).
    """
    if "vulnerability_type" in finding:
        return _from_ai_logic_finding(finding)
    # Legacy format from hint generators
    return Finding(
        function_name=finding.get("function_name", "?"),
        source_type="logic_vulnerability",
        source_category=finding.get("category", ""),
        sink=finding.get("dangerous_op", ""),
        sink_category="logic_unsafe",
        severity=finding.get("severity", "MEDIUM"),
        score=finding.get("score", 0.0),
        guards=[g for g in finding.get("guards_on_path", [])],
        path=finding.get("path", []),
        evidence_lines=finding.get("evidence_lines", []),
        summary=finding.get("summary", ""),
    )


def _from_ai_logic_finding(finding: dict) -> Finding:
    """Convert an AI logic scanner finding to a unified Finding.

    AI scanner output schema::

        {
            "vulnerability_type": "auth_bypass_missing_check",
            "cwe_id": "CWE-862",
            "affected_functions": ["Func1", "Func2"],
            "entry_point": "EntryPoint",
            "call_chain": ["EntryPoint", "Func1", "Func2"],
            "description": "...",
            "evidence": {"code_lines": [...], "assembly_confirmation": "..."},
            "data_flow": "...",
            "exploitation_assessment": "...",
            "severity_assessment": "HIGH",
            "mitigations_present": [...],
            "guards_on_path": [...]
        }
    """
    affected = finding.get("affected_functions", [])
    primary_func = affected[0] if affected else finding.get("entry_point", "?")
    evidence = finding.get("evidence", {})
    code_lines = evidence.get("code_lines", [])
    asm_confirmation = evidence.get("assembly_confirmation", "")
    severity_raw = finding.get("severity_assessment", "MEDIUM")
    severity = severity_raw.split()[0].upper() if severity_raw else "MEDIUM"
    if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        severity = "MEDIUM"
    return Finding(
        function_name=primary_func,
        source_type="logic_vulnerability",
        source_category=finding.get("vulnerability_type", ""),
        sink=finding.get("vulnerability_type", ""),
        sink_category="logic_unsafe",
        severity=severity,
        score={"CRITICAL": 0.95, "HIGH": 0.8, "MEDIUM": 0.5, "LOW": 0.2}.get(severity, 0.5),
        guards=[{"description": g} for g in finding.get("guards_on_path", [])],
        path=finding.get("call_chain", []),
        evidence_lines=code_lines + ([asm_confirmation] if asm_confirmation else []),
        summary=finding.get("description", ""),
        verification_subgraph=finding.get("verification_subgraph", {}),
        extra={
            "cwe_id": finding.get("cwe_id", ""),
            "entry_point": finding.get("entry_point", ""),
            "data_flow": finding.get("data_flow", ""),
            "exploitation_assessment": finding.get("exploitation_assessment", ""),
            "mitigations_present": finding.get("mitigations_present", []),
            "affected_functions": affected,
        },
    )


def from_verified_finding(verified: dict) -> Finding:
    """Convert a VerificationResult dict to a unified Finding.

    Works for both memory-corruption and logic-vulnerability verified outputs.
    Accepts ``verdict`` (new 2-gate format) or ``confidence`` (legacy format).
    """
    inner = verified.get("finding", {})
    is_logic = "dangerous_op" in inner

    base = from_logic_finding(inner) if is_logic else from_memory_finding(inner)
    base.verification_status = verified.get("verdict") or verified.get("confidence", "UNCERTAIN")
    base.score = verified.get("verified_score", base.score)
    return base


def normalize_scanner_output(data: dict, source_type: str) -> list[Finding]:
    """Extract findings from a scanner's JSON output and normalize them.

    Handles both raw findings lists and verified findings lists.
    """
    findings: list[Finding] = []

    raw = data.get("findings", [])
    verified = data.get("verified_findings", [])
    func_info = data.get("function", {})

    if verified:
        for vf in verified:
            f = from_verified_finding(vf)
            f.module = func_info.get("module_name", f.module)
            findings.append(f)
    elif raw:
        for item in raw:
            if source_type == "taint":
                f = from_taint_finding(item, func_info)
            elif source_type == "memory_corruption":
                f = from_memory_finding(item)
            elif source_type == "logic_vulnerability":
                f = from_logic_finding(item)
            else:
                continue
            f.module = func_info.get("module_name", f.module)
            findings.append(f)

    forward = data.get("forward_findings", [])
    if forward and not raw and not verified:
        for item in forward:
            f = from_taint_finding(item, func_info)
            findings.append(f)

    return findings
