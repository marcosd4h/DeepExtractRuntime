"""Unified finding schema for normalizing results across all vulnerability scanners.

Provides a common ``Finding`` dataclass and adapter functions that convert
taint-analysis, memory-corruption-detector, and logic-vulnerability-detector
JSON outputs into a uniform shape.  This enables cross-scanner merging,
deduplication, and ranking via :mod:`helpers.finding_merge`.
"""

from __future__ import annotations

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
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None and v != [] and v != {}}

    @property
    def dedup_key(self) -> str:
        """Key for deduplication: same function + same sink = one finding."""
        fid = self.function_id if self.function_id is not None else self.function_name
        return f"{fid}::{self.sink}::{self.source_category}"


def from_taint_finding(finding: dict, func_info: dict | None = None) -> Finding:
    """Convert a taint-analysis finding dict to a unified Finding."""
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
    )


def from_memory_finding(finding: dict) -> Finding:
    """Convert a MemCorruptionFinding dict to a unified Finding."""
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


def from_logic_finding(finding: dict) -> Finding:
    """Convert a LogicFinding dict to a unified Finding."""
    cat = finding.get("category", "")
    return Finding(
        function_name=finding.get("function_name", "?"),
        function_id=finding.get("function_id"),
        source_type="logic_vulnerability",
        source_category=cat,
        sink=finding.get("dangerous_op", cat),
        sink_category=finding.get("dangerous_op_category", "uncategorized_dangerous"),
        severity=finding.get("severity", "MEDIUM"),
        score=finding.get("score", 0.3),
        guards=[g for g in finding.get("guards_on_path", [])],
        path=finding.get("path", []),
        evidence_lines=finding.get("evidence_lines", []),
        summary=finding.get("summary", ""),
        extra=finding.get("extra", {}),
    )


def from_verified_finding(verified: dict) -> Finding:
    """Convert a VerificationResult dict to a unified Finding.

    Works for both memory-corruption and logic-vulnerability verified outputs.
    """
    inner = verified.get("finding", {})
    source = inner.get("dangerous_api_category") or inner.get("dangerous_op_category")
    is_logic = "dangerous_op" in inner

    base = from_logic_finding(inner) if is_logic else from_memory_finding(inner)
    base.verification_status = verified.get("confidence", "UNCERTAIN")
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
