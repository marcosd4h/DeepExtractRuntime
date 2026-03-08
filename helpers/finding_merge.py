"""Merge, deduplicate, and rank findings across multiple scanner outputs.

Works with the unified :class:`~helpers.finding_schema.Finding` dataclass to
combine results from taint-analysis, memory-corruption-detector, and
logic-vulnerability-detector into a single prioritized list.
"""

from __future__ import annotations

from typing import Any

from .finding_schema import Finding, normalize_scanner_output


def merge_findings(*scanner_outputs: tuple[dict, str]) -> list[Finding]:
    """Merge findings from multiple scanner outputs.

    Each argument is a ``(data_dict, source_type)`` tuple where
    ``source_type`` is one of ``"taint"``, ``"memory_corruption"``,
    or ``"logic_vulnerability"``.

    Returns a deduplicated, score-sorted list of :class:`Finding` objects.
    """
    all_findings: list[Finding] = []
    for data, source_type in scanner_outputs:
        if data:
            all_findings.extend(normalize_scanner_output(data, source_type))
    return deduplicate(all_findings)


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Remove duplicate findings (same function + same sink + same category).

    When duplicates exist, keep the one with the highest score.
    """
    best: dict[str, Finding] = {}
    for f in findings:
        key = f.dedup_key
        existing = best.get(key)
        if existing is None or f.score > existing.score:
            best[key] = f
    return rank(list(best.values()))


def rank(findings: list[Finding]) -> list[Finding]:
    """Sort findings by composite score (descending).

    Uses exploitability_score if available, otherwise raw score.
    Severity is used as a tiebreaker.
    """
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    return sorted(
        findings,
        key=lambda f: (
            f.exploitability_score if f.exploitability_score is not None else f.score,
            severity_order.get(f.severity, 0),
        ),
        reverse=True,
    )


def findings_summary(findings: list[Finding]) -> dict[str, Any]:
    """Produce a summary dict from a list of findings."""
    return {
        "total": len(findings),
        "by_severity": {
            sev: sum(1 for f in findings if f.severity == sev)
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        },
        "by_source": {
            src: sum(1 for f in findings if f.source_type == src)
            for src in ("taint", "memory_corruption", "logic_vulnerability")
        },
        "top_score": findings[0].score if findings else 0.0,
        "top_function": findings[0].function_name if findings else "N/A",
    }


def to_json(findings: list[Finding]) -> list[dict]:
    """Convert a list of findings to JSON-serializable dicts."""
    return [f.to_dict() for f in findings]
