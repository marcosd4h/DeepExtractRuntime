"""Cross-report finding comparison for AI vulnerability scanners.

Discovers previous scan reports, loads structured `.findings.json`
companion files, and compares findings across runs to identify new,
recurring, missed, and changed findings.

Public API:
    discover_reports(reports_dir, scan_type=None) -> list[ReportMeta]
    load_findings_json(path) -> dict
    compare_findings(current, previous) -> ComparisonResult
    format_comparison_section(result, previous_report_path) -> str
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


__all__ = [
    "ReportMeta",
    "ComparisonResult",
    "FindingMatch",
    "discover_reports",
    "load_findings_json",
    "compare_findings",
    "format_comparison_section",
]


FINDINGS_JSON_SUFFIX = ".findings.json"

_SCAN_TYPE_PREFIXES = {
    "logic": "ai_logic_scan_",
    "memory": "ai_memory_scan_",
    "taint": "ai_taint_scan_",
}


@dataclass
class ReportMeta:
    """Lightweight metadata for a discovered report."""

    findings_json_path: Path
    md_path: Optional[Path]
    scan_type: str
    timestamp_str: str

    @property
    def label(self) -> str:
        stem = self.findings_json_path.stem.replace(".findings", "")
        return stem


@dataclass
class FindingMatch:
    """A pair of matched findings across two reports."""

    current: dict
    previous: dict
    severity_changed: bool = False
    verdict_changed: bool = False
    remediation_changed: bool = False
    vulnerability_class_changed: bool = False


@dataclass
class ComparisonResult:
    """Result of comparing two scan reports."""

    current_report: str = ""
    previous_report: str = ""
    recurring: list[FindingMatch] = field(default_factory=list)
    new_findings: list[dict] = field(default_factory=list)
    missed: list[dict] = field(default_factory=list)
    severity_changes: list[FindingMatch] = field(default_factory=list)
    verdict_conflicts: list[FindingMatch] = field(default_factory=list)
    remediation_changes: list[FindingMatch] = field(default_factory=list)
    vulnerability_class_changes: list[FindingMatch] = field(default_factory=list)
    coverage_delta: dict = field(default_factory=dict)
    threat_model_changes: dict = field(default_factory=dict)


def _extract_timestamp(filename: str) -> str:
    """Extract YYYYMMDD_HHMM timestamp from a report filename."""
    m = re.search(r"(\d{8}_\d{4})", filename)
    return m.group(1) if m else ""


def _infer_scan_type(filename: str) -> str:
    """Infer scan type from filename prefix."""
    for stype, prefix in _SCAN_TYPE_PREFIXES.items():
        if filename.startswith(prefix):
            return stype
    return "unknown"


def discover_reports(
    reports_dir: Path | str,
    scan_type: Optional[str] = None,
) -> list[ReportMeta]:
    """Find `.findings.json` files in a reports directory.

    Returns reports sorted by timestamp descending (newest first).

    Parameters
    ----------
    reports_dir:
        Path to ``extracted_code/<module>/reports/``.
    scan_type:
        If provided, filter to only ``logic``, ``memory``, or ``taint``.
    """
    reports_dir = Path(reports_dir)
    if not reports_dir.is_dir():
        return []

    results: list[ReportMeta] = []
    for p in reports_dir.iterdir():
        if not p.name.endswith(FINDINGS_JSON_SUFFIX):
            continue

        stem = p.name[: -len(FINDINGS_JSON_SUFFIX)]
        inferred_type = _infer_scan_type(stem)

        if scan_type and inferred_type != scan_type:
            continue

        md_path = reports_dir / f"{stem}.md"
        results.append(
            ReportMeta(
                findings_json_path=p,
                md_path=md_path if md_path.exists() else None,
                scan_type=inferred_type,
                timestamp_str=_extract_timestamp(stem),
            )
        )

    results.sort(key=lambda r: r.timestamp_str, reverse=True)
    return results


def load_findings_json(path: Path | str) -> dict:
    """Load and validate a ``.findings.json`` companion file.

    Raises
    ------
    FileNotFoundError
        If the path does not exist.
    json.JSONDecodeError
        If the file contains invalid JSON.
    ValueError
        If required top-level keys are missing.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Findings JSON not found: {path}")

    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object, got {type(data).__name__}")

    required = {"scan_type", "module"}
    missing = required - set(data.keys())
    if missing:
        raise ValueError(f"Missing required keys in {path.name}: {missing}")

    return data


def _finding_match_key(finding: dict) -> str:
    """Generate a match key for cross-report comparison.

    Uses vulnerability_type + primary_function for loose matching
    that survives ID renumbering across scans.
    """
    vtype = finding.get("vulnerability_type", "")
    pfunc = finding.get("primary_function", "")
    if not pfunc:
        chain = finding.get("call_chain", [])
        pfunc = chain[-1] if chain else ""
    return f"{vtype}::{pfunc}".lower()


def _all_findings(report: dict) -> list[dict]:
    """Collect all findings (TP + FP) from a report."""
    tp = report.get("true_positives", [])
    fp = report.get("false_positives", [])
    return tp + fp


def _diff_field(current: dict, previous: dict, field_name: str) -> bool:
    """Check if a field differs between two findings."""
    c_val = current.get(field_name, "")
    p_val = previous.get(field_name, "")
    if not c_val and not p_val:
        return False
    return str(c_val).strip() != str(p_val).strip()


def _compute_coverage_delta(current: dict, previous: dict) -> dict:
    """Compute differences in analysis coverage between two reports."""
    c_funcs = set(current.get("functions_analyzed", []))
    p_funcs = set(previous.get("functions_analyzed", []))

    c_cov = current.get("coverage", {})
    p_cov = previous.get("coverage", {})

    return {
        "current_only_functions": sorted(c_funcs - p_funcs),
        "previous_only_functions": sorted(p_funcs - c_funcs),
        "current_count": c_cov.get("functions_analyzed_count", len(c_funcs)),
        "previous_count": p_cov.get("functions_analyzed_count", len(p_funcs)),
    }


def _compute_threat_model_changes(current: dict, previous: dict) -> dict:
    """Compare threat model sections between two reports."""
    c_tm = current.get("threat_model", {})
    p_tm = previous.get("threat_model", {})

    if not c_tm or not p_tm:
        return {}

    changes = {}
    for key in ("attacker_model", "privilege", "entry_point_count", "service_type"):
        c_val = c_tm.get(key)
        p_val = p_tm.get(key)
        if c_val != p_val and (c_val is not None and p_val is not None):
            changes[key] = {"current": c_val, "previous": p_val}

    return changes


def compare_findings(current: dict, previous: dict) -> ComparisonResult:
    """Compare findings between two scan reports.

    Matches findings by ``vulnerability_type + primary_function`` to handle
    ID renumbering across runs. Returns a :class:`ComparisonResult` with
    recurring, new, missed, and changed findings.
    """
    result = ComparisonResult(
        current_report=current.get("report_path", ""),
        previous_report=previous.get("report_path", ""),
    )

    c_findings = _all_findings(current)
    p_findings = _all_findings(previous)

    c_by_key: dict[str, dict] = {}
    for f in c_findings:
        c_by_key[_finding_match_key(f)] = f

    p_by_key: dict[str, dict] = {}
    for f in p_findings:
        p_by_key[_finding_match_key(f)] = f

    matched_p_keys: set[str] = set()

    for c_key, c_finding in c_by_key.items():
        if c_key in p_by_key:
            p_finding = p_by_key[c_key]
            matched_p_keys.add(c_key)

            sev_changed = _diff_field(c_finding, p_finding, "severity")
            verdict_changed = _diff_field(c_finding, p_finding, "skeptic_verdict")
            remed_changed = _diff_field(c_finding, p_finding, "remediation")
            vclass_changed = _diff_field(c_finding, p_finding, "vulnerability_class")

            match = FindingMatch(
                current=c_finding,
                previous=p_finding,
                severity_changed=sev_changed,
                verdict_changed=verdict_changed,
                remediation_changed=remed_changed,
                vulnerability_class_changed=vclass_changed,
            )

            result.recurring.append(match)

            if sev_changed:
                result.severity_changes.append(match)
            if verdict_changed:
                result.verdict_conflicts.append(match)
            if remed_changed:
                result.remediation_changes.append(match)
            if vclass_changed:
                result.vulnerability_class_changes.append(match)
        else:
            result.new_findings.append(c_finding)

    for p_key, p_finding in p_by_key.items():
        if p_key not in matched_p_keys:
            result.missed.append(p_finding)

    result.coverage_delta = _compute_coverage_delta(current, previous)
    result.threat_model_changes = _compute_threat_model_changes(current, previous)

    return result


def _finding_one_liner(f: dict) -> str:
    """Format a finding as a single-line summary."""
    fid = f.get("id", "?")
    sev = f.get("severity", "?")
    title = f.get("title", "untitled")
    return f"{fid} ({sev}): {title}"


def format_comparison_section(
    result: ComparisonResult,
    previous_report_path: Optional[str] = None,
    previous_timestamp: Optional[str] = None,
) -> str:
    """Generate a markdown section for cross-report comparison.

    Returns a string suitable for appending to a scan report.
    """
    if not result.previous_report and not previous_report_path:
        return (
            "## Previous Findings Comparison\n\n"
            "First scan of this type for this module — no previous report to compare against.\n"
        )

    prev_ref = previous_report_path or result.previous_report
    prev_ts = f" ({previous_timestamp})" if previous_timestamp else ""

    lines = [
        "## Previous Findings Comparison",
        "",
        f"Compared against: `{prev_ref}`{prev_ts}",
        "",
    ]

    if result.recurring:
        lines.append(f"### Recurring Findings ({len(result.recurring)})")
        lines.append("")
        lines.append("| Current | Previous | Changes |")
        lines.append("|---|---|---|")
        for m in result.recurring:
            c_line = _finding_one_liner(m.current)
            p_line = _finding_one_liner(m.previous)
            changes = []
            if m.severity_changed:
                changes.append(
                    f"severity: {m.previous.get('severity')} -> {m.current.get('severity')}"
                )
            if m.verdict_changed:
                changes.append(
                    f"verdict: {m.previous.get('skeptic_verdict')} -> {m.current.get('skeptic_verdict')}"
                )
            if m.remediation_changed:
                changes.append("remediation changed")
            if m.vulnerability_class_changed:
                changes.append("vulnerability class changed")
            change_str = "; ".join(changes) if changes else "no changes"
            lines.append(f"| {c_line} | {p_line} | {change_str} |")
        lines.append("")

    if result.new_findings:
        lines.append(f"### New Findings ({len(result.new_findings)})")
        lines.append("")
        for f in result.new_findings:
            lines.append(f"- {_finding_one_liner(f)}")
        lines.append("")

    if result.missed:
        lines.append(
            f"### Previously Found, Now Missed ({len(result.missed)})"
        )
        lines.append("")
        for f in result.missed:
            verdict = f.get("skeptic_verdict", "")
            v_note = f" [{verdict}]" if verdict else ""
            lines.append(
                f"- {_finding_one_liner(f)}{v_note} — *not detected in current scan*"
            )
        lines.append("")

    if result.verdict_conflicts:
        lines.append(
            f"### Verdict Conflicts ({len(result.verdict_conflicts)})"
        )
        lines.append("")
        for m in result.verdict_conflicts:
            c_v = m.current.get("skeptic_verdict", "?")
            p_v = m.previous.get("skeptic_verdict", "?")
            lines.append(
                f"- {m.current.get('id', '?')}: {p_v} -> {c_v}"
            )
            p_reason = m.previous.get("skeptic_summary", "")
            c_reason = m.current.get("skeptic_summary", "")
            if p_reason:
                lines.append(f"  - Previous reasoning: {p_reason}")
            if c_reason:
                lines.append(f"  - Current reasoning: {c_reason}")
        lines.append("")

    if result.coverage_delta:
        cd = result.coverage_delta
        prev_only = cd.get("previous_only_functions", [])
        curr_only = cd.get("current_only_functions", [])
        if prev_only or curr_only:
            lines.append("### Coverage Delta")
            lines.append("")
            lines.append(
                f"Functions analyzed: {cd.get('previous_count', '?')} (previous) vs "
                f"{cd.get('current_count', '?')} (current)"
            )
            if curr_only:
                lines.append(f"- Current-only: {', '.join(curr_only)}")
            if prev_only:
                lines.append(f"- Previous-only: {', '.join(prev_only)}")
            lines.append("")

    if not result.recurring and not result.new_findings and not result.missed:
        lines.append("No findings in either report to compare.")
        lines.append("")

    return "\n".join(lines)
