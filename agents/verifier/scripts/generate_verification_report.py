#!/usr/bin/env python3
"""Generate a formal verification report from compare_lifted.py output and agent findings.

Combines automated check results with agent-driven findings into a structured
verification report suitable for review. The report includes a verdict,
evidence for each check, discrepancies found, and recommendations.

Usage:
    python generate_verification_report.py --compare-output compare.json --agent-findings findings.json
    python generate_verification_report.py --compare-output compare.json --agent-findings findings.json --output report.md
    python generate_verification_report.py --compare-output compare.json
    python generate_verification_report.py --compare-output compare.json --json

Input formats:
    compare.json: Output from compare_lifted.py --json
    findings.json: Agent findings in JSON format:
        {
            "findings": [
                {
                    "category": "missing_branch",
                    "severity": "CRITICAL",
                    "description": "...",
                    "assembly_evidence": "...",
                    "lifted_evidence": "...",
                    "recommendation": "..."
                }
            ],
            "notes": "...",
            "manual_verdict": "PASS|FAIL|WARN"  (optional override)
        }
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Import shared utilities
from _common import WORKSPACE_ROOT
from helpers.errors import ErrorCode, emit_error, safe_parse_args
from helpers.json_output import emit_json
from helpers.script_runner import get_workspace_args


def _load_json(path: str) -> dict:
    """Load and parse a JSON file."""
    p = Path(path)
    if not p.is_absolute():
        p = WORKSPACE_ROOT / path
    if not p.exists():
        emit_error(f"File not found: {p}", ErrorCode.NOT_FOUND)
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        emit_error(f"Malformed JSON in {p}: {exc}", ErrorCode.PARSE_ERROR)


def _severity_rank(severity: str) -> int:
    """Convert severity string to numeric rank for sorting."""
    return {
        "CRITICAL": 4,
        "FAIL": 3,
        "HIGH": 3,
        "WARNING": 2,
        "MODERATE": 2,
        "INFO": 1,
        "LOW": 1,
    }.get(severity.upper(), 0)


def generate_markdown_report(
    compare_data: dict,
    agent_findings: dict | None = None,
) -> str:
    """Generate a formal Markdown verification report."""
    lines: list[str] = []

    func_name = compare_data.get("function_name", "(unknown)")
    func_id = compare_data.get("function_id", 0)
    verdict = compare_data.get("verdict", "UNKNOWN")
    confidence = compare_data.get("overall_confidence", 0.0)
    total_checks = compare_data.get("total_checks", 0)
    passed = compare_data.get("passed", 0)
    failed = compare_data.get("failed", 0)

    # Agent findings
    agent_items = []
    agent_notes = ""
    manual_verdict = None
    if agent_findings:
        agent_items = agent_findings.get("findings", [])
        agent_notes = agent_findings.get("notes", "")
        manual_verdict = agent_findings.get("manual_verdict")

    # Combine verdict: agent manual override takes priority
    if manual_verdict:
        final_verdict = manual_verdict.upper()
    elif agent_items:
        # If agent found CRITICAL issues, override to FAIL
        agent_severities = [_severity_rank(f.get("severity", "INFO")) for f in agent_items]
        if any(s >= 4 for s in agent_severities):
            final_verdict = "FAIL"
        elif any(s >= 3 for s in agent_severities):
            final_verdict = "FAIL"
        elif any(s >= 2 for s in agent_severities):
            final_verdict = "WARN" if verdict == "PASS" else verdict
        else:
            final_verdict = verdict
    else:
        final_verdict = verdict

    # Header
    lines.append(f"# Verification Report: {func_name}")
    lines.append("")
    lines.append(f"**Function ID**: {func_id}")
    if compare_data.get("original_function_signature"):
        lines.append(f"**Signature**: `{compare_data['original_function_signature']}`")
    if compare_data.get("original_mangled_name"):
        lines.append(f"**Mangled Name**: `{compare_data['original_mangled_name']}`")
    lines.append(f"**Generated**: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("")

    # Verdict box
    verdict_emoji = {"PASS": "PASS", "FAIL": "FAIL", "WARN": "WARN"}.get(final_verdict, "????")
    lines.append(f"## Verdict: [{verdict_emoji}] {final_verdict}")
    lines.append("")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Overall Confidence | {confidence:.1%} |")
    lines.append(f"| Automated Checks | {passed}/{total_checks} passed |")
    lines.append(f"| Agent Findings | {len(agent_items)} issue(s) |")
    if compare_data.get("asm_instruction_count"):
        lines.append(f"| Assembly Instructions | {compare_data['asm_instruction_count']} |")
    if compare_data.get("lifted_line_count"):
        lines.append(f"| Lifted Code Lines | {compare_data['lifted_line_count']} |")
    lines.append("")

    # Automated check results
    lines.append("## Automated Check Results")
    lines.append("")
    checks = compare_data.get("checks", [])
    if checks:
        lines.append("| # | Check | Result | Expected | Actual | Severity |")
        lines.append("|---|-------|--------|----------|--------|----------|")
        for i, check in enumerate(checks, 1):
            status = "PASS" if check.get("passed") else check.get("severity", "FAIL")
            icon = "+" if check.get("passed") else "X"
            lines.append(
                f"| {i} | {check['name']} | [{icon}] {status} | "
                f"{check.get('expected', '-')} | {check.get('actual', '-')} | "
                f"{check.get('severity', '-')} |"
            )
        lines.append("")

        # Detailed discrepancies
        has_discrepancies = any(check.get("discrepancies") for check in checks)
        if has_discrepancies:
            lines.append("### Discrepancies from Automated Checks")
            lines.append("")
            for check in checks:
                discreps = check.get("discrepancies", [])
                if discreps:
                    lines.append(f"**{check['name']}** ({check.get('severity', 'INFO')})")
                    for d in discreps:
                        lines.append(f"- {d}")
                    lines.append("")
    else:
        lines.append("No automated checks were run.")
        lines.append("")

    # Agent findings
    if agent_items:
        lines.append("## Agent Findings (Manual Verification)")
        lines.append("")

        # Sort by severity
        sorted_findings = sorted(agent_items, key=lambda f: -_severity_rank(f.get("severity", "INFO")))

        for i, finding in enumerate(sorted_findings, 1):
            sev = finding.get("severity", "INFO")
            cat = finding.get("category", "general")
            desc = finding.get("description", "")

            lines.append(f"### Finding #{i}: [{sev}] {cat}")
            lines.append("")
            lines.append(desc)
            lines.append("")

            if finding.get("assembly_evidence"):
                lines.append("**Assembly evidence:**")
                lines.append("```asm")
                lines.append(finding["assembly_evidence"])
                lines.append("```")
                lines.append("")

            if finding.get("lifted_evidence"):
                lines.append("**Lifted code evidence:**")
                lines.append("```cpp")
                lines.append(finding["lifted_evidence"])
                lines.append("```")
                lines.append("")

            if finding.get("recommendation"):
                lines.append(f"**Recommendation:** {finding['recommendation']}")
                lines.append("")

    elif not agent_items:
        lines.append("## Agent Findings (Manual Verification)")
        lines.append("")
        lines.append("No agent findings provided.")
        lines.append("")

    # Notes
    if agent_notes:
        lines.append("## Notes")
        lines.append("")
        lines.append(agent_notes)
        lines.append("")

    # Summary and recommendations
    lines.append("## Summary")
    lines.append("")

    all_issues = []
    for check in checks:
        if not check.get("passed"):
            all_issues.append({
                "source": "automated",
                "name": check["name"],
                "severity": check.get("severity", "INFO"),
            })
    for finding in agent_items:
        all_issues.append({
            "source": "agent",
            "name": finding.get("category", "general"),
            "severity": finding.get("severity", "INFO"),
        })

    if not all_issues:
        lines.append("All automated checks passed and no agent findings were reported. "
                      "The lifted code appears to faithfully represent the original binary behavior.")
    else:
        critical = sum(1 for i in all_issues if _severity_rank(i["severity"]) >= 4)
        fails = sum(1 for i in all_issues if _severity_rank(i["severity"]) == 3)
        warnings = sum(1 for i in all_issues if _severity_rank(i["severity"]) == 2)

        lines.append(f"Total issues: {len(all_issues)} "
                      f"({critical} critical, {fails} fail, {warnings} warning)")
        lines.append("")

        if critical > 0:
            lines.append("**Action required:** Critical issues found. The lifted code "
                          "has significant discrepancies from the original binary behavior "
                          "that must be addressed before the code can be trusted.")
        elif fails > 0:
            lines.append("**Review required:** Failed checks indicate the lifted code "
                          "may not faithfully represent all aspects of the original binary. "
                          "Review the specific discrepancies above.")
        else:
            lines.append("**Minor issues:** Only warnings detected. The lifted code is "
                          "likely correct but should be reviewed for the noted discrepancies.")

    lines.append("")
    lines.append("---")
    lines.append(f"*Report generated by DeepExtractIDA verifier subagent*")

    return "\n".join(lines)


def generate_json_report(
    compare_data: dict,
    agent_findings: dict | None = None,
) -> dict:
    """Generate a structured JSON verification report."""
    agent_items = agent_findings.get("findings", []) if agent_findings else []
    agent_notes = agent_findings.get("notes", "") if agent_findings else ""
    manual_verdict = agent_findings.get("manual_verdict") if agent_findings else None

    # Compute final verdict
    verdict = compare_data.get("verdict", "UNKNOWN")
    if manual_verdict:
        final_verdict = manual_verdict.upper()
    elif agent_items:
        agent_severities = [_severity_rank(f.get("severity", "INFO")) for f in agent_items]
        if any(s >= 4 for s in agent_severities):
            final_verdict = "FAIL"
        elif any(s >= 3 for s in agent_severities):
            final_verdict = "FAIL"
        elif any(s >= 2 for s in agent_severities):
            final_verdict = "WARN" if verdict == "PASS" else verdict
        else:
            final_verdict = verdict
    else:
        final_verdict = verdict

    return {
        "function_name": compare_data.get("function_name", "(unknown)"),
        "function_id": compare_data.get("function_id", 0),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "final_verdict": final_verdict,
        "automated_verdict": verdict,
        "overall_confidence": compare_data.get("overall_confidence", 0.0),
        "automated_checks": {
            "total": compare_data.get("total_checks", 0),
            "passed": compare_data.get("passed", 0),
            "failed": compare_data.get("failed", 0),
            "checks": compare_data.get("checks", []),
        },
        "agent_findings": {
            "count": len(agent_items),
            "findings": agent_items,
            "notes": agent_notes,
            "manual_verdict": manual_verdict,
        },
        "metadata": {
            "function_signature": compare_data.get("original_function_signature"),
            "mangled_name": compare_data.get("original_mangled_name"),
            "asm_instruction_count": compare_data.get("asm_instruction_count"),
            "lifted_line_count": compare_data.get("lifted_line_count"),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a formal verification report from comparison results.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--compare-output", required=True,
        help="Path to compare_lifted.py --json output"
    )
    parser.add_argument(
        "--agent-findings",
        help="Path to agent findings JSON (optional)"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file path (default: stdout)"
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output as JSON instead of Markdown"
    )
    args = safe_parse_args(parser)

    # Force JSON output when workspace mode is active so bootstrap captures
    # structured data instead of human-readable Markdown.
    force_json = args.json or bool(get_workspace_args(args)["workspace_dir"])

    # Load inputs
    compare_data = _load_json(args.compare_output)
    agent_findings = _load_json(args.agent_findings) if args.agent_findings else None

    # Generate report
    if force_json:
        report_data = generate_json_report(compare_data, agent_findings)

        if args.output:
            out_path = Path(args.output)
            if not out_path.is_absolute():
                out_path = WORKSPACE_ROOT / args.output
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(
                json.dumps(report_data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            print(f"Report also written to: {out_path}", file=sys.stderr)

        emit_json(report_data)
    else:
        report_text = generate_markdown_report(compare_data, agent_findings)

        if args.output:
            out_path = Path(args.output)
            if not out_path.is_absolute():
                out_path = WORKSPACE_ROOT / args.output
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(report_text, encoding="utf-8")
            print(f"Report also written to: {out_path}", file=sys.stderr)

        print(report_text)


if __name__ == "__main__":
    main()
