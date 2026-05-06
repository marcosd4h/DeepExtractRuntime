"""Tests for helpers.report_comparison.

Covers discover_reports, load_findings_json, compare_findings, and
format_comparison_section using realistic fixture data modeled on
actual NetrShareAdd logic scan outputs.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from helpers.report_comparison import (
    ComparisonResult,
    FindingMatch,
    compare_findings,
    discover_reports,
    format_comparison_section,
    load_findings_json,
)


def _make_finding(
    *,
    id: str = "FINDING-001",
    vulnerability_type: str = "auth_bypass",
    vulnerability_class: str = "Authorization bypass",
    severity: str = "MEDIUM",
    title: str = "Test finding",
    description: str = "Test description with full LLM content.",
    call_chain: list | None = None,
    primary_function: str = "TargetFunc",
    evidence: str = "v9 = RpcImpersonateClient(nullptr);",
    assembly_confirmation: str = "test eax, eax; jns short loc_1234",
    impact_assessment: str = "Stale token could be used.",
    practical_exploitability: str = "LOW. Requires race condition.",
    structural_mitigation: str = "Defense-in-depth at NtOpenThreadToken.",
    remediation: str = "Change if (v9 < 0) to if (v9 != 0).",
    skeptic_verdict: str = "TRUE_POSITIVE",
    skeptic_summary: str = "Confirmed by assembly analysis.",
    skeptic_criteria: dict | None = None,
    dedup_key: str = "",
) -> dict:
    return {
        "id": id,
        "vulnerability_type": vulnerability_type,
        "vulnerability_class": vulnerability_class,
        "severity": severity,
        "title": title,
        "description": description,
        "call_chain": call_chain or ["EntryPoint", "TargetFunc"],
        "primary_function": primary_function,
        "evidence": evidence,
        "assembly_confirmation": assembly_confirmation,
        "impact_assessment": impact_assessment,
        "practical_exploitability": practical_exploitability,
        "structural_mitigation": structural_mitigation,
        "remediation": remediation,
        "skeptic_verdict": skeptic_verdict,
        "skeptic_summary": skeptic_summary,
        "skeptic_criteria": skeptic_criteria or {
            "data_flow": "Confirmed.",
            "validation_checks": "Present.",
            "reachability": "Reachable.",
            "exploitability": "LOW.",
        },
        "dedup_key": dedup_key or f"{primary_function}::{vulnerability_type}::logic_vulnerability",
    }


def _make_fp_finding(
    *,
    id: str = "FINDING-FP1",
    vulnerability_type: str = "dead_code_bypass",
    primary_function: str = "DeadFunc",
    hypothesis: str = "Bypass via dead code path.",
    why_dismissed: str = "Global never written; dead code confirmed.",
    **kwargs,
) -> dict:
    base = _make_finding(
        id=id,
        vulnerability_type=vulnerability_type,
        primary_function=primary_function,
        skeptic_verdict="FALSE_POSITIVE",
        **kwargs,
    )
    base["hypothesis"] = hypothesis
    base["why_dismissed"] = why_dismissed
    return base


def _make_report(
    *,
    scan_type: str = "logic",
    module: str = "srvsvc.dll",
    entry_point: str = "NetrShareAdd",
    true_positives: list | None = None,
    false_positives: list | None = None,
    false_leads: list | None = None,
    functions_analyzed: list | None = None,
    overall_severity: str = "LOW",
    report_path: str = "",
) -> dict:
    return {
        "scan_type": scan_type,
        "module": module,
        "entry_point": entry_point,
        "entry_point_opnum": 9,
        "entry_point_interface": "4b324fc8-1670-01d3-1278-5a47bf6ee188",
        "depth": 4,
        "timestamp": "2026-03-15T23:45:00Z",
        "db_path": "extracted_dbs/srvsvc_dll_7af81c0428.db",
        "workspace_run_dir": ".claude/workspace/test_run/",
        "report_path": report_path,
        "callgraph_stats": {
            "total_nodes": 480,
            "must_read_count": 58,
            "module_count": 10,
            "modules": ["srvsvc.dll"],
        },
        "functions_analyzed": functions_analyzed or ["NetrShareAdd", "I_NetrShareAdd"],
        "threat_model": {
            "module": module,
            "module_description": "Server Service DLL",
            "service_type": "RPC service",
            "attacker_model": "Remote unauthenticated",
            "interface": "4b324fc8-1670-01d3-1278-5a47bf6ee188",
            "entry_point_count": 123,
            "privilege": "SYSTEM",
            "dangerous_api_refs": 207,
            "dangerous_api_functions": 144,
            "narrative": "Test narrative.",
        },
        "true_positives": true_positives if true_positives is not None else [],
        "false_positives": false_positives if false_positives is not None else [],
        "false_leads": false_leads or [],
        "attack_chain_analysis": "No attack chains identified.",
        "overall_severity": overall_severity,
        "overall_severity_justification": "Test justification.",
        "coverage_summary": {
            "threat_model": "rpc_service",
            "callgraph_prep": "480 nodes",
            "quick_triage": "1/1 likely",
            "deep_scan": "findings found",
            "skeptic_verification": "verified",
        },
        "coverage": {
            "functions_analyzed_count": len(
                functions_analyzed or ["NetrShareAdd", "I_NetrShareAdd"]
            ),
            "depth_reached": 4,
            "functions_read": functions_analyzed or ["NetrShareAdd", "I_NetrShareAdd"],
            "functions_skipped": [],
        },
        "provenance": {
            "threat_model": "threat_model/results.json",
            "findings": "findings/results.json",
            "skeptic": "skeptic/results.json",
        },
    }


def _write_findings_json(
    reports_dir: Path, name: str, report: dict
) -> Path:
    """Write a .findings.json file and return its path."""
    path = reports_dir / f"{name}.findings.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# TestDiscoverReports
# ---------------------------------------------------------------------------


class TestDiscoverReports:
    def test_discover_finds_findings_json_files(self, tmp_path):
        rd = tmp_path / "reports"
        rd.mkdir()
        _write_findings_json(rd, "ai_logic_scan_20260314_1400", _make_report())
        _write_findings_json(rd, "ai_logic_scan_20260315_2100", _make_report())
        _write_findings_json(rd, "ai_logic_scan_20260315_2345", _make_report())

        results = discover_reports(rd)
        assert len(results) == 3
        assert results[0].timestamp_str == "20260315_2345"
        assert results[1].timestamp_str == "20260315_2100"
        assert results[2].timestamp_str == "20260314_1400"

    def test_discover_filters_by_scan_type(self, tmp_path):
        rd = tmp_path / "reports"
        rd.mkdir()
        _write_findings_json(rd, "ai_logic_scan_20260315_2345", _make_report(scan_type="logic"))
        _write_findings_json(rd, "ai_memory_scan_20260315_1200", _make_report(scan_type="memory"))

        logic_only = discover_reports(rd, scan_type="logic")
        assert len(logic_only) == 1
        assert logic_only[0].scan_type == "logic"

        memory_only = discover_reports(rd, scan_type="memory")
        assert len(memory_only) == 1
        assert memory_only[0].scan_type == "memory"

    def test_discover_empty_dir(self, tmp_path):
        rd = tmp_path / "reports"
        rd.mkdir()
        assert discover_reports(rd) == []

    def test_discover_ignores_md_without_companion(self, tmp_path):
        rd = tmp_path / "reports"
        rd.mkdir()
        (rd / "ai_logic_scan_20260315_2345.md").write_text("# Report")
        assert discover_reports(rd) == []


# ---------------------------------------------------------------------------
# TestLoadFindingsJson
# ---------------------------------------------------------------------------


class TestLoadFindingsJson:
    def test_load_valid_file(self, tmp_path):
        report = _make_report(
            true_positives=[_make_finding()],
            false_positives=[_make_fp_finding()],
            false_leads=[{"hypothesis": "test", "reason_dismissed": "ok"}],
        )
        p = _write_findings_json(tmp_path, "test_report", report)
        loaded = load_findings_json(p)

        assert loaded["scan_type"] == "logic"
        assert loaded["module"] == "srvsvc.dll"
        assert len(loaded["true_positives"]) == 1
        assert len(loaded["false_positives"]) == 1
        assert len(loaded["false_leads"]) == 1
        assert loaded["threat_model"]["attacker_model"] == "Remote unauthenticated"
        assert loaded["overall_severity"] == "LOW"
        assert loaded["attack_chain_analysis"] == "No attack chains identified."

    def test_load_preserves_full_finding_content(self, tmp_path):
        finding = _make_finding(
            description="Detailed LLM bug description.",
            evidence="v9 = RpcImpersonateClient(nullptr);",
            assembly_confirmation="test eax, eax; jns",
            impact_assessment="Stale token used for SD creation.",
            practical_exploitability="LOW.",
            structural_mitigation="NtOpenThreadToken defense.",
            remediation="Change if (v9 < 0) to if (v9 != 0).",
        )
        report = _make_report(true_positives=[finding])
        p = _write_findings_json(tmp_path, "test_full", report)
        loaded = load_findings_json(p)

        f = loaded["true_positives"][0]
        assert f["description"] == "Detailed LLM bug description."
        assert f["evidence"] == "v9 = RpcImpersonateClient(nullptr);"
        assert f["assembly_confirmation"] == "test eax, eax; jns"
        assert f["impact_assessment"] == "Stale token used for SD creation."
        assert f["practical_exploitability"] == "LOW."
        assert f["structural_mitigation"] == "NtOpenThreadToken defense."
        assert f["remediation"] == "Change if (v9 < 0) to if (v9 != 0)."
        assert f["skeptic_verdict"] == "TRUE_POSITIVE"
        assert "data_flow" in f["skeptic_criteria"]

    def test_load_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_findings_json(tmp_path / "nonexistent.findings.json")

    def test_load_malformed_json_raises(self, tmp_path):
        bad = tmp_path / "bad.findings.json"
        bad.write_text("{invalid json", encoding="utf-8")
        with pytest.raises(json.JSONDecodeError):
            load_findings_json(bad)


# ---------------------------------------------------------------------------
# TestCompareFindings
# ---------------------------------------------------------------------------


class TestCompareFindings:
    def test_identical_findings_all_recurring(self):
        f = _make_finding(id="F1", vulnerability_type="bug_a", primary_function="FuncA")
        current = _make_report(true_positives=[f])
        previous = _make_report(true_positives=[f])

        result = compare_findings(current, previous)
        assert len(result.recurring) == 1
        assert len(result.new_findings) == 0
        assert len(result.missed) == 0

    def test_new_finding_detected(self):
        f1 = _make_finding(id="F1", vulnerability_type="bug_a", primary_function="FuncA")
        f2 = _make_finding(id="F2", vulnerability_type="bug_b", primary_function="FuncB")
        current = _make_report(true_positives=[f1, f2])
        previous = _make_report(true_positives=[f1])

        result = compare_findings(current, previous)
        assert len(result.new_findings) == 1
        assert result.new_findings[0]["id"] == "F2"

    def test_missed_finding_detected(self):
        f1 = _make_finding(id="F1", vulnerability_type="bug_a", primary_function="FuncA")
        f2 = _make_finding(id="F2", vulnerability_type="bug_b", primary_function="FuncB")
        current = _make_report(true_positives=[f1])
        previous = _make_report(true_positives=[f1, f2])

        result = compare_findings(current, previous)
        assert len(result.missed) == 1
        assert result.missed[0]["id"] == "F2"

    def test_severity_change_detected(self):
        f_prev = _make_finding(
            id="F1", vulnerability_type="bug_a", primary_function="FuncA", severity="HIGH"
        )
        f_curr = _make_finding(
            id="F1", vulnerability_type="bug_a", primary_function="FuncA", severity="LOW"
        )
        current = _make_report(true_positives=[f_curr])
        previous = _make_report(true_positives=[f_prev])

        result = compare_findings(current, previous)
        assert len(result.severity_changes) == 1
        assert result.severity_changes[0].previous["severity"] == "HIGH"
        assert result.severity_changes[0].current["severity"] == "LOW"

    def test_verdict_change_detected(self):
        f_prev = _make_finding(
            id="F1",
            vulnerability_type="bug_a",
            primary_function="FuncA",
            skeptic_verdict="TRUE_POSITIVE",
        )
        f_curr = _make_finding(
            id="F1",
            vulnerability_type="bug_a",
            primary_function="FuncA",
            skeptic_verdict="FALSE_POSITIVE",
        )
        current = _make_report(false_positives=[f_curr])
        previous = _make_report(true_positives=[f_prev])

        result = compare_findings(current, previous)
        assert len(result.verdict_conflicts) == 1

    def test_matching_ignores_id_differences(self):
        f_prev = _make_finding(
            id="FINDING-001", vulnerability_type="bug_a", primary_function="FuncA"
        )
        f_curr = _make_finding(
            id="FINDING-003", vulnerability_type="bug_a", primary_function="FuncA"
        )
        current = _make_report(true_positives=[f_curr])
        previous = _make_report(true_positives=[f_prev])

        result = compare_findings(current, previous)
        assert len(result.recurring) == 1
        assert len(result.new_findings) == 0
        assert len(result.missed) == 0

    def test_false_positive_to_true_positive(self):
        f_prev = _make_finding(
            id="F1",
            vulnerability_type="bug_a",
            primary_function="FuncA",
            skeptic_verdict="FALSE_POSITIVE",
        )
        f_curr = _make_finding(
            id="F1",
            vulnerability_type="bug_a",
            primary_function="FuncA",
            skeptic_verdict="TRUE_POSITIVE",
        )
        current = _make_report(true_positives=[f_curr])
        previous = _make_report(false_positives=[f_prev])

        result = compare_findings(current, previous)
        assert len(result.recurring) == 1
        assert len(result.verdict_conflicts) == 1

    def test_empty_previous_all_new(self):
        f = _make_finding(id="F1", vulnerability_type="bug_a", primary_function="FuncA")
        current = _make_report(true_positives=[f])
        previous = _make_report()

        result = compare_findings(current, previous)
        assert len(result.new_findings) == 1
        assert len(result.missed) == 0

    def test_empty_current_all_missed(self):
        f = _make_finding(id="F1", vulnerability_type="bug_a", primary_function="FuncA")
        current = _make_report()
        previous = _make_report(true_positives=[f])

        result = compare_findings(current, previous)
        assert len(result.new_findings) == 0
        assert len(result.missed) == 1


# ---------------------------------------------------------------------------
# TestFormatComparisonSection
# ---------------------------------------------------------------------------


class TestFormatComparisonSection:
    def test_format_produces_valid_markdown(self):
        f1 = _make_finding(id="F1", vulnerability_type="bug_a", primary_function="FuncA")
        f2 = _make_finding(id="F2", vulnerability_type="bug_b", primary_function="FuncB")
        current = _make_report(true_positives=[f1, f2])
        previous = _make_report(true_positives=[f1])

        result = compare_findings(current, previous)
        md = format_comparison_section(result, "previous_report.md", "2026-03-15 21:01")

        assert "## Previous Findings Comparison" in md
        assert "### Recurring Findings" in md
        assert "### New Findings" in md
        assert "previous_report.md" in md

    def test_format_includes_previous_report_reference(self):
        result = ComparisonResult(
            previous_report="ai_logic_scan_20260315_2101.md",
        )
        md = format_comparison_section(result, "ai_logic_scan_20260315_2101.md", "2026-03-15 21:01")
        assert "ai_logic_scan_20260315_2101.md" in md
        assert "2026-03-15 21:01" in md

    def test_format_no_previous_report(self):
        result = ComparisonResult()
        md = format_comparison_section(result)
        assert "First scan of this type" in md
