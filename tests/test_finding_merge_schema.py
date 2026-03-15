"""Tests for helpers.finding_schema and helpers.finding_merge.

Covers adapter functions, deduplication, ranking, merge, and summary.
"""

from __future__ import annotations

import pytest

from helpers.finding_schema import (
    Finding,
    from_logic_finding,
    from_memory_finding,
    from_taint_finding,
    from_verified_finding,
    normalize_scanner_output,
)
from helpers.finding_merge import (
    deduplicate,
    findings_summary,
    merge_findings,
    rank,
    to_json,
)


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------


class TestFinding:
    def test_to_dict_omits_empty(self):
        f = Finding(function_name="foo", score=0.5)
        d = f.to_dict()
        assert "function_name" in d
        assert "guards" not in d
        assert "extra" not in d

    def test_dedup_key_uses_function_id_when_present(self):
        f = Finding(function_name="foo", function_id=42, sink="HeapAlloc",
                    source_category="heap_overflow")
        assert "42" in f.dedup_key
        assert "HeapAlloc" in f.dedup_key

    def test_dedup_key_falls_back_to_name(self):
        f = Finding(function_name="bar", sink="free", source_category="double_free")
        assert "bar" in f.dedup_key


# ---------------------------------------------------------------------------
# Adapter functions
# ---------------------------------------------------------------------------


class TestFromTaintFinding:
    def test_basic_conversion(self):
        raw = {"param_name": "a1", "sink": "memcpy", "sink_category": "copy",
               "severity": "HIGH", "score": 0.8}
        f = from_taint_finding(raw)
        assert f.source_type == "taint"
        assert f.sink == "memcpy"
        assert f.severity == "HIGH"
        assert f.score == 0.8

    def test_with_func_info(self):
        raw = {"param_name": "a1", "sink": "memcpy", "sink_category": "copy"}
        func = {"function_name": "DoWork", "function_id": 7, "module_name": "foo.dll"}
        f = from_taint_finding(raw, func)
        assert f.function_name == "DoWork"
        assert f.function_id == 7
        assert f.module == "foo.dll"


class TestFromMemoryFinding:
    def test_basic_conversion(self):
        raw = {"function_name": "fn", "function_id": 1, "category": "heap_overflow",
               "dangerous_api": "HeapAlloc", "severity": "CRITICAL", "score": 0.9}
        f = from_memory_finding(raw)
        assert f.source_type == "memory_corruption"
        assert f.source_category == "heap_overflow"
        assert f.sink == "HeapAlloc"
        assert f.score == 0.9


class TestFromLogicFinding:
    def test_legacy_format_conversion(self):
        raw = {"function_name": "fn", "function_id": 2, "category": "missing_auth",
               "dangerous_op": "CreateProcessW", "severity": "HIGH", "score": 0.7,
               "guards_on_path": [{"guard_type": "if"}]}
        f = from_logic_finding(raw)
        assert f.source_type == "logic_vulnerability"
        assert f.source_category == "missing_auth"
        assert f.sink == "CreateProcessW"
        assert len(f.guards) == 1

    def test_ai_format_conversion(self):
        raw = {
            "vulnerability_type": "auth_bypass_missing_check",
            "cwe_id": "CWE-287",
            "affected_functions": ["NetrShareAdd"],
            "entry_point": "NetrShareAdd",
            "call_chain": ["NetrShareAdd", "SsShareAdd"],
            "description": "Missing auth check",
            "evidence": {
                "code_lines": ["CreateFileW(...)"],
                "assembly_confirmation": "call CreateFileW",
            },
            "severity_assessment": "HIGH because...",
        }
        f = from_logic_finding(raw)
        assert f.source_type == "logic_vulnerability"
        assert f.source_category == "auth_bypass_missing_check"
        assert f.severity == "HIGH"

    def test_ai_format_severity_parsing_critical(self):
        raw = {"vulnerability_type": "toctou", "severity_assessment": "CRITICAL -- remote RCE"}
        f = from_logic_finding(raw)
        assert f.severity == "CRITICAL"
        assert f.score == 0.95

    def test_ai_format_severity_parsing_garbage(self):
        raw = {"vulnerability_type": "toctou", "severity_assessment": "maybe bad"}
        f = from_logic_finding(raw)
        assert f.severity == "MEDIUM"
        assert f.score == 0.5

    def test_ai_format_evidence_aggregation(self):
        raw = {
            "vulnerability_type": "dll_injection",
            "evidence": {
                "code_lines": ["LoadLibraryW(v3)", "v3 = *(a2 + 0x10)"],
                "assembly_confirmation": "call cs:LoadLibraryW",
            },
        }
        f = from_logic_finding(raw)
        assert len(f.evidence_lines) == 3
        assert "LoadLibraryW(v3)" in f.evidence_lines
        assert "call cs:LoadLibraryW" in f.evidence_lines

    def test_ai_format_extra_fields(self):
        raw = {
            "vulnerability_type": "service_binary_injection",
            "cwe_id": "CWE-426",
            "affected_functions": ["SvcRegister", "CreateServiceW"],
            "entry_point": "SvcRegister",
            "data_flow": "RPC a2 -> lpBinaryPathName",
            "exploitation_assessment": "SYSTEM service creation",
            "mitigations_present": ["none"],
        }
        f = from_logic_finding(raw)
        assert f.extra["cwe_id"] == "CWE-426"
        assert f.extra["data_flow"] == "RPC a2 -> lpBinaryPathName"
        assert f.extra["exploitation_assessment"] == "SYSTEM service creation"
        assert f.extra["affected_functions"] == ["SvcRegister", "CreateServiceW"]

    def test_ai_format_empty_affected_functions(self):
        raw = {"vulnerability_type": "test", "entry_point": "FallbackFunc"}
        f = from_logic_finding(raw)
        assert f.function_name == "FallbackFunc"

    def test_dispatch_routes_ai_format(self):
        ai_raw = {"vulnerability_type": "auth_bypass"}
        legacy_raw = {"category": "missing_auth", "function_name": "fn"}
        ai_f = from_logic_finding(ai_raw)
        legacy_f = from_logic_finding(legacy_raw)
        assert ai_f.sink_category == "logic_unsafe"
        assert legacy_f.sink_category == "logic_unsafe"
        assert ai_f.source_category == "auth_bypass"
        assert legacy_f.source_category == "missing_auth"


class TestFromVerifiedFinding:
    def test_memory_verified(self):
        verified = {
            "finding": {"function_name": "fn", "category": "heap_overflow",
                        "dangerous_api": "HeapAlloc",
                        "dangerous_api_category": "memory_unsafe"},
            "confidence": "CONFIRMED",
            "verified_score": 0.95,
        }
        f = from_verified_finding(verified)
        assert f.verification_status == "CONFIRMED"
        assert f.score == 0.95

    def test_logic_verified(self):
        verified = {
            "finding": {"function_name": "fn", "category": "missing_auth",
                        "dangerous_op": "CreateProcessW",
                        "dangerous_op_category": "execution"},
            "confidence": "LIKELY",
            "verified_score": 0.6,
        }
        f = from_verified_finding(verified)
        assert f.source_type == "logic_vulnerability"
        assert f.verification_status == "LIKELY"


# ---------------------------------------------------------------------------
# normalize_scanner_output
# ---------------------------------------------------------------------------


class TestNormalizeScannerOutput:
    def test_raw_taint_findings(self):
        data = {
            "findings": [
                {"param_name": "a1", "sink": "memcpy", "sink_category": "copy"},
            ],
            "function": {"function_name": "DoWork", "module_name": "mod.dll"},
        }
        results = normalize_scanner_output(data, "taint")
        assert len(results) == 1
        assert results[0].module == "mod.dll"

    def test_verified_findings_take_precedence(self):
        data = {
            "findings": [{"param_name": "a1", "sink": "x", "sink_category": "y"}],
            "verified_findings": [
                {"finding": {"function_name": "fn", "dangerous_api": "HeapAlloc",
                             "category": "heap_overflow"},
                 "confidence": "CONFIRMED", "verified_score": 0.9},
            ],
        }
        results = normalize_scanner_output(data, "memory_corruption")
        assert len(results) == 1
        assert results[0].verification_status == "CONFIRMED"

    def test_empty_data(self):
        assert normalize_scanner_output({}, "taint") == []

    def test_forward_findings_fallback(self):
        data = {
            "forward_findings": [
                {"param_name": "a1", "sink": "free", "sink_category": "dealloc"},
            ],
        }
        results = normalize_scanner_output(data, "taint")
        assert len(results) == 1


# ---------------------------------------------------------------------------
# Deduplication and ranking
# ---------------------------------------------------------------------------


class TestDeduplicate:
    def test_keeps_highest_score(self):
        f1 = Finding(function_name="fn", function_id=1, sink="memcpy",
                     source_category="copy", score=0.5)
        f2 = Finding(function_name="fn", function_id=1, sink="memcpy",
                     source_category="copy", score=0.9)
        result = deduplicate([f1, f2])
        assert len(result) == 1
        assert result[0].score == 0.9

    def test_different_sinks_kept(self):
        f1 = Finding(function_name="fn", function_id=1, sink="memcpy",
                     source_category="copy", score=0.5)
        f2 = Finding(function_name="fn", function_id=1, sink="HeapAlloc",
                     source_category="alloc", score=0.5)
        result = deduplicate([f1, f2])
        assert len(result) == 2

    def test_empty(self):
        assert deduplicate([]) == []


class TestRank:
    def test_sorted_by_score_descending(self):
        findings = [
            Finding(function_name="a", score=0.3, severity="LOW"),
            Finding(function_name="b", score=0.9, severity="HIGH"),
            Finding(function_name="c", score=0.6, severity="MEDIUM"),
        ]
        ranked = rank(findings)
        assert ranked[0].function_name == "b"
        assert ranked[-1].function_name == "a"

    def test_exploitability_score_preferred(self):
        f1 = Finding(function_name="a", score=0.9, severity="HIGH")
        f2 = Finding(function_name="b", score=0.3, severity="LOW",
                     exploitability_score=1.0)
        ranked = rank([f1, f2])
        assert ranked[0].function_name == "b"

    def test_severity_tiebreaker(self):
        f1 = Finding(function_name="a", score=0.5, severity="LOW")
        f2 = Finding(function_name="b", score=0.5, severity="CRITICAL")
        ranked = rank([f1, f2])
        assert ranked[0].function_name == "b"


# ---------------------------------------------------------------------------
# Merge
# ---------------------------------------------------------------------------


class TestMergeFindings:
    def test_merges_multiple_sources(self):
        taint_data = {
            "findings": [
                {"param_name": "a1", "sink": "memcpy", "sink_category": "copy",
                 "score": 0.7},
            ],
        }
        memory_data = {
            "findings": [
                {"function_name": "fn2", "category": "heap_overflow",
                 "dangerous_api": "HeapAlloc", "score": 0.8},
            ],
        }
        result = merge_findings(
            (taint_data, "taint"),
            (memory_data, "memory_corruption"),
        )
        assert len(result) == 2

    def test_deduplicates_across_sources(self):
        data1 = {
            "findings": [
                {"function_name": "fn", "function_id": 1, "category": "heap_overflow",
                 "dangerous_api": "HeapAlloc", "score": 0.5},
            ],
        }
        data2 = {
            "findings": [
                {"function_name": "fn", "function_id": 1, "category": "heap_overflow",
                 "dangerous_api": "HeapAlloc", "score": 0.9},
            ],
        }
        result = merge_findings(
            (data1, "memory_corruption"),
            (data2, "memory_corruption"),
        )
        assert len(result) == 1
        assert result[0].score == 0.9

    def test_empty_inputs(self):
        assert merge_findings() == []


# ---------------------------------------------------------------------------
# Summary and JSON serialization
# ---------------------------------------------------------------------------


class TestFindingsSummary:
    def test_summary_structure(self):
        findings = [
            Finding(function_name="a", severity="CRITICAL", score=0.9,
                    source_type="taint"),
            Finding(function_name="b", severity="HIGH", score=0.7,
                    source_type="memory_corruption"),
        ]
        s = findings_summary(findings)
        assert s["total"] == 2
        assert s["by_severity"]["CRITICAL"] == 1
        assert s["by_severity"]["HIGH"] == 1
        assert s["by_source"]["taint"] == 1
        assert s["top_score"] == 0.9

    def test_empty_findings(self):
        s = findings_summary([])
        assert s["total"] == 0
        assert s["top_score"] == 0.0
        assert s["top_function"] == "N/A"


class TestToJson:
    def test_round_trips(self):
        findings = [Finding(function_name="fn", score=0.5, severity="MEDIUM")]
        result = to_json(findings)
        assert isinstance(result, list)
        assert result[0]["function_name"] == "fn"
        assert result[0]["score"] == 0.5
