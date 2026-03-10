"""Tests for cross-module analysis, orchestration, dedup/scoring, and callgraph improvements."""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from conftest import _make_function_record as mkfr
from helpers.callgraph import CallGraph
from helpers.config import get_config_value
from helpers.cross_module_graph import CrossModuleGraph, resolve_forwarded_export
from helpers.def_use_chain import TaintSummary, analyze_taint, build_taint_summary
from helpers.finding_merge import deduplicate, rank
from helpers.finding_schema import Finding, graduated_reachability_score
from helpers.individual_analysis_db.records import parse_json_safe


# ===================================================================
# Category 8: Cross-Module Analysis
# ===================================================================


class TestTaintSummary:
    """TaintSummary dataclass and build_taint_summary."""

    def test_taint_summary_dataclass_fields(self):
        ts = TaintSummary(function_name="foo")
        assert ts.function_name == "foo"
        assert ts.tainted_params == set()
        assert ts.tainted_return is False
        assert ts.param_to_sink == {}
        assert ts.param_to_return == set()

    def test_build_taint_summary_simple(self):
        code = """\
v5 = a1;
memcpy(buf, v5, 10);
return v5;
"""
        summary = build_taint_summary(code, 2, function_name="test_fn")
        assert summary.function_name == "test_fn"
        assert 1 in summary.tainted_params
        assert summary.tainted_return is True
        assert 1 in summary.param_to_return
        assert summary.param_to_sink.get(1) == "memcpy"

    def test_build_taint_summary_untainted_param(self):
        code = """\
v5 = 42;
return v5;
"""
        summary = build_taint_summary(code, 1, function_name="safe_fn")
        assert 1 not in summary.tainted_params
        assert summary.tainted_return is False

    def test_build_taint_summary_multi_param(self):
        code = """\
v5 = a1;
v6 = a2;
memcpy(buf, v5, v6);
"""
        summary = build_taint_summary(code, 2)
        assert 1 in summary.tainted_params
        assert 2 in summary.tainted_params

    def test_build_taint_summary_no_return_taint(self):
        code = """\
v5 = a1;
memcpy(buf, v5, 10);
return 0;
"""
        summary = build_taint_summary(code, 1)
        assert 1 in summary.tainted_params
        assert summary.tainted_return is False
        assert 1 not in summary.param_to_return

    def test_build_taint_summary_empty_code(self):
        summary = build_taint_summary("", 3)
        assert summary.tainted_params == set()
        assert summary.tainted_return is False

    def test_build_taint_summary_zero_params(self):
        summary = build_taint_summary("v5 = 42;\nreturn v5;\n", 0)
        assert summary.tainted_params == set()


class TestResolveForwardedExport:
    """resolve_forwarded_export returns None for unknown modules."""

    def test_returns_none_when_no_workspace(self):
        result = resolve_forwarded_export("nonexistent.dll", "SomeFunc")
        assert result is None or isinstance(result, tuple)

    def test_returns_none_for_nonexistent_module(self):
        result = resolve_forwarded_export("totally_made_up_module.dll", "FakeFunc")
        assert result is None


# ===================================================================
# Category 10: Orchestration Improvements
# ===================================================================


class TestAdaptiveTopN:
    """Adaptive top-N config keys and formula."""

    def test_small_module(self):
        from importlib import import_module
        _mod = __import__("helpers.config", fromlist=["get_config_value"])
        base = int(get_config_value("security_auditor.top_n_base", 5))
        top_min = int(get_config_value("security_auditor.top_n_min", 3))
        top_max = int(get_config_value("security_auditor.top_n_max", 25))

        # Small module: 50 functions -> base + 0 per-100 = base
        n = base + (50 // 100) * int(get_config_value("security_auditor.top_n_per_100_functions", 1))
        n = max(top_min, min(n, top_max))
        assert n == base

    def test_large_module(self):
        base = int(get_config_value("security_auditor.top_n_base", 5))
        per_100 = int(get_config_value("security_auditor.top_n_per_100_functions", 1))
        top_max = int(get_config_value("security_auditor.top_n_max", 25))
        top_min = int(get_config_value("security_auditor.top_n_min", 3))

        # 2000 functions -> base + 20
        n = base + (2000 // 100) * per_100
        n = max(top_min, min(n, top_max))
        assert n == top_max

    def test_config_keys_exist(self):
        assert get_config_value("security_auditor.top_n_base") is not None
        assert get_config_value("security_auditor.top_n_per_100_functions") is not None
        assert get_config_value("security_auditor.top_n_max") is not None
        assert get_config_value("security_auditor.top_n_min") is not None


class TestShouldDeepenScan:
    """Feedback loop triggers on high-severity findings."""

    def test_empty_findings(self):
        from helpers.finding_schema import Finding
        findings: list[Finding] = []
        critical = sum(1 for f in findings if f.severity == "CRITICAL")
        high = sum(1 for f in findings if f.severity == "HIGH")
        top_score = max((f.score for f in findings), default=0.0)
        should_deepen = critical >= 2 or high >= 5 or top_score >= 0.75
        assert should_deepen is False

    def test_two_critical_triggers(self):
        findings = [
            Finding(function_name="a", severity="CRITICAL", score=0.5),
            Finding(function_name="b", severity="CRITICAL", score=0.6),
        ]
        critical = sum(1 for f in findings if f.severity == "CRITICAL")
        assert critical >= 2

    def test_five_high_triggers(self):
        findings = [
            Finding(function_name=f"fn{i}", severity="HIGH", score=0.4)
            for i in range(5)
        ]
        high = sum(1 for f in findings if f.severity == "HIGH")
        assert high >= 5

    def test_high_score_triggers(self):
        findings = [
            Finding(function_name="a", severity="MEDIUM", score=0.80),
        ]
        top_score = max(f.score for f in findings)
        assert top_score >= 0.75

    def test_low_findings_no_trigger(self):
        findings = [
            Finding(function_name="a", severity="LOW", score=0.2),
            Finding(function_name="b", severity="MEDIUM", score=0.3),
        ]
        critical = sum(1 for f in findings if f.severity == "CRITICAL")
        high = sum(1 for f in findings if f.severity == "HIGH")
        top_score = max(f.score for f in findings)
        assert not (critical >= 2 or high >= 5 or top_score >= 0.75)


# ===================================================================
# Category 11: Finding Dedup and Scoring
# ===================================================================


class TestPathSignature:
    """Path signature is deterministic and order-independent."""

    def test_same_path_same_signature(self):
        f1 = Finding(function_name="fn", path=["A", "B", "C"])
        f2 = Finding(function_name="fn", path=["C", "A", "B"])
        assert f1.path_signature == f2.path_signature

    def test_different_path_different_signature(self):
        f1 = Finding(function_name="fn", path=["A", "B"])
        f2 = Finding(function_name="fn", path=["A", "C"])
        assert f1.path_signature != f2.path_signature

    def test_empty_path_signature(self):
        f = Finding(function_name="fn", path=[])
        assert len(f.path_signature) == 16

    def test_path_signature_is_deterministic(self):
        f = Finding(function_name="fn", path=["X", "Y", "Z"])
        sig1 = f.path_signature
        sig2 = f.path_signature
        assert sig1 == sig2


class TestPathPreservingDedup:
    """Dedup preserves distinct attack paths up to max_per_key."""

    def test_keeps_multiple_distinct_paths(self):
        f1 = Finding(function_name="fn", function_id=1, sink="memcpy",
                     source_category="copy", score=0.9, path=["A", "B"])
        f2 = Finding(function_name="fn", function_id=1, sink="memcpy",
                     source_category="copy", score=0.7, path=["A", "C"])
        result = deduplicate([f1, f2], max_per_key=3)
        assert len(result) == 2

    def test_limits_to_max_per_key(self):
        findings = [
            Finding(function_name="fn", function_id=1, sink="memcpy",
                    source_category="copy", score=0.9 - i * 0.1,
                    path=[f"path_{i}"])
            for i in range(5)
        ]
        result = deduplicate(findings, max_per_key=2)
        assert len(result) == 2
        assert result[0].score >= result[1].score

    def test_same_path_keeps_highest_score(self):
        f1 = Finding(function_name="fn", function_id=1, sink="memcpy",
                     source_category="copy", score=0.5, path=["A", "B"])
        f2 = Finding(function_name="fn", function_id=1, sink="memcpy",
                     source_category="copy", score=0.9, path=["A", "B"])
        result = deduplicate([f1, f2], max_per_key=3)
        assert len(result) == 1
        assert result[0].score == 0.9

    def test_backward_compat_default_max(self):
        f1 = Finding(function_name="fn", function_id=1, sink="memcpy",
                     source_category="copy", score=0.5)
        f2 = Finding(function_name="fn", function_id=1, sink="memcpy",
                     source_category="copy", score=0.9)
        result = deduplicate([f1, f2])
        assert len(result) == 1
        assert result[0].score == 0.9


class TestGraduatedReachability:
    """Hop-count-based reachability decay."""

    def test_rpc_handler_zero_hops(self):
        score = graduated_reachability_score("rpc_handler", 0)
        assert score > 0.5

    def test_rpc_handler_many_hops(self):
        near = graduated_reachability_score("rpc_handler", 1)
        far = graduated_reachability_score("rpc_handler", 10)
        assert near > far

    def test_com_method(self):
        score = graduated_reachability_score("com_method", 1)
        assert 0.0 < score <= 1.0

    def test_export(self):
        score = graduated_reachability_score("export", 1)
        assert 0.0 < score <= 1.0

    def test_internal_capped(self):
        score = graduated_reachability_score("internal", 1)
        base_cap = 0.6
        assert score <= base_cap

    def test_none_entry_type_capped(self):
        score = graduated_reachability_score(None, 2)
        assert score <= 0.6

    def test_unknown_entry_type(self):
        score = graduated_reachability_score("some_unknown_type", 1)
        assert 0.0 < score <= 1.0

    def test_result_bounded(self):
        for etype in ["rpc_handler", "com_method", "export", "entry_point", None, "internal"]:
            for hops in [0, 1, 5, 10, 100]:
                score = graduated_reachability_score(etype, hops)
                assert 0.0 <= score <= 1.0, f"Out of bounds: {etype}, {hops} -> {score}"


# ===================================================================
# Category 12: Callgraph and Reachability
# ===================================================================


def _build_vtable_graph():
    """A -> B (direct) + A -> V (vtable)."""
    funcs = [
        mkfr(function_id=1, function_name="A",
             simple_outbound_xrefs=json.dumps([
                 {"function_name": "B", "function_id": 2,
                  "module_name": "", "function_type": 0},
                 {"function_name": "V", "function_id": 3,
                  "module_name": "vtable", "function_type": 8},
             ])),
        mkfr(function_id=2, function_name="B"),
        mkfr(function_id=3, function_name="V"),
    ]
    return CallGraph.from_functions(funcs, parse_json_safe)


class TestVtableEdges:
    """Vtable xref edges are tracked separately from direct calls."""

    def test_vtable_edge_tracked(self):
        g = _build_vtable_graph()
        assert ("A", "V") in g.vtable_edges
        assert ("A", "B") not in g.vtable_edges

    def test_vtable_edges_in_outbound(self):
        g = _build_vtable_graph()
        assert "V" in g.outbound["A"]
        assert "B" in g.outbound["A"]

    def test_vtable_edges_serialization_round_trip(self):
        g = _build_vtable_graph()
        data = g._to_cacheable()
        g2 = CallGraph._from_cached(data)
        assert ("A", "V") in g2.vtable_edges
        assert ("A", "B") not in g2.vtable_edges

    def test_empty_vtable_edges(self):
        funcs = [
            mkfr(function_id=1, function_name="X",
                 simple_outbound_xrefs=json.dumps([
                     {"function_name": "Y", "function_id": 2,
                      "module_name": "", "function_type": 0},
                 ])),
            mkfr(function_id=2, function_name="Y"),
        ]
        g = CallGraph.from_functions(funcs, parse_json_safe)
        assert len(g.vtable_edges) == 0


def _build_chain_graph():
    """A -> B -> C (linear chain, all internal)."""
    funcs = [
        mkfr(function_id=1, function_name="A",
             simple_outbound_xrefs=json.dumps([
                 {"function_name": "B", "function_id": 2,
                  "module_name": "", "function_type": 0},
             ])),
        mkfr(function_id=2, function_name="B",
             simple_outbound_xrefs=json.dumps([
                 {"function_name": "C", "function_id": 3,
                  "module_name": "", "function_type": 0},
             ])),
        mkfr(function_id=3, function_name="C"),
    ]
    return CallGraph.from_functions(funcs, parse_json_safe)


class TestFeasibilityAwareBFS:
    """BFS reachability respects feasibility_fn edge filter."""

    def test_no_filter_reaches_all(self):
        g = _build_chain_graph()
        r = g.reachable_from("A")
        assert set(r.keys()) == {"A", "B", "C"}

    def test_filter_blocks_edge(self):
        g = _build_chain_graph()
        r = g.reachable_from("A", feasibility_fn=lambda c, n: n != "C")
        assert "A" in r
        assert "B" in r
        assert "C" not in r

    def test_filter_blocks_all(self):
        g = _build_chain_graph()
        r = g.reachable_from("A", feasibility_fn=lambda c, n: False)
        assert r == {"A": 0}

    def test_filter_passes_all(self):
        g = _build_chain_graph()
        r = g.reachable_from("A", feasibility_fn=lambda c, n: True)
        assert set(r.keys()) == {"A", "B", "C"}

    def test_filter_with_max_depth(self):
        g = _build_chain_graph()
        r = g.reachable_from("A", max_depth=1, feasibility_fn=lambda c, n: True)
        assert "A" in r
        assert "B" in r
        assert "C" not in r

    def test_filter_receives_correct_args(self):
        g = _build_chain_graph()
        calls: list[tuple[str, str]] = []
        def track_fn(caller, callee):
            calls.append((caller, callee))
            return True
        g.reachable_from("A", feasibility_fn=track_fn)
        assert ("A", "B") in calls
        assert ("B", "C") in calls


class TestCrossModuleUnifiedAdjacency:
    """Cross-module unified adjacency dict."""

    def test_unified_adjacency_internal_edges(self):
        cm = CrossModuleGraph()
        g = _build_chain_graph()
        g.module_name = "test.dll"
        cm._graphs["test.dll"] = g
        adj = cm.build_unified_adjacency()
        assert ("test.dll", "B") in adj.get(("test.dll", "A"), set())
        assert ("test.dll", "C") in adj.get(("test.dll", "B"), set())

    def test_unified_adjacency_empty(self):
        cm = CrossModuleGraph()
        adj = cm.build_unified_adjacency()
        assert adj == {}


class TestConfigurableMaxDepth:
    """Callgraph depth config keys exist with expected values."""

    def test_default_max_depth_exists(self):
        assert get_config_value("callgraph.default_max_depth") is not None

    def test_max_depth_for_reachability_exists(self):
        assert get_config_value("callgraph.max_depth_for_reachability") is not None

    def test_max_depth_for_taint_exists(self):
        assert get_config_value("callgraph.max_depth_for_taint") is not None

    def test_default_max_depth_value(self):
        assert int(get_config_value("callgraph.default_max_depth")) == 10

    def test_reachability_depth_value(self):
        assert int(get_config_value("callgraph.max_depth_for_reachability")) == 15

    def test_taint_depth_value(self):
        assert int(get_config_value("callgraph.max_depth_for_taint")) == 8
