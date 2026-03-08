"""Tests for the CallGraph class.

Target: helpers/callgraph.py
"""

from __future__ import annotations

import json

import pytest

from helpers.callgraph import CallGraph, _is_followable_xref
from helpers.individual_analysis_db.records import parse_json_safe
from conftest import _make_function_record as mkfr


# ---------------------------------------------------------------------------
# Helpers for building test graphs
# ---------------------------------------------------------------------------

def _xrefs_json(*callees: tuple[str, int | None]) -> str:
    """Build a simple_outbound_xrefs JSON string."""
    return json.dumps([
        {"function_name": name, "function_id": fid, "module_name": "", "function_type": 0}
        for name, fid in callees
    ])


def _build_chain_graph():
    """A -> B -> C (linear chain, all internal)."""
    funcs = [
        mkfr(function_id=1, function_name="A",
             simple_outbound_xrefs=_xrefs_json(("B", 2))),
        mkfr(function_id=2, function_name="B",
             simple_outbound_xrefs=_xrefs_json(("C", 3))),
        mkfr(function_id=3, function_name="C"),
    ]
    return CallGraph.from_functions(funcs, parse_json_safe)


def _build_diamond_graph():
    """A -> B -> D, A -> C -> D (diamond)."""
    funcs = [
        mkfr(function_id=1, function_name="A",
             simple_outbound_xrefs=_xrefs_json(("B", 2), ("C", 3))),
        mkfr(function_id=2, function_name="B",
             simple_outbound_xrefs=_xrefs_json(("D", 4))),
        mkfr(function_id=3, function_name="C",
             simple_outbound_xrefs=_xrefs_json(("D", 4))),
        mkfr(function_id=4, function_name="D"),
    ]
    return CallGraph.from_functions(funcs, parse_json_safe)


def _build_cycle_graph():
    """A -> B -> C -> A (cycle)."""
    funcs = [
        mkfr(function_id=1, function_name="A",
             simple_outbound_xrefs=_xrefs_json(("B", 2))),
        mkfr(function_id=2, function_name="B",
             simple_outbound_xrefs=_xrefs_json(("C", 3))),
        mkfr(function_id=3, function_name="C",
             simple_outbound_xrefs=_xrefs_json(("A", 1))),
    ]
    return CallGraph.from_functions(funcs, parse_json_safe)


def _build_external_graph():
    """A calls internal B and external CreateFileW."""
    funcs = [
        mkfr(function_id=1, function_name="A",
             simple_outbound_xrefs=json.dumps([
                 {"function_name": "B", "function_id": 2, "module_name": "", "function_type": 0},
                 {"function_name": "CreateFileW", "function_id": None, "module_name": "kernel32.dll", "function_type": 0},
             ])),
        mkfr(function_id=2, function_name="B"),
    ]
    return CallGraph.from_functions(funcs, parse_json_safe)


# ===================================================================
# _is_followable_xref
# ===================================================================

class TestIsFollowableXref:
    def test_normal_call(self):
        assert _is_followable_xref({"function_name": "foo", "module_name": "", "function_type": 0}) is True

    def test_data_ref_skipped(self):
        assert _is_followable_xref({"function_name": "g_var", "module_name": "data", "function_type": 4}) is False

    def test_vtable_ref_followable_by_default(self):
        assert _is_followable_xref({"function_name": "vt", "module_name": "vtable", "function_type": 8}) is True

    def test_vtable_ref_skipped_when_excluded(self):
        assert _is_followable_xref({"function_name": "vt", "module_name": "vtable", "function_type": 8}, include_vtable=False) is False

    def test_external_call(self):
        assert _is_followable_xref({"function_name": "CreateFileW", "module_name": "kernel32.dll", "function_type": 0}) is True


# ===================================================================
# Graph construction
# ===================================================================

class TestGraphConstruction:
    def test_from_functions_basic(self):
        g = _build_chain_graph()
        assert "A" in g.all_nodes
        assert "B" in g.all_nodes
        assert "C" in g.all_nodes
        assert len(g.all_nodes) == 3

    def test_name_to_id(self):
        g = _build_chain_graph()
        assert g.name_to_id["A"] == 1
        assert g.name_to_id["B"] == 2

    def test_outbound_edges(self):
        g = _build_chain_graph()
        assert "B" in g.outbound["A"]
        assert "C" in g.outbound["B"]

    def test_inbound_edges(self):
        g = _build_chain_graph()
        assert "A" in g.inbound["B"]
        assert "B" in g.inbound["C"]

    def test_external_calls_tracked(self):
        g = _build_external_graph()
        assert "CreateFileW" in g.all_nodes
        ext = g.external_calls.get("A", set())
        assert ("CreateFileW", "kernel32.dll") in ext

    def test_empty_function_list(self):
        g = CallGraph.from_functions([], parse_json_safe)
        assert len(g.all_nodes) == 0

    def test_function_with_no_xrefs(self):
        funcs = [mkfr(function_id=1, function_name="Lonely")]
        g = CallGraph.from_functions(funcs, parse_json_safe)
        assert "Lonely" in g.all_nodes
        assert len(g.outbound.get("Lonely", set())) == 0

    def test_skips_none_function_name(self):
        funcs = [mkfr(function_id=1, function_name=None)]
        g = CallGraph.from_functions(funcs, parse_json_safe)
        assert len(g.all_nodes) == 0


# ===================================================================
# BFS forward: reachable_from
# ===================================================================

class TestReachableFrom:
    def test_linear_chain(self):
        g = _build_chain_graph()
        r = g.reachable_from("A")
        assert r == {"A": 0, "B": 1, "C": 2}

    def test_max_depth_limits(self):
        g = _build_chain_graph()
        r = g.reachable_from("A", max_depth=1)
        assert "A" in r
        assert "B" in r
        assert "C" not in r

    def test_unknown_node(self):
        g = _build_chain_graph()
        assert g.reachable_from("NONEXISTENT") == {}

    def test_leaf_node(self):
        g = _build_chain_graph()
        r = g.reachable_from("C")
        assert r == {"C": 0}

    def test_cycle_terminates(self):
        g = _build_cycle_graph()
        r = g.reachable_from("A")
        assert set(r.keys()) == {"A", "B", "C"}


# ===================================================================
# BFS reverse: callers_of
# ===================================================================

class TestCallersOf:
    def test_reverse_chain(self):
        g = _build_chain_graph()
        c = g.callers_of("C")
        assert c == {"C": 0, "B": 1, "A": 2}

    def test_unknown_target(self):
        g = _build_chain_graph()
        assert g.callers_of("NONEXISTENT") == {}

    def test_max_depth(self):
        g = _build_chain_graph()
        c = g.callers_of("C", max_depth=1)
        assert "B" in c
        assert "A" not in c


# ===================================================================
# Path finding
# ===================================================================

class TestPathFinding:
    def test_bfs_path_exists(self):
        g = _build_chain_graph()
        p = g.bfs_path("A", "C")
        assert p == ["A", "B", "C"]

    def test_bfs_path_not_found(self):
        g = _build_chain_graph()
        assert g.bfs_path("C", "A") is None

    def test_bfs_path_same_node(self):
        g = _build_chain_graph()
        assert g.bfs_path("A", "A") == ["A"]

    def test_bfs_path_unknown_source(self):
        g = _build_chain_graph()
        assert g.bfs_path("X", "A") is None

    def test_all_paths_diamond(self):
        g = _build_diamond_graph()
        paths = g.all_paths("A", "D")
        assert len(paths) == 2
        path_strs = [" -> ".join(p) for p in sorted(paths)]
        assert "A -> B -> D" in path_strs
        assert "A -> C -> D" in path_strs

    def test_all_paths_no_path(self):
        g = _build_chain_graph()
        assert g.all_paths("C", "A") == []

    def test_shortest_path_reverse(self):
        g = _build_chain_graph()
        path = g.shortest_path_reverse("C", {"A"})
        assert path == ["A", "B", "C"]

    def test_shortest_path_reverse_target_in_sources(self):
        g = _build_chain_graph()
        path = g.shortest_path_reverse("A", {"A"})
        assert path == ["A"]


# ===================================================================
# Structural queries
# ===================================================================

class TestStructural:
    def test_scc_detects_cycle(self):
        g = _build_cycle_graph()
        sccs = g.strongly_connected_components()
        assert len(sccs) == 1
        assert set(sccs[0]) == {"A", "B", "C"}

    def test_scc_no_cycles(self):
        g = _build_chain_graph()
        sccs = g.strongly_connected_components()
        assert len(sccs) == 0

    def test_leaf_functions(self):
        g = _build_chain_graph()
        leaves = g.leaf_functions()
        assert "C" in leaves
        assert "A" not in leaves

    def test_root_functions(self):
        g = _build_chain_graph()
        roots = g.root_functions()
        assert "A" in roots
        assert "C" not in roots

    def test_neighbors(self):
        g = _build_diamond_graph()
        callees, callers = g.neighbors("A")
        assert "B" in callees
        assert "C" in callees
        assert len(callers) == 0

    def test_neighbors_unknown(self):
        g = _build_chain_graph()
        callees, callers = g.neighbors("NONEXISTENT")
        assert len(callees) == 0
        assert len(callers) == 0

    def test_max_depth_from(self):
        g = _build_chain_graph()
        assert g.max_depth_from("A") == 2
        assert g.max_depth_from("C") == 0

    def test_max_depth_from_unknown(self):
        g = _build_chain_graph()
        assert g.max_depth_from("NONEXISTENT") == 0


# ===================================================================
# Statistics
# ===================================================================

class TestStats:
    def test_stats_keys(self):
        g = _build_chain_graph()
        s = g.stats()
        assert "internal_functions" in s
        assert "total_nodes" in s
        assert "total_edges" in s

    def test_stats_values(self):
        g = _build_chain_graph()
        s = g.stats()
        assert s["internal_functions"] == 3
        assert s["total_nodes"] == 3
        assert s["total_edges"] == 2  # A->B, B->C


# ===================================================================
# Serialization round-trip
# ===================================================================

class TestSerialization:
    def test_round_trip(self):
        g = _build_diamond_graph()
        data = g._to_cacheable()
        g2 = CallGraph._from_cached(data)
        assert g2.all_nodes == g.all_nodes
        assert set(g2.outbound["A"]) == set(g.outbound["A"])
        assert g2.name_to_id == g.name_to_id


# ===================================================================
# ID-based helpers
# ===================================================================

class TestIdHelpers:
    def test_id_forward_edges(self):
        g = _build_chain_graph()
        fwd = g.id_forward_edges()
        assert 2 in fwd[1]  # A(1) -> B(2)
        assert 3 in fwd[2]  # B(2) -> C(3)

    def test_id_reverse_edges(self):
        g = _build_chain_graph()
        rev = g.id_reverse_edges()
        assert 1 in rev[2]  # B(2) <- A(1)

    def test_id_external_calls(self):
        g = _build_external_graph()
        ext = g.id_external_calls()
        assert "CreateFileW" in ext[1]
