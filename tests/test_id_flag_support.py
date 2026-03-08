"""Tests for --id / --function-id support across all scripts.

Validates the best practice: "After resolving a function, use --id
<function_id> in all subsequent calls."

Covers:
  - CallGraph.find_function_by_id()           (helpers/callgraph.py)
  - resolve_function with function_id          (helpers/function_resolver.py)
  - string_trace.py --id                      (data-flow-tracer)
  - generate_diagram.py --id                  (callgraph-tracer)
  - build_call_graph.py --id                  (callgraph-tracer)
  - cross_module_resolve.py --id              (callgraph-tracer)
  - scan_struct_fields.py --id                (reconstruct-types)
  - collect_functions.py --id                 (batch-lift)
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from helpers.callgraph import CallGraph
from helpers.individual_analysis_db.db import IndividualAnalysisDB
from helpers.individual_analysis_db.records import parse_json_safe
from helpers.function_resolver import resolve_function
from helpers.script_runner import load_skill_module
from conftest import _make_function_record as mkfr, _create_sample_db


# ===================================================================
# Helpers
# ===================================================================

def _xrefs_json(*callees: tuple[str, int | None]) -> str:
    return json.dumps([
        {"function_name": name, "function_id": fid, "module_name": "", "function_type": 0}
        for name, fid in callees
    ])


def _build_test_graph():
    """A -> B -> C, all internal, IDs 1/2/3."""
    funcs = [
        mkfr(function_id=1, function_name="FuncA",
             simple_outbound_xrefs=_xrefs_json(("FuncB", 2))),
        mkfr(function_id=2, function_name="FuncB",
             simple_outbound_xrefs=_xrefs_json(("FuncC", 3))),
        mkfr(function_id=3, function_name="FuncC"),
    ]
    return CallGraph.from_functions(funcs, parse_json_safe)


def _load_skill(skill_name: str, module_name: str):
    """Load a skill module, pre-loading _common first to avoid collisions."""
    load_skill_module(skill_name, "_common")
    return load_skill_module(skill_name, module_name)


@pytest.fixture
def id_test_db(tmp_path):
    """DB with 3 functions suitable for --id testing."""
    db_path = tmp_path / "id_test.db"
    _create_sample_db(db_path)

    conn = sqlite3.connect(db_path)
    conn.execute("""
        INSERT INTO file_info (file_name, file_extension, md5_hash)
        VALUES ('id_test.dll', '.dll', 'abc123')
    """)
    funcs = [
        (10, "void __fastcall Alpha(int)", None, None, "Alpha",
         "push rbp\nret", "void Alpha(int a1) { return; }",
         None, None, None,
         json.dumps([
             {"function_name": "Beta", "function_id": 20,
              "module_name": "internal", "function_type": 1},
         ]),
         None, None, None,
         json.dumps(["hello world"]),
         None, None, None, None),
        (20, "int __fastcall Beta(void)", None, None, "Beta",
         "xor eax, eax\nret", "int Beta() { return 0; }",
         None, None,
         json.dumps([
             {"function_name": "Alpha", "function_id": 10,
              "module_name": "internal", "function_type": 1},
         ]),
         json.dumps([
             {"function_name": "Gamma", "function_id": 30,
              "module_name": "internal", "function_type": 1},
         ]),
         None, None, None,
         json.dumps(["test string"]),
         None, None, None, None),
        (30, "void __fastcall Gamma(void)", None,
         "??0CFoo@@QEAA@XZ", "Gamma",
         "mov eax, 1\nret", "void Gamma() { *(DWORD*)(this + 8) = 1; }",
         None, None,
         json.dumps([
             {"function_name": "Beta", "function_id": 20,
              "module_name": "internal", "function_type": 1},
         ]),
         None, None, None, None, None, None, None, None, None),
    ]
    for f in funcs:
        conn.execute("""
            INSERT INTO functions (
                function_id, function_signature, function_signature_extended,
                mangled_name, function_name, assembly_code, decompiled_code,
                inbound_xrefs, outbound_xrefs, simple_inbound_xrefs,
                simple_outbound_xrefs, vtable_contexts, global_var_accesses,
                dangerous_api_calls, string_literals, stack_frame,
                loop_analysis, analysis_errors, created_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, f)
    conn.commit()
    conn.close()
    return db_path


# ===================================================================
# CallGraph.find_function_by_id
# ===================================================================

class TestCallGraphFindFunctionById:
    def test_found(self):
        g = _build_test_graph()
        assert g.find_function_by_id(1) == "FuncA"
        assert g.find_function_by_id(2) == "FuncB"
        assert g.find_function_by_id(3) == "FuncC"

    def test_not_found(self):
        g = _build_test_graph()
        assert g.find_function_by_id(999) is None

    def test_zero_id(self):
        g = _build_test_graph()
        assert g.find_function_by_id(0) is None

    def test_negative_id(self):
        g = _build_test_graph()
        assert g.find_function_by_id(-1) is None

    def test_after_serialization_roundtrip(self):
        g = _build_test_graph()
        data = g._to_cacheable()
        g2 = CallGraph._from_cached(data)
        assert g2.find_function_by_id(1) == "FuncA"
        assert g2.find_function_by_id(999) is None


# ===================================================================
# resolve_function with function_id (the pattern all scripts use)
# ===================================================================

class TestResolveFunctionById:
    def test_resolve_by_id(self, id_test_db):
        with IndividualAnalysisDB(id_test_db) as db:
            func, err = resolve_function(db, function_id=10)
            assert func is not None
            assert func.function_name == "Alpha"
            assert err is None

    def test_resolve_by_id_not_found(self, id_test_db):
        with IndividualAnalysisDB(id_test_db) as db:
            func, err = resolve_function(db, function_id=999)
            assert func is None
            assert err is not None

    def test_id_takes_priority_over_name(self, id_test_db):
        with IndividualAnalysisDB(id_test_db) as db:
            func, err = resolve_function(db, name="Beta", function_id=10)
            assert func is not None
            assert func.function_name == "Alpha"


# ===================================================================
# string_trace.py: _find_function_strings with function_id
# ===================================================================

class TestStringTraceIdSupport:
    @pytest.fixture(autouse=True)
    def _load_module(self):
        self.mod = _load_skill("data-flow-tracer", "string_trace")

    def test_find_function_strings_by_id(self, id_test_db):
        results = self.mod._find_function_strings(str(id_test_db), function_id=10)
        assert len(results) == 1
        assert results[0]["function_name"] == "Alpha"
        assert "hello world" in results[0]["all_strings"]

    def test_find_function_strings_by_id_not_found(self, id_test_db):
        results = self.mod._find_function_strings(str(id_test_db), function_id=999)
        assert results == []

    def test_trace_function_strings_by_id(self, id_test_db):
        result = self.mod.trace_function_strings(str(id_test_db), function_id=10)
        assert result["status"] == "ok"
        assert len(result["functions"]) == 1
        assert result["functions"][0]["function_name"] == "Alpha"

    def test_trace_function_strings_by_id_not_found(self, id_test_db):
        result = self.mod.trace_function_strings(str(id_test_db), function_id=999)
        assert result["status"] == "not_found"


# ===================================================================
# generate_diagram.py: build_subgraph with start_func_id
# ===================================================================

class TestGenerateDiagramIdSupport:
    @pytest.fixture(autouse=True)
    def _load_module(self):
        self.mod = _load_skill("callgraph-tracer", "generate_diagram")

    def test_build_subgraph_by_id(self, id_test_db):
        edges, internal, external = self.mod.build_subgraph(
            str(id_test_db), start_func_id=10, max_depth=1,
        )
        assert "Alpha" in internal
        assert "Beta" in internal

    def test_build_subgraph_by_id_not_found(self, id_test_db):
        with pytest.raises(SystemExit):
            self.mod.build_subgraph(str(id_test_db), start_func_id=999, max_depth=1)


# ===================================================================
# build_call_graph.py: --id with CallGraph.find_function_by_id
# ===================================================================

class TestBuildCallGraphIdSupport:
    def test_find_function_by_id_then_reachable(self):
        g = _build_test_graph()
        name = g.find_function_by_id(2)
        assert name == "FuncB"
        reachable = g.reachable_from(name)
        assert "FuncC" in reachable

    def test_find_function_by_id_then_callers(self):
        g = _build_test_graph()
        name = g.find_function_by_id(3)
        assert name == "FuncC"
        callers = g.callers_of(name)
        assert "FuncB" in callers
        assert "FuncA" in callers

    def test_find_function_by_id_then_neighbors(self):
        g = _build_test_graph()
        name = g.find_function_by_id(2)
        assert name == "FuncB"
        callees, callers = g.neighbors(name)
        assert "FuncC" in callees
        assert "FuncA" in callers

    def test_find_function_by_id_unknown_returns_none(self):
        g = _build_test_graph()
        assert g.find_function_by_id(999) is None


# ===================================================================
# cross_module_resolve.py: resolve_from_function with function_id
# ===================================================================

class TestCrossModuleResolveIdSupport:
    @pytest.fixture(autouse=True)
    def _load_module(self):
        self.mod = _load_skill("callgraph-tracer", "cross_module_resolve")

    def test_resolve_from_function_by_id(self, id_test_db, capsys):
        self.mod.resolve_from_function(
            str(id_test_db), "_ignored_",
            function_id=10, as_json=False,
        )
        captured = capsys.readouterr()
        assert "Alpha" in captured.out

    def test_resolve_from_function_bad_id(self, id_test_db):
        with pytest.raises(SystemExit):
            self.mod.resolve_from_function(
                str(id_test_db), "_ignored_",
                function_id=999, as_json=False,
            )

    def test_resolve_all_xrefs_by_id(self, id_test_db, capsys):
        self.mod.resolve_all_xrefs(
            str(id_test_db), "_ignored_",
            function_id=10, as_json=False,
        )
        captured = capsys.readouterr()
        assert "Alpha" in captured.out

    def test_resolve_all_xrefs_bad_id(self, id_test_db):
        with pytest.raises(SystemExit):
            self.mod.resolve_all_xrefs(
                str(id_test_db), "_ignored_",
                function_id=999, as_json=False,
            )


# ===================================================================
# scan_struct_fields.py: scan_module with function_id
# ===================================================================

class TestScanStructFieldsIdSupport:
    @pytest.fixture(autouse=True)
    def _load_module(self):
        self.mod = _load_skill("reconstruct-types", "scan_struct_fields")

    def test_scan_module_by_id(self, id_test_db):
        result = self.mod.scan_module(str(id_test_db), function_id=30)
        assert result["functions_scanned"] == 1
        scanned_names = list(result["per_function"].keys())
        assert len(scanned_names) == 1
        assert "Gamma" in scanned_names[0]

    def test_scan_module_by_id_not_found(self, id_test_db):
        result = self.mod.scan_module(str(id_test_db), function_id=999)
        assert result["functions_scanned"] == 0


# ===================================================================
# collect_functions.py: collect_call_chain with start_id
# ===================================================================

class TestCollectFunctionsIdSupport:
    @pytest.fixture(autouse=True)
    def _load_module(self):
        self.mod = _load_skill("batch-lift", "collect_functions")

    def test_collect_chain_by_id(self, id_test_db):
        result = self.mod.collect_call_chain(str(id_test_db), start_id=10, max_depth=1)
        assert result["start_function"] == "Alpha"
        assert result["function_count"] >= 1
        names = [f["function_name"] for f in result["functions"]]
        assert "Alpha" in names

    def test_collect_chain_by_id_reaches_callees(self, id_test_db):
        result = self.mod.collect_call_chain(str(id_test_db), start_id=10, max_depth=2)
        names = [f["function_name"] for f in result["functions"]]
        assert "Alpha" in names
        assert "Beta" in names

    def test_collect_chain_by_id_not_found(self, id_test_db):
        with pytest.raises(SystemExit):
            self.mod.collect_call_chain(str(id_test_db), start_id=999, max_depth=1)

    def test_collect_export_down_by_id(self, id_test_db):
        result = self.mod.collect_export_down(
            str(id_test_db), "_ignored_", function_id=10, max_depth=1,
        )
        assert result["start_function"] == "Alpha"
        assert result["mode"] == "export_down"

    def test_collect_export_down_by_id_not_found(self, id_test_db):
        with pytest.raises(SystemExit):
            self.mod.collect_export_down(
                str(id_test_db), "_ignored_", function_id=999, max_depth=1,
            )
